"""Slave (secondary) authoritative node for the lab.test zone.

Pulls full zone snapshots from the master over HTTP and serves DNS over UDP.

Guarantees:
- atomic version switch: a snapshot is verified (shape + SHA-256), written to
  SQLite in a single transaction, and only then swapped into memory — clients
  never see a mix of old and new records, and every answer's records and SOA
  come from the same version;
- no rollback: a snapshot whose serial is not greater than the active one is
  rejected, so a late old version can never overwrite a newer one;
- survives master outages and own restarts: the last good version is kept in
  SQLite and reloaded on boot; if no version was ever synced, the node answers
  SERVFAIL (unavailable) instead of guessing.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, closing
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from dnslab import dnsproto

ZONE = "lab.test"
DB_PATH = os.environ.get("SLAVE_DB", "/data/slave.db")
MASTER_URL = os.environ.get("MASTER_URL", "http://master:8000").rstrip("/")
DNS_HOST = os.environ.get("DNS_HOST", "0.0.0.0")
DNS_PORT = int(os.environ.get("DNS_PORT", "5353"))
SYNC_INTERVAL = float(os.environ.get("SYNC_INTERVAL", "0"))  # seconds; 0 = manual only
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "10"))

SOA_TIMERS = {"refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 300}


class ZoneData:
    """One immutable, internally consistent zone version."""

    __slots__ = ("serial", "soa", "records")

    def __init__(self, serial: int, soa: dict, records: dict):
        self.serial = serial
        self.soa = soa
        self.records = records  # {fqdn: (ip, ttl)}


class SlaveState:
    def __init__(self) -> None:
        self.zone: Optional[ZoneData] = None  # swapped atomically
        self.sync_lock = asyncio.Lock()
        self.last_attempt: Optional[str] = None
        self.last_success: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_source: Optional[str] = None


state = SlaveState()
_apply_lock = threading.Lock()  # serializes check+commit+swap


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with closing(connect()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records(
                name TEXT PRIMARY KEY,
                ip   TEXT NOT NULL,
                ttl  INTEGER NOT NULL
            );
            """
        )
        conn.commit()


def load_persisted() -> Optional[ZoneData]:
    """Rebuild the last successfully synced version from SQLite, if any."""
    with closing(connect()) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key='snapshot'").fetchone()
    if row is None:
        return None
    try:
        snap = json.loads(row["value"])
        verify_snapshot(snap)
        return _zone_from_snapshot(snap)
    except Exception:
        # Corrupt local state: better to report unavailable than serve junk.
        return None


def _zone_from_snapshot(snap: dict) -> ZoneData:
    records = {r["name"]: (r["ip"], int(r["ttl"])) for r in snap["records"]}
    return ZoneData(snap["serial"], dict(snap["soa"]), records)


# --------------------------------------------------------------------------
# snapshot verification + atomic apply
# --------------------------------------------------------------------------

def verify_snapshot(snap: dict) -> None:
    if not isinstance(snap, dict):
        raise ValueError("snapshot is not an object")
    for key in ("zone", "serial", "soa", "records", "sha256"):
        if key not in snap:
            raise ValueError(f"snapshot missing {key!r}")
    if snap["zone"] != ZONE:
        raise ValueError(f"snapshot is for zone {snap['zone']!r}, not {ZONE!r}")
    if not isinstance(snap["serial"], int) or snap["serial"] < 1:
        raise ValueError("bad serial")
    payload = {k: snap[k] for k in ("zone", "serial", "soa", "records")}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    if digest != snap["sha256"]:
        raise ValueError("sha256 mismatch")
    soa = snap["soa"]
    if not isinstance(soa, dict) or soa.get("serial") != snap["serial"]:
        raise ValueError("SOA serial does not match zone serial")
    if not isinstance(snap["records"], list):
        raise ValueError("records is not a list")
    for r in snap["records"]:
        name = str(r["name"]).rstrip(".").lower()
        if name != ZONE and not name.endswith("." + ZONE):
            raise ValueError(f"record {name!r} outside zone")
        ipaddress.IPv4Address(r["ip"])  # raises on junk
        ttl = int(r["ttl"])
        if not (0 <= ttl <= 2**31 - 1):
            raise ValueError(f"bad ttl {ttl}")


def apply_snapshot(snap: dict) -> tuple[bool, str]:
    """Apply a verified snapshot iff it is strictly newer than the active one.

    The new version is committed to SQLite first; the in-memory pointer is
    swapped only after the commit succeeds, so a crash can never leave memory
    ahead of durable state.
    """
    new_serial = snap["serial"]
    with _apply_lock:
        current = state.zone
        if current is not None and new_serial <= current.serial:
            return False, (
                f"stale: offered serial {new_serial} <= current {current.serial}"
            )
        zone = _zone_from_snapshot(snap)
        raw = json.dumps(snap, sort_keys=True)
        with closing(connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM records")
            conn.executemany(
                "INSERT INTO records(name, ip, ttl) VALUES (?, ?, ?)",
                [(n, ip, ttl) for n, (ip, ttl) in sorted(zone.records.items())],
            )
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('serial', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(new_serial),),
            )
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('snapshot', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (raw,),
            )
            conn.commit()
        state.zone = zone  # atomic swap, after durable commit
    return True, f"applied serial {new_serial} ({len(zone.records)} records)"


# --------------------------------------------------------------------------
# sync
# --------------------------------------------------------------------------

class SyncRequest(BaseModel):
    serial: Optional[int] = None  # pull a specific version instead of latest
    url: Optional[str] = None     # override source URL (default: master's snapshot)


async def do_sync(req: SyncRequest) -> dict:
    url = req.url or f"{MASTER_URL}/zone/snapshot"
    if req.serial is not None:
        url += ("&" if "?" in url else "?") + f"serial={req.serial}"
    async with state.sync_lock:
        state.last_attempt = _now()
        state.last_source = url
        try:
            async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
                resp = await client.get(url)
        except Exception as exc:  # includes mid-stream disconnects
            state.last_error = f"fetch failed: {exc}"
            raise HTTPException(502, state.last_error)
        if resp.status_code != 200:
            state.last_error = f"master returned HTTP {resp.status_code}"
            raise HTTPException(502, state.last_error)
        try:
            snap = json.loads(resp.content)
            verify_snapshot(snap)
        except Exception as exc:
            state.last_error = f"snapshot rejected: {exc}"
            raise HTTPException(502, state.last_error)
        applied, message = apply_snapshot(snap)
        if applied:
            state.last_success = _now()
            state.last_error = None
        return {
            "applied": applied,
            "reason": message,
            "serial": state.zone.serial if state.zone else None,
            "source": url,
        }


async def _poll_loop() -> None:
    while True:
        await asyncio.sleep(SYNC_INTERVAL)
        try:
            await do_sync(SyncRequest())
        except HTTPException:
            pass  # already recorded in state.last_error
        except Exception as exc:
            state.last_error = f"poll failed: {exc}"


# --------------------------------------------------------------------------
# DNS over UDP
# --------------------------------------------------------------------------

def handle_query(data: bytes) -> Optional[bytes]:
    try:
        query = dnsproto.Query(data)
    except dnsproto.DnsError:
        return dnsproto.formerr(data)
    zone = state.zone  # one atomic read -> whole answer from one version
    return dnsproto.answer(query, zone, ZONE)


class DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        response = handle_query(data)
        if response is not None:
            self.transport.sendto(response, addr)

    def error_received(self, exc):
        pass


# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    persisted = load_persisted()
    if persisted is not None:
        state.zone = persisted
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        DnsProtocol, local_addr=(DNS_HOST, DNS_PORT)
    )
    poller = asyncio.create_task(_poll_loop()) if SYNC_INTERVAL > 0 else None
    try:
        yield
    finally:
        transport.close()
        if poller is not None:
            poller.cancel()


app = FastAPI(
    title="lab.test DNS slave",
    description="Pulls snapshots from the master and answers A/SOA/NXDOMAIN "
    "over UDP. Only complete, newer versions are applied.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
def root() -> dict:
    return {"service": "dns-slave", "zone": ZONE, "serial": state.zone.serial if state.zone else None}


@app.get("/status")
def status() -> dict:
    """Active version and sync health (the serial shown here is the one being served)."""
    zone = state.zone
    return {
        "serving": zone is not None,
        "serial": zone.serial if zone else None,
        "records": len(zone.records) if zone else 0,
        "zone": ZONE,
        "master_url": MASTER_URL,
        "dns_port": DNS_PORT,
        "last_sync_attempt": state.last_attempt,
        "last_sync_success": state.last_success,
        "last_error": state.last_error,
        "last_source": state.last_source,
    }


@app.get("/zone")
def zone_dump() -> dict:
    """The version currently being served (503 if none)."""
    zone = state.zone
    if zone is None:
        raise HTTPException(503, "no version synced yet")
    return {
        "serial": zone.serial,
        "soa": zone.soa,
        "records": [
            {"name": n, "ip": ip, "ttl": ttl}
            for n, (ip, ttl) in sorted(zone.records.items())
        ],
    }


@app.post("/sync")
async def sync(req: Optional[SyncRequest] = None) -> dict:
    """Pull a snapshot from the master and apply it if complete and newer."""
    return await do_sync(req or SyncRequest())
