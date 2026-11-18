"""Master (primary) authoritative node for the lab.test zone.

Publishes the full set of A records over HTTP (manageable via /docs):
- every publish (single upsert/delete or bulk replace) runs in one SQLite
  transaction that also bumps an incrementing SOA serial and stores an
  immutable, checksummed snapshot of the whole zone;
- slaves pull /zone/snapshot and apply it atomically;
- /zone/snapshot?serial=N serves older versions (kept up to KEEP_VERSIONS)
  so late/arbitrary pulls can be exercised;
- /debug/snapshot/truncated and /debug/snapshot/corrupt exist only to let
  tests simulate a broken transfer / tampered payload.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, closing
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

ZONE = "lab.test"
DB_PATH = os.environ.get("MASTER_DB", "/data/master.db")
DEFAULT_TTL = 300
KEEP_VERSIONS = int(os.environ.get("KEEP_VERSIONS", "100"))

SOA_TEMPLATE = {
    "mname": "ns1.lab.test.",
    "rname": "hostmaster.lab.test.",
    "refresh": 7200,
    "retry": 3600,
    "expire": 1209600,
    "minimum": 300,
}

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Serializes publishes inside this process; SQLite serializes across processes.
_publish_lock = threading.Lock()


# --------------------------------------------------------------------------
# storage
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
            CREATE TABLE IF NOT EXISTS records(
                name TEXT PRIMARY KEY,
                ip   TEXT NOT NULL,
                ttl  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta(
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS versions(
                serial     INTEGER PRIMARY KEY,
                snapshot   TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        row = conn.execute("SELECT value FROM meta WHERE key='serial'").fetchone()
        if row is None:
            # Version 1: the empty zone, so a serial always exists.
            conn.execute("INSERT INTO meta(key, value) VALUES('serial', '1')")
            snap = _snapshot_json(1, [])
            conn.execute(
                "INSERT INTO versions(serial, snapshot, created_at) VALUES (1, ?, ?)",
                (json.dumps(snap), time.time()),
            )
        conn.commit()


def _records(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT name, ip, ttl FROM records ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def _current_serial(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT value FROM meta WHERE key='serial'").fetchone()["value"])


def _snapshot_json(serial: int, records: list[dict]) -> dict:
    payload = {
        "zone": ZONE,
        "serial": serial,
        "soa": {**SOA_TEMPLATE, "serial": serial},
        "records": records,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {**payload, "sha256": digest}


def _publish_locked(conn: sqlite3.Connection) -> dict:
    """Bump the serial and store an immutable snapshot of the current records.

    Must be called inside conn's transaction, with _publish_lock held.
    """
    serial = _current_serial(conn) + 1
    snap = _snapshot_json(serial, _records(conn))
    conn.execute("UPDATE meta SET value=? WHERE key='serial'", (str(serial),))
    conn.execute(
        "INSERT INTO versions(serial, snapshot, created_at) VALUES (?, ?, ?)",
        (serial, json.dumps(snap), time.time()),
    )
    conn.execute(
        "DELETE FROM versions WHERE serial NOT IN "
        "(SELECT serial FROM versions ORDER BY serial DESC LIMIT ?)",
        (KEEP_VERSIONS,),
    )
    return snap


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    n = name.strip().rstrip(".").lower()
    if not n:
        raise HTTPException(400, "empty name")
    if n != ZONE and not n.endswith("." + ZONE):
        raise HTTPException(400, f"name {n!r} is outside zone {ZONE}")
    for label in n.split("."):
        if not _LABEL_RE.match(label):
            raise HTTPException(400, f"bad label {label!r} in name {n!r}")
    return n


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except ValueError:
        raise HTTPException(400, f"invalid IPv4 address {ip!r}")


def validate_ttl(ttl: int) -> int:
    if not (0 <= ttl <= 2**31 - 1):
        raise HTTPException(400, f"ttl {ttl} out of range")
    return ttl


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

class RecordPut(BaseModel):
    ip: str
    ttl: int = Field(DEFAULT_TTL, ge=0, le=2**31 - 1)


class RecordIn(BaseModel):
    name: str
    ip: str
    ttl: int = Field(DEFAULT_TTL, ge=0, le=2**31 - 1)


class BulkReplace(BaseModel):
    records: list[RecordIn]


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="lab.test DNS master",
    description="Publishes the full A-record set of lab.test with an "
    "incrementing SOA serial; slaves pull /zone/snapshot.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
def root() -> dict:
    with closing(connect()) as conn:
        serial = _current_serial(conn)
    return {"service": "dns-master", "zone": ZONE, "serial": serial}


@app.get("/records")
def list_records() -> dict:
    with closing(connect()) as conn:
        return {"serial": _current_serial(conn), "records": _records(conn)}


@app.put("/records/{name}")
def put_record(name: str, body: RecordPut) -> dict:
    """Create or update one A record and publish a new zone version."""
    n = normalize_name(name)
    ip = validate_ip(body.ip)
    ttl = validate_ttl(body.ttl)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO records(name, ip, ttl) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET ip=excluded.ip, ttl=excluded.ttl",
            (n, ip, ttl),
        )
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "record": {"name": n, "ip": ip, "ttl": ttl}}


@app.delete("/records/{name}")
def delete_record(name: str) -> dict:
    """Delete one A record and publish a new zone version."""
    n = normalize_name(name)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute("DELETE FROM records WHERE name=?", (n,))
        if cur.rowcount == 0:
            conn.rollback()
            raise HTTPException(404, f"no such record {n!r}")
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "deleted": n}


@app.post("/records/bulk")
def bulk_replace(body: BulkReplace) -> dict:
    """Atomically replace the whole A-record set (one new zone version)."""
    items: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for r in body.records:
        n = normalize_name(r.name)
        if n in seen:
            raise HTTPException(400, f"duplicate name {n!r} in bulk request")
        seen.add(n)
        items.append((n, validate_ip(r.ip), validate_ttl(r.ttl)))
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM records")
        conn.executemany("INSERT INTO records(name, ip, ttl) VALUES (?, ?, ?)", items)
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "records": len(items)}


@app.get("/zone/serial")
def zone_serial() -> dict:
    """The currently published SOA serial."""
    with closing(connect()) as conn:
        return {"serial": _current_serial(conn)}


@app.get("/zone/versions")
def zone_versions() -> dict:
    with closing(connect()) as conn:
        rows = conn.execute("SELECT serial FROM versions ORDER BY serial").fetchall()
    return {"serials": [r["serial"] for r in rows]}


@app.get("/zone/snapshot")
def zone_snapshot(serial: Optional[int] = None) -> dict:
    """Full zone snapshot: latest version, or a specific kept version."""
    with closing(connect()) as conn:
        if serial is None:
            row = conn.execute(
                "SELECT snapshot FROM versions ORDER BY serial DESC LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT snapshot FROM versions WHERE serial=?", (serial,)
            ).fetchone()
    if row is None:
        raise HTTPException(
            404, "no such serial" if serial is not None else "no version published yet"
        )
    return json.loads(row["snapshot"])


# --------------------------------------------------------------------------
# test-only fault injection
# --------------------------------------------------------------------------

def _latest_snapshot_bytes() -> bytes:
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT snapshot FROM versions ORDER BY serial DESC LIMIT 1"
        ).fetchone()
    if row is None:
        raise HTTPException(404, "no version published yet")
    return row["snapshot"].encode()


@app.get("/debug/snapshot/truncated")
def debug_truncated() -> StreamingResponse:
    """Drops the connection in the middle of the body (simulates断流)."""
    raw = _latest_snapshot_bytes()
    half = raw[: max(1, len(raw) // 2)]

    def gen():
        yield half
        raise RuntimeError("simulated upstream disconnect")

    return StreamingResponse(gen(), media_type="application/json")


@app.get("/debug/snapshot/corrupt")
def debug_corrupt() -> dict:
    """Returns a syntactically valid snapshot with a wrong checksum."""
    snap = json.loads(_latest_snapshot_bytes())
    snap["sha256"] = "0" * 64
    return snap
