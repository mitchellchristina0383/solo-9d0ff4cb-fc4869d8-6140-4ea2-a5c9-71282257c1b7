#!/usr/bin/env python3
"""End-to-end self-test for the lab.test master/slave DNS setup.

Spins up real master and slave processes (uvicorn) on loopback and drives
them over HTTP and DNS/UDP. Exits non-zero if any check fails.

Run:  python tests/selftest.py
Env:  PYBIN (python with fastapi/uvicorn/httpx installed, default sys.executable)
      MASTER_PORT (18080) SLAVE_PORT (18081) SLAVE_DNS_PORT (15353)
      SLAVE2_PORT (18082) SLAVE2_DNS_PORT (15354)
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from dnslab import dnsproto  # noqa: E402

PYBIN = os.environ.get("PYBIN", sys.executable)
MASTER_PORT = int(os.environ.get("MASTER_PORT", "18080"))
SLAVE_PORT = int(os.environ.get("SLAVE_PORT", "18081"))
SLAVE_DNS_PORT = int(os.environ.get("SLAVE_DNS_PORT", "15353"))
SLAVE2_PORT = int(os.environ.get("SLAVE2_PORT", "18082"))
SLAVE2_DNS_PORT = int(os.environ.get("SLAVE2_DNS_PORT", "15354"))

MASTER = f"http://127.0.0.1:{MASTER_PORT}"
SLAVE = f"http://127.0.0.1:{SLAVE_PORT}"
SLAVE2 = f"http://127.0.0.1:{SLAVE2_PORT}"

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((bool(cond), name, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def http(method: str, url: str, body: dict | None = None, timeout: float = 10.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw or b"{}")
            except ValueError:
                return resp.status, {"_raw": raw[:200].decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return None, {"error": str(e)}


def dns_query(name: str, qtype: int, port: int, timeout: float = 3.0) -> dict:
    xid = 0x1234
    qname = dnsproto.encode_name(name)
    query = struct.pack("!HHHHHH", xid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    rxid, flags, qd, an, ns, _ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = dnsproto.parse_name(data, off)
        off += 4

    def parse_rrs(count, off):
        rrs = []
        for _ in range(count):
            rname, off = dnsproto.parse_name(data, off)
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata_off = off
            off += rdlen
            if rtype == dnsproto.QTYPE_A:
                val = ".".join(str(b) for b in data[rdata_off:rdata_off + rdlen])
            elif rtype == dnsproto.QTYPE_SOA:
                mname, p = dnsproto.parse_name(data, rdata_off)
                rname2, p = dnsproto.parse_name(data, p)
                serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[p:p + 20])
                val = {"mname": mname, "rname": rname2, "serial": serial,
                       "refresh": refresh, "retry": retry, "expire": expire, "minimum": minimum}
            else:
                val = data[rdata_off:rdata_off + rdlen].hex()
            rrs.append({"name": rname, "type": rtype, "ttl": ttl, "value": val})
        return rrs, off

    answers, off = parse_rrs(an, off)
    authority, off = parse_rrs(ns, off)
    return {"xid": rxid, "rcode": flags & 0xF, "aa": bool(flags & dnsproto.FLAG_AA),
            "answers": answers, "authority": authority}


class Node:
    def __init__(self, name: str, module: str, port: int, env: dict, logdir: str):
        self.name, self.module, self.port = name, module, port
        self.env, self.logdir = env, logdir
        self.proc = None

    def start(self):
        log = open(os.path.join(self.logdir, f"{self.name}.log"), "ab")
        self.proc = subprocess.Popen(
            [PYBIN, "-m", "uvicorn", self.module, "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=REPO, env={**os.environ, **self.env}, stdout=log, stderr=subprocess.STDOUT,
        )

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


def wait_http(url: str, node: Node, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not node.alive():
            return False
        status, _ = http("GET", url, timeout=2)
        if status == 200:
            return True
        time.sleep(0.25)
    return False


# --------------------------------------------------------------------------
# test flow
# --------------------------------------------------------------------------

def main() -> int:
    tmp = tempfile.mkdtemp(prefix="dnslab-test-")
    print(f"# workdir: {tmp}")
    slave_env = {
        "SLAVE_DB": os.path.join(tmp, "slave.db"),
        "MASTER_URL": MASTER,
        "DNS_PORT": str(SLAVE_DNS_PORT),
        "SYNC_INTERVAL": "0",
    }
    slave = Node("slave", "dnslab.slave_app:app", SLAVE_PORT, slave_env, tmp)
    master = Node("master", "dnslab.master_app:app", MASTER_PORT,
                  {"MASTER_DB": os.path.join(tmp, "master.db")}, tmp)

    try:
        # ---- 1. slave up, master down: must report unavailable --------------
        print("\n== 1. initial sync failure -> unavailable ==")
        slave.start()
        assert wait_http(f"{SLAVE}/status", slave), "slave did not start"
        st, body = http("GET", f"{SLAVE}/status")
        check("status: not serving before first sync", st == 200 and body.get("serving") is False and body.get("serial") is None, json.dumps(body))
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("sync with master down -> 502", st == 502, f"got {st} {body}")
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("A query before any sync -> SERVFAIL", r["rcode"] == dnsproto.RCODE_SERVFAIL, json.dumps(r))
        r = dns_query("lab.test", dnsproto.QTYPE_SOA, SLAVE_DNS_PORT)
        check("SOA query before any sync -> SERVFAIL", r["rcode"] == dnsproto.RCODE_SERVFAIL, json.dumps(r))

        # ---- 2. publish v1, sync, serve ------------------------------------
        print("\n== 2. publish v1 -> sync -> serve ==")
        master.start()
        assert wait_http(f"{MASTER}/zone/serial", master), "master did not start"
        st, body = http("POST", f"{MASTER}/records/bulk", {"records": [
            {"name": "host1.lab.test", "ip": "10.0.0.1"},
            {"name": "host2.lab.test", "ip": "10.0.0.2", "ttl": 60},
        ]})
        check("bulk publish v1 accepted", st == 200, f"got {st} {body}")
        v1 = body.get("serial")
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("sync v1 applied", st == 200 and body.get("applied") is True and body.get("serial") == v1, f"got {st} {body}")
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("A host1 answered with 10.0.0.1, AA set",
              r["rcode"] == 0 and r["aa"] and any(a["value"] == "10.0.0.1" for a in r["answers"]), json.dumps(r))
        r = dns_query("host2.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("A host2 answered with ttl=60",
              r["rcode"] == 0 and any(a["value"] == "10.0.0.2" and a["ttl"] == 60 for a in r["answers"]), json.dumps(r))
        r = dns_query("lab.test", dnsproto.QTYPE_SOA, SLAVE_DNS_PORT)
        soa = r["answers"][0]["value"] if r["answers"] else {}
        check("SOA answered, serial == v1", r["rcode"] == 0 and soa.get("serial") == v1, json.dumps(r))
        r = dns_query("nosuch.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        auth_soa = r["authority"][0]["value"] if r["authority"] else {}
        check("NXDOMAIN for missing name, SOA in authority with same serial",
              r["rcode"] == dnsproto.RCODE_NXDOMAIN and auth_soa.get("serial") == v1, json.dumps(r))
        r = dns_query("example.com", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("out-of-zone query -> REFUSED", r["rcode"] == dnsproto.RCODE_REFUSED, json.dumps(r))

        # ---- 3. batch update -> atomic switch to v2 -------------------------
        print("\n== 3. batch update -> atomic switch ==")
        st, body = http("POST", f"{MASTER}/records/bulk", {"records": [
            {"name": "host1.lab.test", "ip": "10.9.9.1"},   # changed
            {"name": "host3.lab.test", "ip": "10.0.0.3"},   # added
        ]})                                                  # host2 removed
        v2 = body.get("serial")
        check("bulk publish v2 accepted", st == 200 and isinstance(v2, int) and v2 > v1, f"got {st} {body}")
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("sync v2 applied", st == 200 and body.get("serial") == v2, f"got {st} {body}")
        r1 = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        r2 = dns_query("host2.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        r3 = dns_query("host3.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        rs = dns_query("lab.test", dnsproto.QTYPE_SOA, SLAVE_DNS_PORT)
        check("v2: host1 new IP", any(a["value"] == "10.9.9.1" for a in r1["answers"]), json.dumps(r1))
        check("v2: host2 removed -> NXDOMAIN", r2["rcode"] == dnsproto.RCODE_NXDOMAIN, json.dumps(r2))
        check("v2: host3 present", any(a["value"] == "10.0.0.3" for a in r3["answers"]), json.dumps(r3))
        check("v2: SOA serial == v2 (records and SOA same version)",
              rs["answers"] and rs["answers"][0]["value"]["serial"] == v2, json.dumps(rs))
        check("v2: NXDOMAIN authority SOA serial == v2",
              r2["authority"] and r2["authority"][0]["value"]["serial"] == v2, json.dumps(r2))

        # ---- 4. late old version must not overwrite -------------------------
        print("\n== 4. late old version rejected ==")
        st, body = http("POST", f"{SLAVE}/sync", {"serial": v1})
        check("re-pull v1 -> not applied (stale)", st == 200 and body.get("applied") is False and body.get("serial") == v2, f"got {st} {body}")
        st, body = http("POST", f"{SLAVE}/sync", {"serial": 1})
        check("re-pull serial 1 -> not applied (stale)", st == 200 and body.get("applied") is False and body.get("serial") == v2, f"got {st} {body}")
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("still serving v2 after stale pulls", any(a["value"] == "10.9.9.1" for a in r["answers"]), json.dumps(r))

        # ---- 5. broken transfer / tampered payload --------------------------
        print("\n== 5. truncated / corrupt snapshot rejected ==")
        st, body = http("POST", f"{SLAVE}/sync", {"url": f"{MASTER}/debug/snapshot/truncated"})
        check("truncated stream -> 502, sync fails", st == 502, f"got {st} {body}")
        st, body = http("POST", f"{SLAVE}/sync", {"url": f"{MASTER}/debug/snapshot/corrupt"})
        check("corrupt checksum -> 502, sync fails", st == 502, f"got {st} {body}")
        st, body = http("GET", f"{SLAVE}/status")
        check("still serving v2 after broken syncs", st == 200 and body.get("serial") == v2 and body.get("serving") is True, json.dumps(body))
        r = dns_query("host3.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("DNS still answers v2 after broken syncs", any(a["value"] == "10.0.0.3" for a in r["answers"]), json.dumps(r))

        # ---- 6. concurrent publish + sync storm -----------------------------
        print("\n== 6. concurrent publish/sync interleaving ==")
        stop = threading.Event()
        serials_seen = []
        sync_errors = []

        def publisher():
            for i in range(15):
                st, b = http("PUT", f"{MASTER}/records/storm{i}.lab.test", {"ip": f"10.1.0.{i}"})
                if st != 200:
                    sync_errors.append(f"publish {i}: {st} {b}")
                time.sleep(0.02)

        def syncer():
            while not stop.is_set():
                st, b = http("POST", f"{SLAVE}/sync", {})
                if st != 200:
                    sync_errors.append(f"sync: {st} {b}")
                st2, b2 = http("GET", f"{SLAVE}/status")
                if st2 == 200 and b2.get("serial") is not None:
                    serials_seen.append(b2["serial"])
                time.sleep(0.01)

        threads = [threading.Thread(target=publisher)] + [threading.Thread(target=syncer) for _ in range(3)]
        for t in threads:
            t.start()
        threads[0].join()
        time.sleep(0.5)
        stop.set()
        for t in threads[1:]:
            t.join()
        check("no sync errors during storm", not sync_errors, "; ".join(sync_errors[:3]))
        check("served serial monotonically non-decreasing during storm",
              all(a <= b for a, b in zip(serials_seen, serials_seen[1:])),
              f"serials: {serials_seen[:20]}...")
        st, mser = http("GET", f"{MASTER}/zone/serial")
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("final sync converges to master serial", st == 200 and body.get("serial") == mser.get("serial"), f"got {st} {body}, master {mser}")
        st, snap = http("GET", f"{MASTER}/zone/snapshot", None)
        st, szone = http("GET", f"{SLAVE}/zone")
        master_recs = {(r["name"], r["ip"], r["ttl"]) for r in snap.get("records", [])}
        slave_recs = {(r["name"], r["ip"], r["ttl"]) for r in szone.get("records", [])}
        check("slave zone content exactly matches master snapshot at same serial (no mixed state)",
              snap.get("serial") == szone.get("serial") and master_recs == slave_recs,
              f"master serial {snap.get('serial')} slave serial {szone.get('serial')} "
              f"only-master={sorted(master_recs - slave_recs)[:3]} only-slave={sorted(slave_recs - master_recs)[:3]}")
        r = dns_query("storm14.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("storm record answered correctly", any(a["value"] == "10.1.0.14" for a in r["answers"]), json.dumps(r))

        # ---- 7. master outage: slave keeps serving last version -------------
        print("\n== 7. master outage ==")
        master.stop()
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("sync with master down -> 502", st == 502, f"got {st} {body}")
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("still answers last version during outage", any(a["value"] == "10.9.9.1" for a in r["answers"]), json.dumps(r))
        rs = dns_query("lab.test", dnsproto.QTYPE_SOA, SLAVE_DNS_PORT)
        check("SOA serial unchanged during outage",
              rs["answers"] and rs["answers"][0]["value"]["serial"] == mser.get("serial"), json.dumps(rs))

        # ---- 8. slave restart with master still down ------------------------
        print("\n== 8. slave restart, master still down ==")
        slave.stop()
        time.sleep(0.5)
        slave.start()
        assert wait_http(f"{SLAVE}/status", slave), "slave did not restart"
        st, body = http("GET", f"{SLAVE}/status")
        check("after restart: serving persisted version without any sync",
              st == 200 and body.get("serving") is True and body.get("serial") == mser.get("serial"), json.dumps(body))
        r = dns_query("host3.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("after restart: DNS answers persisted version", any(a["value"] == "10.0.0.3" for a in r["answers"]), json.dumps(r))

        # ---- 9. fresh slave, master down -> unavailable ---------------------
        print("\n== 9. fresh slave with master down -> unavailable ==")
        slave2 = Node("slave2", "dnslab.slave_app:app", SLAVE2_PORT, {
            "SLAVE_DB": os.path.join(tmp, "slave2.db"),
            "MASTER_URL": MASTER,
            "DNS_PORT": str(SLAVE2_DNS_PORT),
            "SYNC_INTERVAL": "0",
        }, tmp)
        try:
            slave2.start()
            assert wait_http(f"{SLAVE2}/status", slave2), "slave2 did not start"
            r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE2_DNS_PORT)
            check("fresh slave + master down -> SERVFAIL", r["rcode"] == dnsproto.RCODE_SERVFAIL, json.dumps(r))
            st, body = http("GET", f"{SLAVE2}/status")
            check("fresh slave status: not serving", st == 200 and body.get("serving") is False, json.dumps(body))
        finally:
            slave2.stop()

        # ---- 10. /docs and recovery after master returns --------------------
        print("\n== 10. /docs usable; recovery when master returns ==")
        master.start()
        assert wait_http(f"{MASTER}/zone/serial", master), "master did not restart"
        for base, paths in ((MASTER, ("/records", "/records/bulk", "/zone/serial", "/zone/snapshot")),
                            (SLAVE, ("/sync", "/status"))):
            st, _ = http("GET", f"{base}/docs")
            check(f"/docs reachable on {base}", st == 200)
            st, spec = http("GET", f"{base}/openapi.json")
            missing = [p for p in paths if p not in spec.get("paths", {})]
            check(f"openapi on {base} exposes {paths}", st == 200 and not missing, f"missing: {missing}")
        st, body = http("PUT", f"{MASTER}/records/back.lab.test", {"ip": "10.7.7.7"})
        new_serial = body.get("serial")
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("sync recovers after master returns", st == 200 and body.get("serial") == new_serial, f"got {st} {body}")
        r = dns_query("back.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("new record served after recovery", any(a["value"] == "10.7.7.7" for a in r["answers"]), json.dumps(r))

    finally:
        slave.stop()
        master.stop()

    failed = [r for r in RESULTS if not r[0]]
    print(f"\n{'=' * 60}\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed; logs in {tmp}")
    if failed:
        print("FAILED:")
        for _, name, detail in failed:
            print(f"  - {name}  {detail}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
