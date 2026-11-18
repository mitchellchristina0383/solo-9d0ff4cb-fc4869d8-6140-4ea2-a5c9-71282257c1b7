"""Minimal DNS wire-format helpers for an authoritative-only server.

Supports exactly what the lab.test master/slave setup needs:
- parsing standard queries (one question, compression-pointer tolerant)
- building A / SOA answers, NXDOMAIN / NODATA / SERVFAIL / REFUSED / FORMERR

No dependencies outside the standard library.
"""

from __future__ import annotations

import struct
from typing import Optional

QTYPE_A = 1
QTYPE_SOA = 6
QTYPE_ANY = 255
QCLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_RD = 0x0100


class DnsError(Exception):
    """Malformed or unsupported DNS message."""


def parse_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Parse a (possibly compressed) domain name. Returns (name, next_offset)."""
    labels = []
    jumped = False
    next_offset = offset
    seen = set()
    while True:
        if offset >= len(msg):
            raise DnsError("name runs past packet")
        length = msg[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(msg):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if pointer in seen:
                raise DnsError("compression pointer loop")
            seen.add(pointer)
            if not jumped:
                next_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        if length & 0xC0:
            raise DnsError("invalid label length bits")
        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break
        if offset + length > len(msg):
            raise DnsError("truncated label")
        labels.append(msg[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower(), next_offset


def encode_name(name: str) -> bytes:
    out = bytearray()
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            raw = label.encode("ascii")
            if len(raw) > 63:
                raise DnsError("label too long")
            out.append(len(raw))
            out += raw
    out.append(0)
    return bytes(out)


class Query:
    """A parsed DNS query: header + exactly one question."""

    def __init__(self, data: bytes):
        if len(data) < 12:
            raise DnsError("short header")
        (self.xid, flags, qdcount, _an, _ns, _ar) = struct.unpack("!HHHHHH", data[:12])
        if flags & FLAG_QR:
            raise DnsError("not a query")
        if (flags >> 11) & 0xF != 0:
            raise DnsError("unsupported opcode")
        if qdcount != 1:
            raise DnsError("qdcount != 1")
        self.rd = bool(flags & FLAG_RD)
        self.qname, offset = parse_name(data, 12)
        if offset + 4 > len(data):
            raise DnsError("short question")
        self.qtype, self.qclass = struct.unpack("!HH", data[offset:offset + 4])
        self.question_bytes = data[12:offset + 4]


def rr_a(name: str, ttl: int, ip: str) -> bytes:
    rdata = bytes(int(part) for part in ip.split("."))
    return (
        encode_name(name)
        + struct.pack("!HHIH", QTYPE_A, QCLASS_IN, ttl, len(rdata))
        + rdata
    )


def rr_soa(name: str, soa: dict) -> bytes:
    rdata = (
        encode_name(soa["mname"])
        + encode_name(soa["rname"])
        + struct.pack(
            "!IIIII",
            soa["serial"] & 0xFFFFFFFF,
            soa["refresh"],
            soa["retry"],
            soa["expire"],
            soa["minimum"],
        )
    )
    ttl = soa.get("minimum", 300)
    return (
        encode_name(name)
        + struct.pack("!HHIH", QTYPE_SOA, QCLASS_IN, ttl, len(rdata))
        + rdata
    )


def build_response(query: Query, rcode: int, answers=(), authorities=(), aa: bool = True) -> bytes:
    flags = FLAG_QR | (rcode & 0xF)
    if query.rd:
        flags |= FLAG_RD
    if aa:
        flags |= FLAG_AA
    header = struct.pack(
        "!HHHHHH", query.xid, flags, 1, len(answers), len(authorities), 0
    )
    return header + query.question_bytes + b"".join(answers) + b"".join(authorities)


def formerr(data: bytes) -> Optional[bytes]:
    """Best-effort FORMERR for an unparseable message (echo id + RD if possible)."""
    if len(data) < 12:
        return None
    xid, flags = struct.unpack("!HH", data[:4])
    rflags = FLAG_QR | RCODE_FORMERR
    if flags & FLAG_RD:
        rflags |= FLAG_RD
    return struct.pack("!HHHHHH", xid, rflags, 0, 0, 0, 0)


def answer(query: Query, zone, apex: str) -> bytes:
    """Build an authoritative answer for `query` from `zone`.

    `zone` is either None (no version loaded yet -> SERVFAIL) or an object
    with attributes: serial (int), soa (dict), records ({fqdn: (ip, ttl)}).
    Every response is built from exactly one zone object, so the records and
    the SOA in a single answer always belong to the same version.
    """
    if query.qclass != QCLASS_IN:
        return build_response(query, RCODE_REFUSED, aa=False)
    name = query.qname
    if not (name == apex or name.endswith("." + apex)):
        return build_response(query, RCODE_REFUSED, aa=False)
    if zone is None:
        # Never synced: must report unavailable rather than guess.
        return build_response(query, RCODE_SERVFAIL, aa=False)

    rec = zone.records.get(name)
    is_apex = name == apex
    exists = is_apex or rec is not None
    if not exists:
        return build_response(
            query, RCODE_NXDOMAIN, authorities=[rr_soa(apex, zone.soa)]
        )

    answers = []
    if query.qtype in (QTYPE_A, QTYPE_ANY):
        if rec is not None:
            ip, ttl = rec
            answers.append(rr_a(name, ttl, ip))
        if query.qtype == QTYPE_ANY and is_apex:
            answers.append(rr_soa(apex, zone.soa))
    elif query.qtype == QTYPE_SOA:
        if is_apex:
            answers.append(rr_soa(apex, zone.soa))
    # Any other qtype at an existing name -> NODATA below.

    if not answers:
        return build_response(
            query, RCODE_NOERROR, authorities=[rr_soa(apex, zone.soa)]
        )
    return build_response(query, RCODE_NOERROR, answers=answers)
