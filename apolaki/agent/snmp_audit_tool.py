"""SNMP default-community audit (network/infra pentest — CWE-1188 / CWE-284). An SNMP agent still using a
documented DEFAULT community string ('public' / 'private') hands device configuration, interfaces, routes,
processes, and often ARP/user data to anyone who asks — a staple infrastructure finding on routers, switches,
printers, hypervisors, and servers. READ-ONLY (an SNMP GET), and NOT a brute-force: only the ONE or two
DOCUMENTED vendor-default community strings are tried (single known values), never a wordlist.

FP-SAFE ORACLE: an SNMP agent does NOT reply to a wrong community (or replies authorizationError); a GET for
sysDescr.0 that comes back as a GetResponse with error-status 0 and a value therefore PROVES the tried community
is accepted. Zero external deps — the SNMPv2c GET is hand-built BER and the response minimally parsed. build/
parse are pure (unit-testable); probe() does the one read-only UDP round-trip."""
from __future__ import annotations

import os
import socket
import struct

_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)                 # sysDescr.0
DEFAULT_COMMUNITIES = ("public", "private")


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _len(len(val)) + val


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = []
    v = n
    while v:
        b.insert(0, v & 0xFF)
        v >>= 8
    if b[0] & 0x80:                                      # keep it positive
        b.insert(0, 0)
    return _tlv(0x02, bytes(b))


def _oid(arcs) -> bytes:
    body = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        if a < 0x80:
            body += bytes([a])
        else:
            chunk = [a & 0x7F]
            a >>= 7
            while a:
                chunk.insert(0, (a & 0x7F) | 0x80)
                a >>= 7
            body += bytes(chunk)
    return _tlv(0x06, body)


def build_get(community: str, oid_arcs=_SYSDESCR, reqid: int = None) -> bytes:
    """A complete SNMPv2c GetRequest for one OID. Pure."""
    reqid = reqid if reqid is not None else int.from_bytes(os.urandom(3), "big")
    varbind = _tlv(0x30, _oid(oid_arcs) + _tlv(0x05, b""))          # { OID, NULL }
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _int(reqid) + _int(0) + _int(0) + varbinds)    # GetRequest [0xA0]
    msg = _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)  # version 1 = v2c
    return msg


def _read_tlv(data: bytes, off: int):
    tag = data[off]
    off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(data[off:off + nb], "big")
        off += nb
    return tag, data[off:off + ln], off + ln


def parse_response(data: bytes):
    """(error_status, sysdescr_or_None) from an SNMP GetResponse, or None if it is not a parseable response.
    error_status 0 with a returned value == the tried community is accepted."""
    try:
        _, body, _ = _read_tlv(data, 0)                 # outer SEQUENCE
        off = 0
        _, _ver, off = _read_tlv(body, off)             # version
        _, _comm, off = _read_tlv(body, off)            # community
        tag, pdu, _ = _read_tlv(body, off)              # PDU
        if tag != 0xA2:                                 # 0xA2 = GetResponse
            return None
        o = 0
        _, _rid, o = _read_tlv(pdu, o)                  # request-id
        _, errb, o = _read_tlv(pdu, o)                  # error-status
        err = int.from_bytes(errb, "big") if errb else 0
        _, _eidx, o = _read_tlv(pdu, o)                 # error-index
        _, vbs, _ = _read_tlv(pdu, o)                   # varbinds SEQUENCE
        val = None
        try:
            _, vb, _ = _read_tlv(vbs, 0)                # first varbind SEQUENCE
            vo = 0
            _, _name, vo = _read_tlv(vb, vo)           # OID
            vtag, vval, _ = _read_tlv(vb, vo)          # value
            if vtag == 0x04:                            # OCTET STRING (sysDescr text)
                val = vval.decode("latin-1", "replace")[:120]
        except Exception:
            pass
        return err, val
    except Exception:
        return None


def probe(host: str, port: int = 161, communities=DEFAULT_COMMUNITIES, timeout: float = 3.0) -> dict:
    """One read-only UDP SNMPv2c GET (sysDescr.0) per documented default community. Returns the first accepted
    community + sysDescr, else {reachable:False}. Single known values only — never a wordlist."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for community in communities:
            try:
                s.sendto(build_get(community), (host, int(port)))
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                continue
            parsed = parse_response(data)
            if parsed and parsed[0] == 0:
                return {"reachable": True, "community": community, "sysdescr": parsed[1]}
        return {"reachable": False}
    finally:
        try:
            s.close()
        except Exception:
            pass


def analyze(res: dict):
    """(community, sysdescr) when a default community is accepted; None otherwise."""
    if not res or res.get("error") or not res.get("reachable") or not res.get("community"):
        return None
    return (res["community"], res.get("sysdescr"))


def finding(host: str, port: int, community: str, sysdescr: str) -> dict:
    return {
        "title": "SNMP accepts a default community string ('%s') at %s:%d" % (community, host, port),
        "severity": "high", "family": "snmp_default_community", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-1188",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 7.5,
        "evidence": ("The SNMP agent at %s:%d answered a GET with the documented default community '%s'%s. An "
                     "agent does not reply to a wrong community, so this proves the default is in use. Read-only "
                     "GET; no wordlist." % (host, port, community, (" (sysDescr: %s)" % sysdescr) if sysdescr else "")),
        "success_oracle": "GetResponse with error-status 0 to community '%s'" % community,
        "reproduction_steps": [
            "Send an SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) to %s:%d/udp with community '%s'." % (host, port, community),
            "A GetResponse with error-status 0 (and a sysDescr value) returns — the default community is accepted."],
        "impact": ("Full read of device configuration, interfaces, routes, ARP tables, running processes and "
                   "sometimes credentials; a 'private' RW community additionally allows configuration changes."),
        "remediation": ("Change or disable the default community strings; prefer SNMPv3 with authentication + "
                        "privacy; restrict UDP/161 to trusted management hosts."),
        "tags": ["snmp", "default-credentials", "cwe-1188", "network-service"],
    }
