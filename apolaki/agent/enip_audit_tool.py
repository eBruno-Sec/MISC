"""EtherNet/IP (CIP) OT exposure audit — ICS/OT pentest, CWE-306 / CWE-284.

EtherNet/IP (Rockwell/Allen-Bradley and many PLCs) has NO authentication: any host that can reach
UDP/TCP 44818 can enumerate the device. This engine sends a single ListIdentity request and confirms an
UNAUTHENTICATED EtherNet/IP device by parsing its identity response (vendor / product / serial / revision).

HARD SAFETY RAIL — READ-ONLY, ALWAYS. This module builds ONLY the ListIdentity discovery request
(encapsulation command 0x0063). It NEVER builds a CIP write, a ForwardOpen, a SendRRData/SendUnitData
carrying a Set_Attribute or register write, or anything that could interact with a running process. A CIP
write to a real PLC can move an actuator or trip a process and harm people — so writes are categorically
ABSENT from the code, not merely gated.

FP-SAFE ORACLE: a non-EtherNet/IP service will not answer with an encapsulation response echoing command
0x0063, status 0, and a well-formed Identity item (type 0x000C). A matching response therefore PROVES an
unauthenticated EtherNet/IP device. build_* + parse_* are pure (unit-testable); probe() does the read-only
round-trip.
"""
from __future__ import annotations

import socket
import struct

_CMD_LIST_IDENTITY = 0x0063
_ITEM_IDENTITY = 0x000C


def build_list_identity(context: bytes = b"apolaki\x00") -> bytes:
    """The ONLY request this module constructs: a 24-byte encapsulation header, command ListIdentity,
    data length 0. There is no CIP payload and no write path here by construction."""
    context = (bytes(context) + b"\x00" * 8)[:8]
    return struct.pack("<HHII8sI", _CMD_LIST_IDENTITY, 0, 0, 0, context, 0)


def parse_list_identity(data: bytes):
    """Parse a ListIdentity response into a device dict, or None if it is not a well-formed EtherNet/IP
    identity reply (the FP-safe oracle). Pure."""
    if not data or len(data) < 24:
        return None
    command, length, _session, status = struct.unpack("<HHII", data[:12])
    if command != _CMD_LIST_IDENTITY or status != 0:
        return None
    body = data[24:24 + length] if length else data[24:]
    if len(body) < 6:
        return None
    _item_count = struct.unpack("<H", body[0:2])[0]
    item_type, item_len = struct.unpack("<HH", body[2:6])
    if item_type != _ITEM_IDENTITY:
        return None
    item = body[6:6 + item_len]
    if len(item) < 33:                      # version(2)+sockaddr(16)+identity fields
        return None
    off = 18                                # skip encap-version(2) + socket address(16)
    vendor, dtype, pcode = struct.unpack("<HHH", item[off:off + 6]); off += 6
    rev_major, rev_minor = item[off], item[off + 1]; off += 2
    _dev_status = struct.unpack("<H", item[off:off + 2])[0]; off += 2
    serial = struct.unpack("<I", item[off:off + 4])[0]; off += 4
    name_len = item[off]; off += 1
    name = item[off:off + name_len].decode("latin-1", "replace")
    return {"vendor_id": vendor, "device_type": dtype, "product_code": pcode,
            "revision": "%d.%d" % (rev_major, rev_minor), "serial": serial, "product_name": name}


def _list_identity_udp(host: str, port: int, timeout: float) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_list_identity(), (host, int(port)))
        return s.recvfrom(2048)[0]
    except Exception:
        return b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _list_identity_tcp(host: str, port: int, timeout: float) -> bytes:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_list_identity())
            return s.recv(2048)
    except Exception:
        return b""


def probe(host: str, port: int = 44818, timeout: float = 4.0) -> dict:
    """Read-only ListIdentity round-trip, UDP then TCP. NEVER writes.

    BOTH TRANSPORTS, because 44818 is a TCP port that also answers ListIdentity over UDP. UDP is the
    discovery path and the natural first try, but explicit messaging is TCP, and a controller behind a
    firewall that permits only TCP — or a stack that simply does not bind UDP — answers on TCP alone. A
    UDP-only probe reports such a device as unreachable, which reads in the report as "no ICS device
    here". This was not hypothetical: a real EtherNet/IP stack answered TCP with a full identity while
    the shipping probe returned reachable=False.

    `answered_unparsed` keeps a parser gap distinguishable from silence. Returning reachable=False for a
    device that replied with bytes we could not decode makes a decoding bug look exactly like an empty
    network, and the FP-safe oracle then hides its own failures."""
    for transport, fn in (("udp", _list_identity_udp), ("tcp", _list_identity_tcp)):
        data = fn(host, port, timeout)
        if not data:
            continue
        info = parse_list_identity(data)
        if info:
            return {"reachable": True, "transport": transport, "device_info": info}
        return {"reachable": False, "transport": transport, "answered_unparsed": True,
                "bytes": len(data)}
    return {"reachable": False}


def finding(host: str, port: int, info: dict) -> dict:
    return {
        "title": "Unauthenticated EtherNet/IP (CIP) device exposed",
        "severity": "high", "family": "ics_ot", "cwe": "CWE-306", "owasp": "A05:2021",
        "target": "enip://%s:%d" % (host, port), "confidence": "confirmed",
        "evidence": ("ListIdentity (0x0063) answered: vendor_id=%s device_type=%s product=%r serial=%s rev=%s"
                     % (info.get("vendor_id"), info.get("device_type"), info.get("product_name"),
                        info.get("serial"), info.get("revision"))),
        "description": ("An EtherNet/IP (CIP) device answered an unauthenticated ListIdentity request, "
                        "disclosing vendor/product/serial/revision. EtherNet/IP has no authentication; any "
                        "host that can reach it can enumerate the controller."),
        "impact": ("Unauthenticated exposure of an industrial controller. An attacker who can reach it can "
                   "fingerprint the PLC for known-vulnerability targeting and, with CIP writes (NOT performed "
                   "by this read-only audit), could disrupt a physical process."),
        "remediation": ("Segment OT from IT/Internet; restrict UDP/TCP 44818 to the engineering network; use "
                        "a firewall/data-diode; never expose EtherNet/IP to untrusted networks."),
        "reproduction_steps": ["Send an EtherNet/IP ListIdentity (encapsulation command 0x0063) to UDP/44818",
                               "Observe the identity response disclosing vendor/product/serial (no auth required)"],
        "false_positive_check": ("Confirmed only when the response echoes encapsulation command 0x0063, status 0, "
                                 "and a well-formed Identity item (0x000C). Read-only: no CIP write is ever sent."),
    }
