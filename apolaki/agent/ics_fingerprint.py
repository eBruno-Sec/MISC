"""ICS/OT read-only fingerprint engine (#107) — SAFETY-RAILED.

Industrial protocols speak to PLCs/RTUs that drive physical processes. Apolaki NEVER writes to them: this
engine builds ONLY read/identify request frames and parses the identity responses. Writing a coil/register or
sending a control/stop command to an ICS device can cause physical damage, so every builder here is proven
read-only by `is_write_frame` (a self-check the tests assert), and the driver that imports this must refuse
any frame that fails it.

What it does, per protocol, is a SINGLE read-only identity probe:
  * Modbus/TCP (502)      — Read Device Identification (function 0x2B / MEI 0x0E) → vendor / product / revision.
  * EtherNet/IP (44818)   — List Identity (encapsulation command 0x0063) → vendor / product name / serial.
  * S7comm (102), DNP3 (20000), BACnet/IP (47808) — identified by port + banner (frame builders are a
    follow-up; we never guess-write).

An ICS device reachable from the scanner's network position is itself a high-severity EXPOSURE finding
(these protocols are unauthenticated by design). Pure — no sockets here; fully unit-testable.
"""
from __future__ import annotations

import struct

PROTO_PORTS = {502: "modbus", 102: "s7comm", 44818: "ethernetip", 20000: "dnp3", 47808: "bacnet"}

# Modbus function codes that MUTATE device state — this engine must NEVER emit any of these.
_MODBUS_WRITE_FCS = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x18, 0x08}   # incl. diagnostics(0x08) as a precaution


def identify_protocol(port: int = 0, banner: str = "") -> str:
    """Best-effort protocol id from a port and/or a service banner. Returns '' when unknown."""
    b = (banner or "").lower()
    if port in PROTO_PORTS:
        return PROTO_PORTS[port]
    for name, needles in (("modbus", ("modbus",)), ("s7comm", ("siemens", "s7", "step7")),
                          ("ethernetip", ("ethernet/ip", "enip", "rockwell", "allen-bradley")),
                          ("dnp3", ("dnp3", "dnp 3")), ("bacnet", ("bacnet",))):
        if any(n in b for n in needles):
            return name
    return ""


# ── read-only request builders (identity only) ──────────────────────────────
def modbus_read_device_id(unit: int = 0, transaction: int = 1) -> bytes:
    """Modbus/TCP Read Device Identification (function 0x2B, MEI type 0x0E, 'basic' category). READ-ONLY —
    it returns the vendor/product strings and mutates nothing. MBAP header + the 4-byte MEI PDU."""
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])            # func, MEI type, read-device-id code (basic), object id 0
    mbap = struct.pack(">HHHB", transaction & 0xFFFF, 0x0000, len(pdu) + 1, unit & 0xFF)
    return mbap + pdu


def ethernetip_list_identity() -> bytes:
    """EtherNet/IP encapsulation 'List Identity' (command 0x0063) — a discovery request that returns the
    device identity object. READ-ONLY. 24-byte encapsulation header, zero payload."""
    return struct.pack("<HHII8sI", 0x0063, 0x0000, 0x00000000, 0x00000000, b"\x00" * 8, 0x00000000)


def is_write_frame(proto: str, frame: bytes) -> bool:
    """SAFETY self-check: True if `frame` would MUTATE the device (a write/control), so the driver can refuse
    it. For Modbus, the function code is at MBAP offset 7. Anything unrecognized is treated as write=unsafe for
    a strict caller only via the explicit read-only allowlist below — here we flag KNOWN writes as True and
    known reads as False."""
    if not frame:
        return False
    if proto == "modbus":
        if len(frame) < 8:
            return False
        return frame[7] in _MODBUS_WRITE_FCS
    if proto == "ethernetip":
        cmd = struct.unpack("<H", frame[:2])[0] if len(frame) >= 2 else 0
        # RegisterSession(0x65)/SendRRData(0x6F)/SendUnitData(0x70) can carry Set_Attribute writes;
        # ListIdentity(0x63)/ListServices(0x04)/ListInterfaces(0x64)/NOP(0x00) are read-only discovery.
        return cmd not in (0x0000, 0x0004, 0x0063, 0x0064)
    return False


def is_read_only(proto: str, frame: bytes) -> bool:
    return not is_write_frame(proto, frame)


# ── identity-response parsers ────────────────────────────────────────────────
_MODBUS_OBJ = {0x00: "vendor", 0x01: "product_code", 0x02: "revision", 0x03: "vendor_url",
               0x04: "product_name", 0x05: "model", 0x06: "app_name"}


def parse_modbus_device_id(resp: bytes) -> dict:
    """Parse a Modbus Read-Device-Identification response into {vendor, product_code, revision, ...}.
    Defensive: returns whatever it can, never raises."""
    out = {}
    try:
        if len(resp) < 8 or resp[7] != 0x2B or resp[8] != 0x0E:
            return out
        num = resp[13]                                  # number of objects
        i = 14
        for _ in range(num):
            if i + 2 > len(resp):
                break
            oid, olen = resp[i], resp[i + 1]
            val = resp[i + 2:i + 2 + olen].decode("latin-1", "replace")
            out[_MODBUS_OBJ.get(oid, "obj_%d" % oid)] = val
            i += 2 + olen
    except Exception:
        pass
    return out


def parse_ethernetip_identity(resp: bytes) -> dict:
    """Parse an EtherNet/IP List Identity response for {vendor_id, product_code, serial, product_name}.
    Defensive: returns whatever it can, never raises."""
    out = {}
    try:
        # 24-byte encapsulation header, then CPF: item count(2), item type(2), item len(2), then the identity
        p = 24
        p += 2                                           # item count
        p += 2                                           # item type (0x000C CIP Identity)
        p += 2                                           # item length
        p += 2                                           # encap protocol version
        p += 16                                          # socket address (sin_family/port/addr/zero)
        vendor_id = struct.unpack("<H", resp[p:p + 2])[0]; p += 2
        p += 2                                           # device type
        product_code = struct.unpack("<H", resp[p:p + 2])[0]; p += 2
        p += 2                                           # revision (major/minor)
        p += 2                                           # status
        serial = struct.unpack("<I", resp[p:p + 4])[0]; p += 4
        name_len = resp[p]; p += 1
        name = resp[p:p + name_len].decode("latin-1", "replace")
        out = {"vendor_id": vendor_id, "product_code": product_code, "serial": serial, "product_name": name}
    except Exception:
        pass
    return out


def finding(proto: str, host: str, port: int, identity: dict) -> dict:
    """An exposed, unauthenticated ICS/OT device is a high-severity exposure. We report the read-only
    fingerprint ONLY and state explicitly that no control/write command was sent."""
    ident = ", ".join("%s=%s" % (k, v) for k, v in (identity or {}).items() if v) or "(identity unavailable)"
    return {
        "title": "Exposed ICS/OT device — %s reachable (read-only fingerprint)" % proto,
        "severity": "high", "family": "ics_ot", "confidence": "confirmed",
        "cwe": "CWE-306", "owasp": "A05:2021", "target": "%s:%s" % (host, port),
        "tags": ["ics", "ot", proto, "exposure", "read-only", "unauthenticated"],
        "description": ("An industrial %s endpoint is reachable at %s:%s and answered an unauthenticated "
                        "read-only identity request (%s). Industrial protocols are unauthenticated by design; "
                        "network reachability to a PLC/RTU is a direct safety + security exposure."
                        % (proto, host, port, ident)),
        "impact": ("An attacker on this network path could read process data and, with control-plane frames "
                   "(NOT sent by Apolaki), manipulate the physical process. ICS reachability must be segmented."),
        "reproduction_steps": [
            "From the scanner's network position, send the %s read-only identity request to %s:%s." % (proto, host, port),
            "Observe the device returns its identity (%s) without authentication." % ident,
        ],
        "evidence": "read-only %s identity: %s" % (proto, ident),
        "false_positive_check": ("only a well-formed protocol identity response counts; Apolaki sends ONLY the "
                                 "read/identify frame (is_write_frame == False) — never a control/write command."),
        "remediation": ("Segment ICS/OT networks (no routable path from IT); put an authenticating gateway in "
                        "front; disable unused protocol services; monitor for unsolicited industrial traffic."),
        "safety_note": "READ-ONLY fingerprint — no coil/register write or control command was sent.",
    }
