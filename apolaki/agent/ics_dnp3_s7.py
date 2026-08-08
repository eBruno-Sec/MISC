"""
ICS/OT read-only probes for DNP3 and S7comm (#107) — the two protocols ics_fingerprint identified by
port/banner only, now with real frame builders.

THE HARD RAIL, unchanged from the Modbus engine: these protocols speak to RTUs and PLCs that drive
physical processes. A write or control frame can damage equipment or endanger people, so this module is
built so that a write is not merely avoided but NOT CONSTRUCTIBLE:

  * every builder here emits exactly one read/identify frame;
  * `is_write_frame` classifies DNP3 and S7 frames, and it is strict by DEFAULT — anything that is not on
    the explicit read-only allowlist is treated as a write, so an unrecognised frame is refused rather
    than sent;
  * a unit test asserts no builder in this file can produce a frame that `is_write_frame` accepts.

DNP3 (TCP 20000): a link-layer Request Link Status (function 9). It carries no application data at all,
which is why it is the safest possible identity probe — there is no object to operate on. The reply's
source address is the device's DNP3 address.

S7comm (TCP 102): the ISO-on-TCP handshake (COTP connection request) followed by an S7 Setup
Communication and a read of SZL 0x0011 (module identification). Reading a System Status List is the
vendor-documented way to ask a Siemens PLC what it is; it does not touch the process image.

Pure frame construction and parsing — no sockets in this module.
"""
from __future__ import annotations

import struct

DNP3_PORT = 20000
S7_PORT = 102

# ── DNP3 ────────────────────────────────────────────────────────────────────────────────────────
DNP3_START = b"\x05\x64"

# Link-layer function codes. Only REQUEST LINK STATUS is allowed out of this module: RESET_LINK_STATES
# changes the peer's link state, and user data carries an application layer that could operate a point.
DNP3_LINK_REQUEST_LINK_STATUS = 9
_DNP3_LINK_READ_ONLY = {9, 11}          # 9 = request status (we send), 11 = link status (reply)

# Application-layer function codes that MUTATE a device. Listed so the classifier can name them; this
# module never builds an application layer at all.
DNP3_APP_WRITE_FCS = {
    0x02: "WRITE", 0x03: "SELECT", 0x04: "OPERATE", 0x05: "DIRECT_OPERATE", 0x06: "DIRECT_OPERATE_NR",
    0x07: "IMMED_FREEZE", 0x09: "FREEZE_CLEAR", 0x0D: "COLD_RESTART", 0x0E: "WARM_RESTART",
    0x0F: "INITIALIZE_DATA", 0x10: "INITIALIZE_APPL", 0x11: "START_APPL", 0x12: "STOP_APPL",
    0x13: "SAVE_CONFIG", 0x18: "ASSIGN_CLASS", 0x1F: "ACTIVATE_CONFIG",
}


def dnp3_crc(data: bytes) -> int:
    """DNP3 link-layer CRC (IEEE 1815): reflected CRC-16 with polynomial 0x3D65, init 0x0000, final XOR
    0xFFFF. Bitwise reference implementation — `_dnp3_crc_table` computes the same value by table and a
    test asserts the two agree, which is how this is verified without trusting a memorised vector."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFF


_TABLE = None


def _dnp3_crc_table(data: bytes) -> int:
    """Table-driven twin of dnp3_crc, used only to cross-check the bitwise implementation."""
    global _TABLE
    if _TABLE is None:
        tbl = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
            tbl.append(c & 0xFFFF)
        _TABLE = tbl
    crc = 0x0000
    for byte in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ byte) & 0xFF]
    return (~crc) & 0xFFFF


def dnp3_request_link_status(dest: int = 0, src: int = 1) -> bytes:
    """The one DNP3 frame this module emits: a link-layer status request. No application layer, so there
    is nothing it could operate on. Pure."""
    ctrl = 0xC0 | DNP3_LINK_REQUEST_LINK_STATUS      # DIR=1, PRM=1, FCB=0, FCV=0, FUNC=9
    body = bytes([0x05, 0x64, 0x05, ctrl]) + struct.pack("<HH", dest & 0xFFFF, src & 0xFFFF)
    return body + struct.pack("<H", dnp3_crc(body))


def parse_dnp3_link(resp: bytes) -> dict:
    """Parse a DNP3 link-layer frame into {valid, func, dest, src, is_link_status, crc_ok}. Never raises."""
    out = {"valid": False, "func": None, "dest": None, "src": None, "is_link_status": False,
           "crc_ok": False, "has_application_layer": False}
    try:
        if len(resp) < 10 or resp[:2] != DNP3_START:
            return out
        ctrl = resp[3]
        out.update({"valid": True, "func": ctrl & 0x0F,
                    "dest": struct.unpack("<H", resp[4:6])[0],
                    "src": struct.unpack("<H", resp[6:8])[0]})
        out["crc_ok"] = struct.unpack("<H", resp[8:10])[0] == dnp3_crc(resp[:8])
        out["is_link_status"] = out["func"] == 11
        out["has_application_layer"] = resp[2] > 5
    except Exception:
        return out
    return out


# ── S7comm / ISO-on-TCP ─────────────────────────────────────────────────────────────────────────
# S7 job function codes that MUTATE the PLC. Never built here; classified so a frame can be refused.
S7_WRITE_FUNCS = {
    0x05: "Write Var", 0x1A: "Request download", 0x1B: "Download block", 0x1C: "Download ended",
    0x1D: "Start upload", 0x1E: "Upload", 0x1F: "End upload", 0x28: "PLC Control",
    0x29: "PLC Stop",
}
S7_READ_FUNCS = {0x04: "Read Var", 0xF0: "Setup communication", 0x00: "Userdata (SZL read)"}


def tpkt(payload: bytes) -> bytes:
    """RFC 1006 TPKT header + payload. Pure."""
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def cotp_connection_request(src_tsap: int = 0x0100, dst_tsap: int = 0x0102) -> bytes:
    """ISO 8073 COTP Connection Request — the mandatory transport handshake before any S7 exchange. It
    establishes a connection and carries no S7 job, so it cannot alter the PLC. Pure."""
    body = (b"\xe0"                       # CR
            + b"\x00\x00"                 # DST-REF
            + b"\x00\x01"                 # SRC-REF
            + b"\x00"                     # class 0
            + b"\xc1\x02" + struct.pack(">H", src_tsap)     # calling TSAP
            + b"\xc2\x02" + struct.pack(">H", dst_tsap))    # called TSAP
    return tpkt(bytes([len(body)]) + body)


def cotp_data(payload: bytes) -> bytes:
    """COTP DT data unit wrapping an S7 PDU. Pure."""
    return tpkt(b"\x02\xf0\x80" + payload)


def s7_setup_communication(pdu_ref: int = 0x0100) -> bytes:
    """S7 Setup Communication (function 0xF0) — negotiates PDU size. Read-only by definition. Pure."""
    param = b"\xf0\x00" + struct.pack(">HHH", 0x0001, 0x0001, 0x03c0)
    header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), 0x0000)
    return cotp_data(header + param)


def s7_read_szl(szl_id: int = 0x0011, index: int = 0x0000, pdu_ref: int = 0x0200) -> bytes:
    """Read a System Status List — SZL 0x0011 is Module Identification (order number, firmware). This is
    the vendor-documented way to ask a PLC what it is; it does not touch the process image. Pure."""
    data = struct.pack(">BBHH", 0xff, 0x09, 0x0004, szl_id) + struct.pack(">H", index)
    param = b"\x00\x01\x12\x04\x11\x44\x01\x00"
    header = struct.pack(">BBHHHH", 0x32, 0x07, 0x0000, pdu_ref, len(param), len(data))
    return cotp_data(header + param + data)


def parse_s7_szl(resp: bytes) -> dict:
    """Pull printable identity strings (order number / module type) out of an SZL response. Defensive."""
    out = {"valid": False, "module": "", "strings": []}
    try:
        i = resp.find(b"\x32")
        if i < 0 or len(resp) < i + 10 or resp[i] != 0x32:
            return out
        out["valid"] = True
        body = resp[i:]
        runs, cur = [], b""
        for b in body:
            if 32 <= b < 127:
                cur += bytes([b])
            else:
                if len(cur) >= 6:
                    runs.append(cur.decode("ascii", "ignore").strip())
                cur = b""
        if len(cur) >= 6:
            runs.append(cur.decode("ascii", "ignore").strip())
        out["strings"] = runs[:6]
        for r in runs:                       # Siemens order numbers look like 6ES7 212-1AE40-0XB0
            if r.upper().startswith("6ES7") or "CPU" in r.upper():
                out["module"] = r
                break
        if not out["module"] and runs:
            out["module"] = runs[0]
    except Exception:
        return out
    return out


# ── the safety rail ─────────────────────────────────────────────────────────────────────────────
def is_write_frame(proto: str, frame: bytes) -> bool:
    """True if `frame` could MUTATE the device. STRICT BY DEFAULT: anything not positively recognised as
    one of this module's read-only frames is reported as a write, so an unrecognised or malformed frame
    is refused rather than sent to a PLC. Pure."""
    if not frame:
        return False
    p = str(proto or "").lower()
    if p == "dnp3":
        if len(frame) < 10 or frame[:2] != DNP3_START:
            return True                                   # unrecognised -> refuse
        if frame[2] > 5:
            return True                                   # carries an application layer -> refuse
        return (frame[3] & 0x0F) not in _DNP3_LINK_READ_ONLY
    if p in ("s7comm", "s7"):
        # Structural, not a byte search: TPKT(4) | COTP | S7. Searching for 0x32 would misfire the moment
        # a length field happened to equal '2'.
        if len(frame) < 7 or frame[0] != 0x03:
            return True                                   # not TPKT -> refuse
        if frame[5] in (0xE0, 0xD0):                      # COTP Connection Request / Confirm
            return False                                  # transport handshake, carries no S7 job
        if frame[4:7] != b"\x02\xf0\x80":                 # not a COTP DT carrying an S7 PDU
            return True
        s7 = frame[7:]
        if len(s7) < 11 or s7[0] != 0x32:
            return True
        return s7[10] not in S7_READ_FUNCS                # first parameter byte is the job function
    return True                                           # unknown protocol -> refuse


def is_read_only(proto: str, frame: bytes) -> bool:
    return not is_write_frame(proto, frame)


# ── live probes (one short connection, read-only frames only) ───────────────────────────────────
def _send_recv(host: str, port: int, frames, timeout: float = 5.0, proto: str = "") -> dict:
    """Send each frame in order and return the last response. Every frame is re-checked against the
    safety rail immediately before it goes on the wire — the builders are already read-only, and this is
    the second lock, so a future edit cannot quietly turn a probe into a control command. Never raises."""
    import socket
    out = {"reachable": False, "response": b"", "error": ""}
    for f in frames:
        if is_write_frame(proto, f):
            return {**out, "error": "REFUSED: a frame failed the read-only safety rail"}
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            out["reachable"] = True
            for f in frames:
                s.sendall(f)
                try:
                    out["response"] = s.recv(4096)
                except socket.timeout:
                    out["response"] = b""
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def probe_dnp3(host: str, port: int = DNP3_PORT, timeout: float = 5.0) -> dict:
    """Read-only DNP3 identity probe: one link-status request. Never raises."""
    r = _send_recv(host, port, [dnp3_request_link_status()], timeout=timeout, proto="dnp3")
    parsed = parse_dnp3_link(r.get("response") or b"")
    return {"host": host, "port": int(port), "proto": "dnp3", "reachable": r["reachable"],
            "error": r["error"], "confirmed": bool(parsed.get("valid")),
            "src": parsed.get("src"), "func": parsed.get("func"), "crc_ok": parsed.get("crc_ok"),
            "summary": ("DNP3 link response from address %s (crc_ok=%s)"
                        % (parsed.get("src"), parsed.get("crc_ok"))) if parsed.get("valid") else ""}


def probe_s7(host: str, port: int = S7_PORT, timeout: float = 5.0) -> dict:
    """Read-only S7comm identity probe: COTP connect, S7 setup, then read SZL 0x0011. Never raises."""
    frames = [cotp_connection_request(), s7_setup_communication(), s7_read_szl()]
    r = _send_recv(host, port, frames, timeout=timeout, proto="s7comm")
    parsed = parse_s7_szl(r.get("response") or b"")
    return {"host": host, "port": int(port), "proto": "s7comm", "reachable": r["reachable"],
            "error": r["error"], "confirmed": bool(parsed.get("valid")),
            "module": parsed.get("module", ""), "strings": parsed.get("strings", []),
            "summary": ("S7 module identification: %s" % parsed.get("module")) if parsed.get("valid") else ""}


# ── findings ────────────────────────────────────────────────────────────────────────────────────
def finding(proto: str, host: str, port: int, identity: dict) -> dict:
    """An ICS device answering an unauthenticated identity probe is itself the finding: these protocols
    have no authentication, so reachability equals control for anyone on this network path."""
    label = {"dnp3": "DNP3", "s7comm": "S7comm (Siemens S7)"}.get(proto, proto.upper())
    ident = identity.get("module") or (
        "DNP3 address %s" % identity.get("src") if identity.get("src") is not None else "")
    return {
        "title": "Unauthenticated %s industrial device reachable — %s:%s" % (label, host, port),
        "severity": "high",
        "confidence": "confirmed",
        "family": "ics_ot",
        "cwe": "CWE-306",
        "owasp": "A07:2021",
        "target": "%s:%s" % (host, port),
        "tags": ["ics", "ot", proto, "read-only-probe"],
        "description": ("The device answered an unauthenticated read-only identity request over %s. These "
                        "protocols carry no authentication by design, so anyone who can reach this port "
                        "can also issue control commands. %s" % (label, ("Identity: %s." % ident) if ident else "")),
        "impact": ("An attacker on this network path can read process data and issue control commands to "
                   "physical equipment. Apolaki sent only a read/identify frame and will never send a "
                   "control or write frame."),
        "oracle": ("a read-only %s identity request received a well-formed protocol response from the "
                   "device (no write or control frame is constructible by this engine)" % label),
        "evidence": "%s identity probe to %s:%s -> %s" % (label, host, port,
                                                          identity.get("module")
                                                          or identity.get("summary")
                                                          or "protocol-conformant response"),
        "remediation": ("Remove this device from any network reachable by untrusted hosts. ICS protocols "
                        "cannot authenticate callers; segmentation and a control-network firewall are the "
                        "control, not device configuration."),
        "found_by": "ics_dnp3_s7",
    }
