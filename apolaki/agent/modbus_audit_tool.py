"""Modbus/TCP OT exposure audit (ICS/OT pentest — CWE-306 / CWE-284). Modbus has NO authentication and NO
encryption: any host that can reach TCP/502 can read (and, on a real device, write) process data. This engine
confirms an UNAUTHENTICATED Modbus/OT device is reachable and fingerprints it — the first ICS finding for the
'Apolaki as THE ICS-in-cloud pentest tool' goal.

HARD SAFETY RAIL — READ-ONLY, ALWAYS. This module builds ONLY Modbus READ function codes: Read Device
Identification (0x2B/0x0E) and Read Holding Registers (0x03). It NEVER builds a write (0x05/0x06/0x0F/0x10) or a
diagnostic that could perturb a physical process. A write to real OT can move a valve, trip a breaker, or harm
people — so writes are categorically absent from the code, not merely gated.

FP-SAFE ORACLE: a non-Modbus service on 502 will not answer with a well-formed Modbus response that echoes our
transaction id, protocol id 0, and a function code matching our request. A matching 0x2B/0x03 (or its 0xAB/0x83
exception) response therefore PROVES an unauthenticated Modbus device. build_* + parse_* are pure (unit-testable);
probe() does the read-only TCP round-trip."""
from __future__ import annotations

import socket
import struct


def _mbap(tid: int, pdu: bytes, unit: int = 1) -> bytes:
    # MBAP: transaction id, protocol id (0), length (unit + pdu), unit id  +  PDU
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def build_read_device_id(tid: int = 1, unit: int = 1) -> bytes:
    # FC 0x2B / MEI 0x0E, ReadDeviceIDCode 0x01 (basic), ObjectId 0x00 — READ-ONLY identification.
    return _mbap(tid, bytes([0x2B, 0x0E, 0x01, 0x00]), unit)


def build_read_holding(tid: int = 1, unit: int = 1, addr: int = 0, count: int = 1) -> bytes:
    # FC 0x03 Read Holding Registers — READ-ONLY.
    return _mbap(tid, struct.pack(">BHH", 0x03, addr, count), unit)


def parse_response(resp: bytes, want_tid: int):
    """(function_code, payload) if `resp` is a well-formed Modbus/TCP response to our transaction, else None.
    Verifies the MBAP echoes our tid + protocol id 0 — so random TCP noise on 502 does not false-positive."""
    try:
        if len(resp) < 8:
            return None
        tid, proto, length, unit = struct.unpack(">HHHB", resp[:7])
        if tid != want_tid or proto != 0:
            return None
        fc = resp[7]
        return fc, resp[8:7 + length]
    except Exception:
        return None


def _decode_device_id(payload: bytes) -> dict:
    """Best-effort vendor/product/revision from a Read Device ID (0x2B) response object list."""
    info = {}
    try:
        # payload after FC: MEI(1) ReadDevIDCode(1) Conformity(1) MoreFollows(1) NextObjId(1) NumObjects(1) [objects]
        n = payload[5]
        off = 6
        names = {0: "vendor", 1: "product_code", 2: "revision"}
        for _ in range(n):
            oid = payload[off]
            ln = payload[off + 1]
            val = payload[off + 2:off + 2 + ln].decode("latin-1", "replace")
            if oid in names:
                info[names[oid]] = val
            off += 2 + ln
    except Exception:
        pass
    return info


def probe(host: str, port: int = 502, timeout: float = 4.0) -> dict:
    """Read-only Modbus/TCP conversation: try Read Device ID, then a single Read Holding Register. Returns
    {reachable, device_info, readable} or {reachable: False}. NEVER writes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        # 1) device identification (fingerprint)
        s.sendall(build_read_device_id(tid=0x0001))
        r = parse_response(s.recv(512), 0x0001)
        device_info = {}
        if r and r[0] == 0x2B:
            device_info = _decode_device_id(r[1])
            return {"reachable": True, "device_info": device_info, "readable": True}
        # 2) read one holding register — a 0x03 (data) or 0x83 (exception) both prove a live Modbus device
        s.sendall(build_read_holding(tid=0x0002, addr=0, count=1))
        r = parse_response(s.recv(512), 0x0002)
        if r and r[0] in (0x03, 0x83):
            return {"reachable": True, "device_info": {}, "readable": r[0] == 0x03}
        return {"reachable": False}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def analyze(res: dict):
    """(severity, evidence) when an unauthenticated Modbus device is confirmed reachable; None otherwise."""
    if not res or res.get("error") or not res.get("reachable"):
        return None
    info = res.get("device_info") or {}
    who = ", ".join("%s=%s" % (k, v) for k, v in info.items())
    tail = (" (%s)" % who if who else "") + ("; holding registers are readable" if res.get("readable") else "")
    return ("high", "an unauthenticated Modbus/TCP device answered a read-only request%s" % tail)


def finding(host: str, port: int, severity: str, evidence: str, res: dict) -> dict:
    info = res.get("device_info") or {}
    return {
        "title": "Unauthenticated Modbus/OT device exposed (%s:%d)" % (host, port),
        "severity": severity, "family": "modbus_exposed", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-306",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
        "evidence": ("The Modbus/TCP service at %s:%d answered a READ-ONLY request with no authentication (Modbus "
                     "has none): %s. Apolaki only READ — it never issued a write to the OT device." % (host, port, evidence)),
        "success_oracle": "a well-formed Modbus response (matching transaction id, protocol 0) to a read request",
        "reproduction_steps": [
            "Open TCP to %s:%d and send a Modbus Read Device Identification (0x2B/0x0E) request." % (host, port),
            "A Modbus response returns with no authentication — the OT device is exposed to the network.",
            "(Read-only. Do NOT issue write function codes against production OT.)"],
        "impact": ("Full unauthenticated read of process/register data" + (" from %s" % info.get("vendor") if info.get("vendor") else "")
                   + "; an attacker who can reach TCP/502 could also WRITE coils/registers to manipulate the "
                   "physical process (valves, breakers, setpoints) — a safety-critical exposure."),
        "remediation": ("Never expose Modbus/OT to untrusted networks: segment OT behind a firewall/DMZ + VPN, "
                        "restrict TCP/502 to the SCADA master(s), and front legacy Modbus with an authenticating "
                        "gateway; disable internet reachability entirely."),
        "tags": ["ics", "ot", "modbus", "scada", "cwe-306", "read-only-audit"],
    }
