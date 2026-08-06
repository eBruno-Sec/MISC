"""IPMI 2.0 RMCP+ exposure audit (BMC/infra pentest — CWE-522 / CVE-2013-4786). Every IPMI 2.0 baseboard
management controller (Dell iDRAC, HP iLO, Supermicro, etc.) that answers RMCP+ over LAN (UDP/623) is inherently
vulnerable to the RAKP authentication hash disclosure: on session setup the BMC returns an HMAC keyed with a
user's password, which an attacker can capture and crack OFFLINE — no lockout, no logging. BMC compromise is
typically full host compromise (power/console/virtual-media). This is a design flaw of the IPMI 2.0 RAKP
protocol, so simply CONFIRMING the BMC speaks RMCP+ establishes the exposure.

READ-ONLY + FP-SAFE: the engine sends ONE RMCP+ Open Session Request and confirms an Open Session Response
(payload type 0x11 over RMCP class 0x07). It deliberately does NOT proceed to RAKP Message 1 (which would elicit
the crackable hash) and never attempts any credential — detection only. A non-IPMI UDP service cannot forge a
valid Open Session Response. build/parse are pure (unit-testable); probe() does the one read-only UDP round-trip."""
from __future__ import annotations

import os
import socket
import struct


def build_open_session_request(console_sid: bytes = b"\xa4\xa3\xa2\xa0") -> bytes:
    """A complete RMCP+ Open Session Request: RMCP header + IPMI 2.0 session header + the open-session payload
    negotiating RAKP-HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128. Pure."""
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])              # version 6, reserved, seq 0xff, class 0x07 (IPMI)
    payload = (bytes([0x00, 0x00, 0x00, 0x00])          # message tag, max priv (0=highest offered), reserved x2
               + console_sid                             # remote console session id (4 bytes)
               + bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])   # auth   payload: RAKP-HMAC-SHA1
               + bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])   # integ  payload: HMAC-SHA1-96
               + bytes([0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]))  # conf   payload: AES-CBC-128
    session = (bytes([0x06, 0x10])                       # auth type 0x06 (RMCP+), payload type 0x10 (open sess req)
               + bytes([0x00, 0x00, 0x00, 0x00])         # session id (0 during setup)
               + bytes([0x00, 0x00, 0x00, 0x00])         # session sequence
               + struct.pack("<H", len(payload)))        # payload length (LE)
    return rmcp + session + payload


def parse_open_session_response(resp: bytes):
    """(is_ipmi2, bmc_session_id_hex, status) when `resp` is a valid RMCP+ Open Session Response; None otherwise.
    Confirmed by RMCP class 0x07 + IPMI auth 0x06 + payload type 0x11 (low 6 bits)."""
    try:
        if len(resp) < 24 or resp[0] != 0x06 or resp[3] != 0x07:
            return None
        if resp[4] != 0x06 or (resp[5] & 0x3F) != 0x11:     # 0x11 = Open Session Response
            return None
        status = resp[17]                                    # RMCP+ status code in the payload
        bmc_sid = resp[24:28].hex() if len(resp) >= 28 else ""
        return True, bmc_sid, status
    except Exception:
        return None


def probe(host: str, port: int = 623, timeout: float = 4.0) -> dict:
    """One READ-ONLY RMCP+ Open Session Request. Returns {ipmi2: True, bmc_session_id, status} or {reachable:
    False}. Never sends RAKP Message 1 (which would elicit the crackable hash) and never tries a credential."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_open_session_request(os.urandom(4)), (host, int(port)))
        data, _ = s.recvfrom(1024)
        parsed = parse_open_session_response(data)
        if not parsed:
            return {"reachable": False}
        return {"ipmi2": True, "bmc_session_id": parsed[1], "status": parsed[2]}
    except socket.timeout:
        return {"reachable": False}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def analyze(res: dict):
    """(evidence) when the target is an IPMI 2.0 BMC speaking RMCP+ (inherently RAKP-hash-disclosure vulnerable)."""
    if not res or res.get("error") or not res.get("ipmi2"):
        return None
    return ("the BMC speaks IPMI 2.0 RMCP+ (Open Session Response received), so it is inherently vulnerable to "
            "the RAKP authentication hash disclosure (CVE-2013-4786) — a password HMAC is offline-crackable",)


def finding(host: str, port: int, evidence: str, res: dict) -> dict:
    return {
        "title": "IPMI 2.0 BMC exposed — RAKP hash disclosure (%s:%d)" % (host, port),
        "severity": "high", "family": "ipmi_rakp", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-522",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 7.5,
        "evidence": ("The management controller at %s:%d answered an RMCP+ Open Session Request (BMC session id "
                     "%s): %s. Detection only — Apolaki did NOT request the RAKP hash and tried no credential."
                     % (host, port, res.get("bmc_session_id") or "n/a", evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Send an RMCP+ Open Session Request to %s:%d/udp." % (host, port),
            "The BMC returns an Open Session Response (payload type 0x11) — it is an IPMI 2.0 controller.",
            "IPMI 2.0 RAKP inherently discloses a crackable password HMAC (CVE-2013-4786); do not exfiltrate/crack "
            "without explicit authorization."],
        "impact": "BMC credential recovery via offline cracking of the RAKP hash -> full out-of-band control of "
                  "the host (power, serial-over-LAN console, virtual media) = host compromise, often domain-wide.",
        "remediation": ("Restrict IPMI/BMC UDP/623 to a dedicated, isolated management VLAN reachable only by "
                        "trusted admins; set strong unique BMC passwords; disable IPMI over LAN where possible and "
                        "prefer the vendor's authenticated Redfish/HTTPS interface."),
        "tags": ["ipmi", "bmc", "rakp", "cwe-522", "network-service"],
    }
