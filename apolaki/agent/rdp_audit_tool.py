"""RDP Network Level Authentication (NLA) audit (infra pentest — CWE-287). An RDP service that does NOT require
NLA/CredSSP exposes the full RDP login + protocol stack to UNAUTHENTICATED clients — the pre-auth attack surface
behind BlueKeep-class RCE (CVE-2019-0708) and unlimited online credential guessing. READ-ONLY: only the X.224 /
RDP security-negotiation handshake; no login, no credential, no session.

FP-SAFE ORACLE: send an X.224 Connection Request offering ONLY standard RDP security (requestedProtocols = 0).
A server that ENFORCES NLA replies with an RDP Negotiation FAILURE (type 0x03, HYBRID_REQUIRED_BY_SERVER); a
server that allows non-NLA connections replies with a Negotiation RESPONSE (type 0x02). So a 0x02 response == NLA
not required. A non-RDP TCP service cannot produce a valid TPKT/X.224 negotiation reply. build/parse are pure
(unit-testable); probe() does the one read-only TCP handshake."""
from __future__ import annotations

import socket
import struct

_PROTO = {0: "RDP (standard security)", 1: "TLS", 2: "CredSSP/NLA", 4: "RDSTLS", 8: "CredSSP+EarlyUser"}
_FAILCODE = {1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER", 3: "SSL_CERT_NOT_ON_SERVER",
             4: "INCONSISTENT_FLAGS", 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"}


def build_neg_request(protocols: int = 0) -> bytes:
    """X.224 Connection Request + RDP Negotiation Request offering `protocols` (0 = standard RDP). Pure."""
    neg = struct.pack("<BBHI", 0x01, 0x00, 0x0008, protocols)          # type 1, flags, len 8, requestedProtocols
    x224 = bytes([0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + neg     # LI, CR(0xE0), dst-ref, src-ref, class
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(x224))      # TPKT version + total length
    return tpkt + x224


def parse_neg_response(resp: bytes):
    """(kind, value) from an RDP negotiation reply: ('response', selectedProtocol) or ('failure', failureCode),
    or None if `resp` is not a valid TPKT/X.224 RDP negotiation. The negotiation PDU sits at offset 11 (TPKT 4 +
    X.224 CC header 7)."""
    try:
        if len(resp) < 11 or resp[0] != 0x03:
            return None
        if resp[5] != 0xD0:                                 # 0xD0 = X.224 Connection Confirm
            return None
        if len(resp) < 19:
            # a bare CC with no negotiation PDU = the server just accepted (legacy RDP, no NLA)
            return ("response", 0)
        ntype = resp[11]
        val = struct.unpack("<I", resp[15:19])[0]
        if ntype == 0x02:
            return ("response", val)
        if ntype == 0x03:
            return ("failure", val)
        return None
    except Exception:
        return None


def probe(host: str, port: int = 3389, timeout: float = 5.0) -> dict:
    """One READ-ONLY RDP security-negotiation handshake (offer standard RDP). Returns {nla_required, selected/
    failure} or {reachable: False}. No login attempted."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        s.sendall(build_neg_request(0))
        data = s.recv(512)
        parsed = parse_neg_response(data)
        if not parsed:
            return {"reachable": False}
        if parsed[0] == "failure":
            return {"nla_required": parsed[1] == 5, "failure_code": parsed[1]}   # 5 = HYBRID_REQUIRED_BY_SERVER
        return {"nla_required": False, "selected_protocol": parsed[1]}
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
    """(evidence) when RDP accepts a non-NLA connection; None when NLA is required / not reachable."""
    if not res or res.get("error") or res.get("nla_required") is not False:
        return None
    proto = res.get("selected_protocol", 0)
    return ("the RDP server negotiated %s without requiring Network Level Authentication (CredSSP), so the login "
            "and pre-auth RDP stack are reachable unauthenticated" % _PROTO.get(proto, "protocol %d" % proto),)


def finding(host: str, port: int, evidence: str, res: dict) -> dict:
    return {
        "title": "RDP does not require Network Level Authentication (%s:%d)" % (host, port),
        "severity": "medium", "family": "rdp_no_nla", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-287",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "cvss_score": 5.3,
        "evidence": ("The RDP service at %s:%d completed a security negotiation without CredSSP/NLA: %s. Read from "
                     "the handshake only — no login was attempted." % (host, port, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Send an X.224 Connection Request to %s:%d offering only standard RDP security (protocols=0)." % (host, port),
            "The server returns an RDP Negotiation Response (not a HYBRID_REQUIRED failure) — NLA is not enforced.",
            "The pre-auth RDP surface + login are reachable by any client (credential guessing, BlueKeep-class RCE)."],
        "impact": "Exposes the RDP login to unlimited online credential attacks and the pre-authentication RDP "
                  "protocol surface (e.g. CVE-2019-0708 BlueKeep), a common ransomware entry point.",
        "remediation": ("Require Network Level Authentication (CredSSP) on all RDP hosts (GPO: 'Require user "
                        "authentication for remote connections by using NLA'); restrict TCP/3389 to VPN/jump hosts; "
                        "prefer an authenticated RD Gateway."),
        "tags": ["rdp", "nla", "cwe-287", "network-service"],
    }
