"""NTP monlist / amplification audit (network/infra pentest — CWE-406). An NTP server with the legacy ntpdc
'monlist' (mode 7, REQ_MON_GETLIST_1) command enabled answers a tiny request with a large list of recent
clients — a massive UDP-amplification DDoS reflector (CVE-2013-5211) that also leaks the addresses of everyone
who recently talked to it. READ-ONLY: one query; nothing is changed. A patched/hardened ntpd (>=4.2.7) does not
answer mode-7 monlist.

FP-SAFE ORACLE: the server must reply with a MODE-7 response (response bit set, mode == 7) to the monlist
request. A non-NTP UDP service, or a patched ntpd that ignores mode 7, does not — so no false positive. build/
parse are pure (unit-testable); probe() does the one read-only UDP round-trip."""
from __future__ import annotations

import socket
import struct


def build_monlist() -> bytes:
    """The classic ntpdc REQ_MON_GETLIST_1 (monlist) request. Byte0 0x17 = response 0 | more 0 | version 2 |
    mode 7; impl 3 (NTPDC); reqcode 42 (0x2a). Padded to the standard 48-byte request."""
    pkt = bytes([0x17, 0x00, 0x03, 0x2A]) + b"\x00" * 44
    return pkt


def parse_monlist_response(resp: bytes):
    """(is_mode7_response, nitems) from a mode-7 reply, or None if it is not a mode-7 NTP response. Byte0 =
    response(1)|more(1)|version(3)|mode(3); a monlist reply sets the response bit and mode==7. nitems lives in
    the err|nitems 16-bit field (err = top 4 bits, nitems = low 12)."""
    try:
        if len(resp) < 8:
            return None
        b0 = resp[0]
        is_response = bool(b0 & 0x80)
        mode = b0 & 0x07
        if not (is_response and mode == 7):
            return None
        errnitems = struct.unpack(">H", resp[4:6])[0]
        nitems = errnitems & 0x0FFF
        return True, nitems
    except Exception:
        return None


def probe(host: str, port: int = 123, timeout: float = 4.0) -> dict:
    """One READ-ONLY UDP monlist query. Returns {monlist: bool, nitems} or {reachable: False}. No modification."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_monlist(), (host, int(port)))
        data, _ = s.recvfrom(4096)
        parsed = parse_monlist_response(data)
        if not parsed:
            return {"reachable": False}
        return {"monlist": True, "nitems": parsed[1], "resp_len": len(data)}
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
    """(evidence) when the server answers the monlist request (amplification + client-list disclosure); None else."""
    if not res or res.get("error") or not res.get("monlist"):
        return None
    n = res.get("nitems", 0)
    return ("the NTP server answers the legacy 'monlist' (mode 7) request%s — a UDP-amplification reflector "
            "(CVE-2013-5211) that also discloses recent client addresses" % (" with %d client record(s)" % n if n else ""),)


def finding(host: str, port: int, evidence: str, res: dict) -> dict:
    return {
        "title": "NTP monlist enabled — amplification + client disclosure (%s:%d)" % (host, port),
        "severity": "high", "family": "ntp_monlist", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-406",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", "cvss_score": 8.2,
        "evidence": ("The NTP service at %s:%d answered a %d-byte monlist (mode 7) request with a %d-byte "
                     "response: %s. Read passively with one query; nothing was changed."
                     % (host, port, len(build_monlist()), res.get("resp_len", 0), evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Send an ntpdc REQ_MON_GETLIST_1 (monlist) request to %s:%d/udp." % (host, port),
            "The server returns a mode-7 response listing recent clients — many times larger than the request.",
            "This is exploitable as a UDP-amplification DDoS reflector and leaks recent client IPs."],
        "impact": "Serves as a high-ratio UDP-amplification DDoS reflector against third parties, and discloses "
                  "the network addresses of hosts that recently synchronised time with this server.",
        "remediation": ("Upgrade ntpd to >=4.2.7 (monlist removed) or add 'disable monitor' to ntp.conf; restrict "
                        "mode-6/7 queries ('restrict ... noquery'); block/limit inbound UDP/123 from untrusted networks."),
        "tags": ["ntp", "amplification", "ddos-reflector", "cwe-406", "network-service"],
    }
