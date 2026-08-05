"""VNC no-authentication audit (network/infra pentest — CWE-306). A VNC server that offers the RFB security type
'None' (1) grants full remote desktop/keyboard/mouse control to anyone who connects — no password. A staple
infrastructure exposure on jump boxes, kiosks, hypervisor consoles, and misconfigured remote-support setups.
READ-ONLY: the engine performs only the RFB version + security-type handshake and NEVER completes a session or
attempts a password.

FP-SAFE ORACLE: the server must speak RFB (banner 'RFB 00x.00y') AND advertise security type 1 (None) in its
handshake. A password-protected server offers only type 2 (VNC auth) / others and yields nothing. build/parse are
pure (unit-testable); probe() does the one read-only TCP handshake."""
from __future__ import annotations

import socket
import struct

_SECTYPE = {0: "invalid", 1: "None", 2: "VNC-auth", 5: "RA2", 16: "Tight", 18: "TLS", 19: "VeNCrypt", 30: "ARD"}


def parse_security_types(after_version: bytes, rfb_minor: int) -> list:
    """The security types the server advertises after the version exchange. RFB >=3.7 sends [count][types...];
    RFB 3.3 sends a single 4-byte security type. Returns a list of ints (empty if unparseable)."""
    if not after_version:
        return []
    if rfb_minor >= 7:
        count = after_version[0]
        if count == 0 or count > 8 or len(after_version) < 1 + count:
            # 3.7 with 0 = the server rejected us (failure) — not a security-type list
            return []
        return list(after_version[1:1 + count])
    if len(after_version) >= 4:                              # RFB 3.3: one uint32 security type
        return [struct.unpack(">I", after_version[:4])[0]]
    return []


def probe(host: str, port: int = 5900, timeout: float = 5.0) -> dict:
    """One READ-ONLY RFB handshake: read the server version, echo a client version, read the offered security
    types. Returns {rfb_version, security_types, no_auth} or {error}. No password is ever sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        banner = s.recv(12)
        if len(banner) < 12 or not banner.startswith(b"RFB "):
            return {"error": "not an RFB/VNC service"}
        try:
            minor = int(banner[8:11])
        except Exception:
            minor = 3
        client_ver = b"RFB 003.008\n" if minor >= 7 else b"RFB 003.003\n"
        s.sendall(client_ver)
        data = s.recv(256)
        types = parse_security_types(data, minor)
        if not types:
            return {"error": "no security types offered (server rejected handshake)"}
        return {"rfb_version": banner.decode("latin-1", "replace").strip(),
                "security_types": types, "no_auth": 1 in types}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def analyze(res: dict):
    """(evidence) when the VNC server offers 'None' auth (unauthenticated control); None otherwise."""
    if not res or res.get("error") or not res.get("no_auth"):
        return None
    names = ", ".join(_SECTYPE.get(t, str(t)) for t in (res.get("security_types") or []))
    return ("an unauthenticated VNC server offers RFB security type 'None' (types offered: %s)" % names,)


def finding(host: str, port: int, evidence: str, res: dict) -> dict:
    return {
        "title": "Unauthenticated VNC remote desktop exposed (%s:%d)" % (host, port),
        "severity": "high", "family": "vnc_no_auth", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-306",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
        "evidence": ("The VNC server at %s:%d (%s) advertises the 'None' security type in its RFB handshake — any "
                     "client can take full remote-desktop control with no password. Read passively from the "
                     "handshake; no session was opened and no password tried." % (host, port, res.get("rfb_version", "RFB"))),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Connect to %s:%d and complete the RFB version exchange." % (host, port),
            "Read the offered security types — 'None' (1) is present.",
            "Any VNC client can connect with no credentials and control the desktop."],
        "impact": "Full unauthenticated remote control of the desktop (keyboard/mouse/screen) — complete takeover "
                  "of the host and anything the logged-in session can reach.",
        "remediation": ("Require a strong VNC password or, better, disable password-only VNC and tunnel it over "
                        "SSH/VPN; restrict TCP/5900 to trusted management hosts; prefer authenticated remote-access."),
        "tags": ["vnc", "no-auth", "remote-desktop", "cwe-306", "network-service"],
    }
