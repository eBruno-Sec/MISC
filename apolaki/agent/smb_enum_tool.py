"""SMB null-session audit (AD/file-server pentest — CWE-306 / CWE-287). A Windows/Samba server that lets an
UNAUTHENTICATED ("null" / anonymous-guest) session enumerate its shares leaks the file-server layout and often
readable data to anyone on the network — a staple AD-engagement finding on file servers and domain members.
READ-ONLY, no credentials, no brute-force (an EMPTY username/password is the null session, not a guess).

FP-SAFE ORACLE: 'an anonymous session connects AND listShares() returns a share'. A hardened server refuses the
anonymous session (restrict anonymous / map-to-guest = never) and yields nothing. Severity escalates to HIGH when
a NON-administrative share (not the IPC$/ADMIN$/*$ built-ins) is exposed to the null session (real data
exposure); enumerating only the admin/IPC shares is MEDIUM (layout disclosure). analyze() is pure (unit-testable
without a server); probe() runs the read-only pysmb conversation."""
from __future__ import annotations

_ADMIN_SHARES = ("ipc$", "admin$", "print$")           # built-ins; a trailing-$ share is administrative by convention


def _is_admin_share(name: str) -> bool:
    n = (name or "").lower()
    return n in _ADMIN_SHARES or n.endswith("$")


def analyze(res: dict):
    """(severity, evidence, data_shares) when a null session can enumerate shares; None otherwise. A NON-admin
    share => high (data exposure); only admin/$ shares => medium (layout disclosure)."""
    if not res or res.get("error") or not res.get("connected"):
        return None
    shares = [s for s in (res.get("shares") or []) if s]
    if not shares:
        return None
    data = [s for s in shares if not _is_admin_share(s)]
    if data:
        return ("high", "a null (unauthenticated) session enumerates %d share(s) including the non-administrative "
                "share(s) %s" % (len(shares), ", ".join(data[:5])), data)
    return ("medium", "a null (unauthenticated) session enumerates %d administrative share(s): %s"
            % (len(shares), ", ".join(shares[:5])), [])


def probe(host: str, port: int = 445, timeout: float = 6.0) -> dict:
    """One READ-ONLY anonymous SMB conversation: connect with an EMPTY username/password (null session) and
    listShares(). Returns {connected, shares} or {error}. No writes, no credential guessing."""
    try:
        from smb.SMBConnection import SMBConnection
    except Exception as e:
        return {"error": "pysmb unavailable: %s" % e}
    conn = None
    try:
        conn = SMBConnection("", "", "apolaki-audit", host, use_ntlm_v2=True, is_direct_tcp=True)
        if not conn.connect(host, int(port), timeout=int(timeout)):
            return {"connected": False}
        shares = []
        for s in conn.listShares(timeout=int(timeout)):
            shares.append(getattr(s, "name", str(s)))
        return {"connected": True, "shares": shares}
    except Exception as e:
        return {"error": str(e)[:140]}
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass


def _smb2_negotiate_request() -> bytes:
    """A minimal SMB2 NEGOTIATE request (dialects 2.0.2 .. 3.0.2), direct-TCP framed. No auth, no session."""
    import os
    import struct
    header = (b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0)
              + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0)
              + struct.pack("<Q", 0) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0)
              + b"\x00" * 16)
    dialects = struct.pack("<HHHH", 0x0202, 0x0210, 0x0300, 0x0302)
    body = (struct.pack("<H", 36) + struct.pack("<H", 4) + struct.pack("<H", 1) + struct.pack("<H", 0)
            + struct.pack("<I", 0) + os.urandom(16) + struct.pack("<Q", 0) + dialects)
    msg = header + body
    return struct.pack(">I", len(msg)) + msg          # 4-byte direct-TCP length prefix


def parse_signing(resp: bytes):
    """Server SecurityMode from an SMB2 NEGOTIATE response: True if signing is REQUIRED, False if only
    enabled/optional (relay-able), None if unparseable. SecurityMode is 2 bytes at the start of the response
    body (after the 4-byte TCP prefix + 64-byte SMB2 header + 2-byte StructureSize)."""
    import struct
    try:
        if len(resp) < 4 + 64 + 4 or resp[4:8] != b"\xfeSMB":
            return None
        sec_mode = struct.unpack("<H", resp[4 + 64 + 2:4 + 64 + 4])[0]
        return bool(sec_mode & 0x0002)                # SMB2_NEGOTIATE_SIGNING_REQUIRED
    except Exception:
        return None


def probe_signing(host: str, port: int = 445, timeout: float = 6.0) -> dict:
    """One read-only SMB2 NEGOTIATE (no auth) to read whether the server REQUIRES message signing. Returns
    {signing_required: bool} or {error}. A server that does not require signing is relay-able."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        s.sendall(_smb2_negotiate_request())
        data = b""
        while len(data) < 200:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= 4 + 64 + 4:
                break
        req = parse_signing(data)
        if req is None:
            return {"error": "no SMB2 negotiate response"}
        return {"signing_required": req}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def signing_finding(host: str, port: int) -> dict:
    return {
        "title": "SMB message signing not required (%s:%d)" % (host, port),
        "severity": "medium", "family": "smb_signing_disabled", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-347",
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", "cvss_score": 6.4,
        "evidence": ("The SMB server at %s:%d returned an SMB2 NEGOTIATE with SecurityMode that does NOT set "
                     "SIGNING_REQUIRED, so a MITM/relay attacker can tamper with or relay authenticated SMB "
                     "sessions (NTLM relay). Read passively from the negotiate response; no auth." % (host, port)),
        "success_oracle": "SMB2 NEGOTIATE SecurityMode lacks the SIGNING_REQUIRED (0x0002) flag",
        "reproduction_steps": [
            "Send an SMB2 NEGOTIATE to %s:%d and read the server SecurityMode field." % (host, port),
            "SIGNING_REQUIRED (0x0002) is not set — signing is optional, so sessions are relay-able."],
        "impact": ("NTLM relay: capture/coerce an authentication and relay it to this host to act as the victim "
                   "(e.g. to a domain controller or file server) — a common lateral-movement + privilege path."),
        "remediation": ("Require SMB signing everywhere ('server signing = mandatory' on Samba / 'Microsoft "
                        "network server: Digitally sign communications (always) = Enabled' via GPO), and enable "
                        "SMB signing + EPA/channel binding on domain controllers."),
        "tags": ["smb", "ntlm-relay", "signing", "cwe-347", "network-service"],
    }


def finding(host: str, port: int, severity: str, evidence: str, data_shares: list) -> dict:
    vec = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "high"
           else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    return {
        "title": "SMB allows null-session share enumeration (%s:%d)" % (host, port),
        "severity": severity, "family": "smb_null_session", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-306",
        "cvss_vector": vec, "cvss_score": 7.5 if severity == "high" else 5.3,
        "evidence": ("The SMB service at %s:%d accepts an anonymous (null) session and %s. Read passively with an "
                     "empty username/password — no credential was guessed." % (host, port, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Connect to %s:%d with an EMPTY username and password (a null session)." % (host, port),
            "Call the SRVSVC share enumeration (listShares).",
            "Shares return to the unauthenticated session — %s." % evidence],
        "impact": ("Pre-auth reconnaissance of the file-server layout"
                   + (" and read access to non-administrative share(s) %s" % ", ".join(data_shares[:5]) if data_shares else "")
                   + " — feeds data theft and lateral-movement planning."),
        "remediation": ("Restrict anonymous access: set 'restrict anonymous = 2' (Windows) / 'map to guest = "
                        "Never' + 'restrict anonymous = yes' (Samba); require authentication for share enumeration "
                        "and remove guest-readable shares."),
        "tags": ["smb", "null-session", "active-directory", "cwe-306", "network-service"],
    }
