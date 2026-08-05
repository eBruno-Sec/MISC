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
