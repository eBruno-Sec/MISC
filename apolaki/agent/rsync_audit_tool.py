"""rsync daemon anonymous-module audit (network/infra pentest — CWE-306). A native rsync daemon (TCP/873) that
lets an anonymous client ENUMERATE its modules leaks the server's share layout to anyone, and such modules are
frequently readable without a password too (backups, web roots, config) — a classic data-theft foothold. READ-
ONLY: the engine performs only the rsync greeting + a '#list' request; it never downloads a module or tries a
password.

FP-SAFE ORACLE: the server must greet with '@RSYNCD:' AND return at least one module to the anonymous '#list'.
A non-rsync service (no @RSYNCD greeting) or a daemon that refuses the list yields nothing. parse is pure
(unit-testable); probe() does the one read-only TCP conversation."""
from __future__ import annotations

import socket


def parse_modules(list_response: str) -> list:
    """Module names from an rsync '#list' response. Lines are 'name<TAB>comment'; '@RSYNCD:' lines are protocol
    control (EXIT / AUTHREQD), not modules."""
    mods = []
    for line in (list_response or "").splitlines():
        line = line.strip()
        if not line or line.startswith("@RSYNCD") or line.startswith("@ERROR"):
            continue
        name = line.split("\t")[0].split()[0]
        if name:
            mods.append(name)
    return mods


def probe(host: str, port: int = 873, timeout: float = 5.0) -> dict:
    """One READ-ONLY rsync conversation: read the @RSYNCD greeting, echo the version, send '#list', collect the
    module list. Returns {rsync_version, modules} or {error}. No module is downloaded, no password sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        greeting = b""
        while b"\n" not in greeting and len(greeting) < 64:
            c = s.recv(1)
            if not c:
                break
            greeting += c
        if not greeting.startswith(b"@RSYNCD:"):
            return {"error": "not an rsync daemon"}
        s.sendall(greeting)                                 # echo the daemon's version back as our version
        s.sendall(b"#list\n")
        data = b""
        try:
            while len(data) < 16384:
                c = s.recv(2048)
                if not c:
                    break
                data += c
                if b"@RSYNCD: EXIT" in data:
                    break
        except socket.timeout:
            pass
        return {"rsync_version": greeting.decode("latin-1", "replace").strip(),
                "modules": parse_modules(data.decode("latin-1", "replace"))}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def analyze(res: dict):
    """(evidence) when an anonymous client can enumerate rsync modules; None otherwise."""
    if not res or res.get("error"):
        return None
    mods = res.get("modules") or []
    if not mods:
        return None
    return ("an anonymous client enumerates %d rsync module(s): %s" % (len(mods), ", ".join(mods[:6])),)


def finding(host: str, port: int, evidence: str, res: dict) -> dict:
    return {
        "title": "rsync daemon allows anonymous module enumeration (%s:%d)" % (host, port),
        "severity": "high", "family": "rsync_anon", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-306",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 7.5,
        "evidence": ("The rsync daemon at %s:%d (%s) returns its module list to an anonymous client: %s. Such "
                     "modules are frequently readable without a password (backups/web roots/config). Read "
                     "passively; no module was downloaded and no password tried." % (host, port, res.get("rsync_version", "rsync"), evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Connect to rsync://%s:%d and complete the @RSYNCD greeting." % (host, port),
            "Send '#list' — the daemon returns its module names with no authentication.",
            "Enumerate/attempt-read each module (authorized testing only) to assess data exposure."],
        "impact": "Anonymous disclosure of the server's rsync share layout, and often anonymous READ of sensitive "
                  "modules (backups, source, credentials) — data theft and lateral-movement intelligence.",
        "remediation": ("Set 'list = no' and require 'auth users' + a secrets file on every rsync module; bind the "
                        "daemon to trusted interfaces and restrict TCP/873 to trusted hosts, or tunnel rsync over SSH."),
        "tags": ["rsync", "no-auth", "info-disclosure", "cwe-306", "network-service"],
    }
