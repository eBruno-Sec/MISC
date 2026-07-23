"""
Web cache-poisoning / unkeyed-header detection (CWE-444-adjacent: cache-key
confusion via an unkeyed request input).

Method (mirrors PortSwigger Academy's web-cache-poisoning methodology):

  1. Add a unique cache-buster query param so this test owns its own cache
     entry — it never touches (or poisons) a real visitor's cached response.
  2. Send an UNKEYED header (X-Forwarded-Host, X-Forwarded-Scheme, X-Host,
     X-Original-URL, ...) carrying a canary value, on the SAME cache-buster URL.
  3. If the canary is reflected into the response (an absolute link, a redirect
     Location, a header echoed back) AND the response looks cacheable
     (Cache-Control: public/max-age, or an Age/X-Cache/CF-Cache-Status hint),
     re-request the SAME cache-buster URL with NO poison header.
  4. CONFIRMED only if that clean, unpoisoned request still receives the
     canary — proof the cache served poisoned content to a request that never
     sent the header. Reflected-but-not-persisted is a LEAD, not a finding (no
     real caching layer was proven to store it).

Single-shot: stops at the first confirmed header and never repeats poisoning
attempts against the same endpoint. The canary is inert (a fake hostname
marker) — no payload does anything beyond proving reflection.
"""
from __future__ import annotations

import os
import re

# unkeyed headers commonly excluded from the cache key by CDNs/reverse proxies
POISON_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Host", "X-Original-URL", "X-Rewrite-URL",
]

_CACHEABLE_RE = re.compile(r"\b(?:public|s-maxage=[1-9]|max-age=[1-9])\b", re.IGNORECASE)
_CACHE_HINT_HEADERS = ("age", "x-cache", "cf-cache-status", "x-served-by", "x-cache-hits")


def canary_value(token: str) -> str:
    return f"bbh-cachepoison-{token}.apolaki-test.invalid"


def is_cacheable(headers: dict) -> bool:
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    cc = headers.get("cache-control", "")
    if _CACHEABLE_RE.search(cc):
        return True
    return any(h in headers for h in _CACHE_HINT_HEADERS)


def reflects(canary: str, body: str, headers: dict) -> bool:
    if canary and canary in (body or ""):
        return True
    for v in (headers or {}).values():
        if canary and canary in str(v):
            return True
    return False


def _base(surface: str, header: str, sev: str, desc: str, evidence: str, steps: list, confidence: str) -> dict:
    return {
        "title": f"Web cache poisoning via unkeyed header '{header}'", "severity": sev, "target": surface,
        "description": desc,
        "impact": ("An attacker can poison a shared cache so every subsequent unpoisoned visitor to the same "
                   "URL receives attacker-controlled content served from YOUR trusted domain — a powerful "
                   "phishing/defacement/XSS-delivery primitive with no per-request attacker interaction needed."),
        "reproduction_steps": steps, "evidence": evidence, "cwe": "CWE-444",
        "family": "cache_poisoning", "tags": ["cache_poisoning", header.lower()], "confidence": confidence,
    }


def poison_confirmed_finding(surface: str, header: str, canary: str) -> dict:
    return _base(surface, header, "high",
                (f"Sending the unkeyed header '{header}: {canary}' caused it to be reflected into a cacheable "
                 f"response, and a SUBSEQUENT request to the SAME URL with NO '{header}' header still received "
                 "the poisoned content — the cache stored and served the attacker-controlled response to an "
                 "unpoisoned visitor."),
                f"Clean re-request still contained the injected value '{canary}'",
                [f"Request the target URL with a cache-buster query param and header '{header}: {canary}'",
                 "Observe the canary reflected in the cacheable response",
                 "Re-request the SAME URL with NO poison header",
                 "Observe the canary STILL present — the cache served poisoned content"],
                confidence="confirmed")


def unkeyed_header_lead(surface: str, header: str, canary: str) -> dict:
    f = _base(surface, header, "medium",
             (f"The unkeyed header '{header}' is reflected into the response, but a clean re-request did not "
              "return the poisoned content — no caching layer was proven to store it on this request path. "
              "Worth manual verification against the actual CDN/reverse-proxy in front of the target."),
             f"Header '{header}: {canary}' reflected; not confirmed persisted in cache",
             [f"Request the target with header '{header}: {canary}'",
              "Observe the value reflected in the response",
              "Verify manually with the real CDN/cache layer (may need a longer TTL or a different cache key)"],
             confidence="candidate")
    f["severity"] = "medium"
    return f
