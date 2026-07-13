"""
WAF / filter-evasion primitives for Yggdrasil's authorized active testing.

Pure and deterministic (no network I/O), same style as core.web_security. These
helpers let Tyr's offensive engine assess whether a target's WAF/CDN actually
blocks real attacks or merely naive scanner traffic — a legitimate, reportable
outcome — and let it *recognise* when it is being blocked so the report says
"inconclusive" instead of falsely implying "clean".

Everything here is non-destructive: it obfuscates *detection* payloads (reflection
canaries, quote-breakers, read-only traversal markers). It never adds destructive
operations. Use only against targets you are authorized to test.
"""
from __future__ import annotations

# A current, mainstream Chrome UA. WAFs cheaply fingerprint "python-httpx",
# "sqlmap", "curl", etc.; presenting a real browser UA (what a manual tester's
# browser sends anyway) avoids the lowest-effort bot block.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# sqlmap tamper chains — stock sqlmap scripts only (no custom/unknown code).
# Order matters: structural rewrites (spaces, case, syntax) come BEFORE encoders so
# encoding does not lock the payload into a form the earlier scripts cannot rewrite.
# Default is conservative (rarely breaks a payload on a WAF-less target); the
# aggressive chain adds encoders for hardened targets.
SQLMAP_TAMPER = "between,randomcase,space2comment"
SQLMAP_TAMPER_AGGRESSIVE = (
    "space2comment,equaltolike,between,randomcase,charencode,charunicodeencode"
)

# Response signals that mean "a WAF/CDN bounced us", not "the app is clean".
WAF_BLOCK_STATUS = {403, 406, 409, 429, 501, 503}
WAF_BODY_SIGNATURES = (
    "mod_security", "modsecurity", "request blocked", "access denied",
    "request rejected", "has been blocked", "web application firewall",
    "attention required", "cloudflare to restrict", "incapsula", "imperva",
    "sucuri", "aws waf", "not acceptable", "malicious request", "blocked by",
)


def _url_encode_all(s: str) -> str:
    return "".join("%{:02X}".format(b) for b in s.encode("utf-8", "surrogatepass"))


def _double_url_encode(s: str) -> str:
    return "".join("%25{:02X}".format(b) for b in s.encode("utf-8", "surrogatepass"))


def _alt_case(s: str) -> str:
    """Deterministic alternating case — defeats naive case-sensitive keyword filters
    without the non-reproducibility of random casing (keeps tests deterministic)."""
    out, i = [], 0
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if i % 2 else ch.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def payload_variants(payload: str, family: str = "generic", max_variants: int = 6) -> list[str]:
    """Return WAF-evasion rewrites of one detection payload, most-natural first and
    always including the original. `family` in {sql, xss, traversal, generic}.

    Deterministic and deduped so probe loops stay reproducible and bounded."""
    if not payload:
        return []
    fam = (family or "generic").lower()
    variants = [payload, _url_encode_all(payload), _double_url_encode(payload)]

    if fam == "sql":
        variants += [
            payload.replace(" ", "/**/"),
            _alt_case(payload),
            payload.replace("--", "#"),
        ]
    elif fam == "xss":
        variants += [
            _alt_case(payload),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("<", "%253C").replace(">", "%253E"),
        ]
    elif fam == "traversal":
        variants += [
            payload.replace("../", "..%2f").replace("..\\", "..%5c"),
            payload.replace("../", "....//"),
        ]

    out, seen = [], set()
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= max_variants:
            break
    return out


def expand_payloads(payloads, family: str = "generic", max_variants: int = 3) -> list[str]:
    """Expand a payload list with evasion variants, deduped and order-preserving.
    Keep max_variants small in request-bound probe loops to avoid a request blowup."""
    out, seen = [], set()
    for p in payloads or []:
        for v in payload_variants(p, family, max_variants):
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def looks_waf_blocked(status_code, headers=None, body=None) -> bool:
    """True when a single response looks like a WAF/CDN block or challenge rather
    than a genuine application response. Aggregate this across many probes (with a
    ratio threshold) before declaring a target WAF-protected — a lone 403 on
    /admin is normal, a wall of 403/429 across app endpoints is not."""
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0
    if code in WAF_BLOCK_STATUS:
        return True
    hay = " ".join(str(v) for v in (headers or {}).values()).lower()
    hay += " " + str(body or "")[:4000].lower()
    return any(sig in hay for sig in WAF_BODY_SIGNATURES)
