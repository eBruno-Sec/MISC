"""WAF inspection-window bypass engine (CWE-693, Protection Mechanism Failure). Distilled from the WAF-evasion
TTP material (RedCyber/NotebookLM corpus): many WAFs, to hold sub-millisecond latency, only inspect the first
~8KB/16KB of a request. A payload placed AFTER that ceiling reaches the app unvetted. This is a standard,
authorized web-pentest check — the DELIVERABLE is "your WAF has a bypassable inspection window, fix it (add
app-layer validation / raise the limit)", so a team can close the gap.

CONFIRMATION IS A THREE-STATE DIFFERENTIAL, non-destructive: (1) a benign baseline value returns normally;
(2) a signature payload (a bare <script>/SQLi string) is BLOCKED — proving a WAF is inspecting; (3) the SAME
payload preceded by junk that exceeds the inspection window is NOT blocked AND the payload REFLECTS — proving
it slipped past the WAF and reached the app. All three conditions are required, so a target with no WAF (the
signature is never blocked) or a WAF with no window limit (the padded payload is still blocked) yields nothing.
Pure logic here (payloads + block/reflection oracle + finding); the HTTP transport lives in tools."""
from __future__ import annotations

# benign detection payloads whose bare form a signature-WAF blocks (we never need them to EXECUTE — the
# reflection of the literal string is all the oracle needs; no exploitation is performed).
SIGNATURE_PAYLOADS = [
    ("xss", "<script>alert(1)</script>"),
    ("sqli", "' UNION SELECT NULL-- -"),
]

# status codes a WAF/edge returns on a block (distinct from the app's own 200/404).
_BLOCK_CODES = {403, 406, 419, 429, 501, 999}
# block-page body signatures — matched only when NEW relative to the baseline body (avoids app-text FPs).
_BLOCK_SIGNS = ["request blocked", "access denied", "web application firewall", "mod_security", "modsecurity",
                "cloudflare", "akamai", "incapsula", "attention required", "not acceptable", "blocked by",
                "your request has been blocked", "malicious", "waf"]


def pad(payload: str, size: int = 8300, position: str = "prefix") -> str:
    """The payload with `size` bytes of benign junk positioned to exceed the WAF's inspection window."""
    junk = "A" * max(0, size)
    return junk + payload if position == "prefix" else payload + junk


def is_blocked(baseline_status: int, baseline_body: str, status: int, body: str) -> bool:
    """A WAF block: a block status code the baseline didn't have, or a block-page signature new to this body."""
    if status in _BLOCK_CODES and baseline_status not in _BLOCK_CODES:
        return True
    b, base = (body or "").lower(), (baseline_body or "").lower()
    for s in _BLOCK_SIGNS:
        if s in b and s not in base:
            return True
    return False


def reflected(payload: str, body: str) -> bool:
    return payload in (body or "")


def evaluate(baseline, raw, padded, payload):
    """Confirmed ONLY when the raw signature is blocked, the padded signature is NOT blocked, and it reflects.
    Each arg is (status, body)."""
    bs, bb = baseline
    rs, rb = raw
    ps, pb = padded
    raw_blocked = is_blocked(bs, bb, rs, rb)
    padded_blocked = is_blocked(bs, bb, ps, pb)
    if raw_blocked and not padded_blocked and reflected(payload, pb):
        return {"confirmed": True,
                "oracle": "the signature payload was blocked by the WAF (HTTP %s) but the same payload after "
                          "~8KB of junk was NOT blocked (HTTP %s) and reflected in the response — the WAF's "
                          "inspection window was exceeded" % (rs, ps)}
    return {"confirmed": False, "oracle": ""}


def finding(url: str, param: str, cls: str, oracle: str) -> dict:
    return {
        "title": "WAF inspection-window bypass via payload padding in '%s'" % param,
        "severity": "medium", "family": "waf_bypass", "confidence": "confirmed", "target": url,
        "cwe": "CWE-693", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "cvss_score": 6.5,
        "evidence": ("The WAF protecting '%s' inspects only the start of the request. A %s signature payload was "
                     "blocked, but the identical payload placed after ~8KB of junk reached the application. %s"
                     % (param, cls.upper(), oracle)),
        "success_oracle": oracle,
        "reproduction_steps": [
            "Send a bare signature payload in '%s' — the WAF returns a block." % param,
            "Prepend ~8KB of junk (e.g. 8300 'A' characters) before the same payload.",
            "The padded request is NOT blocked and the payload reflects — the WAF's inspection ceiling was exceeded."],
        "impact": ("The WAF is a bypassable speed-bump: an attacker can smuggle any blocked payload (XSS, SQLi, "
                   "etc.) past it by padding, so the app's own input validation is the only real defense."),
        "remediation": ("Do not rely on the WAF as the sole control — enforce server-side input validation/encoding. "
                        "Configure the WAF to inspect the full request body (raise or remove the inspection-size "
                        "limit) and to fail closed on oversized requests it cannot fully inspect."),
        "tags": ["waf-bypass", "inspection-window", "cwe-693"],
    }
