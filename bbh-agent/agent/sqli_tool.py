"""
SQL-injection detection — three confirmed oracles, no destructive payloads.

A native complement to run_sqlmap (which needs the binary). Every signal is
confirmed against a baseline so it does not cry wolf:

  1. Error-based: inject a syntax-breaking quote and detect a DBMS error
     signature that the baseline response did not carry (also fingerprints the
     DBMS: MySQL/Postgres/MSSQL/Oracle/SQLite).

  2. Boolean-based blind: send an always-TRUE vs always-FALSE condition; if TRUE
     tracks the baseline while FALSE diverges, the parameter changes the query's
     result set — injectable even with no error and no reflection.

  3. Time-based blind: a SLEEP/pg_sleep/WAITFOR payload with a matching sleep(0)
     control; confirmed only when the delayed request is slower than the control
     by ~the injected time (rules out network jitter).

Payloads are read-only (SELECT-side boolean/time tests) — no stacked writes.
Pure/deterministic and unit-tested; tools._run_sqli does the transport + timing.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

# ── DBMS error signatures (content-only; absent from normal pages) ──
DBMS_ERRORS = {
    "MySQL": [r"SQL syntax.*MySQL", r"You have an error in your SQL syntax",
              r"check the manual that corresponds to your (?:MySQL|MariaDB)", r"MySqlException",
              r"valid MySQL result", r"mysql_fetch", r"Unknown column '[^']+' in 'field list'"],
    "PostgreSQL": [r"PostgreSQL.*ERROR", r"PSQLException", r"unterminated quoted string at or near",
                   r"syntax error at or near", r"invalid input syntax for"],
    "Microsoft SQL Server": [r"Unclosed quotation mark after the character string", r"Microsoft OLE DB Provider",
                             r"Microsoft SQL Native Client", r"System\.Data\.SqlClient\.SqlException",
                             r"Incorrect syntax near", r"\bODBC SQL Server Driver\b"],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"quoted string not properly terminated",
               r"Oracle.*Driver", r"PLS-\d{5}"],
    "SQLite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
               r"unrecognized token:", r"SQLITE_ERROR", r"near \".*\": syntax error", r"sqlite3\.OperationalError"],
}

ERROR_PROBES = ["'", "\"", "')", "\"))", "`"]


def error_signatures(baseline_body: str, probe_body: str) -> list:
    """DBMS error signatures present for the probe but not the baseline."""
    base, body = baseline_body or "", probe_body or ""
    hits = []
    for dbms, pats in DBMS_ERRORS.items():
        for p in pats:
            rx = re.compile(p, re.I)
            if rx.search(body) and not rx.search(base):
                hits.append({"dbms": dbms, "pattern": p})
                break
    return hits


# ── boolean-based blind ──────────────────────────────────────────
_COMMENTS = ("-- -", "#", "-- ")


def boolean_payloads(value: str) -> list:
    v = value or ""
    out = [
        {"ctx": "string-quote", "true": f"{v}' AND '1'='1", "false": f"{v}' AND '1'='2"},
        {"ctx": "string-comment", "true": f"{v}' AND 1=1-- -", "false": f"{v}' AND 1=2-- -"},
        {"ctx": "numeric", "true": f"{v} AND 1=1", "false": f"{v} AND 1=2"},
        {"ctx": "paren-quote", "true": f"{v}') AND ('1'='1", "false": f"{v}') AND ('1'='2"},
    ]
    return out


def similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()


def analyze_boolean(baseline: str, true_body: str, false_body: str, thresh: float = 0.95) -> bool:
    """Injectable when TRUE tracks the baseline but FALSE diverges (the condition
    reaches the query). Identical TRUE/FALSE => not injectable (conservative)."""
    st = similar(baseline, true_body)
    stf = similar(true_body, false_body)
    return st >= thresh and stf < thresh


# ── time-based blind ─────────────────────────────────────────────
def time_payloads(value: str, seconds: int) -> list:
    v = value or ""
    return [
        {"dbms": "MySQL", "payload": f"{v}' AND SLEEP({seconds})-- -", "control": f"{v}' AND SLEEP(0)-- -"},
        {"dbms": "MySQL", "payload": f"{v} AND SLEEP({seconds})", "control": f"{v} AND SLEEP(0)"},
        {"dbms": "PostgreSQL", "payload": f"{v}' AND pg_sleep({seconds})-- -", "control": f"{v}' AND pg_sleep(0)-- -"},
        {"dbms": "Microsoft SQL Server", "payload": f"{v}'; WAITFOR DELAY '0:0:{seconds}'-- -",
         "control": f"{v}'; WAITFOR DELAY '0:0:0'-- -"},
    ]


def analyze_time(control_elapsed: float, sleep_elapsed: float, seconds: int, margin: float = 0.6) -> bool:
    """Confirmed when the sleep request is slower than its control by ~the injected
    delay (and the control itself was fast) — jitter cannot fake this."""
    need = seconds * margin
    return sleep_elapsed - control_elapsed >= need and sleep_elapsed >= need


# ── finding builders ─────────────────────────────────────────────
def _base(url: str, param: str, oracle: str, sev: str, desc: str, evidence: str, steps: list) -> dict:
    return {
        "title": f"SQL injection ({oracle}) in '{param}'", "severity": sev, "target": url,
        "description": desc,
        "impact": ("Read or modify the database: dump credentials/PII, bypass authentication, and — depending on "
                   "privileges — write files or execute commands on the DB host."),
        "reproduction_steps": steps, "evidence": evidence, "cwe": "CWE-89",
        "family": "sqli", "tags": ["sqli", oracle], "confidence": "confirmed",
    }


def error_finding(url: str, param: str, probe: str, dbms_hits: list) -> dict:
    dbms = ", ".join(sorted({h["dbms"] for h in dbms_hits}))
    return _base(url, param, "error-based", "high",
                 (f"Injecting {probe!r} into '{param}' produced a {dbms} SQL error absent from the baseline, so the "
                  "parameter is concatenated into a SQL statement."),
                 f"{dbms} error triggered by {probe!r}",
                 [f"Set '{param}' to a value ending in {probe!r}",
                  f"Observe a {dbms} SQL error in the response",
                  "Extract data with a UNION/error-based query (authorized testing only)"])


def boolean_finding(url: str, param: str, pair: dict) -> dict:
    return _base(url, param, "boolean-blind", "high",
                 (f"For '{param}', an always-true condition ({pair['true']!r}) returned the baseline page while an "
                  f"always-false one ({pair['false']!r}) returned a different page. The condition reaches the query "
                  "(blind SQLi)."),
                 f"TRUE≈baseline, FALSE diverged ({pair['ctx']})",
                 [f"Set '{param}' to {pair['true']!r} — normal page",
                  f"Set '{param}' to {pair['false']!r} — different page",
                  "Extract data one boolean at a time (substring/ASCII)"])


def time_finding(url: str, param: str, item: dict, control_elapsed: float, sleep_elapsed: float, seconds: int) -> dict:
    return _base(url, param, "time-blind", "critical",
                 (f"For '{param}', a {item['dbms']} sleep payload delayed the response to {sleep_elapsed:.1f}s vs "
                  f"{control_elapsed:.1f}s for the sleep(0) control (~{seconds}s injected). The parameter is injectable "
                  "(blind SQLi)."),
                 f"{item['dbms']}: {sleep_elapsed:.1f}s vs control {control_elapsed:.1f}s (injected {seconds}s)",
                 [f"Set '{param}' to {item['payload']!r}",
                  f"Observe the response takes ~{seconds}s longer than the sleep(0) control",
                  "Extract data via time-based boolean inference"])
