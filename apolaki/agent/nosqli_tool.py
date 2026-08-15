"""
NoSQL-injection detection — MongoDB-style operator injection, no destructive
writes. Two confirmed oracles:

  1. Boolean-based (query string): a `[$ne]=` / `[$gt]=` operator suffix on a
     param changes an always-true comparison into an always-different one; if
     the TRUE-shaped payload tracks the baseline while the FALSE-shaped one
     diverges, the parameter reaches a NoSQL query unsanitised.

  2. Auth-bypass (JSON body): the canonical NoSQL login bypass — replacing a
     credential value with an operator object ({"$ne": null} / {"$gt": ""})
     neutralises the match clause, exactly like the SQL analogue but shaped
     for a JSON request body. Confirmed by an issued session/JWT token that
     the benign baseline lacked, or a 401->200 flip — mirrors sqli_tool's
     auth_bypass_confirmed so the same discipline applies to both injection
     families.

Error-based: broken MongoDB/Mongoose error signatures are checked too (some
drivers DO surface a stack trace on a malformed operator), but boolean/auth-
bypass are the primary oracles since NoSQL stores often fail silently.

Pure/deterministic and unit-tested; tools._run_nosqli does the transport.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# ── NoSQL/driver error signatures (content-only; absent from normal pages) ──
NOSQL_ERRORS = {
    "MongoDB": [r"MongoError", r"MongoServerError", r"BSONError", r"E11000 duplicate key",
                r"\$where.*not (?:supported|allowed)", r"unknown operator", r"unknown top level operator",
                r"CastError.*ObjectId", r"MongooseError", r"ValidatorError"],
    "CouchDB": [r"CouchDB Error", r"illegal_database_name", r"no_db_file"],
    "Redis": [r"WRONGTYPE", r"ERR unknown command", r"ReplyError"],
    "Elasticsearch": [r"elasticsearch\.exceptions", r"search_phase_execution_exception", r"illegal_argument_exception"],
}

# operator-injection suffixes appended to a param name: id[$ne]=1, id[$gt]=
# bounded to the 3 highest-signal operators — $exists dropped (weakest/least
# universal signal, and every extra suffix is another remote round-trip per param)
OPERATOR_SUFFIXES = ["[$ne]", "[$gt]", "[$regex]"]

# JSON-body auth-bypass operator payloads — replace a credential value outright
AUTH_BYPASS_OPERATORS = [
    {"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$regex": ".*"}, {"$exists": True},
]

LOGIN_FIELD_HINTS = ("email", "username", "user", "login", "userid", "user_name", "account", "password")


def set_operator_param(url: str, param: str, suffix: str, value: str) -> str:
    """Build `?param[$op]=value`, REMOVING the original `param=...` pair — a bare
    xss_tool.set_param(url, param+suffix, value) call is a no-op here because it
    can only replace an EXISTING key's value, never inject a new key name. Without
    this, the 'operator' request silently reuses the unmodified baseline URL,
    which is indistinguishable from the baseline and guarantees a false positive
    on any endpoint whose param genuinely varies its output by value."""
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    pairs.append((param + suffix, value))
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))


def missing_param_url(url: str, param: str) -> str:
    """The same URL with `param` entirely absent — the baseline for 'did the
    operator suffix just make the framework treat the param as missing' (the
    dominant false-positive shape on non-bracket-aware frameworks)."""
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))


def error_signatures(baseline_body: str, probe_body: str) -> list:
    """DBMS/driver error signatures present in probe but absent from baseline."""
    base, body = baseline_body or "", probe_body or ""
    hits = []
    for store, patterns in NOSQL_ERRORS.items():
        for pat in patterns:
            rx = re.compile(pat, re.IGNORECASE)
            if rx.search(body) and not rx.search(base):
                hits.append({"store": store, "pattern": pat})
    return hits


def similar(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def boolean_probe_pairs(value: str) -> list:
    """(true_suffix, false_suffix, label) pairs — each appended to the param NAME,
    e.g. `id[$ne]=<garbage>` (true: never equals, matches broadly) vs
    `id[$eq]=<garbage>` (false: exact-match a value that doesn't exist). Bounded
    to the 2 highest-signal operators ($gt dropped as redundant with $ne for
    detection purposes) — each extra pair is another remote round-trip per param."""
    garbage = "bbh_nosqli_" + value[:6]
    return [
        {"suffix": "[$ne]", "value": garbage, "ctx": "$ne (should broaden the match)"},
        {"suffix": "[$regex]", "value": ".*", "ctx": "$regex wildcard (should match everything)"},
    ]


def _row_fragment(body: str) -> str:
    """The baseline's real record content, stripped of ONE enclosing array
    bracket pair if present (so a broadened `[row, row2, row3]` response can
    still be checked for literally CONTAINING the original single-row content
    as a substring — a $ne/$gt/$regex bypass typically returns a SUPERSET of
    rows, not a byte-identical response, so pure text similarity scores it as
    dissimilar even though the injection worked)."""
    b = (body or "").strip()
    if b.startswith("[") and b.endswith("]") and len(b) > 2:
        b = b[1:-1]
    return b


def analyze_boolean(baseline: str, operator_body: str, control_body: str,
                    missing_body: str = None, thresh: float = 0.97) -> bool:
    """TRUE-shaped (operator injection) diverges from a control that uses the SAME
    param but a value guaranteed not to match (garbage). An operator bypass
    ($ne/$gt/$regex) commonly BROADENS the result set (returns more rows, not a
    byte-identical response) rather than reproducing the baseline verbatim, so
    the oracle checks CONTAINMENT of the baseline's real record content — present
    (at or past baseline length) in the operator response, absent from the
    garbage-value control — rather than raw text similarity, which under-scores a
    genuinely broadened match.

    False-positive guards: (1) a fragment shorter than 8 chars is too generic to
    fingerprint reliably and is never matched; (2) if `missing_body` (the
    response when the param is entirely ABSENT) is supplied and the operator
    response looks like THAT instead, the framework is simply treating
    `param[$op]` as an unrecognised, absent parameter — not engaging any
    operator semantics — and this must NOT be flagged (the dominant FP shape on
    non-bracket-aware frameworks, e.g. a Java/PHP app whose query parser doesn't
    do MongoDB-style bracket-array parsing)."""
    b, op, ctl = baseline or "", operator_body or "", control_body or ""
    if not b or not op:
        return False
    if missing_body is not None and similar(op, missing_body) >= thresh:
        return False
    frag = _row_fragment(b)
    if not frag or len(frag) < 8:
        return False

    def _matches(body: str) -> bool:
        return len(body) >= len(b) and frag in body

    return _matches(op) and not _matches(ctl)


def _base(surface: str, param: str, oracle: str, sev: str, desc: str, evidence: str, steps: list) -> dict:
    return {
        "title": f"NoSQL injection ({oracle}) in '{param}'", "param": param,  # Q-046
        "severity": sev, "target": surface,
        "description": desc,
        "impact": ("Read or modify the NoSQL store: bypass authentication, dump/alter documents outside "
                   "the caller's scope, and — depending on the driver — reach $where/JS execution."),
        "reproduction_steps": steps, "evidence": evidence, "cwe": "CWE-943",
        "family": "nosqli", "tags": ["nosqli", oracle], "confidence": "confirmed",
    }


def error_finding(surface: str, param: str, probe: str, hits: list) -> dict:
    store = ", ".join(sorted({h["store"] for h in hits}))
    return _base(surface, param, "error-based", "high",
                (f"Injecting a NoSQL operator into '{param}' produced a {store} error/driver signature absent "
                 "from the baseline, so the parameter reaches a NoSQL query unsanitised."),
                f"{store} error triggered by {probe!r}",
                [f"Set '{param}' to an operator payload, e.g. {probe!r}",
                 f"Observe a {store} error/stack trace in the response",
                 "Confirm the operator reaches the query (authorized testing only)"])


def boolean_finding(surface: str, param: str, ctx: str) -> dict:
    return _base(surface, param, "boolean-blind", "high",
                (f"Appending a NoSQL operator suffix to '{param}' ({ctx}) broadened the match to look like the "
                 "baseline (all/most results), while a plain non-matching value on the same param did not — the "
                 "operator changes the query's matching logic (blind NoSQL injection)."),
                f"Operator response ≈ baseline; garbage-value control diverged ({ctx})",
                [f"Set '{param}[$ne]' (or [$gt]/[$regex]) instead of '{param}'",
                 "Observe the result set broadens/matches versus a non-matching plain value",
                 "Escalate to extract data via operator-based boolean inference"])


def auth_bypass_confirmed(base_status: int, base_body: str, inj_status: int, inj_body: str) -> dict:
    """Same discipline as sqli_tool.auth_bypass_confirmed: a session/JWT token
    appearing where the benign baseline had none, or a rejected status flipping
    to success, confirms a real NoSQL auth-bypass — not a request that merely
    changed shape."""
    b, i = (base_body or ""), (inj_body or "")
    tok = re.compile(r'"(authentication|token|access_token|refresh_token|authorization)"\s*:\s*"|'
                     r'\beyJ[A-Za-z0-9_-]{10,}\.', re.IGNORECASE)
    base_has = bool(tok.search(b))
    inj_has = bool(tok.search(i))
    if inj_has and not base_has:
        return {"signal": "session/JWT token issued for an operator-injected credential", "how": "token"}
    if base_status in (401, 403, 400) and inj_status == 200 and len(i) > len(b):
        return {"signal": f"login rejected ({base_status}) but the operator injection returned 200", "how": "status"}
    return {}


def auth_bypass_finding(surface: str, field: str, operator: dict, signal: str) -> dict:
    f = _base(surface, field, "auth-bypass", "critical",
             (f"A NoSQL operator object ({operator!r}) in the '{field}' body field of a login request bypassed "
              f"authentication: {signal}. The field is passed directly into a query match without validating "
              "its type, so an object payload overrides the intended string comparison."),
             f"{signal} via {field}={operator!r}",
             [f"POST the login request with '{field}' set to the JSON object {operator!r} instead of a string",
              "Observe authentication succeed without valid credentials (token issued / 200)",
              "Log in as the first/matched account, or enumerate via $regex"])
    f["impact"] = ("Full authentication bypass: sign in as any user (typically the first matched document) "
                   "without credentials by replacing a credential field with a NoSQL operator object.")
    return f
