"""
GraphQL testing helpers (pure) + endpoint probing.

Deterministic logic — endpoint candidates, the introspection query, schema
parsing, and the abuse-signal analyzers — is unit-tested here. The network calls
live in tools._run_graphql. Attack angles drawn from Learning GraphQL (Banks &
Porcello): introspection exposure (Ch 3), and the production-security controls
that are often missing (Ch 7: query depth/complexity limits, batching).
"""
from __future__ import annotations

from urllib.parse import urlparse

COMMON_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                "/v2/graphql", "/query", "/gql", "/api/gql", "/graphql/console")

# Compact introspection query — enough to enumerate roots + types.
# NOTE (#125): the args sub-selection must request the argument's TYPE, not only its name. Without it
# every argument reads as untyped, and a payload aimed at an Int argument is rejected by the type system
# before it can reach any sink — observed live on DVGA, where paste(id:) returned 'Expected type "Int"'
# and the probe accomplished nothing. The `type` block after `args` belongs to the FIELD; arguments need
# their own.
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } subscriptionType { name } "
    "types { name kind fields { name "
    "args { name type { name kind ofType { name kind ofType { name kind } } } } "
    "type { name kind ofType { name kind } } } } } }"
)

# A field name that will not exist — used to trigger "Did you mean" suggestions.
BOGUS_FIELD_QUERY = "{ bbhNonexistentField_zzz }"


def endpoint_candidates(url: str) -> list:
    """The URL as given, plus common GraphQL paths on the same host."""
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    out = [url]
    for path in COMMON_PATHS:
        cand = base + path
        if cand not in out:
            out.append(cand)
    return out


def looks_like_graphql(resp_json) -> bool:
    """A GraphQL endpoint answers a query with a `data` or `errors` envelope."""
    if isinstance(resp_json, dict):
        return "data" in resp_json or "errors" in resp_json
    if isinstance(resp_json, list) and resp_json:
        return looks_like_graphql(resp_json[0])
    return False


def _root_fields(types: list, root_name: str) -> list:
    if not root_name:
        return []
    for t in types or []:
        if t.get("name") == root_name:
            return [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
    return []


def parse_schema(resp_json: dict) -> dict:
    """Extract root query/mutation/subscription fields + type count from an
    introspection response."""
    schema = ((resp_json or {}).get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return {"introspection": False}
    types = schema.get("types") or []
    return {
        "introspection": True,
        "query_fields": _root_fields(types, (schema.get("queryType") or {}).get("name")),
        "mutation_fields": _root_fields(types, (schema.get("mutationType") or {}).get("name")),
        "subscription_fields": _root_fields(types, (schema.get("subscriptionType") or {}).get("name")),
        "type_count": len([t for t in types if not str(t.get("name", "")).startswith("__")]),
    }


# ── argument extraction + injection wiring (#125, Black Hat GraphQL Ch.8) ──
# parse_schema above returns root field NAMES, which is enough to say "introspection is enabled" but not
# enough to TEST anything: Ch.8 names query arguments, field arguments, directive arguments and mutations
# as the injection entry points, and Apolaki's injection engines only ever look at query strings and form
# fields. Without the argument list they cannot reach a GraphQL sink at all. These functions close that.

# Argument names whose value is worth handing to the injection engines first.
_INTERESTING_ARG = ("id", "ids", "name", "email", "user", "username", "search", "query", "filter",
                    "q", "term", "slug", "path", "file", "url", "order", "sort", "where")


def _type_name(t) -> str:
    """Unwrap NON_NULL / LIST wrappers to the underlying named type. Pure."""
    seen = 0
    while isinstance(t, dict) and seen < 6:
        if t.get("name"):
            return str(t["name"])
        t = t.get("ofType")
        seen += 1
    return ""


# Scalars that carry text. A payload sent to an Int/Float/Boolean argument is rejected by the type system
# before it can reach any sink — proven live on DVGA, where deletePaste(id:) returned
# 'Expected type "Int"' and the probe accomplished nothing.
_TEXTUAL_TYPES = {"String", "ID"}


def schema_operations(resp_json) -> list:
    """[{operation, kind, args}] for every root query and mutation, where each arg is
    {name, type, textual}. Pure.

    This is the surface map: the same introspection response parse_schema already consumes, read for the
    arguments and TYPES it discards."""
    schema = ((resp_json or {}).get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return []
    types = schema.get("types") or []
    roots = {(schema.get("queryType") or {}).get("name"): "query",
             (schema.get("mutationType") or {}).get("name"): "mutation"}
    out = []
    for t in types:
        if not isinstance(t, dict):
            continue
        kind = roots.get(t.get("name"))
        if not kind:
            continue
        for f in (t.get("fields") or []):
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = []
            for a in (f.get("args") or []):
                if not isinstance(a, dict) or not a.get("name"):
                    continue
                tn = _type_name(a.get("type"))
                args.append({"name": a["name"], "type": tn, "textual": tn in _TEXTUAL_TYPES})
            out.append({"operation": f["name"], "kind": kind, "args": args})
    out.sort(key=lambda o: (o["kind"], o["operation"]))
    return out


def injectable_arguments(operations, max_out: int = 60, include_mutations: bool = False) -> list:
    """Arguments worth handing to the existing injection engines. Pure.

    Two filters, both learned from a live run against DVGA:

    * **Type.** Only textual arguments (String/ID) can carry a payload; an Int argument rejects it at the
      type system and the probe proves nothing. Non-textual args are returned marked `injectable=False`
      so the caller can see them without wasting requests.
    * **Safety.** Mutations CHANGE STATE — `deletePaste(id:)` is not something to fire a payload at
      speculatively. Queries are auto-fireable; mutations are excluded unless the caller explicitly opts
      in (`include_mutations`), which is the operator-gated path."""
    out = []
    for op in operations or []:
        if op.get("kind") == "mutation" and not include_mutations:
            continue
        for a in op.get("args") or []:
            name = a["name"] if isinstance(a, dict) else str(a)
            tn = a.get("type", "") if isinstance(a, dict) else ""
            textual = a.get("textual", True) if isinstance(a, dict) else True
            al = str(name).lower()
            out.append({"operation": op["operation"], "kind": op["kind"], "arg": name, "type": tn,
                        "injectable": bool(textual),
                        "state_changing": op.get("kind") == "mutation",
                        "interesting": any(al == h or al.endswith(h) for h in _INTERESTING_ARG)})
    out.sort(key=lambda x: (not x["injectable"], not x["interesting"], x["kind"], x["operation"],
                            x["arg"]))
    return out[:max_out]


def build_query(operation: str, kind: str, arg: str, value: str) -> str:
    """A minimal single-argument operation carrying `value` — the vehicle a payload rides in. Pure.

    The value is JSON-encoded so a payload can never break out of the string and restructure the document
    into a different (possibly far heavier) query. That is a safety property, not just hygiene."""
    op_kw = "mutation" if kind == "mutation" else "query"
    import json as _json
    return "%s { %s(%s: %s) { __typename } }" % (op_kw, operation, arg, _json.dumps(str(value)))


def build_batch_array(query: str, n: int = 5) -> list:
    """A JSON-array batch — accepted only if the server allows request batching
    (an auth-brute-force / rate-limit amplification vector; Ch 7)."""
    return [{"query": query} for _ in range(max(1, n))]


def detect_batching(resp_json, expected: int) -> bool:
    """True if the server answered an array batch with an array of results."""
    return isinstance(resp_json, list) and len(resp_json) == expected


def detect_field_suggestion(resp_json) -> bool:
    """True if a bogus-field error leaks real field names via 'Did you mean' —
    schema is still discoverable even with introspection disabled."""
    errs = (resp_json or {}).get("errors") if isinstance(resp_json, dict) else None
    for e in (errs or []):
        if "did you mean" in str(e.get("message", "")).lower():
            return True
    return False


def analyze(endpoint: str, introspection_resp, batch_resp, batch_n, bogus_resp) -> list:
    """Turn the probe responses into findings."""
    findings = []
    schema = parse_schema(introspection_resp)

    if schema.get("introspection"):
        q = len(schema.get("query_fields", []))
        m = len(schema.get("mutation_fields", []))
        findings.append({
            "title": "GraphQL introspection enabled",
            "severity": "medium", "target": endpoint,
            "description": (f"Introspection is enabled and exposes the full schema "
                            f"({schema.get('type_count')} types, {q} queries, {m} mutations). "
                            "Attackers can map every operation and object type."),
            "impact": "Full API surface disclosure; accelerates auth-bypass, IDOR/BOLA, and mass-assignment discovery.",
            "reproduction_steps": [f"POST an introspection query to {endpoint}",
                                   "Observe the __schema in the response"],
            "cwe": "CWE-200", "family": "graphql", "tags": ["graphql", "api"],
            "remediation": "Disable introspection in production; enforce per-field authorization.",
        })
    elif detect_field_suggestion(bogus_resp):
        findings.append({
            "title": "GraphQL field suggestions leak schema",
            "severity": "low", "target": endpoint,
            "description": "Introspection is disabled but the server returns 'Did you mean' "
                           "suggestions on unknown fields, so field names remain discoverable.",
            "impact": "Schema fields can be brute-forced despite disabled introspection.",
            "reproduction_steps": [f"POST {BOGUS_FIELD_QUERY} to {endpoint}",
                                   "Read the 'Did you mean' hint in the error"],
            "cwe": "CWE-200", "family": "graphql", "tags": ["graphql", "api"],
            "remediation": "Disable field suggestions (e.g. Apollo: set introspection and suggestions off in prod).",
        })

    if detect_batching(batch_resp, batch_n):
        findings.append({
            "title": "GraphQL request batching enabled",
            "severity": "medium", "target": endpoint,
            "description": f"The endpoint accepted a JSON array batch of {batch_n} operations in one request.",
            "impact": "Rate-limit bypass and brute-force amplification (e.g. password/OTP guessing) via batched operations.",
            "reproduction_steps": [f"POST a JSON array of {batch_n} queries to {endpoint}",
                                   "Observe an array of results returned"],
            "cwe": "CWE-770", "family": "graphql", "tags": ["graphql", "api"],
            "remediation": "Disable array batching or apply per-operation rate limiting + query cost limits.",
        })
    return findings
