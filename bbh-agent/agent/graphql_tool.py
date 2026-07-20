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
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } subscriptionType { name } "
    "types { name kind fields { name args { name } "
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
