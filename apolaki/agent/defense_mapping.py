"""Curated defensive-control mapping (Codex cross-check Tier-1 #3).

Apolaki already emits per-finding remediation text (report.py `_FAMILY_FIX`). This adds the more STRUCTURED
view the books point at: finding -> weakness -> the defensive control(s) that neutralize it -> the attacker
CAPABILITY each control reduces. That makes reports useful for engineering + purple-team planning.

HONESTY RAILS:
  * These are CURATED local mappings, NOT official D3FEND technique IDs. We do not ship the D3FEND graph, so
    `scheme` is "curated_defense" and `provenance` is "Apolaki local mapping" — we never stamp authoritative
    D3FEND ids we can't back.
  * An UNKNOWN family returns NO mapping (never a fabricated control).
"""
from __future__ import annotations

SCHEME = "curated_defense"
PROVENANCE = "Apolaki local mapping"


def _ctrl(control_id, name, reduces, notes):
    return {"scheme": SCHEME, "control_id": control_id, "name": name, "reduces": list(reduces),
            "implementation_notes": list(notes), "confidence": "curated", "provenance": PROVENANCE}


# family -> ordered list of curated defensive controls. `reduces` = attacker capabilities the control removes.
_CONTROLS = {
    "sqli": [
        _ctrl("parameterized-queries", "Parameterized query / prepared-statement enforcement",
              ["database_read", "database_write", "authentication_bypass"],
              ["Bind all data values as parameters; never string-concatenate SQL.",
               "For structural clauses (ORDER BY / column names) use an allowlist of known-safe identifiers.",
               "Apply least-privilege DB accounts so a leak cannot escalate."]),
    ],
    "cmdi": [
        _ctrl("no-shell-exec", "Avoid shell interpretation / use argument-vector APIs",
              ["remote_code_execution", "command_execution"],
              ["Call binaries via argv arrays (execve-style), never a shell string.",
               "Allowlist the command and validate arguments against a strict schema."]),
    ],
    "ssti": [
        _ctrl("logic-less-templates", "Logic-less templates + no user-controlled template source",
              ["remote_code_execution", "server_data_read"],
              ["Never render user input as a template; pass it only as data context.",
               "Prefer sandboxed / logic-less engines for user-influenced output."]),
    ],
    "deserialization": [
        _ctrl("safe-deserialization", "Do not deserialize untrusted data into live objects",
              ["remote_code_execution", "object_injection"],
              ["Use data-only formats (JSON) with schema validation; avoid native object deserialization.",
               "If unavoidable, use type allowlists / signed payloads."]),
    ],
    "xxe": [
        _ctrl("disable-external-entities", "Disable DTDs / external entity resolution in XML parsers",
              ["file_read", "ssrf", "denial_of_service"],
              ["Set parser features to forbid DOCTYPE and external general/parameter entities.",
               "Disable entity expansion to prevent billion-laughs DoS."]),
    ],
    "xss": [
        _ctrl("contextual-output-encoding", "Context-aware output encoding",
              ["session_theft", "credential_theft", "action_forgery"],
              ["Encode per sink context (HTML body, attribute, JS, URL, CSS).",
               "Prefer framework auto-escaping; treat any raw-HTML sink as high risk."]),
        _ctrl("csp-hardening", "Content-Security-Policy hardening",
              ["script_injection", "data_exfiltration"],
              ["Deploy a strict nonce/hash-based CSP; avoid 'unsafe-inline'/'unsafe-eval'.",
               "CSP is defense-in-depth, not a substitute for output encoding."]),
    ],
    "csti": [
        _ctrl("client-template-isolation", "Do not bind untrusted data into client-side template expressions",
              ["script_injection", "session_theft"],
              ["Keep user data out of framework template-expression contexts ({{ }} / directives).",
               "Sanitize before binding; prefer text bindings over HTML bindings."]),
    ],
    "prototype_pollution": [
        _ctrl("prototype-pollution-guards", "Guard object merges against __proto__/constructor keys",
              ["property_injection", "logic_tampering", "remote_code_execution"],
              ["Reject or strip __proto__ / constructor / prototype keys in recursive merges.",
               "Use null-prototype objects (Object.create(null)) or Map for untrusted key/values."]),
    ],
    "crlf": [
        _ctrl("header-value-sanitization", "Strip CR/LF from response header values",
              ["response_splitting", "cache_poisoning", "session_theft"],
              ["Reject or encode CR/LF in any user-influenced header value.",
               "Use framework header APIs that validate values."]),
    ],
    "idor": [
        _ctrl("object-level-authorization", "Per-request object-level authorization (ownership checks)",
              ["cross_object_read", "cross_object_write", "data_theft"],
              ["Verify the authenticated principal owns / may access the referenced object server-side.",
               "Do not rely on unguessable ids; use indirect object references where practical."]),
    ],
    "bola": [
        _ctrl("object-level-authorization", "Per-request object-level authorization (ownership checks)",
              ["cross_object_read", "cross_object_write", "data_theft"],
              ["Enforce ownership on every object reference, including nested/related resources."]),
    ],
    "bfla": [
        _ctrl("function-level-authorization", "Function/endpoint-level authorization (role enforcement)",
              ["privilege_escalation", "unauthorized_action"],
              ["Enforce required role/permission on every privileged endpoint server-side.",
               "Default-deny; never rely on the UI hiding an action."]),
    ],
    "access_control": [
        _ctrl("centralized-access-control", "Centralized, default-deny access-control enforcement",
              ["unauthorized_access", "privilege_escalation", "data_theft"],
              ["Enforce authorization in one server-side chokepoint, not per-handler ad hoc.",
               "Deny by default; add explicit allow rules; log denials."]),
    ],
    "mass_assignment": [
        _ctrl("bind-allowlist", "Bind only allowlisted request fields to models",
              ["privilege_escalation", "attribute_tampering"],
              ["Use explicit DTOs / field allowlists; never bind the whole request body to a model.",
               "Mark privileged attributes read-only at the binding layer."]),
    ],
    "path_traversal": [
        _ctrl("path-canonicalization", "Canonicalize + confine file paths to a base directory",
              ["file_read", "file_write"],
              ["Resolve the real path and assert it stays under the intended base directory.",
               "Prefer opaque ids over user-supplied filenames."]),
    ],
    "ssrf": [
        _ctrl("egress-allowlist", "Outbound egress allowlist + metadata isolation",
              ["internal_service_access", "cloud_metadata_theft", "port_scanning"],
              ["Allowlist outbound hosts; block link-local/loopback/RFC1918 unless explicitly needed.",
               "Block cloud metadata (169.254.169.254) and require IMDSv2-style session tokens.",
               "Resolve + re-validate the final IP after redirects (DNS-rebinding safe)."]),
    ],
    "cors": [
        _ctrl("strict-cors", "Strict CORS: no reflected origins with credentials",
              ["cross_origin_data_theft"],
              ["Allowlist explicit origins; never reflect the Origin header with credentials.",
               "Do not pair Access-Control-Allow-Credentials:true with a wildcard/reflected origin."]),
    ],
    "open_redirect": [
        _ctrl("redirect-allowlist", "Redirect-target allowlist / relative-only redirects",
              ["phishing", "oauth_token_theft"],
              ["Only redirect to allowlisted destinations or same-origin relative paths."]),
    ],
    "takeover": [
        _ctrl("dangling-dns-hygiene", "Decommission DNS records before releasing backing resources",
              ["subdomain_takeover", "phishing", "cookie_theft"],
              ["Remove CNAME/ALIAS records before deleting the cloud resource they point to.",
               "Continuously monitor for dangling records pointing to unclaimed providers."]),
    ],
    "exposure": [
        _ctrl("no-sensitive-web-exposure", "Keep secrets/backups/VCS metadata out of the web root",
              ["information_disclosure", "credential_theft"],
              ["Block access to .git/.env/backup/.bak; keep them out of deployable artifacts.",
               "Serve only an explicit allowlist of static paths."]),
    ],
    "vulnerable_component": [
        _ctrl("dependency-patching", "Dependency inventory + timely patching",
              ["known_exploit_execution"],
              ["Maintain an SBOM; monitor advisories (NVD/GHSA/KEV); patch on a defined SLA.",
               "Remove unused dependencies to shrink attack surface."]),
    ],
    "jwt": [
        _ctrl("jwt-verification", "Strict JWT verification (pinned alg, verified signature)",
              ["authentication_bypass", "privilege_escalation"],
              ["Pin the expected algorithm server-side; reject 'none' and alg-confusion.",
               "Verify signature, issuer, audience and expiry; rotate signing keys."]),
    ],
    "oauth": [
        _ctrl("oauth-hardening", "OAuth flow hardening (exact redirect + PKCE + state)",
              ["token_theft", "account_takeover"],
              ["Exact-match redirect URIs; require PKCE for public clients; validate 'state'.",
               "Short-lived tokens; bind tokens to the requesting client."]),
    ],
    "graphql": [
        _ctrl("graphql-hardening", "GraphQL depth/cost limits + introspection control + field authz",
              ["schema_disclosure", "resource_exhaustion", "excessive_data_exposure"],
              ["Disable introspection in production or gate it; enforce query depth/complexity limits.",
               "Apply field/type-level authorization, not just endpoint auth."]),
    ],
}
# aliases -> canonical family key
_ALIASES = {
    "dom_xss": "xss", "stored_xss": "xss", "reflected_xss": "xss",
    "dom_data_manipulation": "xss", "dom_link_manipulation": "xss",
    "backup_exposure": "exposure", "sensitive_exposure": "exposure", "git_exposure": "exposure",
    "information_disclosure": "exposure", "base64_param": "exposure",
    "broken_access_control": "access_control", "privilege_escalation": "bfla",
    "xpath": "sqli", "xpath_injection": "sqli", "ldap": "sqli", "nosqli": "sqli", "nosql_injection": "sqli",
    "command_injection": "cmdi", "broken_auth": "access_control",
}


def _family(finding) -> str:
    if isinstance(finding, str):
        fam = finding.strip().lower()
    else:
        fam = str((finding or {}).get("family") or (finding or {}).get("vuln_class") or "").strip().lower()
    return _ALIASES.get(fam, fam)


def controls_for(finding) -> list:
    """Curated defensive controls for a finding (or a family string). UNKNOWN family -> [] (no fake control)."""
    return list(_CONTROLS.get(_family(finding), []))


def reduces_for(finding) -> list:
    """Flattened, de-duplicated set of attacker capabilities the mapped controls reduce (order-preserved)."""
    out = []
    for c in controls_for(finding):
        for cap in c["reduces"]:
            if cap not in out:
                out.append(cap)
    return out


def families_covered() -> list:
    return sorted(_CONTROLS.keys())
