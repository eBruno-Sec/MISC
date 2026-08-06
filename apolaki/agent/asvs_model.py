"""OWASP ASVS 5 objective model (Codex cross-check Tier-1 #1).

WSTG answers "what tests exist"; ASVS answers "what security PROPERTY was verified, failed, blocked, or
not assessed." Apolaki already has an honest WSTG catalog (wstg_catalog.py) — this adds the complementary
verification-objective view.

HONESTY RAILS (non-negotiable):
  * This is a CURATED PARTIAL model, NOT an official ASVS import. We do not ship the official ASVS JSON,
    so we NEVER stamp authoritative requirement numbers (e.g. "V6.2.1") as if verbatim, and NEVER claim
    full ASVS coverage. Requirement text is our own short summary. `provenance` is always "curated".
  * A finding can VIOLATE an objective (status -> failed). A clean attempted check can VERIFY it. A
    blocked objective (safety-excluded, e.g. lockout/MFA) is NOT a passed objective. Untested is untested.
  * The `violated_by` family sets are grounded in the families Apolaki actually emits — an unmapped
    finding family would let a violated property read "verified", which is the one failure mode we refuse.
  * ASVS is a per-objective property model; it is NOT a chain score.
"""
from __future__ import annotations

STANDARD = "OWASP_ASVS"
VERSION = "5.0-curated-partial"
STATUSES = ("verified", "attempted", "failed", "not_tested", "not_applicable", "blocked")

# Curated ASVS-5 verification objectives. `engine` is the Apolaki tool (or tuple of acceptable tool names)
# that attempts each; a clean run of it (no violating finding) is real evidence the property held. `violated_by`
# is the set of finding families whose presence FAILS the objective — grounded in the families Apolaki emits.
# `blocked_reason` => Apolaki deliberately does not test it on safety grounds (never "verified"). `attempt_only`
# => a run is inconclusive-by-nature (status "attempted", never "verified"). cid is a LOCAL curated id,
# deliberately NOT an official ASVS clause number.
OBJECTIVES = (
    # ── Authentication ──
    {"chapter": "Authentication", "cid": "AUTHN-01", "level": 1,
     "summary": "Application does not ship or accept vendor/well-known default credentials.",
     "objective": "Confirm no default admin login is accepted.",
     "engine": "run_default_creds", "violated_by": ("default_creds",), "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-02", "level": 1,
     "summary": "Authentication cannot be bypassed by injection or forced browsing.",
     "objective": "Confirm the auth schema is not bypassable.",
     "engine": ("run_auth_sqli", "authz_matrix"), "violated_by": ("auth_bypass", "broken_auth"),
     "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-03", "level": 1,
     "summary": "Accounts are not enumerable via response/timing discrepancies.",
     "objective": "Confirm login/registration does not leak account existence.",
     "engine": "run_username_enum", "violated_by": ("username_enum",), "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-04", "level": 1,
     "summary": "Credentials are transported only over an encrypted channel.",
     "objective": "Confirm no cleartext credential transport.",
     "engine": "header_analysis", "violated_by": ("cleartext_transport",), "verifiable": False},
    {"chapter": "Authentication", "cid": "AUTHN-05", "level": 2,
     "summary": "Repeated failed authentication is rate-limited / locked out.",
     "objective": "Verify anti-automation on login.",
     "engine": "n/a", "violated_by": (),
     "blocked_reason": "lockout testing needs repeated failed logins (brute) — excluded by no-brute rule"},
    {"chapter": "Authentication", "cid": "AUTHN-06", "level": 2,
     "summary": "Multi-factor authentication is enforced where required.",
     "objective": "Verify MFA presence/enforcement.",
     "engine": "n/a", "violated_by": (),
     "blocked_reason": "MFA prompts PAUSE the engine (never bypassed), so it is not auto-verified"},

    # ── Session Management ──
    {"chapter": "Session Management", "cid": "SESS-01", "level": 1,
     "summary": "Session identifiers are unpredictable and high-entropy.",
     "objective": "Verify session-token randomness/meaningfulness.",
     "engine": "run_session_token", "violated_by": ("weak_session", "predictable_token"), "verifiable": True},
    {"chapter": "Session Management", "cid": "SESS-02", "level": 1,
     "summary": "Session cookies carry Secure/HttpOnly/SameSite attributes.",
     "objective": "Verify session-cookie hardening flags.",
     "engine": ("header_analysis", "run_encoded_cookie"), "violated_by": ("cookie_flags",), "verifiable": True},
    {"chapter": "Session Management", "cid": "SESS-03", "level": 2,
     "summary": "Session identifier is rotated on authentication (no fixation).",
     "objective": "Confirm token rotates on login.",
     "engine": "run_session_fixation", "violated_by": ("session_fixation",), "verifiable": True},
    {"chapter": "Session Management", "cid": "SESS-04", "level": 2,
     "summary": "Self-contained tokens (JWT) resist tampering and algorithm confusion.",
     "objective": "Confirm JWT signature/alg integrity.",
     "engine": "run_jwt", "violated_by": ("jwt",), "verifiable": True},

    # ── Access Control / Authorization ──
    {"chapter": "Authorization", "cid": "ATHZ-00", "level": 1,
     "summary": "Access control is enforced end-to-end (no broken access control).",
     "objective": "Confirm no broken-access-control violation was demonstrated.",
     "engine": ("run_bfla", "confirm_idor", "authz_matrix"),
     "violated_by": ("access_control", "broken_access_control"), "verifiable": True},
    {"chapter": "Authorization", "cid": "ATHZ-01", "level": 1,
     "summary": "Object-level authorization prevents access to others' resources (no IDOR/BOLA).",
     "objective": "Confirm object-level authz is enforced.",
     "engine": ("confirm_idor", "run_bfla"), "violated_by": ("idor", "bola"), "verifiable": True},
    {"chapter": "Authorization", "cid": "ATHZ-02", "level": 1,
     "summary": "Function-level authorization prevents privilege escalation (no BFLA).",
     "objective": "Confirm function-level authz is enforced.",
     "engine": "run_bfla", "violated_by": ("bfla", "privilege_escalation"), "verifiable": True},
    {"chapter": "Authorization", "cid": "ATHZ-03", "level": 1,
     "summary": "Directory traversal cannot reach files outside the intended scope.",
     "objective": "Confirm path traversal is blocked.",
     "engine": ("run_web_probes", "run_content_discovery"), "violated_by": ("path_traversal",),
     "verifiable": True},
    {"chapter": "Authorization", "cid": "ATHZ-04", "level": 2,
     "summary": "Mass-assignment cannot set privileged attributes.",
     "objective": "Confirm mass-assignment protections.",
     "engine": "run_mass_assignment", "violated_by": ("mass_assignment",), "verifiable": True},

    # ── Validation, Sanitization, Encoding ──
    {"chapter": "Validation & Encoding", "cid": "VAL-01", "level": 1,
     "summary": "Input is not interpreted as SQL (no SQL injection).",
     "objective": "Confirm no SQLi sink.",
     "engine": "run_sqli", "violated_by": ("sqli",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-02", "level": 1,
     "summary": "Input is not interpreted as OS commands (no command injection).",
     "objective": "Confirm no command-injection sink.",
     "engine": ("run_cmdi", "run_form_cmdi"), "violated_by": ("cmdi",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-03", "level": 1,
     "summary": "Output is contextually encoded (no reflected/stored/DOM XSS or client-side template injection).",
     "objective": "Confirm no XSS/CSTI sink.",
     "engine": ("run_xss", "run_form_xss", "run_dalfox", "run_dom_audit"),
     "violated_by": ("xss", "dom_xss", "stored_xss", "reflected_xss", "csti",
                     "dom_data_manipulation", "dom_link_manipulation"), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-04", "level": 2,
     "summary": "Server does not evaluate user input as a template (no SSTI).",
     "objective": "Confirm no SSTI sink.",
     "engine": "run_injection_probes", "violated_by": ("ssti",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-05", "level": 2,
     "summary": "XML parsing disables external entities (no XXE).",
     "objective": "Confirm XXE is not exploitable.",
     "engine": "run_xxe", "violated_by": ("xxe",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-06", "level": 2,
     "summary": "Untrusted data is not deserialized into live objects.",
     "objective": "Confirm no insecure deserialization.",
     "engine": ("run_deserialization", "run_deser"), "violated_by": ("deserialization",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-07", "level": 2,
     "summary": "LDAP/XPath/NoSQL queries are parameterized (no injection).",
     "objective": "Confirm no directory/query injection.",
     "engine": ("run_ldap", "run_xpath", "run_form_nosqli"),
     "violated_by": ("ldap", "xpath", "xpath_injection", "nosqli", "nosql_injection"), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-08", "level": 2,
     "summary": "Objects are not corruptible via prototype pollution.",
     "objective": "Confirm no prototype-pollution sink.",
     "engine": ("run_dom_audit", "run_injection_probes"), "violated_by": ("prototype_pollution",),
     "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-09", "level": 2,
     "summary": "Responses are not injectable via CRLF / response-header splitting.",
     "objective": "Confirm no CRLF/header-injection sink.",
     "engine": ("run_injection_probes", "run_web_probes"), "violated_by": ("crlf",), "verifiable": True},

    # ── Configuration & Dependencies ──
    {"chapter": "Configuration & Dependencies", "cid": "CONF-01", "level": 1,
     "summary": "No components with known vulnerabilities are in use.",
     "objective": "Confirm no known-vulnerable component was fingerprinted.",
     "engine": ("run_fingerprint", "dependency_intel"), "violated_by": ("vulnerable_component",),
     "verifiable": True},

    # ── API & Web Service ──
    {"chapter": "API & Web Service", "cid": "API-01", "level": 1,
     "summary": "GraphQL endpoints do not over-expose schema/introspection unsafely.",
     "objective": "Assess GraphQL exposure/authorization.",
     "engine": "run_graphql", "violated_by": ("graphql",), "verifiable": True},
    {"chapter": "API & Web Service", "cid": "API-02", "level": 2,
     "summary": "OAuth flows resist redirect/token/consent abuse.",
     "objective": "Assess OAuth weaknesses.",
     "engine": "run_oauth", "violated_by": ("oauth",), "verifiable": True},

    # ── Communication / Config ──
    {"chapter": "Communication & Config", "cid": "COMM-01", "level": 1,
     "summary": "Server-side request forgery is not reachable via user-supplied URLs.",
     "objective": "Confirm SSRF is not exploitable.",
     "engine": "run_ssrf", "violated_by": ("ssrf",), "verifiable": True},
    {"chapter": "Communication & Config", "cid": "COMM-02", "level": 1,
     "summary": "CORS policy does not trust arbitrary/reflected origins with credentials.",
     "objective": "Confirm CORS is not overly permissive.",
     "engine": ("run_injection_probes", "run_client_checks"), "violated_by": ("cors",), "verifiable": True},
    {"chapter": "Communication & Config", "cid": "COMM-03", "level": 1,
     "summary": "No sensitive files, backups, or VCS metadata are web-exposed.",
     "objective": "Confirm no sensitive exposure.",
     "engine": ("run_exposure", "run_dir_harvest"),
     "violated_by": ("exposure", "git_exposure", "backup_exposure", "sensitive_exposure",
                     "information_disclosure", "base64_param"), "verifiable": True},
    {"chapter": "Communication & Config", "cid": "COMM-04", "level": 2,
     "summary": "Subdomains do not dangle to takeover-able providers.",
     "objective": "Confirm no subdomain takeover.",
     "engine": "check_takeover", "violated_by": ("takeover",), "verifiable": True},

    # ── Business Logic (inconclusive by nature -> "attempted", never auto-"verified") ──
    {"chapter": "Business Logic", "cid": "BUSL-01", "level": 2,
     "summary": "Business rules cannot be bypassed by request forgery or workflow skipping.",
     "objective": "Reason about business-logic integrity.",
     "engine": "bizlogic_graph", "violated_by": ("business_logic",), "verifiable": True,
     "attempt_only": True},
    {"chapter": "Business Logic", "cid": "BUSL-02", "level": 2,
     "summary": "Sensitive operations are not exploitable via timing/race conditions.",
     "objective": "Reason about race/timing abuse.",
     "engine": "run_race", "violated_by": ("race",), "verifiable": True, "attempt_only": True},
)


def _engine_names(obj: dict) -> tuple:
    e = obj.get("engine")
    return (e,) if isinstance(e, str) else tuple(e or ())


def _engine_ran(obj: dict, ran: set) -> bool:
    return any(name in ran for name in _engine_names(obj))


def _family(finding: dict) -> str:
    return str((finding or {}).get("family") or (finding or {}).get("vuln_class") or "").strip().lower()


def _finding_id(finding: dict, idx: int) -> str:
    return str((finding or {}).get("id") or (finding or {}).get("finding_id") or "finding-%d" % idx)


def map_findings(findings: list) -> dict:
    """objective cid -> list of finding ids that VIOLATE it. Pure; only families that appear in an
    objective's `violated_by` count. A finding that matches nothing is simply not mapped (no fake link)."""
    fams = [(_family(f), _finding_id(f, i)) for i, f in enumerate(findings or [])]
    out: dict = {}
    for obj in OBJECTIVES:
        vb = set(obj["violated_by"])
        hits = [fid for fam, fid in fams if fam and fam in vb]
        if hits:
            out[obj["cid"]] = sorted(set(hits))
    return out


def assess(findings: list = None, attempted_engines=None) -> dict:
    """Assess every curated objective. `attempted_engines` is the set of engine/tool names that actually RAN
    this mission (a clean run of a verifiable objective's engine, with no violating finding, => "verified").

    Status precedence: failed (a violating finding exists) > blocked (safety-excluded) > attempted (ran but
    inconclusive-by-nature) > verified (ran clean) > not_tested. Returns per-objective rows, a tally, and a
    per-chapter breakdown — with an explicit disclaimer that this is a curated partial model."""
    findings = findings or []
    ran = set(attempted_engines or ())
    violations = map_findings(findings)
    rows, tally, chapters = [], {s: 0 for s in STATUSES}, {}
    for obj in OBJECTIVES:
        cid = obj["cid"]
        finding_ids = violations.get(cid, [])
        if finding_ids:
            status = "failed"
        elif obj.get("blocked_reason"):
            status = "blocked"
        elif _engine_ran(obj, ran) and obj.get("verifiable"):
            status = "attempted" if obj.get("attempt_only") else "verified"
        else:
            status = "not_tested"
        row = {
            "standard": STANDARD, "version": VERSION, "cid": cid, "chapter": obj["chapter"],
            "level": obj["level"], "requirement": obj["summary"], "objective": obj["objective"],
            "engine": " | ".join(_engine_names(obj)), "status": status, "finding_ids": finding_ids,
            "evidence_refs": [], "provenance": "curated",
        }
        if obj.get("blocked_reason"):
            row["blocked_reason"] = obj["blocked_reason"]
        rows.append(row)
        tally[status] += 1
        ch = chapters.setdefault(obj["chapter"], {s: 0 for s in STATUSES})
        ch[status] += 1
    total = len(OBJECTIVES)
    return {
        "standard": STANDARD, "version": VERSION, "model_type": "curated_partial",
        "disclaimer": ("Curated partial ASVS-5 model — objective summaries are Apolaki's own wording, not "
                       "the official ASVS text, and this is NOT full ASVS coverage."),
        "total_objectives": total, "tally": tally,
        "verified_pct": round(100.0 * tally["verified"] / total, 1) if total else 0.0,
        "chapters": chapters, "objectives": rows,
    }
