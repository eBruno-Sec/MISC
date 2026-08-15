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
  * Every `engine` name MUST resolve to something a real dispatcher can reach (Q-012). `ToolRegistry.execute`
    dispatches `getattr(self, "_" + tool_name)` and the ledger records the REQUESTED tool name — measured, see
    docs/handoff/asvs.md — so the model must name `run_authz_matrix`, never the `ToolResult` label
    `authz_matrix`, and never a MODULE (`dependency_intel`, `bizlogic_graph`) that no dispatcher exposes.
    A phantom engine name silently pins its objective to "not_tested" even on a perfect run.
  * A capability Apolaki DOES NOT HAVE reports "not_implemented", never "not_tested". "not_tested" reads as
    "we did not get to it"; conflating the two lets an absent engine hide behind a skipped one. An objective
    with no engine carries NO_ENGINE plus an explicit reason key (`blocked_reason` for safety-excluded,
    `not_implemented_reason` for absent capability). A finding still FAILS a not-implemented objective — a
    demonstrated violation outranks our inability to go looking for it.
"""
from __future__ import annotations

STANDARD = "OWASP_ASVS"
VERSION = "5.0-curated-partial"
STATUSES = ("verified", "attempted", "failed", "not_tested", "not_applicable", "blocked",
            "not_implemented")

# Explicit sentinel for "this objective has no engine". Legal ONLY on an objective that also declares
# `blocked_reason` (safety-excluded) or `not_implemented_reason` (capability absent) — enforced by
# tests/test_asvs_model.py so the sentinel can never become a quiet way to park a broken name.
NO_ENGINE = "n/a"

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
     # Q-048: `violated_by` was ("default_creds",) — a string NOTHING in the tree emits. The engine that
     # carries this objective produces family "default_credentials" (default_creds_tool.py:59), so a REAL
     # confirmed default-credential login did not fail this objective and it read "verified" anyway. Sole
     # producer of the family is default_creds_tool, reachable only from run_default_creds, so re-pointing
     # cannot fail this objective spuriously.
     "engine": "run_default_creds", "violated_by": ("default_credentials",), "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-02", "level": 1,
     "summary": "Authentication cannot be bypassed by injection or forced browsing.",
     "objective": "Confirm the auth schema is not bypassable.",
     "engine": ("run_auth_sqli", "run_authz_matrix"), "violated_by": ("auth_bypass", "broken_auth"),
     "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-03", "level": 1,
     "summary": "Accounts are not enumerable via response/timing discrepancies.",
     "objective": "Confirm login/registration does not leak account existence.",
     # Q-048: was ("username_enum",), which nothing emits; the engine produces "username_enumeration"
     # (username_enum_tool). Sole producer, reachable only from run_username_enum — no spurious-FAIL risk.
     "engine": "run_username_enum", "violated_by": ("username_enumeration",), "verifiable": True},
    {"chapter": "Authentication", "cid": "AUTHN-04", "level": 1,
     "summary": "Credentials are transported only over an encrypted channel.",
     "objective": "Confirm no cleartext credential transport.",
     # Q-012: was engine "header_analysis" — a name no dispatcher can reach — AND "verifiable": False, so it
     # fell through to "not_tested" on a perfect run no matter what. Two independent reasons it could never
     # be verified, one of them the author's own admission. Apolaki has no engine that observes a CREDENTIAL
     # crossing a cleartext channel: run_transport_posture grades TLS/cert posture for an origin, which is a
     # different property, and family "cleartext_transport" has zero producers in the tree. Mapping it there
     # would manufacture a verified. It is a capability we do not have, and it now says so.
     "engine": NO_ENGINE, "violated_by": ("cleartext_transport",),
     "not_implemented_reason": ("no engine observes credential transport; run_transport_posture grades TLS "
                                "posture for an origin, which does not establish this property")},
    {"chapter": "Authentication", "cid": "AUTHN-05", "level": 2,
     "summary": "Repeated failed authentication is rate-limited / locked out.",
     "objective": "Verify anti-automation on login.",
     "engine": NO_ENGINE, "violated_by": (),
     "blocked_reason": "lockout testing needs repeated failed logins (brute) — excluded by no-brute rule"},
    {"chapter": "Authentication", "cid": "AUTHN-06", "level": 2,
     "summary": "Multi-factor authentication is enforced where required.",
     "objective": "Verify MFA presence/enforcement.",
     "engine": NO_ENGINE, "violated_by": (),
     "blocked_reason": "MFA prompts PAUSE the engine (never bypassed), so it is not auto-verified"},

    # ── Session Management ──
    {"chapter": "Session Management", "cid": "SESS-01", "level": 1,
     "summary": "Session identifiers are unpredictable and high-entropy.",
     "objective": "Verify session-token randomness/meaningfulness.",
     # Q-048: was ("weak_session", "predictable_token") — two plausible-looking strings, neither of which
     # any producer emits. session_token_tool.finding emits "weak_session_token" and is reachable only
     # from run_session_token. Same property (a predictable/low-entropy session identifier), one producer.
     "engine": "run_session_token", "violated_by": ("weak_session_token",), "verifiable": True},
    {"chapter": "Session Management", "cid": "SESS-02", "level": 1,
     # Q-048 NARROWED from "Secure/HttpOnly/SameSite" to what is actually FAILABLE. See below: the only
     # cookie weakness that becomes a distinguishable finding is the missing Secure attribute (CWE-614).
     "summary": "Session cookies carry the Secure attribute (CWE-614).",
     "objective": "Verify session-cookie hardening flags.",
     # Q-012 re-pointed the engine here and was still wrong, because it fixed the RUN and not the FAIL:
     # family "cookie_flags" has NO producer anywhere in the tree, so SESS-02 read "verified" on every
     # possible run. Both engines it named were dead for it -- run_transport_posture emits
     # "security_misconfig"/"transport_posture", run_encoded_cookie emits "base64_param" (a different
     # property entirely: base64-encoded parameters).
     #
     # The real producer, which the Q-012 pass missed: cookie_flags.py emits family "insecure_cookie"
     # (CWE-614, judged from the RAW Set-Cookie header on session-ish cookies) and is called from
     # _run_web_probes (tools.py:5781). Sole producer, reachable from that one engine -> no spurious FAIL.
     #
     # DELIBERATELY NOT re-pointed to "security_misconfig", which transport_posture DOES emit for its
     # cookie checks: that family is chosen by `"transport_posture" if kind in ("tls","cert") else
     # "security_misconfig"` (transport_posture.py:397) and `kind` is also "header" and "methods". A
     # missing security header or a permitted TRACE would then FAIL "session cookies carry Secure" -- a
     # false FAIL, which is as much a defect as a false verified.
     "engine": "run_web_probes", "violated_by": ("insecure_cookie",), "verifiable": True},
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
     "engine": ("run_bfla", "confirm_idor", "run_authz_matrix"),
     # This is the UMBRELLA access-control property: ANY child access-control violation must fail it too,
     # otherwise it could read "verified" while a child IDOR/BFLA is "failed" (#11 — a self-contradiction).
     # So its violated_by subsumes every specific access-control family (idor/bola/bfla/priv-esc/mass-assign).
     "violated_by": ("access_control", "broken_access_control", "idor", "bola", "bfla",
                     "privilege_escalation", "mass_assignment"), "verifiable": True},
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
     # Q-048: dropped run_content_discovery. It emits family "exposure" (a COMM-03 family) and never
     # "path_traversal" -- it discovers content, it does not test traversal -- so a mission that ran it
     # without run_web_probes stamped this objective verified with nothing able to contradict it.
     "engine": "run_web_probes", "violated_by": ("path_traversal",), "verifiable": True},
    {"chapter": "Authorization", "cid": "ATHZ-04", "level": 2,
     "summary": "Mass-assignment cannot set privileged attributes.",
     "objective": "Confirm mass-assignment protections.",
     # Q-012 / Q-011: `run_mass_assignment` was a phantom — no _run_mass_assignment method, no
     # TOOL_PERMISSIONS entry, no CLAUDE_TOOLS spec. The only code that over-posts a privileged attribute is
     # the LAB SOLVER (juiceshop_solvers.py), which is not a general engine. `violated_by` is deliberately
     # KEPT: if a mass-assignment finding is ever produced, this objective must read "failed" — a
     # demonstrated violation outranks our inability to go looking for it.
     "engine": NO_ENGINE, "violated_by": ("mass_assignment",),
     "not_implemented_reason": ("no general mass-assignment engine exists (Q-011); only the Juice Shop lab "
                                "solver over-posts a privileged attribute, which is not a product capability")},

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
     # Q-048: dropped run_dalfox. _run_dalfox appends RAW dalfox JSON lines as findings, which carry no
     # "family" key at all, so nothing it reports can fail this (or any) objective. That is a real gap in
     # the dalfox integration, not just a model error -- patch handed off in docs/handoff/asvsproducers.md.
     "engine": ("run_xss", "run_form_xss", "run_dom_audit"),
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
     # Q-012: dropped the phantom alias "run_deser" (no method/permission/spec). The real engine
     # `run_deserialization` was already carrying this objective, so its status is unchanged.
     "engine": "run_deserialization", "violated_by": ("deserialization",), "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-07", "level": 2,
     "summary": "LDAP/XPath/NoSQL queries are parameterized (no injection).",
     "objective": "Confirm no directory/query injection.",
     # Q-048: "ldap" has no producer — ldap_tool emits "ldap_injection" — so run_ldap was a dead engine on
     # an objective it was trusted to verify. Added the real family (sole producer ldap_tool, reachable
     # only from run_ldap). "xpath"/"nosql_injection" are likewise producer-less aliases kept beside their
     # live siblings "xpath_injection"/"nosqli"; harmless here because a live family covers each engine.
     "engine": ("run_ldap", "run_xpath", "run_form_nosqli"),
     "violated_by": ("ldap", "ldap_injection", "xpath", "xpath_injection", "nosqli", "nosql_injection"),
     "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-08", "level": 2,
     "summary": "Objects are not corruptible via prototype pollution.",
     "objective": "Confirm no prototype-pollution sink.",
     # Q-048: run_injection_probes emits cors/crlf/host_header/open_redirect/ssti and never
     # prototype_pollution -- dropped. run_dom_audit CONFIRMS it in a real browser (dom_tool), and
     # run_js_review flags it statically (dependency_intel); both really do emit the family.
     "engine": ("run_dom_audit", "run_js_review"), "violated_by": ("prototype_pollution",),
     "verifiable": True},
    {"chapter": "Validation & Encoding", "cid": "VAL-09", "level": 2,
     "summary": "Responses are not injectable via CRLF / response-header splitting.",
     "objective": "Confirm no CRLF/header-injection sink.",
     # Q-048: dropped run_web_probes -- it emits seven families, none of them "crlf". Only
     # run_injection_probes (via web_security) can produce a CRLF finding.
     "engine": "run_injection_probes", "violated_by": ("crlf",), "verifiable": True},

    # ── Configuration & Dependencies ──
    {"chapter": "Configuration & Dependencies", "cid": "CONF-01", "level": 1,
     "summary": "No components with known vulnerabilities are in use.",
     "objective": "Confirm no known-vulnerable component was fingerprinted.",
     # Q-012: "dependency_intel" is a MODULE, not a dispatchable tool. Its SCA verdict reaches a mission
     # through run_js_review, the sole production caller of dependency_intel.vulnerable_component_finding
     # (tools.py:5534) — i.e. the only engine that can actually emit the family that FAILS this objective.
     # Q-048: dropped run_fingerprint. It emits family "fingerprint" ONLY, so a mission that fingerprinted
     # the stack but never ran the JS review stamped "no known-vulnerable components" with nothing able to
     # contradict it. run_js_review is the sole engine that can emit vulnerable_component, and Q-012 had
     # already added it -- so the objective could fail; only this sibling was the false-verify path.
     "engine": "run_js_review", "violated_by": ("vulnerable_component",), "verifiable": True},

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
     # Q-048 BROADENED to match the engines: the objective said "CORS" while one of its two engines tests
     # the crossdomain.xml policy, which is the same property (do we grant arbitrary origins access?)
     # through a different mechanism.
     "summary": "Cross-origin trust policy (CORS and crossdomain.xml) does not trust arbitrary origins.",
     "objective": "Confirm cross-origin policy is not overly permissive.",
     # run_client_checks emits "permissive_crossdomain" (CWE-942, client_checks_tool.py:81) and
     # "reverse_tabnabbing" -- never "cors" -- so it was a dead engine that could stamp this objective
     # verified on its own. Sole producer of permissive_crossdomain, reachable only from run_client_checks,
     # so adding it cannot fail this objective spuriously.
     "engine": ("run_injection_probes", "run_client_checks"),
     "violated_by": ("cors", "permissive_crossdomain"), "verifiable": True},
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
     # Q-012: "bizlogic_graph" is a MODULE (bizlogic.py), reachable only from codeintel.py's source-review
     # lane and a REST endpoint — never from ToolRegistry. The dispatchable engines that exercise business
     # logic are run_workflow (executes a declarative logic-abuse pack) and test_numeric_abuse, which is the
     # engine that actually emits family "business_logic" (tools.py:3062). Still attempt_only: business-logic
     # integrity is inconclusive by nature, so this can reach "attempted" and never "verified".
     # Q-048: dropped run_workflow. It returns ToolResult(..., []) by design -- its own docstring says
     # confirmed findings come from the confirm_* steps INSIDE the pack, so the engine itself emits no
     # family and could never contradict this objective. test_numeric_abuse really does emit
     # "business_logic" (tools.py:3062).
     "engine": "test_numeric_abuse", "violated_by": ("business_logic",), "verifiable": True,
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

    Status precedence: failed (a violating finding exists) > not_implemented (Apolaki has no engine for this
    property) > blocked (safety-excluded) > attempted (ran but inconclusive-by-nature) > verified (ran clean)
    > not_tested. Returns per-objective rows, a tally, and a per-chapter breakdown — with an explicit
    disclaimer that this is a curated partial model.

    `failed` outranks `not_implemented` on purpose: a violation someone else demonstrated (a lab solver, an
    imported finding, a human) is still a violation, and must never be hidden behind "we have no engine".
    `not_implemented` outranks everything below it because an absent capability is a property of the PRODUCT,
    not of this mission — no amount of engines running can change it."""
    findings = findings or []
    ran = set(attempted_engines or ())
    violations = map_findings(findings)
    rows, tally, chapters = [], {s: 0 for s in STATUSES}, {}
    for obj in OBJECTIVES:
        cid = obj["cid"]
        finding_ids = violations.get(cid, [])
        if finding_ids:
            status = "failed"
        elif obj.get("not_implemented_reason"):
            status = "not_implemented"
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
        if obj.get("not_implemented_reason"):
            # Carried on the row so a reader is told WHY the property is unassessed, and can tell an absent
            # capability apart from a skipped one without reading this module.
            row["not_implemented_reason"] = obj["not_implemented_reason"]
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
