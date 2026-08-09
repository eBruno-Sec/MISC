"""
Engine descriptors (T6) — one declaration per engine, carrying preconditions AND effects.

Four books arrive at this from different directions:

  * *Black Hat Go* Ch.10 — a pluggable system needs a PUBLISHED contract, because otherwise every new
    plugin forces a change to the consumer, "defeating the entire purpose".
  * *Automated Planning* §4.2 — planning needs three things: a goal test, the actions applicable to a
    state, and **the successor state an action produces**. Apolaki has only the middle one.
  * *Automated Planning* §4.4 — the successor must include NEGATIVE effects, or the planner reproduces
    STRIPS's deleted-condition failure (the Sussman anomaly).
  * *MBT Essentials* §8.1 / *practical MBT* §4.1.3 — structural coverage needs transitions to count, and
    there are no transitions without declared effects.

THE ACTUAL DEFECT, stated precisely, because it is narrower and more fixable than "no effects model":
**preconditions and effects already exist but speak different languages.** Preconditions use the 17-term
observation vocabulary below (`has_api`, `authenticated`, …). Effects exist as `service_router` pack
`enables` lists in an ad-hoc vocabulary (`arbitrary_file_read`, `ot_read`, …) and as free-form
`state.add_capability` strings. Nothing chains, because nothing an engine PRODUCES is expressed in terms
another engine can REQUIRE.

A descriptor therefore states effects in the SAME vocabulary as preconditions. That single choice is what
turns the applicability filter into a searchable graph.

**T7: this module is now the SOURCE OF TRUTH for the engine contract.** `OBSERVATIONS`, `PRECONDITIONS`
and `ALWAYS_ON` live here and `technique_planner` re-exports them, inverting a dependency that used to run
the other way. Nothing else changed: the tables are the same objects, so every consumer
(`plan_techniques`, `orchestration_audit`, the graph projection, `/orchestration/*`) sees byte-identical
data. `tests/test_t7_zero_delta.py` pins that against a snapshot taken before the move, because a refactor
that quietly alters routing would be indistinguishable from one that does not.

Why the contract belongs in one record rather than three tables in two modules: *Black Hat Go* Ch.10's
point is that a plugin system's value comes from the consumer depending on a PUBLISHED contract, not on
the plugins. While preconditions lived in the planner and effects lived here, adding an engine meant
editing whichever module happened to own each half.
"""
from __future__ import annotations


# The deterministic observation vocabulary -- what recon/harvest can establish about a target.
OBSERVATIONS = (
    "serves_js", "has_api", "has_search_param", "has_login", "has_object_id", "has_file_upload",
    "has_xml_input", "has_redirect_param", "has_versions", "has_coupon", "reflects_input",
    "sql_error_seen", "authenticated", "has_sensitive_route", "has_workflow", "credentials_exposed",
    "saml_sso_detected",
)

# technique_id -> observations that must ALL hold for the technique to be applicable (the precondition gate).
PRECONDITIONS = {
    "sqli_auth_bypass":        ["has_login"],
    "sqli_union_extract":      ["has_search_param"],
    "nosql_injection":         ["has_api"],
    "reflected_xss":           ["reflects_input"],
    "stored_xss":              ["has_api"],
    "idor_bola_read":          ["has_object_id"],
    "bfla_privileged_action":  ["has_sensitive_route"],
    "mass_assignment":         ["has_api"],
    "excessive_data_exposure": ["has_api"],
    "xxe_file_ssrf":           ["has_xml_input"],
    "ssrf":                    ["has_api"],
    "open_redirect":           ["has_redirect_param"],
    "business_logic_abuse":    ["has_workflow"],
    "weak_secret_forgery":     ["has_coupon"],
    "exposed_files_harvest":   ["serves_js"],
    "target_intel_harvest":    ["serves_js"],
    "path_traversal":          ["has_api"],
    "archive_slip":            ["has_file_upload"],
    "unrestricted_file_upload": ["has_file_upload"],
    "soft_deleted_login":      ["has_login"],
    "command_injection":       ["has_api"],
    "csrf":                    ["has_login"],
    "jwt_forge":               ["authenticated"],
    "weak_2fa_bypass":         ["authenticated"],
    "weak_password_reset":     ["has_login"],
    "exposed_credentials":     ["credentials_exposed"],
    # session engines distilled from the books/corpus — gated on existing observations so the planner
    # (and the graph, which shares this precondition table) reasons about them, not just the blind sweep.
    "sqli_structural":         ["has_search_param"],   # input in the query STRUCTURE (ORDER BY / column)
    "weak_session_token":      ["serves_js"],          # any web app issues session cookies to sample
    "xpath_injection":         ["has_search_param"],   # input concatenated into an XPath query
    "ldap_injection":          ["has_search_param"],   # input concatenated into an LDAP filter
    "ssi_injection":           ["reflects_input"],     # input reaches an SSI-parsed response
    "css_injection":           ["reflects_input"],     # input reflected into a CSS/style context
    "jwt_key_confusion":       ["authenticated"],      # RS->HS forgery on a captured token
    "cache_deception":         ["authenticated"],      # needs a private page to leak from the cache
    "waf_bypass":              ["has_search_param"],   # a parameter to smuggle a blocked signature through
    "reverse_tabnabbing":      ["serves_js"],          # HTML page with target=_blank links
    "permissive_crossdomain":  ["serves_js"],          # origin may serve crossdomain.xml
    "username_enumeration":    ["has_login"],          # a login form + a known account to differential against
    "session_fixation":        ["has_login", "authenticated"],  # a login + a working credential to drive it
    "default_credentials":     ["has_sensitive_route"],       # a discovered admin/management interface
    "saml_signature_bypass":   ["saml_sso_detected"],         # a captured SAMLResponse / SAML ACS on the surface
}

# Auto-fired, oracle-confirmed techniques that are intentionally NOT evidence-gated in _PRECONDITIONS because an
# ALWAYS-ON path already reaches them: the deterministic injection/DOM sweep, passive recon, the persona
# authorization artery, the autonomy/next-best-action path, or a tool-level target gate. Each MUST state HOW it is
# reached. The orchestration guard (orchestration_audit) treats _PRECONDITIONS ∪ ALWAYS_ON as "wired"; any
# auto+oracle+transferable technique in NEITHER is an island the engagement can't orchestrate, and fails the guard.
ALWAYS_ON = {
    "dom_xss":                  "always-on DOM sweep (run_xss / run_dom_trace on every reflected param + app page)",
    "csti":                     "always-on DOM audit (run_dom_audit on every page with a discoverable param)",
    "prototype_pollution":      "always-on DOM audit (run_dom_audit prototype-gadget scan)",
    "ssti":                     "always-on injection_probes sweep on every parameterized endpoint",
    "crlf_injection":           "always-on injection_probes sweep (header injection) on every endpoint",
    "jsonp_info_leak":          "run_jsonp fired from the next-best-action / autonomy path on discovered endpoints",
    "race_condition":           "run_race probe on single-use actions (probe phase)",
    "insecure_deser":           "run_deserialization probe on requests carrying serialized blobs (probe phase)",
    "missing_authentication":   "persona authorization matrix (_do_persona_authz) whenever personas mint",
    "browser_persona_bola":     "persona authorization artery step 5e (_do_persona_authz -> confirm_browser_persona_bola): "
                                "the Browser Intelligence Engine's runtime swap fires on the same proven persona pair",
    "client_side_authz":        "Browser Intelligence Engine phase 2, inside the same artery step 5e run: the rendered "
                                "control surface is enumerated on every persona route the swap already visits",
    "client_supplied_identity_param": "Browser Intelligence Engine phase 3, same artery step 5e run: identity params both "
                                "personas' browsers sent are mutated by route interception on the observed endpoints",
    "header_trust_authz":       "run_header_trust on every in-scope origin + any denied path the scan met",
    "url_override_acl_bypass":  "run_header_trust: any path that answered 401/403 is retried behind an override header",
    "graphql_introspection":    "planner phase D enrich: run_graphql on any /graphql endpoint or GraphQL URL hint",
    "graphql_field_suggestions": "planner phase D enrich: run_graphql sends a bogus field on the same pass",
    "graphql_batching_enabled": "planner phase D enrich: run_graphql sends a token-sized array batch",
    "graphql_argument_injection": "run_graphql introspection enumerates arguments; the existing injection "
                                "engines consume them via graphql_tool.build_query",
    "tls_posture":              "run_transport_posture on every in-scope origin during recon "
                                "(_do_transport_posture -> read-only pinned handshakes + certificate)",
    "cookie_scope_posture":     "run_transport_posture on every in-scope origin during recon (Set-Cookie read directly)",
    "http_security_headers":    "run_transport_posture on every in-scope origin during recon (response headers)",
    "http_methods_audit":       "run_transport_posture on every in-scope origin during recon (OPTIONS + one TRACE)",
    "vulnerable_component":     "always-on fingerprint / nuclei recon",
    "security_misconfig_errors": "passive stack-trace / error-signature detection on every response",
    "encoded_data_decode":      "passive intel harvest at every transport chokepoint",
    "llm_prompt_injection":     "run_llm_probe, tool-gated on looks_like_chat_endpoint()",
    "llm_output_handling":      "run_llm_probe, tool-gated on looks_like_chat_endpoint()",
    "weak_ssh_crypto":          "service_router pack: fingerprint(port 22/SSH) -> _run_service_pack runs the read-only audit",
    "ldap_anonymous_read":      "service_router pack: fingerprint(port 389/636/LDAP) -> _run_service_pack anonymous read",
    "smb_null_session":         "service_router pack: fingerprint(port 445/SMB) -> _run_service_pack null-session enum",
    "snmp_default_community":   "service_router pack: fingerprint(port 161/SNMP) -> _run_service_pack default-community GET",
    "smb_signing_disabled":     "service_router pack: fingerprint(port 445/SMB) -> _run_service_pack SMB2 negotiate signing check",
    "modbus_exposed":           "service_router pack: fingerprint(port 502/Modbus) -> _run_service_pack read-only OT probe",
    "dnp3_exposed":             "service_router pack: fingerprint(port 20000/DNP3) -> _run_service_pack link-status probe",
    "s7comm_exposed":           "service_router pack: fingerprint(port 102/S7comm) -> _run_service_pack SZL identification",
    "enip_exposed":             "service_router pack: fingerprint(port 44818/EtherNet-IP) -> _run_service_pack ListIdentity",
    "request_url_override":     "always-on DOM sweep (run_dom_trace attacker-host render) + run_js_review static scan of every harvested script",
    "dom_link_manipulation":    "always-on DOM sweep (run_dom_trace canary render on every reflected param + page)",
    "dom_data_manipulation":    "always-on DOM sweep (run_dom_trace canary render on every reflected param + page)",
    "base64_param":             "run_encoded_cookie, fired once per distinct host base in the injection sweep",
    "vnc_no_auth":              "service_router pack: fingerprint(port 5900/VNC) -> _run_service_pack RFB handshake",
    "rsync_anon":               "service_router pack: fingerprint(port 873/rsync) -> _run_service_pack #list probe",
    "ntp_monlist":              "service_router pack: fingerprint(port 123/NTP) -> _run_service_pack monlist query",
    "ipmi_rakp":                "service_router pack: fingerprint(port 623/IPMI) -> _run_service_pack RMCP+ open-session",
    "rdp_no_nla":               "service_router pack: fingerprint(port 3389/RDP) -> _run_service_pack X.224 negotiation",
}


def _observations():
    return set(OBSERVATIONS)


# ── effects, declared in the PRECONDITION vocabulary so they can chain ──────────────────────────
#
# Conservative on purpose. A technique appears here only when its oracle genuinely establishes the
# observation for the rest of the engagement — not when it merely hints at it. An over-declared effect
# would make the planner chase a capability it does not really have, which is worse than no model.
#
# `establishes`  — observations that hold AFTER this technique confirms.
# `invalidates`  — observations that STOP holding. This is the Sussman half: a technique that changes a
#                  credential invalidates the session another technique was relying on, and a planner
#                  without negative effects will happily order those the wrong way round.
EFFECTS = {
    # Authentication achieved -> everything gated on `authenticated` becomes reachable.
    "sqli_auth_bypass":        {"establishes": ["authenticated"], "invalidates": []},
    "default_credentials":     {"establishes": ["authenticated"], "invalidates": []},
    "jwt_forge":               {"establishes": ["authenticated"], "invalidates": []},
    "jwt_key_confusion":       {"establishes": ["authenticated"], "invalidates": []},
    "soft_deleted_login":      {"establishes": ["authenticated"], "invalidates": []},
    "saml_signature_bypass":   {"establishes": ["authenticated"], "invalidates": []},

    # A password reset gets you in AS the victim, but rotates the credential — so any session another
    # technique already established is dead. This is the deleted-condition interaction, in Apolaki.
    "weak_password_reset":     {"establishes": ["authenticated"], "invalidates": ["authenticated"]},

    # Credential material recovered -> the exposed-credentials technique has something to consume.
    "sqli_union_extract":      {"establishes": ["credentials_exposed"], "invalidates": []},
    "exposed_files_harvest":   {"establishes": ["credentials_exposed"], "invalidates": []},
    "target_intel_harvest":    {"establishes": ["credentials_exposed"], "invalidates": []},

    # Surface discovery -> new inputs for the injection engines.
    "graphql_introspection":   {"establishes": ["has_api", "has_object_id"], "invalidates": []},
    # NOT `find_hidden_route`: it is a lab-local catalog entry with no executor and no gate, so an effect
    # declared on it could never fire. Over-declaring is worse than not declaring — it would make the
    # planner believe a capability is obtainable by an action it can never actually take.

    # Runtime/browser discovery of client-rendered surface.
    "browser_persona_bola":    {"establishes": ["has_object_id", "authenticated"], "invalidates": []},

    # An error oracle firing is itself an observation later techniques key on.
    "sqli_structural":         {"establishes": ["sql_error_seen"], "invalidates": []},
}


# Files that DESCRIBE the platform rather than run it. A mention here is prose, not wiring — which is
# exactly how `graphql_argument_injection` came to be declared reachable via a function nobody called.
_PROSE_FILES = {"techniques.py", "engine_descriptor.py"}


def _identifiers(reason: str) -> set:
    """Code identifiers a reason names: snake_case tokens and dotted `module.function` forms. Prose words
    are excluded by requiring an underscore or a dot, which every real identifier here has. Pure."""
    import re
    return {t for t in re.findall(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?", reason or "")
            if "_" in t or "." in t}


def verify_always_on(app_dir: str = None) -> dict:
    """Check that every function an ALWAYS_ON reason NAMES is actually wired.

    The no-island guard proves a technique is DECLARED reached — evidence-gated or always-on with a stated
    reason. It cannot prove the declaration is TRUE, because the reason is prose. That gap was real:
    `graphql_argument_injection` was declared reached "via graphql_tool.build_query", and nothing called
    `build_query`, `injectable_arguments` or `schema_operations`. The engine ran on paper only, and the
    guard passed it.

    This closes the gap. For each identifier a reason names, require a reference from code that RUNS,
    excluding the identifier's own definition and excluding the prose files where the false promise lived.

    Two resolution rules learned from the codebase rather than assumed:
      * a tool is registered under a bare string (`"run_graphql"`) and implemented as `_run_graphql`, so
        both spellings count
      * a dotted `module.function` must have the FUNCTION referenced, not merely the module imported

    Returns {checked, unwired, ok}. `unwired` MUST be empty. Pure apart from reading the source tree."""
    import os
    import re
    app = app_dir or os.path.dirname(os.path.abspath(__file__))
    srcs = {}
    for fn in sorted(os.listdir(app)):
        if fn.endswith(".py") and fn not in _PROSE_FILES:
            try:
                srcs[fn] = open(os.path.join(app, fn), encoding="utf8").read()
            except Exception:
                pass

    checked, unwired = [], []
    for tid, reason in sorted(ALWAYS_ON.items()):
        for tok in sorted(_identifiers(reason)):
            # Strip a leading underscore before matching. A tool is REGISTERED under a bare string
            # ("run_service_pack") and IMPLEMENTED as a private method (`_run_service_pack`); treating
            # those as different names made the verifier report 13 wired ICS engines as broken.
            bare = tok.split(".")[-1].lstrip("_")
            defined = any(re.search(r"^\s*(async\s+)?def\s+_?%s\s*\(" % re.escape(bare), s, re.M)
                          for s in srcs.values())
            if not defined:
                continue                      # names a module/concept, not a function — nothing to verify
            checked.append("%s -> %s" % (tid, tok))
            wired = False
            for fn, s in srcs.items():
                # Strip this file's own definitions of the name so a def never counts as a use, AND strip
                # the permission-map registration line. REGISTRATION IS NOT INVOCATION: `run_header_trust`
                # was registered in `_PERMISSIONS` and fully implemented, yet its name was never passed to
                # execute()/_exec_internal() and it was absent from the CLAUDE_TOOLS spec — unreachable by
                # both the deterministic and the agentic path. Counting the registry key as a reference is
                # exactly what hid that.
                body = re.sub(r"^\s*(async\s+)?def\s+_?%s\s*\(" % re.escape(bare), "", s, flags=re.M)
                body = re.sub(r"^\s*[\"']_?%s[\"']\s*:\s*PermissionLevel.*$" % re.escape(bare), "",
                              body, flags=re.M)
                if re.search(r"(?<![\w])_?%s\b" % re.escape(bare), body) or \
                   re.search(r"[\"']_?%s[\"']" % re.escape(bare), body):
                    wired = True
                    break
            if not wired:
                unwired.append("%s: reason names %s, which nothing outside prose references" % (tid, tok))
    return {"checked": sorted(set(checked)), "unwired": sorted(set(unwired)),
            "ok": not unwired}


def descriptor(tech: dict, preconditions: dict, always_on: dict) -> dict:
    """One engine's full contract. Pure."""
    tid = tech.get("id", "")
    eff = EFFECTS.get(tid, {})
    return {
        "id": tid,
        "permission": tech.get("permission"),
        "vuln_class": tech.get("vuln_class"),
        "oracle": tech.get("oracle") or "",
        "requires": list(preconditions.get(tid, [])),
        "always_on": tid in always_on,
        "reached_by": always_on.get(tid, "") if tid in always_on else "evidence-gated preconditions",
        "establishes": list(eff.get("establishes", [])),
        "invalidates": list(eff.get("invalidates", [])),
        "auto": tech.get("execution", "auto") == "auto",
        "transferable": bool(tech.get("transferable")),
    }


def build() -> dict:
    """{id: descriptor} for every registered technique, built from THIS module's tables.

    Post-T7 these are the tables the platform actually routes on — `technique_planner` re-exports them —
    so a descriptor cannot drift from live behaviour. Before T7 this read the planner's copies, which made
    it a read-only view; the dependency now runs the other way."""
    import techniques as T
    return {t["id"]: descriptor(t, PRECONDITIONS, ALWAYS_ON)
            for t in T.TECHNIQUES.values() if t.get("id")}


def validate(descriptors: dict = None) -> dict:
    """Contract checks. Pure over the supplied descriptors.

    The load-bearing one is `unknown_effect_vocabulary`: an effect that is not a real observation can
    never satisfy any precondition, so it is a declaration that silently does nothing — exactly the kind
    of dead wiring the no-island rule exists to catch."""
    d = descriptors if descriptors is not None else build()
    obs = _observations()
    unknown_effect, unknown_require, unreachable = [], [], []
    for tid, desc in sorted(d.items()):
        for e in desc["establishes"] + desc["invalidates"]:
            if e not in obs:
                unknown_effect.append("%s -> %s" % (tid, e))
        for r in desc["requires"]:
            if r not in obs:
                unknown_require.append("%s <- %s" % (tid, r))
        if desc["auto"] and desc["oracle"] and desc["transferable"] \
                and not desc["requires"] and not desc["always_on"]:
            unreachable.append(tid)
    return {"total": len(d),
            "with_effects": sum(1 for x in d.values() if x["establishes"] or x["invalidates"]),
            "unknown_effect_vocabulary": unknown_effect,
            "unknown_requirement_vocabulary": unknown_require,
            "unreachable": unreachable,
            "ok": not (unknown_effect or unknown_require or unreachable)}


def chains(descriptors: dict = None) -> list:
    """[(producer, observation, consumer)] — every place one engine establishes what another requires.

    This is the payoff and the proof the model is real: today the planner cannot see any of these, so it
    can never decide to run the producer in order to reach the consumer. Pure."""
    d = descriptors if descriptors is not None else build()
    out = []
    for pid, prod in sorted(d.items()):
        for obs in prod["establishes"]:
            for cid, cons in sorted(d.items()):
                if cid != pid and obs in cons["requires"]:
                    out.append((pid, obs, cid))
    return out


def conflicts(descriptors: dict = None) -> list:
    """[(technique, observation, consumer)] where running `technique` DESTROYS a condition `consumer`
    needs — the Sussman anomaly, made visible. Pure."""
    d = descriptors if descriptors is not None else build()
    out = []
    for tid, t in sorted(d.items()):
        for obs in t["invalidates"]:
            for cid, c in sorted(d.items()):
                if cid != tid and obs in c["requires"]:
                    out.append((tid, obs, cid))
    return out
