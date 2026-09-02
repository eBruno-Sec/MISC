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
    # Q-011 CLOSED: this precondition used to gate an engine that did not exist. It now gates
    # `tools.ToolRegistry._run_mass_assign`. Deliberately NO entry in EFFECTS below: the engine
    # creates an object carrying `role: admin` and never logs into it, so it does not establish
    # `authenticated` for the rest of the engagement. Declaring that would teach the planner to
    # chase a capability the oracle has not actually obtained, which this module's own rule forbids.
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
    # Same gate as fixation, and for the same reason: it needs a login boundary to cross and it only runs
    # on an authenticated scan, because minting the sacrificial account through the target's own signup is
    # state-changing. NOT given an `invalidates: ["authenticated"]` effect, deliberately — it is the only
    # engine that ends a session ON PURPOSE, but the session it ends is its own, so the engagement's
    # `authenticated` observation still holds afterwards. Declaring the effect would teach the planner to
    # reorder around a conflict that the mission-safety carve-out (tools._session_kill_is_safe) exists to
    # make impossible. Q-074 MEASURED this by driving the engine rather than by reading it; see EFFECTS.
    # "on purpose" is load-bearing and was corrected there: `run_race` ends the MISSION's session as a
    # side effect, has no such carve-out, and is the one entry in EFFECTS that carries an `invalidates`.
    "session_lifecycle":       ["has_login", "authenticated"],
    "default_credentials":     ["has_sensitive_route"],       # a discovered admin/management interface
    "saml_signature_bypass":   ["saml_sso_detected"],         # a captured SAMLResponse / SAML ACS on the surface
}

# Auto-fired, oracle-confirmed techniques that are intentionally NOT evidence-gated in _PRECONDITIONS because an
# ALWAYS-ON path already reaches them: the deterministic injection/DOM sweep, passive recon, the persona
# authorization artery, the autonomy/next-best-action path, or a tool-level target gate. Each MUST state HOW it is
# reached. The orchestration guard (orchestration_audit) treats _PRECONDITIONS ∪ ALWAYS_ON as "wired"; any
# auto+oracle+transferable technique in NEITHER is an island the engagement can't orchestrate, and fails the guard.
ALWAYS_ON = {
    # CYCLE 18. Each of these was proven to dispatch by a LIVENESS RUN against a lab case, not by
    # reading the call site -- which matters, because one of them (dom_sinks) had a live call site
    # while every recorder it feeds was silently a no-op. The engine named here is the tool the
    # liveness case actually drove.
    "private_key_disclosed":       "always-on passive body scan inside run_web_probes on every fetched response",
    "websocket_url_poisoning":     "always-on DOM sink sweep (run_dom_trace) on every probed source, query and fragment",
    "ajax_header_manipulation":    "always-on DOM sink sweep (run_dom_trace): XHR/fetch header hooks on every render",
    "csp_allows_untrusted_script": "always-on header posture pass (run_transport_posture) on every origin",
    "jwt_signature_not_verified":  "run_jwt whenever a JWT is observed in a session header or cookie",
    "python_code_injection":       "always-on run_injection_probes sweep on every parameterized "
                                   "endpoint (the bare phrase `injection_probes` is not an engine-shaped "
                                   "token, which is why ssti and crlf_injection still read as unrouted)",
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
# `engine`       — Q-007. The dispatch name(s) that PRODUCE the effect. Not decoration: an effect belongs
#                  to an ACTION, and until this key existed the table could name an action that does not
#                  exist. `effects_audit()` checks every name here against two independent FACTS — the
#                  registry (`tools.TOOL_PERMISSIONS`) and the implementation (`ToolRegistry._<name>`) —
#                  so a phantom can no longer be written into this table at all. It is deliberately
#                  REQUIRED rather than optional: an optional field is a declaration you can omit, and
#                  the omission is exactly how `weak_password_reset` survived here for two cycles.
EFFECTS = {
    # Authentication achieved -> everything gated on `authenticated` becomes reachable.
    "sqli_auth_bypass":        {"establishes": ["authenticated"], "invalidates": [],
                                "engine": ["run_auth_sqli"]},
    "default_credentials":     {"establishes": ["authenticated"], "invalidates": [],
                                "engine": ["run_default_creds"]},
    "jwt_forge":               {"establishes": ["authenticated"], "invalidates": [],
                                "engine": ["run_jwt"]},
    "jwt_key_confusion":       {"establishes": ["authenticated"], "invalidates": [],
                                "engine": ["run_jwt"]},
    "saml_signature_bypass":   {"establishes": ["authenticated"], "invalidates": [],
                                "engine": ["run_saml"]},

    # Credential material recovered -> the exposed-credentials technique has something to consume.
    "sqli_union_extract":      {"establishes": ["credentials_exposed"], "invalidates": [],
                                "engine": ["run_sqli"]},
    "exposed_files_harvest":   {"establishes": ["credentials_exposed"], "invalidates": [],
                                "engine": ["run_exposure", "run_dir_harvest"]},
    "target_intel_harvest":    {"establishes": ["credentials_exposed"], "invalidates": [],
                                "engine": ["run_js_review"]},

    # Surface discovery -> new inputs for the injection engines.
    "graphql_introspection":   {"establishes": ["has_api", "has_object_id"], "invalidates": [],
                                "engine": ["run_graphql"]},
    # NOT `find_hidden_route`: it is a lab-local catalog entry with no executor and no gate, so an effect
    # declared on it could never fire. Over-declaring is worse than not declaring — it would make the
    # planner believe a capability is obtainable by an action it can never actually take.
    #
    # NOT `weak_password_reset` (Q-007) and NOT `soft_deleted_login`, removed 2026-08-17 under the rule
    # stated one paragraph up, which they were the only two entries ever to violate. Both were declared
    # here with `establishes: ["authenticated"]` and neither has an executor: MEASURED, no name matching
    # reset/password/passwd or soft_delete anywhere in `TOOL_PERMISSIONS` (111) ∪ `_run*/_confirm*` (96)
    # ∪ `CLAUDE_TOOLS` (76), with `sqli` returning six names on the same probe as the positive control.
    # `weak_password_reset` additionally carried the ONLY non-empty `invalidates` in the table, so all
    # six rows `conflicts()` returned were generated by an engine that does not exist. It is NOT re-homed
    # onto `session_lifecycle`: MEASURED in Q-074 by DRIVING that engine over real HTTP against the
    # `sessionlife` lab with a live mission session held by a different account — it confirmed the
    # vulnerable mount, declined the secure one, and `session_headers`, `_sessions`, `_session_state`
    # and `state.capabilities` were all identical before and after while the mission credential still
    # reached the authenticated marker. Positive control on the same instrument: a direct logout moved
    # it (200, True) -> (401, False). The session that engine ends is a sacrificial one it minted
    # itself, value-checked disjoint from every live session by `tools._session_kill_is_safe`.

    # Runtime/browser discovery of client-rendered surface.
    "browser_persona_bola":    {"establishes": ["has_object_id", "authenticated"], "invalidates": [],
                                "engine": ["confirm_browser_persona_bola"]},

    # An error oracle firing is itself an observation later techniques key on.
    "sqli_structural":         {"establishes": ["sql_error_seen"], "invalidates": [],
                                "engine": ["run_sqli_structural"]},

    # ── the NEGATIVE half (Q-074), and it is the only entry that has ever earned one ────────────
    #
    # Q-007 left `conflicts()` empty. An empty model and a correct model produce the same plan for
    # different reasons, so Q-074 went looking for an engine that genuinely ENDS the engagement's
    # session. It is not `session_lifecycle` (measured above). It is this one.
    #
    # MEASURED, twice, on the shipped `_run_race` with a real mission session (raw output in
    # docs/handoff/effects2.md section 3):
    #   * `tools._SESSION_KILL_RE` has exactly ONE use site — `_add_urls`, which keeps a logout URL
    #     out of the probe surface. `recon["forms"]` is a SECOND door that no session-kill filter
    #     guards, and the planner's form loop (`planner.py:652-661` at run 4's HEAD) turns every POST
    #     form action in it into `run_csrf` + `run_race` steps while `_run_race` merges
    #     `self.session_headers` into all 20-60 of its concurrent requests. Driven end to end against
    #     a logout FORM: mission GET /api/me went (200, True) -> (401, False), and `session_headers`
    #     still held the dead cookie afterwards.
    #     Run 4 sharpened this: the filter DID see that URL. `_http_probe`'s link regex covers
    #     `action=`, so the same URL is correctly quarantined into `session_kill_urls` AND
    #     simultaneously appended to `recon["forms"]` by the branch below it, which filters on
    #     `scope.validate` alone. One registry, one URL, two contradictory policies.
    #   * A harmless form on the same probe left the session up, so the instrument does not report a
    #     kill where there is none.
    #
    # CORRECTION, Q-074 run 4, and it is the reason the paragraph above no longer ends where it used
    # to. This comment previously claimed the effect "SURVIVES the fix for the adjacent quarantine
    # defect", citing a re-measurement on a change-password form the regex cannot match. **That claim
    # does not reproduce, and it was the sole ground for treating this technique differently from
    # three others.** Re-driven against the shipped `sessionlife` lab
    # (`/secure/api/change-password`, `change_evicts=True`, regex match False), with the body the
    # PLANNER ACTUALLY BUILDS — `"&".join(f"{f}=1" for f in fields)`, planner.py:658:
    #
    #     POSITIVE CONTROL  a real change-password by A     -> 200; bystander session B (401, False)
    #     NEGATIVE CONTROL  that planner body, sent by hand -> 403 "current password does not match"
    #     run_race    A (200,True) B (200,True) -> A (200,True) B (200,True)   NO KILL
    #     run_csrf / run_form_cmdi / run_stored_xss: identical, 0 of 4 killed anything
    #     run_race handed a body that DOES rotate the credential -> B (401, False)
    #
    # So the engine can end a session on that form only when handed input the planner never builds.
    # The predecessor handoffs do not record which body they used, so their second route is
    # UNVERIFIED as stated and does not hold under planner-reachable input.
    #
    # WHAT THE EFFECT ACTUALLY IS, measured 4/4 with a clean 4/4 paired control (raw output in
    # docs/handoff/effects4.md sections 1-3): the cause is the `recon["forms"]` DOOR, and the door is
    # not this engine's. The shipped planner emits FOUR steps against a quarantined session-kill
    # action — `run_csrf`, `run_race`, `run_form_cmdi`, `run_stored_xss` — and ALL FOUR end the
    # mission session on a mount that invalidates on logout. `run_csrf` is ACTIVE, so it reaches this
    # in the DEFAULT mode, where `run_race` cannot run at all.
    #
    # WHY THE OTHER THREE ARE NOT ADDED HERE, stated so the absence is a decision and not an
    # oversight. `csrf`, `command_injection` and `stored_xss` are all real technique ids and
    # `effects_audit` would accept them. They are left out because the entry would attribute a DOOR
    # defect to three technique families whose primary engines (`run_cmdi` on query params,
    # `run_xss`) demonstrably do not have it, in a vocabulary that cannot name the real cause — and
    # because the fix recommended in the same handoff makes all four false at once. Writing four
    # entries that this lane simultaneously asks to be deleted is not a more accurate model, it is
    # the same fact recorded four times where nothing reads it. THE ONE ENTRY STAYS because it is
    # true in shipped configuration and removing it returns the model to the empty state Q-074 exists
    # to escape. **When the door is fixed, RE-MEASURE THIS ENTRY — it is expected to become false.**
    #
    # ── THE DOOR WAS FIXED, AND HERE IS THE RE-MEASUREMENT THE LINE ABOVE ASKED FOR ─────────────
    #
    # Q-080 (`928319b`) closed both doors with one predicate in `planner.fresh()` plus an executor
    # ingress guard. MEASURED at HEAD by the Q-074 negative-effects lane, driving the SHIPPED
    # `planner.next_batch` to exhaustion on the fixture the shipped crawler actually produced (raw
    # output in docs/handoff/negative_effects.md section 4):
    #
    #     mode=full     106 steps, at the session-kill url: 0
    #     mode=active    99 steps, at the session-kill url: 0
    #     mode=passive   29 steps, at the session-kill url: 0
    #     POSITIVE CONTROL, the ordinary form on the same page, mode=full: 6 steps, run_race among
    #         them — so the planner is still emitting form steps and the zero is not an empty plan
    #     NEGATIVE CONTROL, `is_session_kill_url` stubbed to False: the 6 and the 3 come straight
    #         back, and restoring it returns them to 0
    #
    # So the row's ENTIRE measured ground — "the planner aims this engine at a session-destroying
    # action carrying the mission session" — no longer exists in the shipped tree. The only surface
    # `run_race` still reaches is the ordinary form, where the measurement recorded 22 lines above is
    # 0 of 4 engines killing anything with the body the planner actually builds.
    #
    # THE ROW IS KEPT, and the reason is narrow enough to state exactly. It is NOT kept because it is
    # still measured — it is not. It is kept as a deliberate OVER-APPROXIMATION under the asymmetry
    # argued at the bottom of this comment: an over-declared `establishes` is UNSOUND, an
    # over-approximated `invalidates` costs only COMPLETENESS, and `run_race` racing an arbitrary
    # session-affecting action still plausibly ends a session even though no planner-reachable input
    # now demonstrates it. What was FALSE was this comment, which presented an expired measurement as
    # a live one. **Anything that reads `conflicts()` is reading a conservative bound, not an
    # observation.** There is exactly one such reader and it is a reporting endpoint; see below.
    #
    # AND NO `csrf` ROW WAS CREATED, though the key would be valid (`routes()['csrf']` is
    # `{'run_csrf': [...]}`, and `csrf` is a real technique id — MEASURED). Q-080 measured `run_csrf`
    # as one of SIX engines that ended the mission session, all six through the two doors it then
    # closed. A `csrf` row would therefore record, in a table nothing schedules from, a behaviour the
    # shipped tree no longer exhibits — the fifth transcription of one door defect. A model is not
    # made more accurate by adding rows whose fact has expired.
    #
    # WHAT ANY OF THIS IS WORTH, so no later reader mistakes it for planner behaviour. MEASURED over
    # all 184 production files: the negative half has ONE production reader, `main.py`'s
    # `POST /orchestration/audit`. `agent.py` and `planner.py` import neither this module nor
    # `effect_search` — not by alias, not by from-import, not as a raw substring. **No scheduling
    # decision anywhere in Apolaki changes because this row exists.** That is pinned by
    # `tests/test_negative_effects_reach.py`, which fails in both directions: delete the row and two
    # tests fail, wire the model into `planner.py` and two tests fail naming the new consumer.
    #
    # `establishes` is EMPTY on purpose: a race proves a limit can be bypassed, which is a finding,
    # not an observation this 17-term vocabulary can express.
    #
    # WHY THIS IS DECLARED UNCONDITIONALLY when the field behaviour is conditional (the race only
    # ends the session when the raced action is session-affecting), and why that is NOT the
    # over-declaration this table forbids two paragraphs up: the two halves are not symmetric. An
    # over-declared `establishes` is UNSOUND — the planner chases a capability it does not have. An
    # over-approximated `invalidates` costs only COMPLETENESS — the search may decline an ordering
    # that would in fact have worked, and never emits one that dies in the field. The measurement
    # above is the second failure actually happening, so the conservative direction is the correct
    # one here.
    "race_condition":          {"establishes": [], "invalidates": ["authenticated"],
                                "engine": ["run_race"]},
}


# Files that DESCRIBE the platform rather than run it. A mention here is prose, not wiring — which is
# exactly how `graphql_argument_injection` came to be declared reachable via a function nobody called.
_PROSE_FILES = {"techniques.py", "engine_descriptor.py",
                # Q-075 turned this into a prose file without anyone noticing. It now records
                # QUALIFIED_BASELINE_SET / METHOD_BASELINE_SET as STRING LITERALS naming
                # functions, so a name here is a record that something is DEAD -- the exact
                # opposite of wiring. Left in, `verify_always_on` read "bie.resolve_locator"
                # off that baseline and concluded the function was wired, which silently
                # disarmed its own negative control (test_the_verifier_catches_an_unwired_reason
                # asserts ok is False and got True). Same shape as the scan_methods self-read:
                # a gate that reads a registry of dead things and counts the entries as alive.
                "deadcode_gate.py"}


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


# ── ROUTING: technique id -> dispatchable engine name (Q-066) ──────────────────────────────────
#
# The gap this closes, measured rather than assumed: `PRECONDITIONS`, `EFFECTS` and the whole technique
# registry are keyed by TECHNIQUE ID (42 of 42, 13 of 13, 88 of 88), while `tools.TOOL_PERMISSIONS` is
# keyed by ENGINE NAME. **0 of 88 technique ids are engine names, and no field on any technique record
# holds one** (exact-value match over all 25 field names). So the planner could rank `jwt_forge` and have
# no route to `run_jwt`. That is the fourth appearance of one defect shape here: two vocabularies for the
# same thing that never meet.
#
# THE MAPPING IS DERIVED, NEVER TYPED. A hand-written {"jwt_forge": "run_jwt"} dict would be a THIRD
# vocabulary and would rot exactly like the two it joins. Both sources below already exist, are already
# maintained for another purpose, and have already been corrected twice for this very class of error
# (Q-011 fixed `wstg_catalog.FULL["WSTG-INPV-20"]`, which had a technique id where an engine belonged):
#
#   always_on_reason — ALWAYS_ON's prose already names the engine that reaches the technique, and
#                      verify_always_on() already proves that name is referenced from code that runs.
#   wstg_full        — a technique record carries `wstg`; `wstg_catalog.FULL[wstg]` is the catalog's
#                      assertion that a DETERMINISTIC CONFIRMING ENGINE exists for that test, named.
#
# Two sources were measured and DELIBERATELY REJECTED, because a wrong route is worse than no route:
#
#   wstg_catalog.PARTIAL — by the catalog's own definition, "a related tool touches it but does not
#                      confirm the specific scenario". That is the negation of an executor. It would add
#                      13 techniques and it gets them wrong in kind: `weak_secret_forgery` (forge a
#                      coupon whose secret is salt-less) would route to `run_hash_id`, which identifies
#                      hash primitives and forges nothing.
#   asvs_model       — joining technique `vuln_class` to a row's `violated_by` family is a name
#                      coincidence, not a binding. Measured: it disagreed with the two sources above on
#                      22 of the 33 techniques it covered, e.g. routing `idor_bola_read` to `run_bfla`
#                      (function-level) alongside the correct `confirm_idor` (object-level).


def _tokens(text: str) -> set:
    """Normalised identifier tokens in a prose string.

    The normalisation is verify_always_on()'s, and for its reason: a tool is REGISTERED under a bare
    string (`"run_service_pack"`) and IMPLEMENTED as a private method (`_run_service_pack`), so the two
    spellings are one engine. Omitting the `lstrip("_")` made my own first probe report 14 wired ICS
    engines as unroutable — an instrument error, not a finding. Pure."""
    import re
    return {t.split(".")[-1].lstrip("_")
            for t in re.findall(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?", text or "")}


def _engines_named(text: str, registry) -> set:
    """Registered engine names a prose string NAMES. Pure."""
    return {t for t in _tokens(text) if t in registry}


# A token shaped like an engine reference. Apolaki's dispatch names are overwhelmingly `run_*`/`confirm_*`,
# and this is deliberately a SEPARATE test from registry membership: filtering candidates by the registry
# and then asserting every candidate is in the registry is a guard that cannot fail, which is the exact
# trap this codebase has fallen into eight times. `run_mass_assignment` (Q-011) was engine-SHAPED and
# unregistered — a route to nothing — and only a shape-based check can see it.
_ENGINE_SHAPED = r"^(?:run|confirm)_[a-z0-9_]+$"


def _engine_shaped(text: str) -> set:
    """Tokens that LOOK like a dispatch name, registered or not. Pure."""
    import re
    return {t for t in _tokens(text) if re.match(_ENGINE_SHAPED, t)}


def engine_registry() -> set:
    """The dispatchable engine names — `tools.TOOL_PERMISSIONS` keys, the registry the executor uses.

    Imported lazily: `tools` is the heavy module that imports every engine, and importing it at module
    scope would invert this module's dependency direction the way T7 exists to prevent. Returns an empty
    set if it cannot be read, which makes routing_audit() fail CLOSED (everything unroutable, loudly)
    rather than reporting a clean sheet from an instrument that loaded nothing."""
    try:
        import tools
        return set(tools.TOOL_PERMISSIONS)
    except Exception:
        return set()


def routes(registry=None, techniques=None) -> dict:
    """{technique_id: {engine_name: [source, ...]}} — the join, derived from the sources above.

    Only engine names that are ACTUALLY IN THE REGISTRY are emitted, so a route is by construction
    dispatchable; `routing_audit()` re-checks that separately rather than trusting this. Pure given the
    registry and technique table.

    THIRD SOURCE, Q-007: `EFFECTS[tid]["engine"]`. It is narrow on purpose — it covers only techniques
    that declare an effect, which is where a missing route is load-bearing rather than merely untidy,
    because the forward search will otherwise hand back a plan whose step nothing can run. It exists
    because the two DERIVED sources are MEASURED to miss real engines: `default_credentials` is reached
    by `run_default_creds` (registered, implemented, dispatched from `agent.py`) and reads as NO ROUTE
    only because `WSTG-ATHN-02` sits in `wstg_catalog.PARTIAL` rather than `FULL`; `saml_signature_bypass`
    is reached by `run_saml` and has no `wstg` id at all. A declaration was the wrong instrument for the
    other 75 techniques and is the right one for these 11, because here it is CHECKED — see
    `effects_audit()`, which resolves every name against the registry AND the implementation AND, where
    a derived source has an opinion, requires the two to agree."""
    reg = engine_registry() if registry is None else set(registry)
    if techniques is None:
        import techniques as T
        techniques = T.TECHNIQUES
    if not reg:
        return {}
    out = {}
    for tid, reason in ALWAYS_ON.items():
        for e in _engines_named(reason, reg):
            out.setdefault(tid, {}).setdefault(e, []).append("always_on_reason")
    for tid, eff in sorted(EFFECTS.items()):
        for e in eff.get("engine") or ():
            if e in reg:
                out.setdefault(tid, {}).setdefault(e, []).append("effect_engine")
    try:
        import wstg_catalog as W
        full = W.FULL
    except Exception:
        full = {}
    for tid, rec in sorted(techniques.items()):
        wid = rec.get("wstg")
        if wid and full.get(wid):
            for e in _engines_named(full[wid], reg):
                out.setdefault(tid, {}).setdefault(e, []).append("wstg_full")
    return {t: {e: sorted(set(s)) for e, s in sorted(v.items())} for t, v in sorted(out.items())}


def routing_audit(registry=None, techniques=None) -> dict:
    """Can every technique the platform can RANK actually be DISPATCHED?

    `phantom` is the load-bearing invariant and MUST stay empty: a derived engine name that is not in
    the registry is a route to nothing, which is the `run_mass_assignment` defect (Q-011) reappearing
    from a different direction.

    `unrouted` is reported, not asserted here — 13 techniques genuinely have no engine today, and
    pretending otherwise would be the declaration-checking guard this codebase has shipped eight times.
    The test pins the exact set so the list can only be shrunk deliberately.

    `effect_producers_unrouted` is the Q-065 half: a technique that DECLARES an effect but has no
    executor lets the forward search return a plan whose step cannot be run. Pure.

    `wstg_key_reachability` is Q-081's half, and it belongs HERE rather than in a module of its own
    because the third route source below is literally `wstg_catalog.FULL[rec["wstg"]]` — this function
    already derives engines by INDEXING a taxonomy table with a technique's declared key, and never
    asked whether that key is a real catalog id. `wstg_audit()`'s hard fault
    `claimed_ids_outside_catalog` therefore joins `ok`: a route derived from a claim on a test that
    does not exist is the `run_mass_assignment` shape one level up, in the KEY instead of the value.
    The other two hard faults and the reported list are surfaced but left out of `ok`, because they
    are properties of `wstg_catalog` rather than of THIS derivation; `tests/test_wstg_key_reachability.py`
    asserts those directly."""
    reg = engine_registry() if registry is None else set(registry)
    if techniques is None:
        import techniques as T
        techniques = T.TECHNIQUES
    r = routes(reg, techniques)
    # Phantoms are found by SHAPE, over the same source prose routes() reads — never by re-filtering
    # routes()' own output, which is registry-filtered and so could never disagree.
    phantom = set()
    for tid, reason in ALWAYS_ON.items():
        phantom |= {"%s (always_on_reason) -> %s" % (tid, e)
                    for e in _engine_shaped(reason) - reg}
    # The EFFECTS source is a literal name list, not prose, so it is checked WITHOUT the shape filter:
    # any declared name outside the registry is a route to nothing whatever it is spelled like. Applying
    # `_engine_shaped` here would let a typo such as `defualt_creds` through silently.
    for tid, eff in sorted(EFFECTS.items()):
        phantom |= {"%s (effect_engine) -> %s" % (tid, e)
                    for e in set(eff.get("engine") or ()) - reg}
    try:
        import wstg_catalog as W
        full = W.FULL
    except Exception:
        full = {}
    for tid, rec in sorted(techniques.items()):
        wid = rec.get("wstg")
        if wid and full.get(wid):
            phantom |= {"%s (wstg_full:%s) -> %s" % (tid, wid, e)
                        for e in _engine_shaped(full[wid]) - reg}
    phantom = sorted(phantom)
    unrouted = sorted(t for t in techniques if t not in r)
    wstg = wstg_audit(techniques=techniques)
    return {
        "registry_size": len(reg),
        "registry_readable": bool(reg),
        "total": len(techniques),
        "routed": len(r),
        "unrouted": unrouted,
        "phantom": phantom,
        "effect_producers_unrouted": sorted(t for t in EFFECTS if t not in r),
        "wstg_key_reachability": wstg,
        "ok": bool(reg) and not phantom and not wstg["claimed_ids_outside_catalog"],
    }


def engine_implementations() -> set:
    """Dispatch names that have a real `ToolRegistry._<name>` — the IMPLEMENTATION fact, kept separate
    from the REGISTRATION fact on purpose.

    They are genuinely two different facts and this project has been bitten by conflating them: a name
    can sit in `TOOL_PERMISSIONS` while nothing implements it, and every consumer reads that as a live
    engine. Checking both means a phantom has to defeat two independent tables to get through.

    MEASURED 2026-08-17: 111 registered names, 163 single-underscore methods, and `TOOL_PERMISSIONS -
    implementations` is EMPTY — the two tables agree on every registered name today. So this check does
    not currently discriminate among REGISTERED names, and saying otherwise would be claiming an
    instrument reading it cannot produce. What it does catch is the invented name (`run_password_reset`
    is in neither table) and a future registration that ships without an implementation.

    Dunders are excluded deliberately: `lstrip("_")` on `__init__` yields `init__`, which is junk in a
    membership set. Returns an empty set on failure, so `effects_audit()` fails CLOSED — an instrument
    that loaded nothing must not report a clean sheet."""
    try:
        import tools
        reg = tools.ToolRegistry
        return {n[1:] for n in dir(reg)
                if n.startswith("_") and not n.startswith("__") and callable(getattr(reg, n, None))}
    except Exception:
        return set()


def effects_audit(effects=None, registry=None, implementations=None, routing=None,
                  techniques=None) -> dict:
    """Q-007's guard. Does every DECLARED EFFECT belong to an engine that EXISTS?

    This is the check that had to fail on a phantom, so it is built out of facts and never out of the
    declaration it is checking:

      * `no_engine_declared` — an EFFECTS entry with no `engine` key at all. This is the one that catches
        the historical shape directly: `weak_password_reset` and `soft_deleted_login` were both declared
        with effects and there was no engine name in existence to write down for either of them.
      * `unregistered` — a declared name outside `tools.TOOL_PERMISSIONS`.
      * `unimplemented` — a declared name with no `ToolRegistry._<name>`; an independent table from the
        one above, so a name has to appear in both to pass.
      * `unknown_technique` — a KEY that is not an id in `techniques.TECHNIQUES`. Q-074 run 4 MEASURED
        this hole by writing the negative control before trusting the guard: an entry
        `{"csrf_token_missing": {"invalidates": ["authenticated"], "engine": ["run_csrf"]}}` — a
        plausible-looking name that is not a technique, pointed at a REAL registered and implemented
        engine — returned `ok=True` from every check above, because all three of them interrogate the
        ENGINE and none of them interrogates the KEY. It is worse than merely untidy: `build()` walks
        `TECHNIQUES`, so the row never becomes a descriptor (`build()` stayed at 88 descriptors, the key
        absent) and `conflicts()` stayed at 6 rows with `race_condition` its only producer. **The entry
        is silently inert and passes.** That is the Q-007 shape wearing different clothes — a
        declaration nothing can act on, recorded as if it were a fact — and this project has shipped a
        guard that checks a declaration instead of a fact ten times. The failure is loud now.
    `differs_from_derived_route` is REPORTED, not asserted — the same treatment `routing_audit()` gives
    `unrouted`, and for the same reason. Where `routes()` independently derives engines from `ALWAYS_ON`
    prose or `wstg_catalog.FULL`, a declaration that shares nothing with the derivation is worth seeing;
    but MEASURED, the derived source is COARSER than this one, so a disagreement is not by itself an
    error. `wstg_catalog.FULL["WSTG-INPV-05"]` is `run_sqli / run_auth_sqli` and THREE techniques carry
    that id, so `sqli_structural` derives the family pair while its actual engine is the more precise
    `run_sqli_structural` (registered and implemented — checked above). Failing on that would punish the
    more accurate declaration. The exact set is pinned in the test instead, so it can only change
    deliberately, and a declaration pointed at the wrong engine still fails there.

    `ok` requires NON-VACUITY: both fact tables non-empty and `checked > 0`. A scan over an empty set
    passes for free, and a guard that passes for free is the defect, not the fix.

    Pure given `effects`, `registry`, `implementations`, `routing` and `techniques`; resolves each from
    the live platform when not supplied."""
    eff = EFFECTS if effects is None else effects
    reg = engine_registry() if registry is None else set(registry)
    impl = engine_implementations() if implementations is None else set(implementations)
    routing = routes() if routing is None else routing
    if techniques is None:
        import techniques as _T
        techniques = _T.TECHNIQUES
    known = set(techniques or ())

    def _derived(tid):
        # Only the routes the OTHER sources produced. A route whose only source is this very table
        # would make the cross-check compare the declaration with itself — a guard that cannot fail.
        return {e for e, s in (routing.get(tid) or {}).items() if [x for x in s if x != "effect_engine"]}

    no_engine, unregistered, unimplemented, differs, verified = [], [], [], [], {}
    unknown_technique = []
    for tid, spec in sorted(eff.items()):
        # Checked BEFORE the `continue` below, so a key that is both unknown AND engineless reports
        # both faults instead of only the first one the loop happens to reach.
        if tid not in known:
            unknown_technique.append(tid)
        declared = list((spec or {}).get("engine") or ())
        if not declared:
            no_engine.append(tid)
            continue
        for e in declared:
            if e not in reg:
                unregistered.append("%s -> %s" % (tid, e))
            if e not in impl:
                unimplemented.append("%s -> %s" % (tid, e))
        derived = _derived(tid)
        if derived and not (derived & set(declared)):
            differs.append("%s: declared %s vs derived %s"
                           % (tid, sorted(declared), sorted(derived)))
        verified[tid] = sorted(e for e in declared if e in reg and e in impl)

    return {
        "checked": len(eff),
        "registry_size": len(reg),
        "implementations_size": len(impl),
        "technique_table_size": len(known),
        "cross_checked_against_derived_route": sum(1 for tid in eff if _derived(tid)),
        "no_engine_declared": no_engine,
        "unregistered": sorted(unregistered),
        "unimplemented": sorted(unimplemented),
        "unknown_technique": sorted(unknown_technique),
        "differs_from_derived_route": sorted(differs),
        "verified": verified,
        # `bool(known)` joins the other two fact tables in the non-vacuity clause: an unreadable
        # technique table would otherwise make EVERY key "unknown", and a guard whose instrument
        # failed must fail closed rather than report the failure as a finding.
        "ok": bool(reg) and bool(impl) and bool(known) and len(eff) > 0
              and not (no_engine or unregistered or unimplemented or unknown_technique),
    }


def wstg_audit(catalog=None, full=None, partial=None, excluded=None, techniques=None) -> dict:
    """Q-081's predicate, one registry over: can a declared WSTG row REACH a consumer at all?

    `effects_audit` interrogated a declared engine three independent ways and never asked whether the
    KEY could reach anything, so a row that no consumer would ever read passed its own audit. The
    fault was not in that one check — it is that a guard can validate a field of a record thoroughly
    while nothing tests the record's reachability. The WSTG tables have the identical structure and
    had no such check, so here it is.

    THE CONSUMER, named because it is what makes these facts and not opinions.
    `wstg_catalog.coverage()` iterates `CATALOG.items()` and buckets each id `if wid in FULL / elif
    wid in PARTIAL / else` (with `EXCLUDED` supplying the reason). Everything below follows from that
    one loop:

      * `map_keys_outside_catalog` — a `FULL`/`PARTIAL`/`EXCLUDED` key that is not a `CATALOG` id.
        `coverage()` never looks it up, so it changes no bucket, no tally and no percentage. It is the
        `csrf_token_missing` row wearing a WSTG id: a declaration that reads like coverage and does
        nothing. On `FULL` it is the worse direction, because a reader takes "a deterministic
        confirming engine exists" from it; on `EXCLUDED` it is a safety refusal about no test at all.
      * `maps_overlap` — an id in two maps. `coverage()`'s `if/elif` then decides the bucket by
        STATEMENT ORDER, so the winner is a property of the code's layout rather than of anything
        anyone declared. Nothing else in the tree records which map is meant to win.
      * `claimed_ids_outside_catalog` — the technique registry's `wstg` column is a SECOND,
        independent declaration of the same taxonomy fact, and `routes()` above already resolves
        `wstg_catalog.FULL[rec["wstg"]]` to derive an engine from it. A claim on an id the catalog
        does not define can never be confirmed or refuted by anything.

    `claimed_but_unmapped` is REPORTED, not asserted — the same treatment `effects_audit` gives
    `differs_from_derived_route` and `routing_audit` gives `unrouted`, and for the same reason. It
    holds techniques that claim a real `CATALOG` id which sits in none of the three maps, so
    `coverage()` reports "not yet implemented" for a test some technique says it performs. That is
    worth seeing — it is the UNDER-report mirror of Q-011, which was `FULL` naming a technique id
    where an engine belonged and over-claiming as a result. But `FULL` is deliberately conservative
    ("only where a deterministic confirming engine exists"), so a technique's claim is not by itself
    proof that such an engine exists, and failing on it would punish the more honest catalog. MEASURED
    at 3 rows, of which two look like the TECHNIQUE record being wrong rather than the catalog. The
    exact set is pinned in `tests/test_wstg_key_reachability.py` instead, so it can only move
    deliberately.

    `ok` requires NON-VACUITY: the catalog and the technique table both non-empty and `checked > 0`.
    A scan over an empty set passes for free, and an unreadable fact table must fail closed rather
    than report its own failure as a list of findings — the rule `effects_audit` learned when
    `bool(known)` joined its non-vacuity clause.

    Pure given the five tables; resolves each from the live platform when not supplied."""
    if catalog is None or full is None or partial is None or excluded is None:
        try:
            import wstg_catalog as W
            catalog = W.CATALOG if catalog is None else catalog
            full = W.FULL if full is None else full
            partial = W.PARTIAL if partial is None else partial
            excluded = W.EXCLUDED if excluded is None else excluded
        except Exception:
            catalog = catalog or {}
            full, partial, excluded = full or {}, partial or {}, excluded or {}
    if techniques is None:
        import techniques as T
        techniques = T.TECHNIQUES
    cat = set(catalog or ())

    outside, overlap = [], []
    for label, table in (("FULL", full), ("PARTIAL", partial), ("EXCLUDED", excluded)):
        for wid in sorted(table or ()):
            if wid not in cat:
                outside.append("%s -> %s" % (label, wid))
    for a_lbl, a_tab, b_lbl, b_tab in (("FULL", full, "PARTIAL", partial),
                                       ("FULL", full, "EXCLUDED", excluded),
                                       ("PARTIAL", partial, "EXCLUDED", excluded)):
        for wid in sorted(set(a_tab or ()) & set(b_tab or ())):
            overlap.append("%s in %s and %s" % (wid, a_lbl, b_lbl))

    mapped = set(full or ()) | set(partial or ()) | set(excluded or ())
    claimed_outside, claimed_unmapped, checked = [], [], 0
    for tid, rec in sorted((techniques or {}).items()):
        wid = (rec or {}).get("wstg")
        if not wid:
            continue
        checked += 1
        if wid not in cat:
            claimed_outside.append("%s -> %s" % (tid, wid))
        elif wid not in mapped:
            claimed_unmapped.append("%s -> %s" % (tid, wid))

    return {
        "catalog_size": len(cat),
        "full_size": len(full or ()), "partial_size": len(partial or ()),
        "excluded_size": len(excluded or ()),
        "technique_table_size": len(techniques or ()),
        "checked": checked,
        "map_keys_outside_catalog": sorted(outside),
        "maps_overlap": sorted(overlap),
        "claimed_ids_outside_catalog": sorted(claimed_outside),
        "claimed_but_unmapped": sorted(claimed_unmapped),
        "ok": bool(cat) and bool(techniques) and checked > 0
              and not (outside or overlap or claimed_outside),
    }


def descriptor(tech: dict, preconditions: dict, always_on: dict, routing: dict = None) -> dict:
    """One engine's full contract, now including HOW IT IS DISPATCHED. Pure.

    `engines` is the Q-066 join: the descriptor's public surface previously carried preconditions and
    effects but nothing an executor could act on, so a consumer holding a ranked technique had to guess
    the tool name. `routing` is passed in by build() so the derivation runs once for the whole registry
    rather than once per technique; None means "resolve it here" for a standalone call."""
    tid = tech.get("id", "")
    eff = EFFECTS.get(tid, {})
    routing = routes() if routing is None else routing
    eng = routing.get(tid, {})
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
        # the join: dispatchable engine names, and which already-existing table each was derived from
        "engines": sorted(eng),
        "routed_by": {e: list(s) for e, s in sorted(eng.items())},
        "routable": bool(eng),
    }


def build() -> dict:
    """{id: descriptor} for every registered technique, built from THIS module's tables.

    Post-T7 these are the tables the platform actually routes on — `technique_planner` re-exports them —
    so a descriptor cannot drift from live behaviour. Before T7 this read the planner's copies, which made
    it a read-only view; the dependency now runs the other way."""
    import techniques as T
    routing = routes()
    return {t["id"]: descriptor(t, PRECONDITIONS, ALWAYS_ON, routing)
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
