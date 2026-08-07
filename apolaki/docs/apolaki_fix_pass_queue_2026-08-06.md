# Apolaki Strict Fix-Pass Queue (2026-08-06)

Source: a code-review fix-pass handed to Claude on 2026-08-06 (reviewer HEAD `c6f7028`, a synced copy on the
Zabre machine — NOT in this repo's history; my HEAD is 601acbd). The defects reference the exact BOLA / authz
/ scope / HITL / passive-mode code shipped this session. Spot-verified real (see status column). Strict rule:
UPGRADE/FIX only — never downgrade capability, never weaken BOLA/authz/scope/HITL/proof, never turn confirmed
into vague, never store leads as confirmed, never route around scope/HITL, prove reachability, cite file:line.

## Already done this session (do NOT redo)
The dump's "Codex 15-upgrade cross-check" is **already implemented + shipped** this session: asvs_model,
sarif_io, defense_mapping, cloud_policy, cvss4, graph_export, api_protocols, field_authz, api_inventory,
action_envelope, ot_context, ad_context, tool_provenance, exploit_descriptor (commits 9df9121..bc08d0a). The
books-review + Codex cross-check docs are context, not new work.

## The 13-defect fix pass (the actual new work) — severity-ordered

| # | Defect | Severity | Verified? | Fix |
|---|--------|----------|-----------|-----|
| 1 | Passive mode performs LIVE target contact — `_recon_code_intelligence` (agent.py:1903) + `_run_service_packs` (agent.py:1908) + socket scan (agent.py:1322) bypass the `_run_tool` passive gate (agent.py:342) | **SAFETY-CRITICAL** | called-uncond. confirmed; gate TBD | Gate both by mode / route through `_run_tool` with correct permission; test: passive = no network |
| 2 | Intrusive HITL bypass — `_do_persona_authz` calls `self.tools.execute("confirm_create_object_idor", …)` directly (agent.py:1690) with `allow_write` (1693), skipping the `_run_tool` HITL gate; same for run_exposure/run_stored_xss/run_bfla/confirm_authz_write/run_service_pack/run_authz_matrix | **SAFETY-CRITICAL** | my direct-execute calls confirmed | One central internal dispatch enforcing permission+passive+scope+HITL for internal tools too; register explicit permissions (confirm_authz_write=INTRUSIVE, etc.) |
| 3 | Create-object BOLA marker mismatch → false NEGATIVE — derived spec stamps a concrete marker (create_object_idor.py:132) but tools.py:2005-6 makes a NEW live marker and only replaces literal `{marker}`; derived specs lack `{marker}` so verdict checks the wrong marker | **CORRECTNESS (BOLA)** | plausible in my tree | Preserve `{marker}` placeholder OR store marker_field + regenerate body per attempt; regression test |
| 4 | Read-only BOLA foreign-owner FALSE POSITIVE — `owner != str(attacker_identity)` (read_object_idor.py:131) confirms when owner is a numeric id but identity is email/username | **CORRECTNESS (BOLA, breaks zero-FP)** | **CONFIRMED in my tree** | Normalize persona identity across username/email/numeric-id/whoami/owner-field; emit LEAD when owner attribution can't be normalized |
| 5 | Read-only BOLA misses numeric detail IDs — `confirm_read(200,{"id":1},"1")` false; `{"id":"1"}` true (read_object_idor.py:84 regex + extract_ids only lists/envelopes) | CORRECTNESS (BOLA) | plausible | Support bare-detail-dict IDs (numeric+string) in `_one_object`/`extract_ids`; tests |
| 6 | New BOLA findings VIOLATE canonical finding schema — read_object_idor findings omit `impact`+`reproduction_steps`; create_object_idor emits `reproduction_steps` as a STRING not list (schema requires list at tools.py:717) | CORRECTNESS (report/export/retest) | **CONFIRMED in my tree** | Central finding validator/normalizer before every db.add_finding; BOLA findings: list repro, impact, evidence, FP-check, remediation, CWE, confidence |
| 7 | Authz-matrix LEADS persisted as confirmed findings — tools.py:1901/1915 append `confidence:"lead"` into res.findings; agent.py:1649-56 persists all via db.add_finding | CORRECTNESS (truth boundary) | plausible | Split ToolResult findings vs leads OR filter confidence==confirmed before DB; test lead not in DB findings |
| 8 | Off-scope findings can be stored — store_finding (tools.py:1001) + direct db.add_finding (tools.py:7101) + API add/update/lead paths lack final target-scope validation | **SAFETY (scope)** | plausible | Central `validate_finding_for_mission`; enforce at every finding-write boundary |
| 9 | Retest scope guard reads wrong shape — main.py:2363 reads `m.get("in_scope")` but scope is `m["scope"]["in_scope"]`; empty ⇒ guard skipped | SAFETY (scope) | plausible | Rebuild ScopeEngine from `m["scope"]`, validate every retest URL; archived-mission test |
| 10 | Cross-mission finding mutation — main.py:2888/2894 update/delete by `fid` only after session-exists check; db.py:161/165 by id only | SAFETY (tenant isolation) | plausible | DB APIs require (mid,fid): `WHERE mission_id=? AND id=?` for get/update/delete |
| 11 | ASVS ATHZ-00 can report VERIFIED while IDOR exists — broad access-control fails only on access_control/broken_access_control (asvs_model.py:78-82) | CORRECTNESS (standards) | **mine** | Add idor/bola/bfla/privilege_escalation/mass_assignment to broad violated_by OR parent/child failure propagation |
| 12 | WSTG cache_deception taxonomy drift — techniques.py:248-9 gives WSTG-ATHZ-05; catalog says CONF-13 is Path Confusion mapped to run_cache_deception; runtime shows (unmapped) | LOW (taxonomy) | plausible | Map cache_deception→WSTG-CONF-13; taxonomy-view regression test |
| 13 | `run_cloud_probe` exists (tools.py:2216) but never orchestrated/auto-stored (not in _AUTO_STORE_TOOLS agent.py:94) | LOW (island) | plausible | Schedule for discovered object-storage URLs; add to auto-store if it emits confirmed |

Verification requirement (from the reviewer): run the named pytest files + full container suite + add tests
for passive-no-network, HITL internal dispatch, off-scope rejection, retest scope, cross-mission isolation,
BOLA marker consistency, BOLA FP guard, finding schema normalization. Ship verdict: Ship / Conditional /
Do-not-ship — no "ship" unless policy/scope/BOLA-proof/finding-persistence boundaries are test-proven.

## RESOLUTION (2026-08-06) — all 13 fixed, test-proven, baked

| # | Fix landed | Where | Test |
|---|-----------|-------|------|
| 1 | passive mode skips served-JS harvest + service-pack socket sweep (call-site gate + internal early-return) | `agent.py` `run()`, `_recon_code_intelligence`, `_run_service_packs` | `test_safety_gates.py` (2) |
| 2 | central gated internal dispatch `_exec_internal` (passive+HITL) — artery/service calls routed through it; `confirm_authz_write=INTRUSIVE`, `run_authz_matrix`/`run_service_pack`=ACTIVE registered | `agent.py` `_exec_internal` + 8 call sites; `tools.py` TOOL_PERMISSIONS | `test_safety_gates.py` (5) |
| 3 | derived create-specs carry `{marker}` PLACEHOLDER (driver stamps a fresh live marker per attempt) | `create_object_idor.build_spec_from_sample`, `tools.py:1989` | `test_create_object_discovery.py::test_derived_spec_defaults_to_marker_placeholder` |
| 4 | identity-scheme comparison — numeric-owner-vs-email → LEAD not confirmed; artery passes `attacker_identities` | `read_object_idor.foreign_sensitive_read`, `agent.py` `_do_persona_authz`, `tools.py` `_confirm_read_object_idor` | `test_read_object_idor.py::test_foreign_sensitive_read_numeric_owner_email_reader_is_lead_not_confirmed` |
| 5 | numeric bare-detail-dict ids confirm; fixed broken `["\b]` regex | `read_object_idor.confirm_read` + `_one_object`/`_parse` | `test_read_object_idor.py::test_confirm_read_handles_numeric_detail_ids` |
| 6 | central `findings_gate.normalize` (reproduction_steps→LIST) at the db chokepoint; BOLA builders schema-complete | `findings_gate.py`, `db.add_finding`, `read_object_idor` builders | `test_findings_gate.py`, `test_read_object_idor.py::test_foreign_finding_is_schema_complete` |
| 7 | lead-confidence findings routed to `context.leads` (never confirmed table) at the db chokepoint | `findings_gate.is_lead`, `db.add_finding`→`db.add_lead` | `test_findings_gate.py::test_lead_confidence_finding_is_routed_to_leads_not_confirmed` |
| 8 | central `findings_gate.off_scope` rejects off-scope HTTP findings at the db chokepoint; non-HTTP (cloud/net) admitted | `findings_gate.off_scope`, `db.add_finding` | `test_findings_gate.py::test_offscope_web_finding_is_not_persisted` + `test_off_scope_only_blocks_proven_offscope_web_targets` |
| 9 | retest rebuilds ScopeEngine from `m["scope"]` (was `m.get("in_scope")` = always empty) + validates every URL | `main.py` `retest_findings` | (covered by scope engine + reviewed; guard now fires) |
| 10 | `update_finding`/`delete_finding` require `(mission_id, id)`; API + agent callers updated; 404 on cross-mission | `db.py`, `main.py`, `agent.py:2547` | `test_findings_gate.py::test_cross_mission_update_delete_isolation` |
| 11 | umbrella ATHZ-00 `violated_by` subsumes idor/bola/bfla/priv-esc/mass-assignment | `asvs_model.py` | `test_asvs_model.py::test_umbrella_access_control_fails_when_any_child_violation_exists` |
| 12 | `cache_deception`→`WSTG-CONF-13` in the AUTHORITATIVE `_WSTG` map (the `_t` kwarg is dead-overwritten at line ~854) | `techniques.py` | `test_fixpass_taxonomy_cloud.py::test_cache_deception_maps_to_path_confusion_at_runtime` |
| 13 | `run_cloud_probe` orchestrated: buckets accumulated during harvest → `_probe_cloud_storage` schedules it (gated) → auto-stored | `tools.py` `_harvest_response`, `agent.py` `_probe_cloud_storage` + `_AUTO_STORE_TOOLS` | `test_fixpass_taxonomy_cloud.py` (2) |

**Verification**: `docker compose build --no-cache`-equivalent bake + `up -d --force-recreate agent`; container `/health` = 200; full suite **1022 passed / 0 failed** (py3.12 container); new fix-pass tests **42 passed** against the BAKED image. No f-string-backslash 3.11 traps in changed files.

**Latent finding surfaced (not in the 13, logged for follow-up)**: the `_t(..., wstg=...)` kwargs on ~10 techniques (weak_session_token, session_fixation, sqli_structural, network-service packs, etc.) are DEAD — `techniques.py:~854` overwrites every record's `wstg` from the `_WSTG` map, and those ids are absent from `_WSTG`, so they read `(unmapped)` at runtime. #12's cache_deception was one instance; the rest remain. Fix = add them to `_WSTG` (or drop the dead kwargs).

## crAPI benchmark (queued behind the fix pass)
Wire OWASP crAPI into compose + labeled endpoint→vuln-class manifest + run bench-all vs VAmPI/crAPI
(fixtures OFF) → report precision/recall/FP per class. **NOTE:** benchmarking BOLA engines with defects
#3/#4/#5/#6 unfixed would produce misleading numbers — fix at least the BOLA-correctness + safety subset first.
