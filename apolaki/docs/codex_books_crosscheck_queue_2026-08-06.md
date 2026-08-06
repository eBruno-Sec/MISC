# Codex Books Cross-Check — Apolaki Upgrade Queue (2026-08-06)

Source: ChatGPT/Codex second-pass review of the restored Books corpus against Apolaki, handed to
Claude on 2026-08-06. Codex's local paths reference a different machine (`C:\Users\Zabre\...`); the
substance applies to this repo (`C:\Users\voice\Desktop\GitHub\MISC\apolaki`).

Thesis (Codex): Apolaki already has a broad deterministic detection spine. The books' real signal is
NOT "add more payloads" — it is **make the security knowledge explicit, replayable, machine-readable,
standards-mapped, and exportable**. Upgrade driver:

> Can Apolaki represent the assessment as durable, scoped, evidence-backed, standards-mapped,
> replayable knowledge?

## Verification pass (Claude, 2026-08-06)

Static grep of `agent/` confirms Codex's "does not exist yet" claims:
- ABSENT (buildable-new): `asvs_model`, `sarif_io`, `defense_mapping`/`d3fend`, `cvss4`,
  `graph_export`, `cloud_policy`, `field_authz`, `api_protocols`, `api_inventory`,
  `rate_limit_observer`, `action_envelope`, `ot_context`, `ad_context`, `tool_provenance`,
  `exploit_descriptor`.
- PRESENT as Codex says: CVSS v3.1 (`report.py` `_FAMILY_CVSS` + `cvss31_base_score()`),
  `wstg_catalog.py` (honest coverage), `asset_graph.py` (provenance/confidence/decay/next-best),
  `technique_model.py` (proof contracts + negative controls), `cloud_intel.py`/`cloud_iam.py`,
  `graphql_tool`/`jwt_tool`/`oauth_tool`/`authz_matrix`, `modbus_audit_tool`/`enip_audit_tool`
  (read-only ICS rails).

## Queue (Codex priority tiers)

### Tier 1 — highest value, lowest risk
1. `agent/asvs_model.py` — ASVS 5 objective model (verification-requirements, not vuln taxonomy).
   Curated partial seed only; never claim full ASVS import without official JSON. Verified/attempted/
   failed/not_tested/not_applicable/blocked per objective; findings map to violated requirements;
   clean attempted checks can mark objectives verified; blocked != passed.
2. `agent/sarif_io.py` — SARIF import/export boundary. Import → `candidate` (needs runtime proof),
   never auto-confirmed; export atomic findings only (never chains). Preserve producer fingerprint +
   suppression metadata (not blindly trusted); redact secret snippets.
3. `agent/defense_mapping.py` — curated finding→control mapping (family/CWE → defensive controls +
   what capability they reduce). Honest provenance ("curated", not official D3FEND IDs). Unknown
   family → no fake mapping.
4. `agent/cloud_policy.py` — first-class provider-policy/authorization object that GATES cloud
   actions pre-execution (provider, tenant/subscription/account/project IDs, regions, allowed/
   requires-approval/prohibited actions, notification). Prohibited wins over allowed.
5. Current-status docs/ledger correction.

### Tier 2 — strong architecture upgrades
6. `agent/cvss4.py` — CVSS v4 atomic scoring, PARALLEL to v3.1 (store both). CVSS scores atomic
   findings only; chains stay Apolaki impact-path severity, never a CVSS vector.
7. `agent/graph_export.py` — sanitized OpenGraph/BloodHound-style export. Namespaced node kinds; no
   raw secrets/cookies/Authorization; distinguish topology edges from capability-bearing edges;
   capability edges carry precondition + resulting capability; temporary edges expire.
8. `agent/api_protocols.py` — SOAP/WSDL/gRPC inventory (beyond REST/OpenAPI/GraphQL). Inventory only;
   route SOAP XML body sinks to existing XXE logic under existing safety rails; no vuln from
   inventory alone; reject off-scope WSDL service URLs.
9. `agent/field_authz.py` — field-level authz / excessive-data-exposure diffing across personas
   (distinct from BOLA). Conservative sensitive-field markers; redact raw secret values; lead unless
   clear role expectation/differential proof.
10. `agent/api_inventory.py` — API drift/version governance (runtime vs OpenAPI vs archived vs
    code-discovered). Mostly observations/leads, not vulns.

### Tier 3 — requires more integration
11. `agent/action_envelope.py` — durable idempotent action envelope every side-effecting tool carries
    (mission/action id, permission, scope_hash, input_hash, idempotency_key, approval). Changed scope
    invalidates prior approval; intrusive w/o approval rejected; no raw secrets in envelope.
12. `agent/ot_context.py` — OT/ICS zone + process-impact modeling (Purdue level, EWS/HMI/SCADA/PLC,
    criticality). Impact stays "potential" until operator context. Any `ot_write` pack rejected by
    default; future DNP3/OPC/Profinet must declare safety class before planner routes.
13. `agent/ad_context.py` — AD/Kerberos/ADCS frontier MODELED (read-only inventory) before exploited;
    everything beyond read-only blocked until a lab exists.
14. `agent/tool_provenance.py` — per external-tool-execution provenance (binary path/version, argv
    hash, timeout, exit code, parser version, input/output hashes, scope hash, permission class).
15. `agent/exploit_descriptor.py` — exploit-module taxonomy WITHOUT reckless execution. Destructive/
    unknown side effects blocked unless lab-only + approved; descriptor enriches planning, does not
    enable execution.

### Tier 4 — environment-gated (do NOT build live without creds+scope+policy)
16. Live AWS/Azure/GCP collectors. 17. Kerberos/ADCS authenticated domain assessment.
18. SAML/OIDC IdP assessment. 19. OT protocols beyond read-only fingerprint. 20. Durable
    Temporal-style orchestration.

## Codex's 15 direct questions (answer with evidence as each area is built)
ASVS-verifiable-vs-WSTG-adjacent; implemented-but-not-surfaced; SARIF-exportable findings; findings
needing control mapping; v3.1 assumptions v4 models better; topology-vs-capability edges; cloud actions
gated by creds-only vs needing policy; API protocols invisible to planner; field-level vs BOLA;
OT impacts needing operator context; AD gated-vs-should-be-read-only-inventory; tool outputs lacking
parser/version provenance; report sections saying "found" but not "verified cleanly"; helper-only tests
vs mission integration; stale docs that would mislead an operator.

## Standing rails (unchanged)
Deterministic-first. No DoS. No credential brute loops. Scope + HITL in front. Secrets vaulted/
redacted, never raw. Intel/SARIF stays candidate until runtime-validated; never auto-promote to
production skills. ICS/cloud stays read-only until policy+lab+creds. Report only reproduced numbers.

## Build log (Claude)
- 2026-08-06: queue persisted; existence claims verified. Building Tier-1 top-down.
- 2026-08-06: **Tier-1 COMPLETE + baked** (image apolaki-agent rebuilt, recreated, endpoints verified).
  - #1 ASVS-5 curated-partial objective model — `asvs_model.py`, report "## ASVS Objective Coverage",
    `GET /coverage/asvs?session=`. Caught+fixed an over-claim bug. (9df9121)
  - #2 SARIF 2.1.0 boundary — `sarif_io.py`, `GET /mission/{sid}/sarif`, `POST /intel/sarif`. Import→
    candidate (never confirmed); export atomic-only; order-stable fingerprints; suppression preserved-not-
    trusted; secrets redacted. (f62c056)
  - #3 curated defensive-control (D3FEND-like) mapping — `defense_mapping.py`, per-finding "Defensive
    Controls" report block, `GET /intel/defenses`. 24 families; unknown→no fake mapping. (e89e321)
  - #4 cloud provider-policy GATE — `cloud_policy.py`, `cloud_iam.collect()` live-path gate, `GET
    /cloud/policy`. Default read-only (Linode flow preserved); writes/active/destructive default-denied;
    prohibited wins; notification/approval/region/provider scope enforced. (7fc0d72)
  - #5 docs/ledger correction = this queue doc + memory [[apolaki-codex-crosscheck-queue]].
  - +37 tests, full suite 903 passed / 0 failed (container 3.12; no f-strings-with-backslash → 3.11-safe).
- 2026-08-06: **Tier-2 COMPLETE** — #6 cvss4 (373d1ff), #7 graph_export (e1b2c92), #8 api_protocols
  (9089c3f), #9 field_authz (cd76b66), #10 api_inventory (d6dd051).
- 2026-08-06: **Tier-3 COMPLETE** — #11 action_envelope (d2b8a66), #12 ot_context (6670414),
  #13 ad_context (40443f4), #14 tool_provenance (d98d0d3), #15 exploit_descriptor (bc08d0a).
- 2026-08-06: **ALL 15 buildable items DONE + baked.** 14 new modules, 12 new endpoints, +80 tests, full
  suite **980 passed / 0 failed** on the freshly-baked image (all 12 endpoints verified from the image).
  - Tier-4 (#16-20: live AWS/Azure/GCP collectors, Kerberos/ADCS authed, SAML/OIDC IdP, more OT protocols,
    Temporal) is ENVIRONMENT-GATED by Codex's own rule ("do NOT build live without creds+scope+policy") —
    deferred by design, not actionable without a lab/creds. The read-only frontier models for AD (#13) and
    OT (#12) already stand in front of them.
  - **BAKE GOTCHA (caught here):** `docker compose build agent` (no `--no-cache`) reused the `COPY *.py .`
    layer even though .py files changed → the image silently lacked the new endpoints while `docker cp` +
    restart made tests pass. Fix: `docker compose build --no-cache agent`, then `up -d --force-recreate`,
    then verify a NEW endpoint answers from the recreated container (not just that pytest passes).
- Adoption follow-ons (Codex "requires more integration", modules+contracts landed, deeper wiring later):
  action_envelope + tool_provenance into each side-effecting tools.py wrapper; field_authz into authz_matrix;
  exploit_descriptor into the #112 ExploitDB feed.
