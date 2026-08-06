# Apolaki Resource-Absorption Ledger

Durable execution ledger for the full-session resource-absorption mission. Survives context
compaction: read this top-to-bottom to resume. **Honest by construction** — a resource is only
marked READ when actually read cover-relevant, not skimmed; a feature is only DONE when
code + integration + test + bake + evidence all exist.

- **Repo:** `C:\Users\voice\Desktop\GitHub\MISC\apolaki` (git root is parent `MISC`; apolaki subtree clean).
- **Resources:** `C:\Users\voice\Desktop\GitHub\Resources` — 35 files, 65 MB (27 .txt, 6 .pdf, 2 .md).
- **Container:** `apolaki-agent-1` (py3.12). CI parity = py3.11. Bake = `docker compose build agent`.
- **Ship gate:** orchestration (no islands) → absorption (techniques.py) → UI → QA (pytest green) → bake → commit.
- **Guardrails:** deterministic-first; oracle decides, LLM advises; no DoS; no credential brute; read-only OT;
  scope+HITL in front; secrets vaulted/redacted; ExploitDB index-only.

## Baseline (start of mission — 2026-08-05)
- Branch `main`, HEAD `512740b` (parallel beyond-web service-pack execution, #110 slice).
- Container healthy; lab fleet up: juice-shop, dvwa, mutillidae, bwapp, vampi, dvga, openldap, smb, snmpd, zap, mitmproxy, headless-chrome.
- agent/: 124 .py modules, 93 test files. **Baseline pytest: 812 passed, 0 fail/err (green).**
- Architecture (from ARCHITECTURE_AUDIT.md): UI → main.py(API) → agent.py → planner(technique_planner/advisor)
  → tools.py(transport) → capture/db(evidence) → memory/db → report.py. Canonical brain = `asset_graph.AssetGraph`
  (planner-authoritative, provenance+confidence+first/last_seen+tested per node). Unified view = `attack_graph.build`.
  Cross-run memory = `attack_chain.py` (append-only per-target ledger).

## Resource inventory + read-status
Legend: [DONE-prior]=distilled in earlier sessions (#88-96); [READ]=read this mission; [PARTIAL]; [QUEUED]; [LOW]=marketing/low-yield; [EMPTY].

| File | MB | Status | Notes |
|------|----|--------|-------|
| Redefining Hacking (AI-driven RT/BBH) | 0.88 | DONE-prior | #88/#94 LLM prompt-injection + web |
| Beginner_WebApp_Pentester_Book.md | 0.56 | DONE-prior | #89/#92 web techniques |
| Pentesting APIs.txt | 0.48 | DONE-prior | #90/#93 API techniques |
| Black Hat Python.txt | 0.36 | DONE-prior | #91/#95 |
| Pentesting Azure Applications.txt | 0.39 | DONE-prior | #91/#95 cloud |
| Bash Shell Scripting.txt | 0.64 | DONE-prior | #96 honest-yield |
| Metasploit Revealed.txt | 0.29 | DONE-prior | #96 |
| Pentesting Active Directory...txt | 0.44 | DONE-prior | #96 AD |
| Pentesting Industrial Control Systems.txt | 0.44 | DONE-prior | #96 ICS (Modbus engine shipped) |
| The Web Application Hacker's Handbook 2e.txt | 1.72 | QUEUED | classic, high yield, unread |
| RedCyber_Book.md | 29.28 | QUEUED | huge; targeted read |
| Web-Application-Hacking-Security-Program-WAHS.pdf | 18.94 | QUEUED | huge PDF |
| Web Application Security 2e.txt | 0.72 | QUEUED | |
| Grokking Web Application Security.txt | 0.44 | QUEUED | |
| Web Penetration Testing with Kali Linux 3e.txt | 0.40 | QUEUED | |
| Advanced Infrastructure Penetration Testing.txt | 0.48 | QUEUED | network/infra |
| Cloud Penetration Testing.txt | 0.53 | PARTIAL | targeted extraction (storage/metadata/snapshot) — see notes |
| Red Team Engineering.txt | 0.62 | QUEUED | |
| Evasion Engineering.txt | 0.37 | QUEUED | #113 evasion |
| Cybersecurity Attacks- Red Team Strategies.txt | 0.67 | QUEUED | |
| Mastering Kali Linux 4e.txt | 0.66 | QUEUED | |
| Advanced WAF Evasion & Parameter Exploitation TTPs.txt | 0.01 | READ | ~fully absorbed (see notes) |
| The Advanced Adversary's Playbook.txt | 0.01 | READ | ~fully absorbed (see notes) |
| Comprehensive Offensive Security Blueprint.txt | 0.01 | READ | ~fully absorbed (see notes) |
| BBH_Bootcamp.txt | 0.68 | QUEUED | |
| Threat Modeling Best Practices.txt | 0.57 | QUEUED | |
| Tribe of Hackers Red Team.txt | 0.83 | QUEUED | interviews, low-mid yield |
| SEC660_AdvancePentest_Syllabus.txt | 0.02 | QUEUED | syllabus only |
| Bug_Chaining.txt | 0 | EMPTY | 0 bytes |
| The_Bug_Hunters_Methodology.txt | 0 | EMPTY | 0 bytes |
| CPENT-brochure.pdf | 2.75 | LOW | marketing |
| SANS SEC522/542/560/587 brochures.pdf | ~0.9 | LOW | marketing |

## Plan (phases)
- P0 baseline+inventory+ledger — **in progress** (this file).
- P1 extraction — targeted reads of QUEUED high-yield, structured TTP notes in scratchpad `book_read_notes.md`.
- P2 knowledge model — enrich technique schema (#115 Nuclei fields).
- P3-P5 integration — highest-value vertical slices, each fully wired (graph/planner/report/UI/test).
- Landing order: **#116 utility+decay (attack-planning keystone)** → #115 schema → #117 retest → new engines from reads.

## Extraction notes (technique-level, deduped, provenance kept)
- **WAF-Evasion TTPs / Adversary Playbook / Offensive Blueprint (3 tiny files, READ):** dense
  methodology overviews; ~everything is ALREADY implemented in Apolaki. Verified against source:
  - WAF inspection-ceiling padding ("10,000 A" / 8-16KB) → `waf_bypass_tool.py` (raw-blocked vs
    padded-not-blocked-and-reflects differential oracle). ALREADY BUILT.
  - JWT alg confusion (RSA→HMAC) + alg:none → `jwt_tool.py` (`_ASYM_ALGS`, `forge_none`). ALREADY BUILT.
  - Open-redirect backslash/@-userinfo/host-suffix bypass → `web_security.py` + `oauth_tool.py`. BUILT.
  - Keyword-reassembly-via-stripping, look-alike Unicode → covered by `encoding_probe.py`/waf_bypass.
  - Recon (crt.sh CT, ASN→prefix, S3, GitHub, dorks, Arjun params, 403-vs-404) → dns_recon/github_recon/
    dorks/param_discovery; ASN→prefix + favicon-hash remain #114. HONEST NEW-ENGINE YIELD: 0.
  - STRUCTURAL find: technique registry had no machine-readable proof contract → became #115 (below).

- **Cloud Penetration Testing (PARTIAL — targeted extraction, not full cover-to-cover):** book
  centers on storage exposure (S3/blob), ACLs, metadata, snapshots. Verified against Apolaki:
  provider fingerprint + public-storage URL recognition + **public bucket-listing oracle**
  (ListBucketResult/EnumerationResults 200 signature) live in `cloud_intel.py`; Linode/Azure ACL
  public-access in `cloud_iam.py`; SSRF→cloud-metadata (169.254.169.254) in `ssrf_tool`. Remaining
  book emphasis (public EBS/RDS snapshots, fine-grained ACL audit) needs AUTHENTICATED cloud-API
  access + real cloud creds → genuinely #106, correctly gated on the user's cloud material. New
  deterministic engine validatable against LOCAL labs: none.

## Emerging pattern (honest, for the final audit)
Apolaki's DETERMINISTIC web/API/infra core is **mature** — the read TTP/methodology resources map
almost entirely onto already-implemented engines (WAF-evasion, JWT confusion, open-redirect bypass,
bucket-listing oracle all pre-built). The genuine remaining frontier is **external-environment-gated**:
cloud-authenticated checks (#106, needs creds), AD/Kerberos (#105, needs a DC lab), SAML (#109, needs an
IdP), WAF-padding proof (needs WAF+vuln lab). Highest-value work I CAN complete now is the
**architectural force-multipliers** the competitive analysis + this mission both identify as Apolaki's
edge — DONE this session: #116 (utility attack-paths + decay) and #115 (executable-knowledge contract).

## OpTest (live mission, Phase 8)
- **VAmPI** (`vampi:5000`, deterministic full mode) — mission `10b07231`, completed in 276s, exit clean.
  - Findings: **2, both CONFIRMED** — critical `exposure` (sensitive data/credentials via /users/v1/_debug),
    medium `exposure` (API schema exposed). No false positives observed. Canonical graph: 25 nodes, 24 edges.
  - `next_best_actions=0` — CORRECT for this target (exposure findings map to no capability-enable; no
    object/service nodes to rank). Populated utility ranking proven separately (baked-image + unit tests).
  - Report renders the evidence-graded business impact LIVE (demonstrated/plausible/unverified, fenced
    "do NOT claim without further evidence").
  - **Discovered improvement (future):** an exposed-CREDENTIALS finding should chain to `credential_material`
    so the planner chases try-login; needs CONTENT-aware enables (title/body signal), not a blunt
    family→capability map (would mis-fire on schema-exposure). Not forced this session (avoids false paths).
- Orchestration audit: **0 islands** (39 gated + 25 always-on), `no_islands=True`.

## Session completion status (honest, by phase)
- P0 baseline/inventory/ledger: **100%**. P1 extraction: **~15%** of the corpus read (3 TTP files fully +
  cloud targeted; WAHH/RedCyber/WAHS/Grokking/RedTeam/Evasion/AdvInfra/etc. UNREAD — see table).
  P2 knowledge-model: **100%** of the planned slice (#115). P3-5 integration/planner: **#116 shipped**;
  broader HTN/behavior-tree NOT built (existing planner+graph deemed sufficient; not re-architected).
  P6 reporting/business-impact: **grading shipped**; HTML-report rendering of the graded block + per-finding
  negative-control from the #115 contract NOT yet wired (MD report only). P7 UI: not touched this session
  (API surfaces verified; no new UI tab). P8 QA/OpTest: full suite green + 1 live mission + orchestration audit.
- Net new this session: 3 integrated+validated capabilities (#116, #115, Phase-6 grading), all baked, tested,
  committed, and (for #116 + grading) live-verified. Baseline 812 -> 823 tests.

## Exact remaining work (prioritized, for continuation)
1. Wire the #115 proof-contract + #116 utility into the HTML report + UI Intel tab (MD + API done).
2. Content-aware finding `enables` (exposed-credentials -> credential_material) so #116 produces attack-paths
   on exposure findings (guard against false paths; add a test).
3. #117 retest/closure loop (Picus): per-family confirming-signal replay — needs findings to persist a
   replay recipe + oracle id; scoped, not started.
4. Read the large unread books (WAHH 2e, RedCyber 29MB, WAHS PDF, Grokking, Red Team Engineering, Evasion
   Engineering, Advanced Infra) in targeted passes; expect low NEW-engine yield (mature core) but verify.
5. External-env-gated frontier (own tasks, need environments): #106 cloud-authed, #105 Kerberos, #109 SAML,
   #113 WAF-padding live proof, #114 ASN/favicon recon.

## Continuation commands
```
cd C:/Users/voice/Desktop/GitHub/MISC/apolaki
docker compose up -d --no-deps agent && curl -s localhost:8000/health
docker exec apolaki-agent-1 sh -c "cd /app && python -m pytest -q -p no:warnings --junitxml=/tmp/j.xml"   # 823 green
# live mission:  docker cp <driver> apolaki-agent-1:/tmp/optest.py && docker exec apolaki-agent-1 python /tmp/optest.py juice-shop:3000
# bake after edits: docker compose build agent && docker compose up -d --no-deps agent
```

## Change log (append-only)
- 2026-08-05: **SLICE 3 shipped (evidence-aware business-impact grading, Phase 6).** `report.py`
  `graded_business_impact()` — per-family DEMONSTRATED (oracle-gated) / PLAUSIBLE next-step / UNVERIFIED
  worst-case (fenced "do NOT claim") + confidence + assumptions; 17 families, reuses business_impact()'s
  family/CWE resolution; grades DOWN so a report never overclaims. Rendered in the finding detail.
  Test `test_report_business_impact.py` (+5, incl. a never-overclaim guard). 823 tests, 0 fail. Baked;
  verified LIVE on the VAmPI report. Files: report.py, tests/test_report_business_impact.py.
- 2026-08-05: **SLICE 2 shipped (#115 executable-knowledge proof contract).** Added first-class
  `negative_control` / `evidence_requirements` / `replayable` / `safety` / `cleanup` to the canonical
  Technique schema (`technique_model.py`) + `proof_contract()` deriving them deterministically from
  vuln_class + oracle (class-specific FP-safety differentials for 30+ families; per-record override).
  `techniques._t()` attaches the contract to all 65 records; `from_registry` surfaces it on the model.
  Guard test `test_technique_contract.py` (+4) enforces every proven technique declares a real
  differential + >=2 evidence items. Wired: `/intel/techniques` serves the contract (53 techniques
  live-verified — ssrf shows OOB-correlation evidence, operator-gated safety). 818 tests, 0 fail.
  Baked + recreated + health 200. Files: technique_model.py, techniques.py, tests/test_technique_contract.py.
- 2026-08-05: P0 started. Inventory + baseline (812 green) + architecture map done. Ledger created.
- 2026-08-05: **SLICE 1 shipped (#116 attack-planning keystone).** Pentera utility scoring + Cosmos
  temporal confidence-decay in `asset_graph.py`: `decay_factor()`, `utility_score()`,
  `decayed_confidence()` (tested facts hold, unverified facts decay by 14d half-life to CONF_FLOOR),
  and `next_best_actions()` now ranks by utility = P(success)·impact·evidence_conf ÷ cost ÷ risk with
  the factor breakdown attached (inspectable, no black box). Wired: `/graph/{sid}` serves it (UI graph
  tab), `main._record_orchestration` snapshots `attack_paths` into report ctx, `report.py` renders a
  utility-ranked Attack-Path Opportunities table. Tests +2 (814 total, 0 fail). Baked + recreated +
  health 200; deployed-image proof: ranked chase 0.72 > service 0.15 > object 0.10, JSON-serializable.
  Files: asset_graph.py, main.py, report.py, tests/test_asset_graph.py, docs/ledger.
