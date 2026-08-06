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
| Cloud Penetration Testing.txt | 0.53 | QUEUED | #106 cloud |
| Red Team Engineering.txt | 0.62 | QUEUED | |
| Evasion Engineering.txt | 0.37 | QUEUED | #113 evasion |
| Cybersecurity Attacks- Red Team Strategies.txt | 0.67 | QUEUED | |
| Mastering Kali Linux 4e.txt | 0.66 | QUEUED | |
| Advanced WAF Evasion & Parameter Exploitation TTPs.txt | 0.01 | QUEUED | small, focused |
| The Advanced Adversary's Playbook.txt | 0.01 | QUEUED | small |
| Comprehensive Offensive Security Blueprint.txt | 0.01 | QUEUED | small |
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

## Change log (append-only)
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
