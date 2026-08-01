# Apolaki Architecture Audit — real-wiring trace + reordered plan

**Date:** 2026-08-01 · **Method:** traced live execution `UI → API (main.py) → agent (agent.py)
→ planner (technique_planner/advisor) → tools (tools.py transport) → evidence (capture/db) →
memory (memory.py/db) → report (report.py)`. Claims below are checked against source, not the
README. Every verdict cites `file:line`.

This audit answers a request to push Apolaki past web scanning into a fuller autonomous pentest
platform. Conclusion up front: **the deterministic proof-first core is real and healthy; the
biggest true gap is autonomous multi-identity access-control testing.** Two concrete defects were
found and fixed this pass. The proposed roadmap is sound but mis-ordered — lead with proof-creating
work (personas + asset graph), defer platform hardening.

---

## 1. Verdicts on the 11 suspected gaps

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | Workflow header extraction wired with empty header map | **CONFIRMED → FIXED** | `workflow.py:142` passed `{}` to `_extract`; the `header` rule (`workflow.py:93`) reads exactly that dict, so it could never fire. Now reads `headers` from the shaped step output. |
| 2 | Path-level scope lost when entries become host-only | **CONFIRMED → FIXED** | `scope.py` `_split_scope_entry` dropped the path; `ScopeEntry` had no path field; `to_rules()` emitted bare host. Downstream `web_security.is_url_in_scope` was already path-aware (`web_security.py:127-150`) but starved. Added SEC-2: path preserved, enforced in `validate()`, emitted as a full-URL identifier. |
| 3 | Auth/session secrets lack an encrypted vault | **CONFIRMED (real, deferred)** | `tools.py:1365` `self._sessions[role]` is an in-memory dict of raw auth headers. Tokens are kept out of model view (`_shape_response` redacts Set-Cookie/Authorization, `tools.py:1237`) but not encrypted at rest. Hardening item → Phase 5. |
| 4 | Technique knowledge and executable workflows not fully connected | **CONFIRMED (real, highest-value)** | Knowledge model is large (597 techniques in the Intel tab; `techniques.py` 570 lines + planner + advisor feed the plan). But **executable** workflow packs (`workflow.py` + `packs.py` 88 lines) are a handful. Catalogued-technique → runnable-workflow is mostly not wired. This is the capability-orchestration gap. |
| 5 | Workflow-pack library is tiny vs scanner coverage | **CONFIRMED** | `packs.py` is 88 lines; scanners span dozens of `*_tool.py`. True. |
| 6 | "Continuous learning" is confirmation-rate weighting, not strategy learning | **CONFIRMED (honest labeling)** | `learning.py` is 46 lines; the Intel tab shows per-class "Learned reliability" (sqli 100%…). It is reliability weighting, as claimed — and labeled as such, not oversold. Low priority. |
| 7 | In-memory sessions + SQLite limit multi-worker | **CONFIRMED (architectural)** | `db.py` is SQLite (252 lines); running missions live in-process. True limit for multi-worker/multi-user → Phase 5. |
| 8 | Report counts / leads / attack-chain may not use one canonical source | **VERIFIED GOOD** | Findings come from `db.get_findings(session_id)` **everywhere** (`main.py:526,1054,1070,1175,1374,1386,1407`); leads from `context.leads`; attack-chain from its own per-target store. Each quantity is single-sourced; they are intentionally different quantities, not one number. |
| 9 | Every advertised UI capability reaches real backend | **MOSTLY GOOD** | Full UI optest this session drove all 9 tabs: all render, **0 console errors**, real data (Conquest 101/113, Intel 597 techniques, Proxy 500 live flows, Code Review 21 endpoints/44 routes). Advertised surfaces reach the backend. |
| 10 | Optional services detected by health, not just env vars | **MOSTLY GOOD** | Proxy tab shows live "Active · 500 flows"; transport degrades to labelled-empty when `PROXY_URL`/ZAP unreachable (health-based, not mere config). Worth a formal health-probe pass in Phase 4. |
| 11 | Lab knowledge kept separate from the general engine | **VERIFIED GOOD** | `juiceshop_solvers.py` / `bwapp_solvers.py` / `mutillidae_solvers.py` are isolated; the general engine carries generalized techniques with `validated_on` labels. Lab-specific `_register` lives only in `juiceshop_solvers.py`. Clean separation. |

**Score: 2 confirmed defects (both fixed), 4 real gaps (personas, workflow-execution library,
vault, multi-worker), 5 healthy.** The suspicions were well-aimed — but the platform is in better
shape than "fake autonomy" framing implies. The confirmation-oracle discipline is genuine.

---

## 2. The single biggest capability gap

**Apolaki cannot autonomously produce access-control findings on a novel target** — the #1
real-world web-vuln class (PortSwigger/OWASP access-control). The parts exist but aren't driven:

- **Have:** multi-role session storage (`tools.py:1365` `_sessions[role]`), an owner-vs-attacker
  differential-authz confirm primitive (`tools.py:1439-1506`), a victim/attacker pack
  (`packs.py:25`), identity metadata with `is_admin` (`investigation.py:48` `add_identity`).
- **Missing:** (a) autonomous **registration** to mint User A / User B on an arbitrary target —
  `auth.py:120` only *detects* register forms in order to *avoid* them; `_register` in
  `juiceshop_solvers.py` is lab-specific. (b) The scan (`BBHAgent`) acquires **one** identity and
  never runs owner-vs-attacker across discovered objects.

Net: the differential-authz engine is a loaded gun with no trigger. Wiring a persona manager +
autonomous registration + a two-user matrix is the highest-ROI next build, and it directly reuses
what's already there.

---

## 3. Pushback on the proposed order (question authority)

The proposed phases are individually good; the sequencing buries the proof-creating work behind
plumbing. Reordered:

- **Reorder graph before beyond-web.** The canonical asset/intelligence graph (proposed Phase 2)
  must precede protocol/cloud/archive connectors (proposed Phase 3/section 5) — otherwise the
  connectors dump into disconnected tables, the exact failure the proposal itself warns against.
  Seeds already exist: `graph_model.py` (148) + `attack_graph.py` (55). Extend those into the one
  canonical store, *then* route service fingerprints into it.
- **Defer the multi-user platform (section 8): Postgres, object storage, worker queue, RBAC,
  vault.** Biggest effort, least *new proof*. Apolaki is a single-operator deterministic tool
  today; multi-tenant hardening is a product decision, not a capability gap. Last phase, and only
  if Apolaki actually goes multi-user.
- **Gate beyond-web behind the pattern, not a scanner pile.** Each service pack must:
  `fingerprint → activate matching technique pack → feed the SAME world model → deterministic
  oracle`. Prove the pattern with DNS (`dns_recon.py` already seeded) + one more before opening the
  full FTP/SSH/SMB/SNMP/SMTP/k8s menu.
- **Keep the crown jewel:** LLM proposes/prioritizes hypotheses; deterministic oracles decide
  proof. Do not let expansion dilute confirmation discipline. (Agreed with the proposal here.)

---

## 4. Recommended execution order

| Phase | What | Why now | Acceptance (deterministic) |
|-------|------|---------|-----------------------------|
| **P1** | **Identity/Persona Manager + autonomous registration + two-user authorization matrix.** Plus the SEC-2 scope + header fixes (**DONE** — they de-risk registration & path-scoped bounty). | Highest ROI; creates a whole new *proven* finding class; reuses `_sessions` + differential-authz. | On a lab with registration (Juice Shop) and a path-scoped target: mint User A & User B, run owner-vs-attacker across discovered objects, emit distinct horizontal / vertical / cross-tenant findings via the differential oracle. Bounded, no brute-force. |
| **P2** | **Canonical asset/intelligence graph** (extend `graph_model`). One node/edge store every phase reads+writes; each fact carries source, timestamp, confidence, scope-asset, enables, tested. Capability-driven planner queries it. | Everything downstream needs one world model; prevents disconnected tables. | Recon fact → graph node with provenance; planner selects next technique *from the graph*; report renders the graph. |
| **P3** | **Service fingerprint → technique-pack routing**, proven with DNS + one more, feeding the graph. | Proves the beyond-web pattern without a scanner pile. | A discovered non-HTTP service activates its pack, results land as graph nodes + oracle-gated findings. |
| **P4** | **Reproducible full-lab compose** (`make up/full-lab/reset-labs/health/versions`, pinned digests, auto lab init) + workflow-pack library expansion. | Fresh clone reproduces the environment; grows executable coverage (gap #4/#5). | `git clone && make full-lab` yields a healthy stack with seeded labs + health truthfully shown in UI. |
| **P5** | **Platform hardening** (encrypted vault, workers, Postgres option, RBAC). | Only if Apolaki goes multi-user. | — |

Every phase: acceptance criteria + deterministic tests + integration tests; preserve scope
enforcement, authorization gates, and truth-first confirmation; run full suite + lab benchmarks;
show measured before/after.

---

## 5. Shipped in this pass

- **SEC-2 path-aware scope** (`scope.py`): path-prefix preserved on `ScopeEntry`, enforced in
  `validate()` for concrete requests (bare-host recon unaffected), emitted as a full-URL identifier
  in `to_rules()` so `web_security` binds host+path with no cross-host bleed.
- **Workflow header extraction** (`workflow.py`): response headers now flow to the `header`
  extractor (registration/redirect flows need this).
- **Tests:** `tests/test_scope_path.py` (7) + `tests/test_workflow_headers.py` (3). Full suite
  **397 passed** (was 387). Baked into `apolaki-agent:latest`; container live, `/health` 200.
