# Codex technology-intelligence audit — verification pass

External read-only audit received 2026-08-10. **Treated as evidence, not as truth.** Codex ran
nothing (its own disclaimer), so every runtime claim is `CANNOT_VERIFY_STATICALLY` until measured.

This file holds the Coordinator's own verification of the load-bearing claims. The Analyst's full
claim-by-claim pass lands in [QUEUE.md](QUEUE.md). Baseline it was checked against:
[TECH_PIPELINE_BASELINE.md](TECH_PIPELINE_BASELINE.md), measured before the audit arrived.

---

## Verdicts — verified by the Coordinator, MEASURED

### 1. CONFIRMED · SCA emits `confidence="confirmed"` without reachability · **CRITICAL**
`agent/dependency_intel.py:210` `vulnerable_component_finding()` sets `"confidence": CONFIRMED`
while its own `impact` string says exploitability "was NOT confirmed in this test" and its
`success_oracle` says "presence-confirmed; reachability not proven".

**Correction to Codex's framing, in the producer's favour:** it is *not* naive. It deliberately caps
severity at MEDIUM — `sev = "medium" if order.get(worst, 0) > order["medium"] else worst` — with a
comment naming "the scanner-inflation pattern" as the thing it is avoiding. Someone thought about
this. The defect is narrower and more interesting than "it overclaims": **the machine-readable field
contradicts the human prose beside it, and every consumer reads the field.**

Root cause, exactly as Codex states it: `confidence` conflates *"we are sure the served version is
X"* with *"we are sure this is exploitable"*. Two different questions, one word. This is the same
defect family as the report badge fixed in `707b3b9` — a surface disagreeing with the gate — and it
is the reason Q-021A must land before anything else in the Q-021 family.

### 2. CONFIRMED · the proof gate never inspects SCA findings
`agent/proof_schema.py:138` — `_DEFAULT_ENFORCE = ("idor", "access_control", "missing_authentication",
"bola_idor", "bfla")`. `vulnerable_component` is absent, so `demote_unproven` passes it straight
through unless `APOLAKI_ENFORCE_PROOF=all`. Claim 1 therefore reaches the client report intact.
The narrow default was a deliberate no-new-false-negatives choice (see the comment at `:136`), which
makes this a *sequencing* decision to revisit, not a bug someone missed.

### 3. CONFIRMED · retest cannot tell "patched" from "still there"
`agent/retest.py` `_GET_ORACLE` maps `"vulnerable_component": "reachable"`. Any patched replacement
that still returns a non-empty 2xx keeps the finding `OPEN`. A remediation-status lie is worse than a
missing feature: the client fixed it and we tell them they did not.

### 4. CONFIRMED, with the mechanism corrected · SCA findings silently miss KEV
Codex said KEV matching reads "structured fields/evidence". It does read evidence — `report.py:2348`
builds its blob from `f.get("cve")`, `f.get("cves")` **and** `f.get("evidence")`, then regex-extracts
CVE IDs. The SCA finding still misses, for a narrower reason: its CVE IDs live in `title` and
`description`, while its `evidence` is `"{comp}@{ver} from {source}: ..."` and contains no CVE. So
the claim holds; the stated cause does not. Fix by emitting a structured `cves` list, not by widening
the regex to scrape titles.

### 5. CONFIRMED but MIS-SCOPED · two competing key names for the same concept
Codex framed `success_oracle` vs `oracle` as one SCA producer/consumer mismatch. Measured, it is a
platform-wide vocabulary split:

| fact | count |
|---|---|
| modules mentioning `success_oracle` | **38** |
| sites writing a plain `"oracle"` key | **78** |
| `poc_bundle.py:119,137` reads | `oracle` **only** |
| `report.py:1696` reads | `success_oracle` **only** |

The two consumers disagree *with each other*. **Do not restate this as "the PoC bundle's oracle is
always empty"** — that would be wrong, since 78 sites do write `oracle`. The correct statement is
that every finding family whose producer chose `success_oracle` reaches the PoC bundle with an empty
oracle, and every family that chose `oracle` is invisible to the report's has-an-oracle check. Sizing
which families fall in which bucket is assigned to the Analyst.

---

## Claims accepted on their merits (consistent with the pre-audit baseline)

Absent, and the baseline independently found them absent: canonical identity (CPE/PURL) · ecosystem
version-range semantics · applicability validation including backported patches · a
`vulnerable_component` route in `candidate_pipeline._ROUTES` · technology-conditioned planner
behaviour · detection evidence · lifecycle exposure in UI/API/report/SARIF/PoC · WPScan/OSV feeds.

## Capabilities to PRESERVE — must not be rebuilt

Codex and the baseline agree, so these are settled: the `fingerprint` signature adapters (and it
**does run** — `planner.py:233` schedules it per live host; any claim that fingerprinting is missing
is false) · `dependency_intel`'s `CONFIRMED/HIGH/LOW` ladder with `CVE_ELIGIBLE` · the governed
source allowlist, audit trail and cache · exact-CVE-only KEV logic (never inferred from CWE) ·
ExploitDB's product-version-as-lead distinction · `intel_registry`'s staged trust model · the
canonical-graph provenance API · the central findings gate · and **the cloud pattern —
detection → bounded probe → content-signature oracle** (`cloud_intel.py:46` → `agent.py:1515` →
`tools.py:2606`), which Codex correctly identifies as the reusable proof-safe template. Q-021E should
copy that shape rather than invent one.

## One claim to note as unfalsifiable-by-design

"No repository code mentions Neocities. There is no repository basis for calling Neocities, or any
hosting-platform match, vulnerable." Correct, and it is the whole point of the proof rule: platform
detection creates a lead. Nothing to build here — it is a constraint to keep holding.

---

## Dependency order

```
Q-021A  contain the SCA proof overclaim        CRITICAL  no dependencies — ship first
   |
Q-019   the funnel (2756 discovered / 36 probed)  CRITICAL  in flight
   |
Q-021B  persist canonical TechnologyFacts        depends on Q-019
   |
Q-021C  identity, ranges, applicability          depends on Q-021B
   |
Q-021D  connect governed feeds to components     depends on Q-021C + feed review
   |
Q-021E  technology drives safe orchestration     depends on Q-019 + B/C/D
   |
Q-021F  expose the lifecycle honestly            depends on B-E
```

**Q-021A jumps the queue ahead of Q-019.** Codex is right that truth containment has no
dependencies, and it is the only item here that is actively shipping a false claim to a client
today. Everything else is a missing capability; this one is a wrong answer.

## First implementation-ready ticket

**Q-021A.** Its oracle is a CVE-specific behaviour differential; its negative control is a
structurally identical request with the trigger absent, plus a patched same-URL response that must
NOT remain `OPEN`. Note for whoever takes it: `agent/tests/test_bbh.py:1844` currently *asserts* that
SCA is confirmed. Changing it is **correcting a wrong expectation, not weakening a test** — but that
distinction must be argued in the commit message, because "the test changed" is exactly what
weakening looks like from the outside.
