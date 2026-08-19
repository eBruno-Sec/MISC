# Q-078 — triage of the 27 entries Q-077 made visible

Lane: island-triage (Builder). Owns `agent/deadcode_gate.py`, `agent/tests/test_deadcode_gate.py`,
new tests of its own, and this file.

**Headline, MEASURED:** of the 27, **17 are REAL ISLANDS**, 9 have a caller that the qualified scan
cannot see by construction, and **1 is a genuine false positive of the resolver with a live production
caller** (`intel.harvest` at `agent/tools.py:1848`). Nobody may quote 27 as the island count, and
nobody may quote 0 either.

The ceiling stays at 37. After the resolver fix and the caller-named allowlist the honest count is
**51**, which is still above 37, so **the strict xfail stays pinned**. That is the full result, not a
failure: see [§6](#6-the-ratchet-arithmetic).

---

## 1. Apparatus, and its positive control

Three passes, all on a clean `git archive HEAD` snapshot so two live lanes editing the shared tree
cannot move the numbers underneath the measurement.

```
git archive HEAD apolaki | tar -x -C <snapshot>
docker run --rm -v "<snapshot>/apolaki/agent:/app:ro" -w /app apolaki-agent \
  python -c "import deadcode_gate as d; r=d.scan_qualified(); print(r['count'], len(r['newly_dead']))"
→ 61 27
```

1. **AST scan** (`scan_qualified`) over `agent/*.py` — production-only, already the gate's own view.
2. **Whole-repo text pass** over every file that is NOT a top-level `agent/*.py`: `agent/tests/`,
   `agent/tier3/`, `agent/rules/`, `scripts/`, `ui/`, `docker-compose.yml`, `Makefile`, Dockerfiles,
   `labs/`. A bare-name hit only counts when the file also names the defining module, otherwise it is
   a collision (`finding` is defined in ~30 modules).
3. **Receiver-resolved pass**: every `ast.Attribute`, `ast.Name` and whole string constant in
   production, printed WITH its receiver path — the pass that found the `self._intel_mod.harvest`
   caller the module-alias resolver cannot follow.

**POSITIVE CONTROL — and it caught a real blind apparatus.** The first run of pass 2 reported zero
hits outside `agent/`, which was true of the *reader*, not the tree: the snapshot had lost every
non-`agent/` directory between two commands, so `scripts/`, `ui/` and `docker-compose.yml` were never
opened. The pass now asserts before searching:

```python
MUST = ["docker-compose.yml", "scripts/liveness.sh", "ui/index.html", "Makefile",
        "agent/tests/test_deadcode_gate.py", "agent/Dockerfile"]
assert not [m for m in MUST if m not in texts]
assert "mitm_addon" in texts["docker-compose.yml"]
→ POSITIVE CONTROL OK: 516 files read
```

Every "no caller exists" verdict below was produced by a reader that had provably opened the places a
caller could hide. Without that assertion this document would have declared 27 islands with total
confidence and been wrong about ten of them.

---

## 2. A correction to Q-078's own brief

> "…while tests and `scripts/liveness.sh` call it."

**UNSUPPORTED — MEASURED FALSE.** `scripts/liveness.sh` is 16 lines and its only payload is
`docker exec … python liveness_run.py`. `agent/liveness_run.py` never imports `deadcode_gate`.

```
grep -rn "deadcode_gate" <snapshot> --exclude-dir=docs
→ agent/description_gate.py:8      (prose)
  agent/engine_descriptor.py:289   (a filename in a skip-set, not a call)
  agent/tests/test_deadcode_gate.py:13,222,434
  agent/tests/test_web_message_source.py:449  (prose)
  agent/tools.py:5946              (prose)
```

The only caller of any `deadcode_gate` entry point anywhere in the repository is
`agent/tests/test_deadcode_gate.py`. Same for `description_gate`: tests only. The verdict does not
change — pytest is a legitimate caller for a gate — but the cited evidence was wrong and a reader
checking `liveness.sh` would have found nothing and distrusted the whole entry.

**Second correction:** the xfail reason and `QUALIFIED_Q077_REVEALED`'s comment cite
`docker-compose.yml:419` for the mitmdump invocation. At HEAD that line is **399**; 419 is the line in
the uncommitted working copy. A line number into a file another lane is editing is already rot, which
is why the allowlist added by this ticket anchors on a *substring*, not a line, and resolves the line
at test time.

---

## 3. The 27, classified

Verdict key: **ISLAND** = no reference of any kind, anywhere, by anything.
**FRAMEWORK** = invoked by name from outside the Python corpus.
**RE-EXPORT** = reached through another module's public surface.
**HARNESS** = the function's product is a CI verdict; pytest is its scheduler and no mission path can
exist. **BLIND SPOT** = a real production caller the resolver cannot follow.

### 3.1 BLIND SPOT — 1 entry, and it is a false positive of the gate

| entry | caller | why the resolver missed it |
|---|---|---|
| `intel.harvest` | `agent/tools.py:1848` — `self._intel_mod.harvest(material, self.intel)` | the module object is stashed on an instance attribute at `agent/tools.py:1246` (`self._intel_mod = _intel`), so the reference resolves as `("self._intel_mod", "harvest")` and never matches the import alias `_intel` |

This is the live scoped-fetch harvest path — every fetched body is dispatched through it. It was never
dead. **Fixed in the resolver** (§5), not allowlisted: an allowlist entry would have recorded a lie.

### 3.2 FRAMEWORK — 2 entries

| entry | caller |
|---|---|
| `mitm_addon.request` | `docker-compose.yml:399` (HEAD) — `exec mitmdump … -s /addon/mitm_addon.py`; mitmproxy invokes addon hooks **by name**. The container mounts only this file (`./agent/mitm_addon.py:/addon/mitm_addon.py:ro`, line 403) and the module imports nothing from Apolaki by design. |
| `mitm_addon.response` | same |

No Python in `agent/` calls these and none should — a caller would mean the addon was being driven
in-process, which is not how the sidecar works.

### 3.3 RE-EXPORT — 1 entry

| entry | caller |
|---|---|
| `sqli_tool.is_inconclusive` | `agent/nosqli_tool.py:35` — `from sqli_tool import INCONCLUSIVE_TOKEN, Inconclusive, is_inconclusive` |

The gate's rule that "an import binds a name, it does not use it" is right for an ordinary import and
wrong for a re-export, where the import **is** the use: it publishes the symbol on `nosqli_tool`'s
surface. The contract that the two are one object is asserted at
`agent/tests/test_boolean_oracle_stability.py:99` (`nosqli.is_inconclusive is sqli.is_inconclusive`).

HONEST CAVEAT, recorded rather than smoothed over: no *production* module currently calls
`nosqli.is_inconclusive` either — the third-outcome convention from Q-070 is consumed by tests today.
The re-export is real; the downstream consumer is a test.

### 3.4 HARNESS — 6 entries

A dead-code gate, a description gate and an effects audit all run on every suite execution. Their
output is a verdict, their scheduler is pytest, and the qualified scan excludes tests *on purpose*, so
"unwired" is the correct answer to the question it asks and the wrong answer to the question a reader
has. Each carries a resolvable caller.

| entry | caller |
|---|---|
| `deadcode_gate.scan` | `agent/tests/test_deadcode_gate.py:22` |
| `deadcode_gate.scan_qualified` | `agent/tests/test_deadcode_gate.py:27` |
| `deadcode_gate.scan_methods` | `agent/tests/test_deadcode_gate.py:384` |
| `description_gate.audit` | `agent/tests/test_description_gate.py:153` (also 264, 292; `test_web_message_source.py:513`) |
| `engine_descriptor.effects_audit` | `agent/tests/test_effects_engine_fact.py:55` (also `test_effects_negative_half.py:63`) |
| `ics_dnp3_s7._dnp3_crc_table` | `agent/tests/test_ics_dnp3_s7.py:72` — `assert ics.dnp3_crc(data) == ics._dnp3_crc_table(data)` |

`_dnp3_crc_table` is the strongest case of the six and the reason the category is not a loophole: it
is a **second, independent implementation of the DNP3 CRC that exists only to falsify the first**. A
production caller would defeat its entire purpose. Deleting it as "dead" would delete a negative
control.

**This category is where a gate goes decorative, so it is the one that got a mechanism.** The entries
live in `ALLOWED_UNUSED_HARNESS`, which stores `(caller_file, anchor_substring, why)` and is checked
by `test_every_harness_allowlist_entry_resolves_to_a_real_caller`: the named file must exist, the
anchor must be present in it, and the anchor must contain the function's own name. An entry that says
"allowed" cannot be written, and an entry whose caller is deleted or renamed fails the suite.

### 3.5 REAL ISLANDS — 17 entries

No reference of any kind in production, in `agent/tier3/`, in `scripts/`, in `ui/`, in compose, or in
any Dockerfile. Several arrive with a partner already recorded in `QUALIFIED_BASELINE_SET`, which
means the island is a *half-built feature*, not a stray helper — those are called out.

| entry | verdict | evidence |
|---|---|---|
| `bench_all.bench` | ISLAND — **and a docstring that states the opposite** | `agent/main.py:1313` says "The full sweep … is driven by `bench_all.bench(reachable, scan_via_mission)`". Nothing calls it. Its partner `bench_all.scan_via_mission` is already in `QUALIFIED_BASELINE_SET`. Production uses only `LAB_URLS`, `MIN_GATE`, `reachable_labs`. **The multi-lab sweep the endpoint advertises does not exist as a callable path** — declaration-versus-fact, in prose, about the benchmark harness. |
| `archive_intel.needs_validation` | ISLAND — half-built loop | the validation queue for archive/repo-derived nodes. Partner `archive_intel.mark_validated` already in `QUALIFIED_BASELINE_SET`. Production calls only `ingest_archived_endpoints` / `ingest_repo_findings`: **archive facts are ingested and never validated against the live target.** The `needs_validation` key at `agent/asset_graph.py:514` is a separately-computed dict key, not this function. |
| `codereview_graph.link_runtime_to_source` | ISLAND — half-built loop | production calls only `seed` (`agent/main.py:3288`, `agent/asset_graph.py:670`). White→black is wired; **black→white — tying a confirmed runtime finding back to the exact source sink — is not.** |
| `codereview_graph.hypotheses` | ISLAND — half-built loop | same module, same gap: the static candidate hypotheses are seeded into the graph and never read back out for the planner or the report. |
| `saml_tool.finding` | ISLAND — orphaned finding-builder | builds the CONFIRMED signature-bypass finding. `confirm_bypass` (`saml_tool.py:95`) returns a raw dict and **does not call it**; `confirm_bypass` and `wrap_assertion` are themselves in `ALLOWED_UNUSED_QUALIFIED` as operator-gated. So the intrusive half has no caller *and* no finding-builder wired to it. Production uses `analyze`, `get`, `harvest`, `plan_leads`. |
| `bie.observe` | ISLAND | the Browser-Intelligence CDP wire-view sensor. `agent.py:3530`'s `_be.observe` is **`browser_engine`** (`import browser_engine as _be`, `agent.py:3510`), a different module — checked because it is exactly the collision that would have made this a false verdict. Production `bie` use is `available`, `retest_recipe`, `retest_verdict`, `run_persona_swap`, `storage_from_login`. |
| `service_router.plan` | ISLAND | turns routed services into an ordered, intrusiveness-gated execution plan. Production stops at `route` (`agent.py:1693`, `asset_graph.py:646`, `tools.py:3060`). Partner `service_router.known_services` already in `QUALIFIED_BASELINE_SET`. |
| `ics_fingerprint.finding` | ISLAND — joins a recorded cluster | production imports `ics_fingerprint` only for `PROTO_PORTS` (`service_router.py:37`). Six sibling functions are already in `QUALIFIED_BASELINE_SET`. The live ICS finding-builder is `ics_dnp3_s7.finding`, which is called. **This makes the cluster 7 of 8 — the module is an island with one constant leaking out of it.** |
| `cloud_iam.collect_live` | ISLAND — self-declared | `agent/capability_matrix.py:91` records the state as "collect_live logic fixture-tested; SDK client glue not built". Production calls `collect` and `to_graph`. The matrix already tells the truth about this one. |
| `report.control_ran` | ISLAND — superseded | superseded by the three-valued `control_status` / `negative_control_claim` in the same module, which production does call. Its own docstring records the supersession. Still heavily asserted by three test files. |
| `fingerprint.fingerprint` | ISLAND — superseded wrapper | body is exactly `public_view(detect(headers, set_cookie, body))`. Production calls `detect` and `public_view` directly (`tools.py:4003`, `memory.py:129`). |
| `ssrf_tool.bypass_payloads` | ISLAND — superseded | its own successor's docstring says it: `metadata_bypass_payloads` exists because "the encodings were already written in `bypass_payloads`, just never fired at the metadata service". Production calls the successor. |
| `api_protocols.inventory` | ISLAND | `agent/main.py:1588` `/intel/api-protocols` assembles its own `out` dict; it calls `detect_wsdl_links`, `parse_wsdl`, `soap_body_candidates`, `detect_protocol`, `grpc_observation` and never `inventory`. |
| `exposure_tool.paths` | ISLAND — accessor | `[c["path"] for c in EXPOSURE_CHECKS]`; production consumes `EXPOSURE_CHECKS` directly (`tools.py:1712`, `tools.py:7553`). |
| `techniques.classes` | ISLAND — accessor | `sorted({t["vuln_class"] …})` over `TECHNIQUES`. 17 production importers of `techniques`, none call it. |
| `tool_provenance.argv_hash` | ISLAND — inlined duplicate | `record()` computes `_hash(redacted_argv)` inline at `tool_provenance.py:62` rather than calling this. |
| `capability_matrix.state_rank` | ISLAND — accessor | `_RANK.get(state, 0)`; no caller in production or tests. |

Count: 1 + 2 + 1 + 6 + 17 = **27**.

---

## 4. Patches for islands this lane may not write

Ownership: this lane may not touch `agent/tools.py`, `agent/planner.py`, `agent/scope.py`,
`agent/engine_descriptor.py`, `agent/techniques.py`, `agent/effect_search.py`,
`agent/tests/test_description_gate.py`. Wiring any of the 17 needs a file it does not own, so the
patches live here — which the ticket names as the correct outcome.

Ranked by what the platform actually loses.

**P1 — `codereview_graph.link_runtime_to_source` (black→white).** The highest-value island here: a
confirmed runtime finding currently cannot be tied to the source line that caused it, although the
code to do it is written and tested. Wire it where a finding is confirmed and the mission has a code
review, e.g. in `agent/agent.py` beside the existing `_crg.seed` path in `asset_graph.py:670`:

```python
# on each confirmed finding, when ctx["code_review"] exists
import codereview_graph as _crg
locs = _crg.link_runtime_to_source(g, f.get("family", ""), f.get("target", ""))
if locs:
    f["source_locations"] = locs
```

`hypotheses(graph)` then has a consumer in the report (the "source says X here, runtime not yet
confirmed" section) — wire both or neither; they are one feature.

**P2 — `archive_intel.needs_validation` + the recorded `mark_validated`.** Archive/repo intel is
ingested and never re-checked against the live target, so a node whose provenance is a 2019 wayback
snapshot is indistinguishable from a fact observed this run. The planner should drain the queue:
`needs_validation(g)` → bounded live probe per node → `mark_validated(g, node_id, present)`. This
closes two recorded entries at once.

**P3 — `saml_tool.finding`.** Either wire the operator-gated confirm path so `confirm_bypass`'s dict
becomes a finding through `finding(kind, acs_url, evidence)`, or move `finding` into
`ALLOWED_UNUSED_QUALIFIED` **beside** `confirm_bypass` and `wrap_assertion` with the same
operator-gated justification. Not done here: it is `saml_tool.py`'s owner's call, and an allowlist
entry claiming `confirm_bypass` calls it would be false.

**P4 — `bench_all.bench`.** Either implement the sweep the `/bench/labs` docstring advertises, or fix
the docstring. Right now `agent/main.py:1313` describes a capability that has no callable path — the
Q-077 defect shape (prose asserting wiring that does not exist), in the benchmark harness, which is
where a false claim is most expensive.

**P5 — deletions.** `fingerprint.fingerprint`, `ssrf_tool.bypass_payloads`, `report.control_ran`,
`tool_provenance.argv_hash`, `exposure_tool.paths`, `techniques.classes`,
`capability_matrix.state_rank` are superseded wrappers or accessors. Deleting them is safe only after
their tests are re-pointed; `report.control_ran` alone carries ~20 assertions across three files.
**Not done by this lane** — "remove obsolete code only after proving it is unused" is satisfied, but
each deletion touches a file another lane owns.

---

## 5. What this lane changed

`agent/deadcode_gate.py` only, plus its test file.

1. **Module-object alias propagation in `_module_bindings`.** A module bound to a dotted path by a
   simple assignment (`self._intel_mod = _intel`, `_M = intel`) is now a binding of that module, so
   `self._intel_mod.harvest(...)` resolves. Precise, not permissive: only an assignment whose RHS is
   already a known module alias creates a binding, so an arbitrary `self.foo.harvest` still resolves
   to nothing. **MEASURED: 61 → 60, and the single entry resolved is `intel.harvest`.**
2. **`ALLOWED_UNUSED_HARNESS`**, the caller-naming allowlist for §3.2–§3.4 (9 entries), each storing
   `(caller_file, anchor, why)`.
3. **`test_every_harness_allowlist_entry_resolves_to_a_real_caller`** — resolves every claimed caller
   against the real tree and reports the line it found it on. Plus its negative control: a fabricated
   entry must fail, proving the check is not vacuous.
4. `QUALIFIED_BASELINE_SET` **not** touched; `QUALIFIED_BASELINE` **not** raised.

---

## 6. The ratchet arithmetic

| | count |
|---|---|
| Q-077 measurement at HEAD | **61** |
| − `intel.harvest`, a false positive with a proven caller | 60 |
| − 9 caller-named allowlist entries (framework / re-export / harness) | **51** |
| ceiling | **37** |

**51 > 37, so the strict xfail STAYS PINNED and the marker is NOT retired.** The ticket asks for this
to be said plainly if it happens, and it happened: the 17 real islands are 14 more than the ceiling
can absorb, and closing them means wiring or deleting code in files this lane does not own.

What changed is that the number now means something. Before this ticket, 61 was "35 recorded plus 27
unclassified". After it, 51 is **34 previously recorded** (`QUALIFIED_BASELINE_SET` minus
`intel_registry.advance`, which another lane has since wired) **plus 17 named, evidenced islands**,
each with a verdict and a patch. The ratchet can be retired the moment those 17 are closed, and §4
says exactly what closing each one costs.

---

## 7. Anti-idle — the method scan's 14th entry

`METHOD_BASELINE` moved 13 → 14 under AST resolution. MEASURED at HEAD: `count 14, ok True,
newly_dead [], resolved []` — the set is exact, so the one that appeared is the one the file's own
comment names, `vault.py::Vault.is_encrypted`. Triage below.
