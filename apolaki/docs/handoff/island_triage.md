# Q-078 — triage of the 27 entries Q-077 made visible

Lane: island-triage (Builder). Owns `agent/deadcode_gate.py`, `agent/tests/test_deadcode_gate.py`,
new tests of its own, and this file.

**Run 1** classified all 27 and built the caller-naming allowlist; a session limit killed it with four
of its own tests red. **Run 2** finished the mechanism, and the reason those four were red is in
[§8](#8-run-2-the-four-red-tests-and-what-each-one-was-actually-telling-us) — one of them was a
negative control that could not fail, which is worth more than the other three put together.

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
comment names, `vault.py::Vault.is_encrypted`.

**Verdict: REAL ISLAND, and the most interesting one in either scan.**

```
grep -rn "is_encrypted" . | grep -v ^./docs/     → 9 hits in 4 files
  agent/vault.py:19                  module docstring (prose)
  agent/vault.py:89                  the definition
  agent/deadcode_gate.py:617,628     this gate's own recorded baseline + its comment
  agent/tests/test_deadcode_gate.py:181,183,185   prose, in a test ABOUT why it was hidden
  agent/__pycache__/vault.cpython-311.pyc         a stale build artefact
```

Positive control: the same unfiltered grep — no `--include`, so `Makefile`, `Dockerfile`, `ui/` and
`scripts/` were all in scope — did find the definition and the docstring, so the reader was looking.
Zero callers in production, zero in tests, zero outside Python. The method is `return self._fernet is
not None`.

**What that costs, and it is not a stray accessor.** `agent/vault.py` is live — `_vault.default().put`
at `agent/main.py:2483`, `.get` at `agent/agent.py:1623`, `1967`, `2058`. Only the protection-level
accessor is dead. Its module docstring is a safety claim:

> If `cryptography` is somehow unavailable the vault degrades to a clearly-labelled NON-encrypted store
> that STILL enforces the redacted-reference contract — it never pretends to be encrypted.
> `is_encrypted()` reports the true protection level.

**The label is never read.** Nothing calls `is_encrypted()`, `ui/` contains the string "vault" zero
times, and no report field carries it. So a mission that stored live credentials in the plaintext
fallback is indistinguishable, in every artefact the operator sees, from one that encrypted them. The
docstring is not lying about the code — the fallback really is labelled — it is lying about the
*system*, because nothing ever asks for the label. That is the Q-077 declaration-versus-fact shape
sitting in the credential store, which is the worst place in this codebase for it.

**Patch (not this lane's files — `main.py`, `report.py`, `ui/`):** have the vault report its own
protection level wherever a secret reference is minted or consumed.

```python
# agent/main.py, beside the put() at 2483
vlt = _vault.default()
snap["scan_auth_ref"] = vlt.put(...)
snap["scan_auth_encrypted"] = vlt.is_encrypted()   # the label, finally read
```

and surface it in the run's provenance so a report can say which of the two stores held the
credentials. That closes the island by using it for its stated purpose rather than deleting it.
`METHOD_BASELINE` stays 14 — the method ratchet passes at 14 and this entry is **recorded, not
excused**; it is in `METHOD_BASELINE_SET`, not in any allowlist.

---

## 8. Run 2 — the four red tests, and what each one was actually telling us

Run 1's last words were "Count is 51, nothing unaccounted for". **MEASURED: the count is exactly 51,
so that sentence was true** — but it was a statement about the ratchet, not about the suite, and the
suite was red in four places. Reproduced first, on a clean `git archive HEAD` snapshot plus run 1's two
files, before anything was changed:

```
FAILED test_the_recorded_q077_delta_excuses_nothing
FAILED test_every_named_caller_allowlist_entry_resolves_to_a_real_caller
FAILED test_a_fabricated_named_caller_does_not_resolve
FAILED test_the_qualified_scan_honours_both_allowlists
```

### 8.1 Two of them were one fact: the caller is outside the mount

`mitm_addon.request` / `response` name `docker-compose.yml`, which sits beside `agent/`. The suite runs
in a container that mounts **only** `agent/` at `/app`:

```
docker run --rm apolaki-agent sh -c "ls /"
→ app bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

No `docker-compose.yml`, and `/app/..` is `/`. So the resolver returned "not found" for a caller that
is genuinely there in the repository and genuinely unreadable from inside the test container.

The wrong fixes were both available and both are the defect in miniature: tolerate any unresolvable
entry (the allowlist goes decorative again) or `pytest.skip` (SKIPPED is never a pass). What landed
instead **separates two facts the boolean was conflating**:

| status | meaning | verdict |
|---|---|---|
| `RESOLVED` | file opened, anchor present | the excuse is a fact |
| `ANCHOR_MISSING` | file is here, anchor is **not** | HARD FAIL, every entry, every environment |
| `FILE_UNREACHABLE` | the file is not in this checkout at all | a limit, not a pass — and bounded below |
| `NOT_LISTED` | not in the allowlist | — |

`ANCHOR_MISSING` and `FILE_UNREACHABLE` are different claims: the first says the excuse died, the
second says this process cannot see far enough to judge. A limit that reports itself as a pass is the
shape of every defect this file exists to catch.

The hole is then **pinned by name, not described by a rule** — `NAMED_CALLER_OUTSIDE_CHECKOUT =
frozenset({"mitm_addon.request", "mitm_addon.response"})`. A rule ("framework entries may be
unverifiable") widens silently; a frozenset of two means a third unverifiable entry takes a deliberate
edit, reviewed the way a raised ratchet would be. `test_the_unverifiable_entries_are_pinned_by_name_and_nothing_else_is`
asserts the set is ≤ 2, that every member is kind `framework`, that no member names a path under
`tests/` (which IS mounted, so claiming it is unreachable would be dodging), and that **every other
entry resolves for real on this run** — MEASURED, 8 of 10 resolve against the real tree.

And the state that the container cannot exercise on the real tree is exercised anyway, deterministically:
`test_the_resolver_reads_a_file_at_the_repository_root` builds a synthetic root holding `agent/` and a
`docker-compose.yml`, then drives **the real entry with the real anchor** through all three states —
anchor present → `RESOLVED`, compose rewritten without the addon → `ANCHOR_MISSING`, file removed →
`FILE_UNREACHABLE`. Without it, `FILE_UNREACHABLE` would be a state nothing ever escapes, which is a
pass wearing a different word.

### 8.2 The one that mattered: a negative control that could not fail

`test_a_fabricated_named_caller_does_not_resolve` asserts that an invented caller does not resolve. It
fabricated the entry with a single string literal:

```python
monkeypatch.setitem(dg.ALLOWED_UNUSED_NAMED_CALLER, "ghost_mod.ghost_fn",
                    ("harness", "tests/test_deadcode_gate.py",
                     "ghost_fn_that_nothing_anywhere_calls()", "fabricated, for the negative control"))
assert dg.resolve_named_caller("ghost_mod.ghost_fn") is None
```

**The fabricated entry names the test file as its caller, and writing the anchor as a literal puts the
anchor into that very file.** MEASURED:

```
resolve -> ('/app/tests/test_deadcode_gate.py', 315,
            '"ghost_fn_that_nothing_anywhere_calls()", "fabricated, for the negative control"))')
```

Line 315 is the fabrication itself. The control's own text was the evidence it was written to prove
absent. It is the same self-reference the whole ticket is about — prose about a call counting as the
call — reappearing one level up, inside the control built to catch it, which is why it is recorded here
rather than quietly fixed.

Two changes, because one of them alone would leave the shape live:

1. The anchor is **assembled at runtime** (`"ghost_fn_" + "nothing_anywhere_calls_this()"`), so it
   cannot exist as a literal, and the test now **asserts its own fabrication is absent** from both
   `deadcode_gate.py` and `tests/test_deadcode_gate.py` before using it. That assertion is the guard
   that would have caught this, and it is the part worth copying to any other negative control that
   searches the tree for a string it defines.
2. `resolve_named_caller` **refuses `deadcode_gate.py` as a caller file outright**. Every anchor in the
   allowlist is a literal in the module that declares the allowlist, so an entry naming that file would
   prove itself. Enforced twice on purpose — in the resolver and in
   `test_no_entry_cites_the_file_that_declares_it` — with
   `test_the_resolver_refuses_a_self_citation` as its negative control: an entry citing
   `deadcode_gate.py` with an anchor that genuinely IS in it must still not resolve.

### 8.3 The fourth: a test named for a world with two allowlists

`test_the_qualified_scan_honours_both_allowlists` asserted every allowed entry was in one of **two**
lists; Q-078 added a third, so the scan honoured a list the test did not know about. Renamed to
`test_the_qualified_scan_honours_all_three_allowlists` rather than left to drift — a name asserting
"both" over three things is the rot this gate exists to catch — and strengthened, not merely widened:
an entry excused by the third list must also not be `ANCHOR_MISSING`, and a positive control asserts
the third list is actually reaching the scan's `allowed` set rather than merely existing.

### 8.4 Mutation-tested, because a checked allowlist that cannot fail is the same as an unchecked one

**Mutant 1 — a resolver that always says `RESOLVED`.** Killed by 3 tests
(`test_a_fabricated_named_caller_does_not_resolve`, `test_the_resolver_reads_a_file_at_the_repository_root`,
`test_the_resolver_refuses_a_self_citation`).

**Mutant 2 — the real caller renamed.** `return dg.scan()` → `return dg.scan( )` in the fixture: still
valid Python, still calls the function, no longer matches the anchor. Killed by 4 tests, each naming
the entry and the file:

```
deadcode_gate.scan was excused by ALLOWED_UNUSED_NAMED_CALLER and its named caller is GONE from a
file that is right here -- so either the excuse was never true or this is an island now
```

That is the property the ticket asked for, demonstrated rather than asserted: delete or rename a named
caller and the suite goes red pointing at the entry that lied.

---

## 9. The arithmetic, re-measured by run 2

Both numbers from `git archive HEAD` snapshots, HEAD alone versus HEAD plus this lane's two files, so
the two live lanes editing the shared tree cannot move them.

```
HEAD           count 61  baseline 37  allowed 8
HEAD + this    count 51  baseline 37  allowed 18
```

Set difference, `unused` at HEAD minus `unused` here — **10 entries cleared, 0 newly flagged**:

```
deadcode_gate.scan          deadcode_gate.scan_methods    deadcode_gate.scan_qualified
description_gate.audit      engine_descriptor.effects_audit  ics_dnp3_s7._dnp3_crc_table
mitm_addon.request          mitm_addon.response           sqli_tool.is_inconclusive
intel.harvest
```

Nine are the caller-named allowlist. The tenth, `intel.harvest`, is the resolver fix — and the
"0 newly flagged" column is the control that matters: widening a resolver is exactly how a gate starts
clearing things it should not, and **this one cleared exactly the entry it was written for and nothing
else**.

| | count |
|---|---|
| Q-077 measurement at HEAD | **61** |
| − `intel.harvest`, a false positive with a proven caller | 60 |
| + `deadcode_gate.resolve_named_caller`, this ticket's own new function | 61 |
| − 10 caller-named allowlist entries (2 framework / 1 re-export / 7 harness) | **51** |
| ceiling | **37** |

**51 > 37, so the strict xfail on `test_the_ratchet_holds` STAYS PINNED and the marker is NOT
retired.** The ticket asks for this to be said plainly if it happens, and it happened. `QUALIFIED_BASELINE`
was not raised, `ALLOWED_UNUSED_QUALIFIED` was not widened, and `QUALIFIED_BASELINE_SET` was not
touched. Retiring the pin needs the 17 islands in §3.5 closed, and §4 prices each one.

The one thing that did change is what the number means. 51 is **34 previously recorded + 17 named,
evidenced islands**, and the 10 entries that left it did not leave by assertion — each names a caller a
test opens a file to find.

---

## 10. Run 4 — the repair: a rule that was RED on arrival, and why

Run 3 was killed mid-test holding uncommitted work. The Coordinator's isolated full-suite run over HEAD
plus those files was `1 failed, 3246 passed, 11 skipped, 12 xfailed in 661s`, the one failure being
run 3's own `test_a_recorded_measurement_cannot_grow_to_absorb_a_new_island`. Reproduced first, before
anything was changed, on a `git archive HEAD` snapshot with run 3's two files overlaid:

```
docker run --rm -v "<snap>/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_deadcode_gate.py -p no:cacheprovider -q
→ FAILED test_a_recorded_measurement_cannot_grow_to_absorb_a_new_island
  AssertionError: deadcode_gate.scan_qualified is excused; it can never be flagged
```

### 10.1 The mechanism was right; one assertion had the direction backwards

Run 3's accounting gate — `unaccounted = flagged - RECORDED_QUALIFIED`, kept separate from `ok` — is
sound and is kept verbatim. What failed is the clause guarding the records against becoming allowlists:

```python
for e in dg.RECORDED_QUALIFIED:
    assert e not in dg.ALLOWED_UNUSED_NAMED_CALLER
```

MEASURED — nine violations, every one from `QUALIFIED_Q077_REVEALED`:

```
deadcode_gate.scan  deadcode_gate.scan_methods  deadcode_gate.scan_qualified   (harness)
description_gate.audit  engine_descriptor.effects_audit  ics_dnp3_s7._dnp3_crc_table   (harness)
mitm_addon.request  mitm_addon.response   (framework)
sqli_tool.is_inconclusive   (re-export)
overlap RECORDED x ALLOWED_UNUSED_QUALIFIED: []
named-caller entries in NO record: ['deadcode_gate.resolve_named_caller']
```

Those nine are **run 2's own work product**. They were flagged when the Q-077 delta was measured, and
run 2's triage then found each one a caller and pinned it with a resolvable anchor. The flat rule
therefore forbade the exact outcome the ticket exists to produce — it would have been satisfied only by
deleting nine names from a record of a measurement, which is rewriting history to match a later opinion.
The Q-077 delta was 27 and stays 27 however the triage of those 27 lands.

**The two directions are different acts, and a set cannot tell you which order its members arrived in:**

| | what happened | verdict |
|---|---|---|
| RECORD-then-EXCUSE | measured while flagged; triage later found a caller | the ticket working |
| EXCUSE-then-RECORD | an already-excused name added to a record; can never be flagged, so it pads the record | dishonest |

### 10.2 What landed — pinned by name, exactly as run 2 pinned `NAMED_CALLER_OUTSIDE_CHECKOUT`

`RECORDED_THEN_EXCUSED`, a frozenset of the nine, in `deadcode_gate.py` beside `RECORDED_QUALIFIED`.
A tenth costs a deliberate edit **there** as well as the allowlist edit — two places a reviewer reads —
on top of a caller `resolve_named_caller` must actually find in the tree. That is the teeth: quietly
excusing a recorded entry is the one move that drops the count without wiring anything.

The check itself moved into `_recorded_entries_excused_without_a_pin(recorded, named_caller, prose,
bare, pin)` and now covers **all three** excuse paths that `scan_qualified._justified` honours
(`ALLOWED_UNUSED_NAMED_CALLER`, `ALLOWED_UNUSED_QUALIFIED`, and bare names in `ALLOWED_UNUSED`). Run 3's
clause knew about two of the three — the same shape run 2 recorded in §8.3, where a test named for two
allowlists silently ignored a third. MEASURED: no recorded entry is excused by the prose list or by a
bare name today, so those two arms are proven by control rather than by observation.

`test_the_recorded_then_excused_pin_is_bounded_and_every_member_earns_its_place` checks the pin in both
directions:

* bounded at the 9 measured;
* every member must still be **both** recorded and excused, so a name whose excuse was withdrawn cannot
  squat there and stay exempt;
* `RECORDED_THEN_EXCUSED == RECORDED_QUALIFIED & set(ALLOWED_UNUSED_NAMED_CALLER)` — exact, not merely
  bounded, which is what stops a name being pinned *before* it is excused. Pre-loading the pin would be
  pre-authorising a future excuse.

**NEGATIVE CONTROL, four ways.** A recorded, unpinned entry is fed to the helper through each excuse
path in turn and must be named; then the same entry, pinned, must not be. Without it the main
assertion's empty list would be indistinguishable from a helper that never looks at anything — which is
precisely the defect run 2 recorded in §8.2. The victim is chosen as
`sorted(RECORDED_QUALIFIED - RECORDED_THEN_EXCUSED)[0]` and the test **asserts its bare name is unique
among the recorded entries** before using it for the bare-name arm, rather than assuming it.

**POSITIVE CONTROL:** the pin is asserted non-empty, so the per-member loop provably ran over nine real
names rather than over nothing.

### 10.3 MEASURED after the repair

```
tests/test_deadcode_gate.py -q  →  47 passed, 1 xfailed          (was 46 passed, 1 xfailed, 1 FAILED)
scan_qualified()  count 51  baseline 37  ok False  allowed 18  unaccounted []
scan_methods()    count 14  ok True  newly_dead []  resolved []
```

Every number identical to run 3's, which is the point: this repair changed a test's premise and added a
frozenset. It did not move the ratchet, raise `QUALIFIED_BASELINE`, or widen any allowlist. No
production module imports `deadcode_gate` — re-confirmed by an unfiltered grep across `.py`, `.sh`,
`.yml`, `.html`, `Dockerfile` and `Makefile` — so a new module constant cannot reach a mission path.

---

## 11. Run 5 — the repair: a test docstring retired an allowlist entry, and the gate was right to notice

Run 4 was killed holding RED uncommitted work. The failure handed to run 5:

```
1 failed, 58 passed, 1 xfailed in 148s
FAILED tests/test_deadcode_gate.py::test_the_allowlist_does_not_rot
AssertionError: these are no longer unused and should be removed from ALLOWED_UNUSED: ['payloads_for']
```

### 11.1 First question, because the brief could not answer it: HEAD, or only the delta?

**MEASURED — only the delta. `070ab54` did not ship it.** Two `git archive HEAD` snapshots, identical
apart from run 4's two uncommitted files, each scanned in its own throwaway container:

```
docker run --rm -i -v "<snap>/apolaki/agent:/app" -w /app apolaki-agent python -
  import deadcode_gate as d; r = d.scan()

git archive HEAD (5d72aa3)     scan() 134.8s   stale_allowlist []                passed True
HEAD + run 4's two files       scan() 132.5s   stale_allowlist ['payloads_for']  passed False
```

`flagged` is `[]` and `total_functions` is 1628 in both, so nothing else moved. (Worth recording for the
next lane: **`scan()` alone costs ~135 seconds**, which is where `test_deadcode_gate.py`'s ~150s goes,
and why every check added here runs against a handful of synthetic files instead of a copy of the tree.)

### 11.2 The brief's instruction was to name the new caller. There is no caller.

> "Remove `payloads_for` from the allowlist, confirm the caller that now exists (name file and line)."

**MEASURED FALSE, and the instruction is the trap rather than the fix.** An unfiltered whole-repo grep —
`.py`, `.html`, `.yml`, `.sh`, `Makefile`, `Dockerfile`, tests, `ui/`, compose, excluding only
`__pycache__` and `docs/` — for all six `ALLOWED_UNUSED` names returns **exactly six lines, and every one
of them is the function's own `def`**:

```
agent/xxe_tool.py:79          def build_error_xml(...)
agent/dependency_intel.py:311 def extract_script_srcs(html)
agent/service_router.py:40    def is_ics_ot(service)
agent/wordlists.py:192        def payloads_for(vuln_class)
agent/wordlists.py:68         def seclists_available()
agent/security.py:80          def validate_targets(values)
```

The only additional `payloads_for` hits in the whole repository are **two sentences in run 4's own new
test docstring** — `agent/tests/test_deadcode_gate.py:817-818` — explaining why the entry is
allowlisted. Positive control on that grep: it found all six definitions and both docstring lines, so
the reader was demonstrably looking; the six zeros are the tree's, not the apparatus's.

So the gate did not catch a rotted allowlist. **It read a sentence about an allowlist entry as a call to
the function the entry is about** — Q-077's exact defect, in the one resolver Q-077 never converted,
triggered by the paperwork of the ticket that exists to fix Q-077's consequences.

Removing the entry as instructed would have been the worst available move: `payloads_for` is still dead,
so the moment anyone rewords that docstring it returns as an *unjustified* island and
`test_no_unexplained_dead_functions` — the blocking gate, not the pinned ratchet — goes red. The
allowlist would have been trimmed on the strength of prose it wrote itself.

### 11.3 Why `scan()`'s conservatism is safe in one direction and not the other

`scan()` resolves `unused` with `re.compile(r"\b%s\b")` over raw source, deliberately, and the module
docstring defends that at length. The same set then fed `stale_allowlist`, and there the identical rule
inverts:

| | rule | effect | verdict |
|---|---|---|---|
| `flagged` | a mention counts as a use | the gate stays quiet | documented, deliberate under-report |
| `stale` | a mention counts as a use | the gate declares a still-dead function "no longer unused" | **LOUD IN THE WRONG DIRECTION**, and the remedy it demands is deleting a true justification |

A retraction is not a conservative error. `stale` is now resolved off the AST
(`_ast_reference_sites`); `unused` is untouched, so the blocking gate keeps exactly the conservatism it
documents and no name newly appears in `flagged`.

Three reference kinds count, the same three `_ast_refs` can prove: `ast.Name`, `ast.Attribute` on any
receiver (type-blind, as `scan_methods` is), and a **whole** string constant equal to the name
(`getattr` dispatch). A docstring is one Constant holding prose, so it can no longer smuggle a name past
the check. Because a reference is a strict subset of a text hit, `stale` **can only get quieter** — which
is why every new check below ships with the pair that proves it can still fire.

The module docstring also claimed *"All three resolvers matched a bare name by REGEX OVER RAW SOURCE"* in
the past tense. Q-077 converted **two**. That sentence has been corrected in place: it was itself a
declaration contradicted by the code beneath it, and it is what let this hole sit unnoticed.

### 11.4 The trap this slice fell into on the way out, which is the part worth copying

`scan()` reads `agent/tests/*.py`, and under the new rule a whole string constant equal to an
allowlisted name **is** a reference. So writing one of those six names as a literal in the test file that
guards them retires the entry it is testing — §8.2's defect, one rule later, in the fix for §8.2's
cousin. Every new test therefore builds the name at runtime (`_an_allowlisted_name()`), and
`test_this_file_does_not_reference_the_names_it_defends` walks this file's own AST and fails if any of
the six appears as a `Name`, an `Attribute` or a whole string — with a positive control (>500 reference
nodes seen, and `ALLOWED_UNUSED` found) so an empty intersection cannot come from a blind walk.

The same hazard is why `_ast_reference_sites` excludes `deadcode_gate.py`, and there the exclusion is
**load-bearing rather than inherited**: every `ALLOWED_UNUSED` key is a whole string constant in that
file, so reading it retires the entire allowlist by declaration.
`test_the_declaring_file_would_retire_its_own_allowlist_if_it_were_read` applies that mutation without
editing the module — the file is copied in under a name the exclusion does not match — and requires
**all six** entries to be retired, then restores the real basename and requires zero. MEASURED: 6 then 0.

### 11.5 What landed, and its controls

`agent/deadcode_gate.py` and `agent/tests/test_deadcode_gate.py` only.

1. `_ast_reference_sites(app, wanted)` → `({name: "file:line"}, nodes_walked)`. Returns the **location**,
   because the failure it replaces named the entry and nothing else and left the reader to guess.
   `scan()` now returns `stale_sites` and `reference_nodes` alongside `stale_allowlist`.
2. `test_prose_about_an_allowlisted_entry_does_not_retire_it` — **negative control and its pair**: a
   comment plus a docstring naming the entry must not retire it; the same directory with one real
   `wl.<name>(x)` added must retire it **and name `uses.py:5`**. Without the pair, a rule that never
   reports staleness passes the first half.
3. `test_a_bare_name_and_a_dispatch_string_also_retire_an_entry` — the other two reference kinds, plus
   the control that a string merely *containing* the name is prose, not dispatch. That is the exact
   distinction the regex could not draw, so it is asserted rather than assumed.
4. `ALLOWED_UNUSED` **not** trimmed. `QUALIFIED_BASELINE` **not** raised, no allowlist widened,
   `QUALIFIED_BASELINE_SET` and `RECORDED_THEN_EXCUSED` untouched. The ratchet still reads 51 against 37
   and the strict xfail stays pinned.

### 11.6 The failure reproduced before it was changed, and afterwards

`git archive HEAD` + run 4's two files, in a throwaway container — the reported failure, verbatim, and
nothing else:

```
docker run --rm -v "<snapB>/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_deadcode_gate.py -p no:cacheprovider -q

.F........................x.......................            1 failed, 49 passed, 1 xfailed
FAILED test_the_allowlist_does_not_rot
  AssertionError: these are no longer unused and should be removed from ALLOWED_UNUSED: ['payloads_for']
  res = {'unused': [], 'allowed': [...5 entries...], 'stale_allowlist': ['payloads_for'], ...}
```

RECORDED DISCREPANCY, not smoothed over: the brief quotes `1 failed, 58 passed, 1 xfailed` — 60 items.
This file collects **50** at HEAD+run 4 and 55 with run 5's five added, so the Coordinator's run
collected ten items this path does not contain and was a broader selection than
`tests/test_deadcode_gate.py`. The failure, its test and its message are identical, so the repair is
against the right defect; the item count is not comparable and should not be quoted as if it were.

### 11.7 Warning attribution, because it was a real delta

Reading `tests/*.py` is the first thing in this module to COMPILE them, and compiling re-emits their
SyntaxWarnings. MEASURED: `tests/test_client_request_source.py:95` has `\w` in a non-raw docstring;
pytest already reports it correctly against that file, and the new reader added a second copy blaming
`test_no_unexplained_dead_functions`. Suppressed at the read only —
`test_reading_the_corpus_does_not_re_report_another_file_s_warning` proves the suppression works AND
opens with a positive control compiling the same source unsuppressed, so it cannot pass vacuously on an
interpreter that does not warn. The original report is untouched:

```
docker run ... pytest tests/test_client_request_source.py -q
  11 passed
  tests/test_client_request_source.py:95: SyntaxWarning: invalid escape sequence '\w'
```
