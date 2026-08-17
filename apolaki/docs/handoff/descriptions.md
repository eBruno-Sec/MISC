# Q-056 — can the description-vs-fact defect class be GATED?

**Lane:** description-gate builder. **Owns:** `agent/description_gate.py`,
`agent/tests/test_description_gate.py`, this file. Edits no product module.

**VERDICT (measured):** the class is **partly** gateable. Two narrow rules catch **2 of the 3 known
instances that a static rule could reach, plus 1 previously-unknown instance, with 0 false positives
across all 111 permission-registered engines.** The third known instance (`run_metadata`) is **NOT
gateable** by any description-vs-code rule and the argument is below. General natural-language
description checking is **NOT gateable** and was not attempted past measurement.

---

## The four known instances, and what happened to each

| instance | claim | fact | live at ece2dbd? | caught? |
|---|---|---|---|---|
| `run_ferox` | *"Recursive content discovery"* | passes `--no-recursion` | **NO — deleted in `466bae8`** | **YES** (rule A, historical fixture) |
| `run_external_surface` | docstring `PASSIVE/ACTIVE-light` | registered `ACTIVE` | yes | **YES** (rule B) |
| `_run_workflow` | docstring claims findings | returned literal `[]` | **NO — fixed by the tools lane mid-run** | no (see "rejected: rule C") |
| `run_metadata` | advertises EXIF GPS | matches ASCII `b"GPS"` | yes | **NO — not gateable, see below** |

`run_ferox` is **historical**: it was deleted with `run_dirsearch`, `run_gobuster` and
`_bin_discovery` in `466bae8` before this lane started. Its source is recovered verbatim from
`git show 466bae8^:agent/tools.py` and pinned as a regression fixture in the test file — that fixture
is now the only place the evidence lives. **A gate measured only against deleted code is measuring
nothing**, so rule A is ALSO measured against the live tree (0 flags, 11 negating flags correctly
ignored) and rule B carries the live instances.

`_run_workflow` was fixed by the lane that owns `tools.py` while this lane was running: at `ece2dbd`
it forwards `findings` and its docstring records the defect. So there is nothing left for a gate to
catch there. The rule that would have caught it was still designed and measured — it is **rejected**,
for reasons that are not "the defect went away".

---

## SHIPPED — the two rules

Both are pure static analysis over one source file's AST. No target, no binary, no network.
`audit()` takes **source text, never a path**, so fixtures pin to the source they were measured
against rather than to whatever `tools.py` says when the test runs — the other lane is writing to
that file continuously.

### Rule A — `negated_capability`

> An engine that passes a literal `--no-X` / `--disable-X` / `--skip-X` / `--without-X` flag must not
> advertise X.

The negated token is **derived from the flag**, stemmed to 6 chars, and looked for in the engine's own
claim text. There is no hardcoded antonym table: `--no-recursion` → `recurs` → matches the word
*"Recursive"* in the description. A test mutates the fixture to `--no-crawling` / *"Crawling"* and the
rule still fires, which is the check that it is a derivation and not a lookup of its own answer.

**MEASURED, `ece2dbd`, all 111 registered engines:**

```
negated_capability: 0 flags
```

11 negating flags exist in the tree and every one is correctly silent:
`--no-sandbox` (×4: `browser_navigate`, `run_dom_audit`, `run_dom_trace`, `run_katana` as `-no-sandbox`),
`--disable-gpu` (×3), `--disable-dev-shm-usage` (×3), `-no-interactsh` (`run_nuclei`).
**False positives: 0.**

**MEASURED, `466bae8^` (pre-deletion, 114 engines): 1 flag — `run_ferox`. 0 false positives.**

### Rule B — `undeclared_tier`

> Every engine's leading declaration phrase must name, as a **bare token**, the `PermissionLevel` it
> is registered under.

Checked on both surfaces an engine speaks through: its `CLAUDE_TOOLS` description (what the **model**
is told) and its implementation docstring (what the **next engineer** is told).

The load-bearing detail is that **`ACTIVE-light` does not count as a declaration of `ACTIVE`.** A
hyphen-qualified tier reads *softer* than the tier it names, and reading softer than you are
registered is the entire defect. `\b` would have accepted it; the rule uses `(?![-\w])`. Mutating
that back to `\b` makes `run_external_surface` stop firing — measured, below.

Compound **honest** declarations pass, because the registered tier is named bare in them:
`ACTIVE/INTRUSIVE:` (`run_nuclei`, registered ACTIVE) and `ACTIVE, INTRUSIVE (opt-in):`
(`confirm_authz_write`, registered INTRUSIVE). A leading-token-only version of this rule flagged both
— **2 false positives** — which is why the rule is "names the registered tier" and not "leads with
it".

**MEASURED, `ece2dbd`, all 111 registered engines:**

```
undeclared_tier: 2 flags
  run_external_surface        registered ACTIVE    but its docstring declares PASSIVE
                              'PASSIVE/ACTIVE-light external attack-surface expansion (#114):'
  confirm_create_object_idor  registered INTRUSIVE but its docstring declares ACTIVE
                              'ACTIVE:'
```

**False positives: 0.** Both are real contradictions, adjudicated by reading the code:

* `run_external_surface` fetches the target's favicon over HTTP. `ACTIVE` is the correct
  registration; the **docstring** is the wrong half. (This is the known instance.)
* `confirm_create_object_idor` — **found by this gate, not by the audit that motivated it.** Its spec
  description says `INTRUSIVE (bounded + self-cleaning):` and `TOOL_PERMISSIONS` says `INTRUSIVE`;
  only the implementation docstring says `ACTIVE:`. Three declarations, one dissenting, in one file —
  and the engine **creates and deletes objects on a live target**. Same class, same shape,
  independently discovered. That is the first evidence that this gate finds instances rather than
  re-describing the four it was handed.

**Rule B is silent for 4 engines that declare no tier at all** (`run_dom_trace`, `run_form_xss`,
`run_jsonp`, `store_finding`). Deliberate: silence is a documentation gap, not a contradiction, and
conflating the two is how a gate acquires the noise that gets it silenced. Named here so the gap is
recorded rather than hidden.

---

## The gate is a RATCHET, not an allowlist

`KNOWN_OPEN` in the test file holds the 2 live contradictions with the ticket that owns each. A
contradiction on any engine **not** in that set fails the suite. And a parametrized test fails when a
`KNOWN_OPEN` entry **stops** firing, so the set cannot decay into a permanent excuse — a fix forces
the ledger to be updated.

Neither description was edited to make the gate pass. **The description is the claim under test;
changing it to fit the code is the same defect wearing a different hat.** The two patches belong to
the lane that owns `tools.py` and are recorded under "patches wanted", below.

---

## MUTATION-TESTED — the gate's own must-fire assertions are real

Both mutants applied to a throwaway copy, **verified present in the file before the run**, and killed
by the exact intended assertion.

```
MUTANT 1  (?![-\w])  ->  \b        # accept a hedged tier as a declaration
  VERIFIED IN FILE: True
  FAILED test_rule_b_fires_on_external_surface
  FAILED test_a_hyphen_qualified_tier_is_a_hedge_not_a_declaration
  FAILED test_known_open_contradictions_are_still_the_ones_recorded[run_external_surface]
  3 failed, 11 passed

MUTANT 2  _STEM_LEN = 6  ->  20    # stop stemming the negated token
  VERIFIED IN FILE: True
  FAILED test_rule_a_fires_on_the_real_ferox_source   ("Right contains one more item: 'run_ferox'")
  1 failed, 13 passed
```

`test_the_gate_actually_reads_the_live_tree` is the negative control for the ratchet itself: a gate
that silently parsed nothing would pass `test_no_new_description_contradiction_in_tools_py`, which is
precisely how a guard in this codebase passed four engines that never ran.

---

## REJECTED — rules that were designed, measured, and are not worth shipping

### Rule C — "claims findings, can never produce one". REJECTED: correct but empty.

Design: if every `ToolResult(...)` return in an engine passes a **literal `[]`** in the findings
position, the engine cannot produce a finding; flag it if its description or docstring positively
claims one.

MEASURED at the time `_run_workflow` still had the defect: the crude claim regex
`\bfinding|\bconfirm` produced **6 flags, 5 of them false** — `acquire_session`, `http_diff`,
`http_request` and `mission_state` all matched on the *tool name* `confirm_idor` or on the verb
"confirm" used about the operator's next step, and `run_external_surface` matched on
*"produces CANDIDATES, **not** findings"*, a claim that says the opposite of what the regex read.

Narrowing the claim to `\bfindings?\b` with a negation window ahead of it dropped it to **1 flag,
0 false positives** — the correct answer. But: **the entire rule rests on distinguishing "produces
findings" from "produces no findings" in English, over a 45-character window.** That is a natural
language judgement wearing a regex, and it is the shape of rule that gets silenced the first time it
is wrong. `run_external_surface` is a live demonstration that the negation form occurs in this tree
in practice, not hypothetically.

It is also **now empty**: `_run_workflow` was fixed at `ece2dbd` and no other engine in the tree has
the shape. Shipping a natural-language heuristic with a 5-in-6 raw false-positive rate to guard zero
live instances is a bad trade. **Not shipped.** What would have caught `_run_workflow` honestly is
what actually caught it: a behaviour test asserting a finding survives a real workflow run (Q-054).

### Rule D — "claims a binary that is absent from the image". REJECTED: environment-dependent.

The `run_metadata` defect had a missing `exiftool` as one of its two causes, so this looks
attractive. It is not gateable:

1. The result **depends on the image**, so the gate passes on a dev box with exiftool and fails in
   CI, or vice versa. A gate whose verdict moves with the machine is a flake, and a flaky gate is a
   silenced gate.
2. `run_metadata`'s description **already hedges correctly**: *"Uses exiftool when present, else a
   native pure-python reader (graceful)"*. The rule would not fire on it. The lie is not "exiftool
   exists" — the lie is that **the fallback can do what the sentence promises**, and no rule about
   binaries reaches that.

### `run_metadata` is NOT GATEABLE by any description-vs-code rule. Argued, not assumed.

The claim is *"extract embedded metadata (EXIF GPS, author, software, timestamps)"*. The fact is that
`upload_tool.extract_metadata`'s only JPEG branch is `b"GPS" in data[:65536]`, and **real binary EXIF
never contains the ASCII bytes `GPS`** — the GPS IFD is a numeric tag, `0x8825`.

The obvious rule — *"a capability token in the description must appear somewhere in the
implementation"* — was **measured and does not fire**:

```
EXIF in _run_metadata source: False | GPS in source: True
EXIF in upload_tool:          True  | GPS in upload_tool: True
```

Both `EXIF` and `GPS` are present in the reachable implementation (`out["EXIF:GPS"] = ...`). The code
**mentions** everything it claims. To know the claim is false you must know that EXIF encodes GPS
numerically rather than as the string `"GPS"` — **domain knowledge about a file format that exists
nowhere in this repository.** No static comparison of a description against its own code can hold it.

**What closes it instead:** a golden-file oracle — the Juice Shop geo-stalking photo, whose
coordinates (59°25'16.17"N 24°48'4.32"E) the islands lane decoded by hand, as a fixture asserting the
engine reports them. That is a behaviour test for Q-055, not a description gate, and it is the honest
answer: **this instance was only ever going to be caught by running the engine.**

### Rule E — "the input_schema declares a parameter the code never reads". REJECTED: 6 of 7 false.

The most promising remaining candidate, because both halves are fully machine-readable and sit in the
same dict: the spec tells the model it may pass `X`, and the implementation never mentions `"X"`.

**MEASURED, `ece2dbd`, 72 spec'd engines carrying an `input_schema`: 7 engines flagged, 25 properties.**

```
confirm_idor        owner_session attacker_session owner_headers attacker_headers session headers
enumerate_ids       url_template start end headers session
http_read           headers session
http_request        headers session
run_hash_crack      hash_type
store_finding       title severity description impact cvss_score cvss_vector cwe
test_numeric_abuse  session headers
```

Adjudicated by reading the code: **6 of the 7 are false.** They consume the parameter *indirectly* —
`_store_finding` forwards the whole dict (`db.add_finding(self.mission_id, dict(inp))`), and the
session/headers families are resolved through helpers (`self._identity(...)`,
`self._role_headers(inp, "owner")`) that take `inp` rather than a named key. Catching those honestly
needs interprocedural analysis across modules, which is the same failure mode as rule C: the rule has
to *interpret* rather than *compare*.

The one true positive is real but minor: **`run_hash_crack` declares `hash_type` ("optional;
auto-identified if omitted") and never reads it** — `cands = hid.identify(h)` always auto-identifies,
so supplying the parameter does nothing. Recorded here as a finding for the `tools.py` lane rather
than gated.

An ~86% engine-level false-positive rate is exactly the noise profile that gets a gate silenced.
**Not shipped.**

### General description-vs-behaviour checking. NOT GATEABLE.

~90 natural-language descriptions do not yield a clean binary signal against ~9,900 lines of
implementation. Every rule that survived measurement here has the same shape and it is a narrow one:
**both halves of the contradiction are machine-readable and sit in the same file** — a flag literal
beside a word, a `PermissionLevel` beside a tier token. Rules that had to *interpret* a description
(rule C) or *observe the environment* (rule D) failed on false positives or on flakiness. The rest of
the class stays a **review discipline**.

---

## PATCHES WANTED — for the lane that owns `tools.py`. Not applied here.

Neither is a description edit. Both correct the half that is wrong:

1. **`_run_external_surface` docstring** — opens `PASSIVE/ACTIVE-light`. It fetches the target's
   favicon; `ACTIVE` is right. Change the docstring to declare `ACTIVE`, and keep the nuance in
   prose after the tier token rather than inside it.
2. **`_confirm_create_object_idor` docstring** — opens `ACTIVE:` on an engine registered `INTRUSIVE`
   by its own spec, its own `TOOL_PERMISSIONS` comment (*"creates+deletes an owned object"*) and its
   own behaviour. Change the docstring to `INTRUSIVE:`.

Each removes its engine from `KNOWN_OPEN` in `agent/tests/test_description_gate.py`; the
parametrized test will fail until that set is updated, by design.

3. **`run_hash_crack`'s `hash_type` parameter** (found by the rejected rule E, above). The schema
   advertises it as *"optional; auto-identified if omitted"* and `_run_hash_crack` never reads it —
   `cands = hid.identify(h)` runs unconditionally. Either honour the supplied type or drop the
   property; do not reword the description to hide it. **Not gated** — the rule that found it is 86%
   false and is not shipped, so this one is a review finding.

4. **The 4 engines that declare no tier at all** — `run_dom_trace`, `run_form_xss`, `run_jsonp`,
   `store_finding`. Rule B is silent on them by design. Adding the tier token to each closes the gap
   the rule cannot see; until then it is recorded, not hidden.

---

## MEASUREMENT HYGIENE

* Every number here is from an **isolated snapshot of `ece2dbd`** (`git archive`), plus this lane's
  two files copied in. The shared tree was never used for a measurement: `HEAD` moved three times
  during this lane (`466bae8` → `c6963f0` → `ece2dbd`) and `tools.py` was dirty throughout.
* `_run_workflow` demonstrates why: this lane read the **working tree** copy first and recorded the
  pre-fix `[]`, then found the committed copy already fixed. Rule 8c, caught by the discrepancy.
* **Full suite, isolated snapshot of `ece2dbd` + this lane's two files: `2672 passed, 13 skipped,
  10 xfailed, 0 failed` in 571s.** Baseline was `2658 passed, 13 skipped, 10 xfailed`; the delta is
  **+14 and nothing else** — exactly this lane's 14 new tests, with skips and xfails unmoved. No
  existing product module was edited, so there was no other way for the count to move, and it did
  not.

---

## WHAT THIS LANE DID NOT SETTLE

* Whether rule A generalises beyond negating **CLI flags**. It only sees a contradiction expressed as
  a literal argv string. An engine that disables a claimed capability through a keyword argument, a
  config constant or an early `return` is invisible to it. The one instance it was built from was a
  CLI flag; there is no second instance in this tree to generalise from, and inventing one to widen
  the rule against would be the invented-fixture failure again.
* Whether the tier convention holds outside `ToolRegistry`. `analyse()` takes a `registry_class`
  argument so another module's engines can be audited the same way, but only `agent/tools.py` was
  measured. Any number quoted for a second module has to be measured before it is quoted.
* `run_hash_crack`'s `hash_type` (rule E's one true positive) is **reported, not gated**.
