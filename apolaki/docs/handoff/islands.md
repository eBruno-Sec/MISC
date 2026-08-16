# ISLANDS BREAKER lane -- soundness verdict per island

Ticket: **Q-050(b) soundness**. Deliverable: a verdict per island engine. This lane WIRES NOTHING and
FIXES NOTHING. Every patch it wants is written here for an owning lane to apply.

Files this lane may write: `docs/handoff/islands.md`, `agent/tests/test_island_soundness.py`.

## The question, and why it is not "add them to the sweep"

A previous lane established that six engines have a `TOOL_PERMISSIONS` row and a `CLAUDE_TOOLS` schema
and **no dispatch site anywhere in the product** (`docs/QUEUE.md`, Q-050 part (b), Cause A), plus one
second-order island (`enumerate_ids`, reachable only through `run_workflow`). It deliberately did not
wire them: *"each island needs an oracle-soundness argument I can't make from static reading, and six
always-on dispatch sites on that basis is the wp1 mistake."*

**An engine that has never run has never had its false-positive behaviour measured.** Turning one on
is a new measurement, not a coverage fix.

## VERDICTS

| engine | can it emit CONFIRMED? | family | verdict | one-line reason |
|---|---|---|---|---|
| `run_ferox` | no (lead only) | `recon` | **UNSOUND (as shipped)** | binary absent from the shipped image; MEASURED to return `not installed` on every call |
| `run_dirsearch` | no (lead only) | `recon` | **UNSOUND (as shipped)** | same, and its stdout shape almost certainly does not match the one parser |
| `run_gobuster` | no (lead only) | `recon` | **UNSOUND (as shipped)** | same |
| `run_external_surface` | no (emits `[]`) | n/a | **SOUND, and it is not a detector** | cannot produce a finding of any kind; it seeds UNVERIFIED graph candidates |
| `run_metadata` | no (lead only) | `exposure` | **SOUND-with-caveat** | evidence is real extracted metadata; the key-selection heuristic is substring-based |
| `run_workflow` | no (emits `[]`), and DROPS its steps' findings | n/a | **UNSOUND as a finding path** | `workflow.run` reads only `res.output/success`; inner `confirm_idor` findings are discarded |
| `enumerate_ids` | no (lead only) | `idor` | **SOUND as a lead engine** | baseline-differenced against a nonexistent id; it is a target-selector, not an oracle |

Detail, evidence and the exact settling measurement for each is below.

---

## 1. `run_dirsearch` / `run_ferox` / `run_gobuster` -- three adapters, one capability

### The capability is already wired; these three are not the capability

`run_content_discovery` (native, `tools.py:5840`) and `run_ffuf` (`tools.py:5819`) are BOTH dispatched
by the deterministic planner:

```
agent/planner.py:590  e_steps.append(_step("run_content_discovery", {"base_url": _b(h)}, ...))
agent/planner.py:650  e_steps.append(_step("run_ffuf", {"url": _b(h) + "/FUZZ"}, ...))
```

So content discovery is NOT a missing capability. The three islands are redundant adapters for a
capability that has a wired native implementation with a strictly better oracle (below).

### MEASURED: none of the three binaries exists in the shipped agent image

```
$ docker run --rm apolaki-agent sh -lc 'for b in feroxbuster dirsearch gobuster exiftool ffuf nosqlmap; do printf "%-14s " $b; command -v $b || echo MISSING; done'
feroxbuster    MISSING
dirsearch      MISSING
gobuster       MISSING
exiftool       MISSING
ffuf           /usr/local/bin/ffuf
nosqlmap       MISSING
```

`agent/Dockerfile` and `docker-compose.yml` contain no reference to any of the three (grep: zero hits).

### MEASURED: driven live against a local lab, all three are no-ops

Driver: `ToolRegistry(ScopeEngine scoped to juice-shop:3000, lab_mode=True)`, calling the method
directly, inside the `apolaki-agent` image on network `apolaki_default`.

```
--- _run_ferox      success=False  error='feroxbuster not installed (native content_discovery + ffuf remain available)'  findings=[]
--- _run_dirsearch  success=False  error='dirsearch not installed (native content_discovery + ffuf remain available)'    findings=[]
--- _run_gobuster   success=False  error='gobuster not installed (native content_discovery + ffuf remain available)'     findings=[]
=== urls added to surface: 0
=== tool_provenance: []
```

Wiring any of the three into a dispatch site **today** buys three guaranteed-failing dispatches per
target and zero coverage. That is the whole verdict for the shipped product.

### The oracle, if a binary were present

`_bin_discovery` (`tools.py:1459`) is the shared driver for all three:

```python
paths = sorted(set(re.findall(r"https?://[^\s\"']+", out or "")))[:400]
in_scope = [p for p in paths if self.scope.validate(p)[0]]
self._add_urls(in_scope)
```

1. **What it confirms:** nothing. It emits ONE lead, `severity: "info"`, `confidence: "lead"`,
   `family: "recon"`, titled "Content discovered via <bin> (N path(s))". It asserts *"paths were
   enumerated"*, not *"a path is a finding"*. On the prompt's test -- "a 200 on `/admin` is not a
   finding" -- this passes: it never claims a 200 is a finding. It also never claims a status code at
   all, because it does not parse one.
2. **It has NO oracle.** The truth condition is "the subprocess printed a URL-shaped string". There
   is no baseline, no response-body check, no content-type check, no soft-404 detection. Everything
   the tool prints that looks like a URL and validates in scope becomes surface.
3. **Negative control: NONE, on any path.** There is no baseline request and nothing to compare
   against. Contrast the native `_run_content_discovery`, which fetches
   `f"{base_url}/bbh-nonexistent-{os.urandom(4).hex()}"` FIRST and passes `base_body` into
   `ws.classify_sensitive_path_hit(...)` so a catch-all SPA that answers 200 to everything is
   detected. **The native engine has the negative control the three adapters lack.**
4. **`self._add_urls(in_scope)` is an unbounded side effect on the mission.** Up to 400 paths per call
   are injected into the crawl surface with no validation. Every downstream per-URL engine then pays
   for them. Given the sweep already spends 92% of dispatches, this is the cost-relevant fact, not the
   adapter's own runtime.

### Cost, bounded

- `run_ferox` and `run_gobuster` default to `/usr/share/seclists/Discovery/Web-Content/common.txt`.
  That path does not exist in the image either, so even with the binary installed the default invocation
  would fail on a missing wordlist. `common.txt` in SecLists is ~4.7k lines -> ~4,700 requests per
  target per call, versus `run_content_discovery`'s `max_paths` default of **120**.
- `_cmd` timeout is 300s, and `_TOOL_WEIGHT` charges the mission budget per external tool.
- The `_add_urls` amplification above is the larger cost and it is unbounded by the adapter.

### UNVERIFIED: the parser probably only fits feroxbuster

`_bin_discovery`'s only extractor is `https?://...`. `feroxbuster --silent` is documented to print bare
URLs, which fits. `gobuster dir -q` and `dirsearch -q` print status-prefixed **paths**, not absolute
URLs -- if that holds, both would parse to zero in-scope paths and report success with 0 findings on a
target full of discoverable content. **This lane did NOT install the binaries to check, so this is
UNVERIFIED and is recorded as a hypothesis, not a result.**

**Exact measurement that would settle it:** install each binary in a throwaway container, run it
against `http://juice-shop:3000/` with a 20-line wordlist, capture the REAL stdout to a file, and
assert `len(re.findall(r"https?://[^\s\"']+", stdout)) > 0` per binary. A recorded-stdout fixture from
that run is the only legitimate fixture here -- inventing the output shape is the exact defect class
this project has been bitten by three times.

### MEASURED: the only test coverage is a declaration test

The sole test naming these engines is `agent/tests/test_bbh.py:3870
test_new_optional_binaries_and_permissions`, which asserts the permission level, that a spec exists,
and that a `_run_X` method exists. `_bin_discovery`'s parser, its lead shape and its `_add_urls`
side effect have **zero** test coverage. A test that checks a declaration passes exactly the thing it
exists to catch.

### Does the product need three? NO -- it does not need any of them

- The capability is wired and native, with a real negative control the adapters do not have.
- Zero of the three can run in the shipped image.
- All three funnel through one parser written for one tool's output shape.

**Recommendation (a patch for an owning lane, not applied by this lane):** keep at most `run_ferox`
(recursive discovery is the one thing the native engine does not do) and only after (a) the binary is
added to `agent/Dockerfile`, (b) its real stdout is captured into a fixture, (c) `_bin_discovery`
grows the native engine's soft-404 baseline before `_add_urls` is allowed to widen the surface.
Delete `run_dirsearch` and `run_gobuster`, or mark them operator-only and remove them from
`CLAUDE_TOOLS` so the model stops being told the product has a capability it cannot execute.

### Secondary observation: a missing binary leaves no provenance

`_cmd` returns `"", "__MISSING__<bin>"` at `tools.py:1237` **before** the `try/finally` block that
appends to `self._tool_provenance`. Measured above: `tool_provenance: []` after three adapter calls.
An operator reading the provenance record cannot distinguish "never attempted" from "attempted and
skipped for a missing binary". Not this lane's file to fix; recorded for the owner of `tools.py`.

---

## Method / status of the remaining engines

| engine | status |
|---|---|
| `run_external_surface` | in progress |
| `run_metadata` | in progress |
| `run_workflow` | in progress |
| `enumerate_ids` | in progress |
