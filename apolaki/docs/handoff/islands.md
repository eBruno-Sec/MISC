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
| `run_ferox` | no (lead only) | `recon` (no consumer) | **UNSOUND -- DELETE** | binary absent (MEASURED); no oracle, no negative control; and `--no-recursion` disables the only thing it would add |
| `run_dirsearch` | no (lead only) | `recon` (no consumer) | **UNSOUND -- DELETE** | binary absent (MEASURED); duplicates a wired native engine that has a soft-404 baseline it lacks |
| `run_gobuster` | no (lead only) | `recon` (no consumer) | **UNSOUND -- DELETE** | binary absent (MEASURED); same duplication, same missing oracle |
| `run_external_surface` | no (emits `[]`) | n/a | **SOUND** (and it is not a detector) | cannot produce a finding of any kind; seeds UNVERIFIED graph candidates, and nothing reads its output either |
| `run_metadata` | no (lead only) | `exposure` | **UNSOUND as shipped** | 0 false positives on 14 negative controls, but MEASURED clean on a file proven to carry EXIF GPS |
| `run_workflow` | no (emits `[]`), and DROPS its steps' findings | n/a | **UNSOUND as a finding path** | MEASURED: an `enumerate_ids` lead exists on a direct call and is gone through `workflow.run` |
| `enumerate_ids` | no (lead only) | `idor` | **SOUND as a lead engine** | nonexistent-id baseline suppressed 8/8 hits on a catch-all-200 route; hard cap 52 requests |

Detail, evidence and the exact settling measurement for each is below.

---

## 1. `run_dirsearch` / `run_ferox` / `run_gobuster` -- a capability the product IMPLIES and CANNOT PERFORM

**Read this one as a product statement, not a wiring statement.** Apolaki tells the model, in three
separate `CLAUDE_TOOLS` entries, that it can do recursive content discovery with feroxbuster, content
discovery with dirsearch, and directory brute force with gobuster. **None of the three binaries exists
in the shipped image.** Every one of those three offers is an offer the product cannot honour, and the
model has been reading all three for 151 missions.

That is worse than "three engines are unwired". An unwired engine is capability the product has and
does not use. This is capability the product advertises and does not have.

**The recommendation is ZERO of the three, not one.** The evidence for that is below and it is not
close: the capability is already wired natively with a better oracle, and the single differentiator
that would have justified keeping feroxbuster is disabled by Apolaki's own invocation.

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

### The last argument for keeping one of them does not survive reading the invocation

The obvious case for keeping `run_ferox` is recursion: feroxbuster recurses into discovered
directories and the native `run_content_discovery` does not. Its own spec sells exactly that
(`tools.py:935`):

> `"INTRUSIVE: Recursive content discovery via feroxbuster (optional; skips gracefully if unavailable)."`

And `tools.py:1483` invokes it as:

```python
["feroxbuster", "-u", url, "-w", wl, "--silent", "--no-recursion", "-k"]
```

**`--no-recursion`.** The one thing feroxbuster would add over the engine that is already wired is
switched off by the call that would add it. So even with the binary installed and the parser fixed,
`run_ferox` would be a slower, oracle-less, 4,700-request re-implementation of a wired 120-request
engine -- with the differentiator disabled. There is no version of this where the adapter wins.

(This is also a fourth instance of the shape that recurs through these seven: the description and the
code disagree, and the description is what a reader -- or the model -- believes. See also
`run_workflow`'s docstring in section 4, `run_external_surface` declaring PASSIVE while registered
ACTIVE, and `run_metadata` advertising EXIF GPS it cannot read.)

### Does the product need three? It does not need ANY of them.

| claim | status |
|---|---|
| the capability is missing | **false** -- `run_content_discovery` + `run_ffuf` are both planner-dispatched |
| the adapters are better | **false** -- the native engine has a soft-404 baseline; `_bin_discovery` has no oracle at all |
| the adapters can run | **false, MEASURED** -- all three binaries absent from the shipped image |
| ferox at least adds recursion | **false** -- `--no-recursion` is hardcoded in the invocation |
| they are cheap | **false** -- ~4,700 requests on the default wordlist vs the native `max_paths=120`, plus an unbounded `_add_urls` of up to 400 paths |
| they are tested | **false** -- one declaration test; the parser and the side effect have zero coverage |

**RECOMMENDATION -- delete all three** (owner: the `tools.py` lane; this lane applies nothing):

1. Remove `run_ferox`, `run_dirsearch`, `run_gobuster` from `CLAUDE_TOOLS` (`tools.py:934/938/942`)
   **first and on its own**. This is the part that is purely subtractive and needs no oracle argument:
   it stops the product claiming a capability it cannot perform. It is also the only change here that
   improves anything today.
2. Remove the three `TOOL_PERMISSIONS` rows (`tools.py:205/206/207`), `_run_ferox`, `_run_dirsearch`,
   `_run_gobuster` and `_bin_discovery`.
3. If recursive discovery is genuinely wanted, it is a feature request against
   `run_content_discovery` -- which is already dispatched, already has the negative control, and is
   already inside the budget model. Adding recursion there costs one engine's worth of oracle work
   instead of three adapters' worth of parser, wordlist, Dockerfile and fixture work.

If someone would rather keep an adapter than delete it, the burden is (a) the binary in
`agent/Dockerfile`, (b) its REAL stdout recorded as a fixture, (c) a soft-404 baseline in
`_bin_discovery` before `_add_urls` may widen the surface, and (d) dropping `--no-recursion`, with a
re-measure of cost. That is four changes to reach parity with an engine that already ships.

### Secondary observation: a missing binary leaves no provenance

`_cmd` returns `"", "__MISSING__<bin>"` at `tools.py:1237` **before** the `try/finally` block that
appends to `self._tool_provenance`. Measured above: `tool_provenance: []` after three adapter calls.
An operator reading the provenance record cannot distinguish "never attempted" from "attempted and
skipped for a missing binary". Not this lane's file to fix; recorded for the owner of `tools.py`.

---

## 2. `run_external_surface` -- SOUND, because it is not a detector at all

### It cannot emit a finding of any kind

`tools.py:2559` -- the single return on the success path:

```python
return ToolResult("external_surface", host, True, json.dumps(out), [])
```

The findings list is a literal `[]`. There is no other return that carries a finding. So the whole
false-positive question is moot for this engine: **it has no oracle because it makes no claim.** It
harvests ASN/BGP, a favicon hash, offline hostname permutations and (gated) CT names, and it seeds them
as UNVERIFIED graph candidates.

That is also the honest reading of its own docstring -- *"Everything here produces CANDIDATES, not
findings... never promoted without a live check"* -- and the code matches the docstring, which in this
codebase is worth checking rather than assuming.

### MEASURED live against a local lab

Driver: `ToolRegistry(ScopeEngine scoped to juice-shop:3000, lab_mode=True)`, method called directly,
inside `apolaki-agent` on `apolaki_default`.

```
=== input {'domain': 'http://juice-shop:3000'} scope juice-shop:3000
  success  = True    error = None    findings = []
  host        = juice-shop
  asn         = {"domain": "juice-shop", "ips": [], "asn": {}}
  favicon     = {"hash": -145098554, "bytes": 9903, "pivots": {"shodan": "http.favicon.hash:-145098554", ...}}
  permutations= 0 []
  ct          = {"enabled": false, "query": "https://crt.sh/?q=%25.juice-shop&output=json",
                 "note": "ct_logs is gated (CT_LOGS_ENABLED); the query is provided for the operator ..."}
  candidates  = 0
  recon[external_surface] = {"juice-shop": {"asn": {...}, "favicon_hash": -145098554,
                             "ct_enabled": false, "candidates": 0}}
```

### NEGATIVE CONTROL: present, and it RUNS on the confirming path

`tools.py:2500` `if not host or not self.scope.validate(host)[0]: return ... "SCOPE BLOCK"`, and the
favicon fetch re-validates the full URL at `tools.py:2514`. Measured by driving an out-of-scope host
with the scope pinned to another lab:

```
=== input {'domain': 'http://vampi:5000'} scope juice-shop:3000
  success  = False   error = 'SCOPE BLOCK'   findings = []
```

The control is on the same code path as the success case (not a branch that the confirming path
skips), which is the distinction this codebase has been burned by.

### Cost per target -- small and bounded

| step | requests | to whom |
|---|---|---|
| `dns_recon.ip_intel` | 1 DoH A-record lookup, + 1 ASN lookup only if an A record resolved | third-party resolver, NOT the target |
| favicon | at most 2 (`https` then `http`, breaks on the first 200) | the in-scope target |
| `permute` | 0 | offline, pure |
| CT | 0 by default (gated off; MEASURED `enabled: false`) or 1 to crt.sh when `CT_LOGS_ENABLED` | crt.sh |

**2 to 5 requests per target, at most 2 of them to the target.** This is the cheapest of the seven
islands by a wide margin. `max_permutations` defaults to 120 and permutation is pure CPU.

### The real objection: its OUTPUT is an island too

MEASURED by grep -- outside `tools.py` and the tests, **nothing reads `recon["external_surface"]` or
`recon["external_candidates"]`** (zero hits across `agent/` and `ui/`). The graph candidates are
seeded with `confidence=0.2, reachable="unverified", provenance_kind="generated"`
(`recon_expand.py:138`), and the only consumer of a `"subdomain"` node is `graph_export.py:25`, which
maps it to a `Domain` node in an export. Nothing probes them, nothing promotes them, nothing reports
them as findings.

So wiring `run_external_surface` today produces: a favicon hash nobody reads, an ASN nobody reads, and
up to 120 generated `Domain` nodes per host in a graph export. **The engine is sound; the value is
close to zero until a consumer exists.**

Note it is also declared PASSIVE in its docstring and registered ACTIVE
(`tools.py:220`) -- see `docs/handoff/tiers.md:409`, already ticketed elsewhere. It does make live
requests to the target (the favicon), so ACTIVE is the correct registration and the docstring is what
is wrong.

**VERDICT: SOUND.** Zero false-positive surface by construction, a real negative control that runs,
and the lowest cost of the seven. **Wiring it is safe and nearly pointless** -- do the consumer first
(promotion of a candidate on a live reachability check, which is the thing its own docstring says has
to happen), then wire the producer.

---

## 3. `run_metadata` -- no false positives measured, and a PROVEN false negative on the one positive case

### What it confirms

Nothing. `tools.py:1396` emits a single lead: `family: "exposure"`, `confidence: "lead"`,
`severity: "medium"` when a matched key contains gps/location/coord, else `"low"`. Its evidence is
real extracted key/value pairs from bytes the target served, so it passes the "did the target produce
this observation" test.

Family cross-check, character for character against the emitted record: the string is `"exposure"`;
`asvs_model.OBJECTIVES` carries `"exposure"` in exactly one objective's `violated_by`, **COMM-03**
(measured, not read: `[o['cid'] for o in A.OBJECTIVES if 'exposure' in o['violated_by']] ==
['COMM-03']`). COMM-03's named engines are `run_exposure` and `run_dir_harvest`, so `run_metadata`
cannot stamp it verified. And because the emission is `confidence: "lead"`, `agent._is_confirmed`
(`agent.py:706`) routes it to `self.leads`, and `report.py` passes only confirmed `raw_findings` to
`asvs_model.assess` -- so it cannot spuriously FAIL COMM-03 either. **No consumer problem in either
direction.**

### MEASURED: 14 negative controls, zero false positives

Driven directly against Juice Shop -- 6 real product images, a PDF path, the SPA index, a JSON API
response, a soft-404 that returns the SPA shell, a Markdown file, plus 4 real uploaded images:

```
/assets/public/images/products/apple_juice.jpg      findings=0  No sensitive metadata (native)
/assets/public/images/products/artwork2.jpg         findings=0  No sensitive metadata (native)
/assets/public/images/products/fan_hoodie.jpg       findings=0  No sensitive metadata (native)
/assets/public/images/products/holo_sticker.png     findings=0  No sensitive metadata (native)
/assets/public/images/products/carrot_juice.jpeg    findings=0  No sensitive metadata (native)
/assets/public/images/uploads/ipsum.pdf             findings=0  No sensitive metadata (native)
/                             (HTML SPA index)      findings=0  No sensitive metadata (native)
/api/Products                 (JSON)                findings=0  No sensitive metadata (native)
/assets/.../does-not-exist-zzz.jpg  (soft-404)      findings=0  No sensitive metadata (native)
/ftp/legal.md                 (text)                findings=0  No sensitive metadata (native)
```

No false positive on a soft-404, on JSON, on HTML or on plain text. The substring key filter
(`gps|location|author|creator|artist|owner|software|make|model|email|coord`) did not fire on anything
it should not have.

### MEASURED: it reports CLEAN on a file that is provably leaking GPS

Positive control, chosen from the target's own API (`GET /rest/memories`) rather than guessed:
`assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg`.

Ground truth first, decoded independently of Apolaki by walking the JPEG segments and dereferencing
the GPS IFD:

```
file: assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg  107952 bytes
GPS IFD tags: ['0x0', '0x1', '0x1d', '0x2', '0x3', '0x4', '0x5', '0x6', '0x7', '0xb']
GPSLatitudeRef : b'N\x00\x00\x00'
GPSLatitude    : [59.0, 25.0, 16.17]
GPSLongitudeRef: b'E\x00\x00\x00'
GPSLongitude   : [24.0, 48.0, 4.32]

ASCII 'GPS' anywhere in the file: False
XMP packet present               : False
PDF info dict present            : False
```

That file discloses 59 deg 25' 16.17" N, 24 deg 48' 4.32" E. Now the engine on that exact URL:

```
== assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg
   http 200 ct=image/jpeg bytes=107952
   upload_tool.extract_metadata() direct -> {}
   engine findings=0 output=No sensitive metadata (native)
```

**MECHANISM (root cause, not a symptom).** Two independent facts compose into the miss:

1. `exiftool` is **not installed in the shipped agent image** (MEASURED, same command as the trio).
   So `shutil.which("exiftool")` is always false and the engine always takes the native fallback.
2. `upload_tool.extract_metadata` (`upload_tool.py:186`) reads only three things: an XMP packet, a PDF
   info dictionary, and -- for JPEG -- the **ASCII** substring `b"GPS"` in the first 64KB
   (`upload_tool.py:214`). Real EXIF GPS is the **binary** IFD pointer tag `0x8825`; the ASCII string
   "GPS" never appears. Measured on this file: `b"GPS" in data == False`, no XMP, no PDF dict.

So the one branch that claims to detect EXIF GPS cannot fire on real EXIF GPS, and the branch that
could (exiftool) is absent from the image. **1 positive case available in the local labs, 0 detected.**

This is the same shape as the memory note *"probe with observed values / an engine reports clean on a
vulnerable field"*: the engine's clean verdicts were indistinguishable from a working engine until a
proven-positive case was put in front of it.

### Negative control: NONE

There is no baseline and nothing the engine compares against. Its "clean" answer is
`if not interesting: return ... "No sensitive metadata"` -- an absence of matches, never a
demonstrated absence of metadata. That is precisely why the false negative above was invisible.

### Cost

One GET per file, capped at 8 MB, 25 s timeout; plus one `exiftool` subprocess when installed. Trivial
per call. The cost question is what would DRIVE it: there is no discovered-file feed today, so wiring
it means someone must also decide which files to point it at -- at one request per file, an
images-and-documents sweep over a media-heavy target is unbounded unless capped.

**VERDICT: UNSOUND AS SHIPPED -- not in the false-positive direction (0/14), but because the
capability it advertises does not exist in the shipped image.** Wiring it today adds requests and
detects nothing on the only proven positive case available.

**Exact measurement that would settle the remaining unknown:** install `exiftool` in a throwaway
container and re-run the same driver against
`http://juice-shop:3000/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg`. If the
exiftool path emits the GPS lead, the fix is a Dockerfile line (`agent/Dockerfile`, owner: the
`tools.py` lane) and the verdict flips to SOUND-with-caveat. If it does not, the engine is dead
regardless of the binary. Either way `upload_tool.extract_metadata` needs a binary EXIF IFD reader
before the native path can be claimed as a fallback -- today it is a fallback that reads three formats
none of which is EXIF.

---

## 4. `run_workflow` -- UNSOUND as a finding path: it is a finding SINK, and its docstring says otherwise

### The claim, and the code

`tools.py:3186`, `_run_workflow`'s own docstring:

> *"Confirmed findings still come from the confirm_* steps inside it (truth-first)."*

`asvs_model.py:308` leans on that sentence to justify dropping `run_workflow` from BUSL-01. The
sentence is not true of the return value. `workflow.run` (`workflow.py:136`) does:

```python
res = await getattr(reg, meth)(inp)
last_out = res.output or "{}"
entry = {"step": i, "do": do, "ok": res.success}
```

It reads `res.output`, `res.success` and `res.error`. **`res.findings` is never read.** The returned
dict is `{ran, asserted, log, variables, produced}` -- there is no field a finding could travel in.
`_run_workflow` then returns `ToolResult("run_workflow", ..., json.dumps(res)[:4000], [])`.

### MEASURED: the same engine, the same target, the finding disappears

One step (`enumerate_ids` over `http://juice-shop:3000/api/Products/{id}`, ids 1..8) run two ways
against the same live lab:

```
########## A) enumerate_ids called DIRECTLY
POSITIVE  real object collection     accessible=[1, 2, 3, 4, 5, 6, 7, 8] leads=1
     family=idor conf=lead sev=medium title=Enumerable objects by id (8 in 1..8)
     evidence='accessible ids: [1, 2, 3, 4, 5, 6, 7, 8]'

########## B) the SAME step through workflow.run
{"ran": true, "asserted": true,
 "log": [{"step": 0, "do": "enumerate_ids", "ok": true}],
 "variables": {}, "produced": []}
any finding anywhere in the workflow result? -> False

########## C) _run_workflow, the actual island entry point
ToolResult.findings = []
ToolResult.output   = {"ran": true, "asserted": true, "log": [{"step": 0, "do": "enumerate_ids",
                       "ok": true}], "variables": {}, "produced": []}
```

The lead exists on path A and does not exist on path B. This is not specific to `enumerate_ids`: the
same drop applies to `confirm_idor` (which emits a **confirmed**, CWE-639, high-severity finding at
`tools.py:1890`) and to `test_numeric_abuse`. The flagship pack `idor_read` (`packs.py:14`) is built
entirely around `confirm_idor` -- so the one pack whose whole purpose is to CONFIRM a cross-user read
would confirm it, record a capability, and report no finding.

Nor do the inner engines store findings by side effect: `_confirm_idor`'s confirming branch calls
`self.state.add_capability(...)` and `self.state.add_object(...)` and nothing else
(`tools.py:1902-1903`). The finding lives only in the `ToolResult` that `workflow.run` discards.

### The SECOND sink, downstream

Even a fixed `workflow.run` would still lose them today. `agent.py:627` auto-stores only for
`tool_name in _AUTO_STORE_TOOLS` (`agent.py:95`). `"confirm_idor"` and `"run_metadata"` are in that
set; **`"run_workflow"`, `"enumerate_ids"`, `"run_external_surface"`, `"run_dirsearch"`,
`"run_ferox"` and `"run_gobuster"` are not.** So a wiring change alone produces nothing: the fix is
two edits in two files, and either one on its own is invisible.

### What it CAN do soundly

`run_workflow` is not a detector and does not pretend to be one where it counts: it emits no family,
so it cannot fail or verify any ASVS objective, and `asvs_model`'s decision to drop it from BUSL-01 is
correct **for the reason stated in the code comment** (it emits no family), even though the docstring
it cites is wrong. Its oracle, `_assert_ok` (`workflow.py:100`), is genuinely deterministic:
`{capability: X}` checks engagement state, `{field: F, equals: V}` checks a named field of the last
step's JSON. No string sniffing, no status-code inference. `_subst` is a plain `{var}` replace with no
eval; `_extract` allows only JSONPath-lite / one-group regex / header. **There is no model-authored
code path.** That part is well built.

### Cost

Bounded at 20 steps (`workflow.py:126`). Each step's cost is the underlying primitive's, so the worst
case today is one `enumerate_ids` step at 52 requests. `_seed_harvest` runs per step and is
in-process. Cheap relative to the sweep.

**VERDICT: UNSOUND as a finding path, SOUND as an execution engine.** Wiring it today would run real
attacks against a target and record no findings from them, which is worse than not running it: the
mission pays the requests and the report says nothing happened. That is the false-clean shape this
project keeps rediscovering.

**Patch this lane wants (owner: the `tools.py`/`agent.py` lane, NOT applied here):**

1. `agent/workflow.py` -- accumulate `res.findings` per step into the returned dict, e.g.
   `findings: [...]`, and count them in the `log` entry so a step that found something is legible.
2. `agent/tools.py:3202` -- return those findings on the `ToolResult` instead of `[]`.
3. `agent/agent.py:95` -- add `"run_workflow"` to `_AUTO_STORE_TOOLS`, otherwise (1) and (2) change
   nothing in a deterministic mission.
4. `agent/tools.py:3186` -- fix the docstring sentence, and re-check the `asvs_model.py:308` comment
   that quotes it. Once findings flow, `run_workflow` CAN emit family `idor` / `business_logic`
   through its steps, and BUSL-01 / ATHZ-00 / ATHZ-01 need re-reading before it is wired.

**Do (1)-(3) as one commit with a test that FAILS before it.** Doing (1) alone is the wp1 shape: a
change that looks like a fix and moves nothing.

---

## 5. `enumerate_ids` -- SOUND as a lead engine; a target selector, not an oracle

### What it confirms, and on what evidence

`tools.py:1942`. It fetches `tmpl.replace("{id}", "99999999")` as a **baseline first**, then walks the
range and keeps id `i` only when the response is `200`, longer than 2 bytes, and *distinct from the
baseline* (`difflib.SequenceMatcher(...).ratio() < 0.95`). It emits ONE lead when `len(accessible) >= 2`,
`family: "idor"`, `confidence: "lead"`, `severity: "medium"`.

It never claims access control is broken. The lead text is explicitly conditional: *"If these belong to
other users this is a bulk IDOR -- confirm ownership with confirm_idor."* Since it uses ONE identity it
cannot know whose objects those are, and it does not pretend to.

### NEGATIVE CONTROL: present, and it RUNS on the confirming path

The nonexistent-id baseline is fetched before the loop and every candidate is differenced against it.
MEASURED against a live lab -- one positive and two negatives, same engine, same call shape:

```
POSITIVE  real object collection  /api/Products/{id}          accessible=[1..8]  leads=1
NEG-CTRL  soft-404 SPA catch-all  /notarealpath-zzz/{id}      accessible=[]      leads=0
NEG-CTRL  auth-required endpoint  /api/Users/{id}             accessible=[]      leads=0
```

The middle row is the one that matters: Juice Shop answers **HTTP 200 with the SPA shell for any
path**, so a status-code oracle would have reported 8 accessible objects on a route that does not
exist. The baseline difference suppressed all 8. **This is the negative control the three
content-discovery adapters do not have, working, on the confirming path.**

### Family cross-check, character for character

Emitted string: `"idor"`. Measured against the model rather than read off the page:
`[o['cid'] for o in asvs_model.OBJECTIVES if 'idor' in o['violated_by']] == ['ATHZ-00', 'ATHZ-01']`.
Both are real consumers, so the family is not invisible. It is also not a spurious-FAIL risk, twice
over: the emission is `confidence: "lead"`, so `agent._is_confirmed` routes it to `self.leads`, and
`report.py` passes only confirmed findings to `asvs_model.assess`. `candidate_pipeline.PRIMARY_HANDLED`
maps family `idor` to *"the two-user authorization matrix (confirm_idor)"*, i.e. an `idor` lead is
explicitly deferred for confirmation and has no auto-promotion path (`agent._promote_leads` handles
XSS-class only).

### The one real objection: class-correctness, read the wp1 way

On the positive case above the 8 "accessible objects" are Juice Shop's **public product catalogue**.
A `family: "idor"`, `severity: "medium"` lead on a public collection is a class mislabel even though
the wording hedges -- exactly the "read by CLASS, not by count" failure that reverted wp1. The engine
cannot distinguish a public collection from a private one, because distinguishing them requires a
second identity and it only has one.

This is survivable ONLY because the emission is a lead and leads are quarantined. It is the reason
this engine must never be promoted, never be counted in a headline, and never have its `family`
changed to something a consumer treats as a violation without a `confirm_idor` step behind it.

### Cost -- bounded, and the tightest of the seven

`hi = min(int(inp.get("end", lo + 20)), lo + 50)` (`tools.py:1957`) is a hard cap: **at most 51 range
requests + 1 baseline = 52 requests per call**, regardless of what the caller asks for. Sequential (no
concurrency), each scope-validated.

**VERDICT: SOUND as a lead engine.** Real baseline-differenced evidence, a negative control that runs
and demonstrably suppresses a catch-all-200 target, a hard request cap, a family with real consumers
and no promotion path.

### Is it a second-order island, or a separate island wearing a dependency?

**A separate island wearing a dependency.** `enumerate_ids` has its OWN top-level dispatch alias
(`tools.py:1986 _enumerate_ids`) and its OWN `CLAUDE_TOOLS` entry (`tools.py:1003`), added
specifically so a top-level call would not fail -- so it is directly reachable by the model without
`run_workflow` at all. It is unreachable from the deterministic product for the ordinary reason (no
dispatch site), not because `run_workflow` is broken.

Therefore: **wiring `run_workflow` is NOT the way to resurrect it, and resurrecting it via
`run_workflow` would be actively wrong today** -- routing a sound lead engine through a proven finding
sink (section 4) means its leads vanish. If `enumerate_ids` is wanted in the deterministic path, give
it its own dispatch site with a real precondition (an observed numeric-id endpoint), which is one
change, testable on its own, and independent of everything in section 4.

Its remaining problem is a caller, not soundness: nothing decides WHICH `{id}` template to point it
at. `authz_matrix.is_object_path` already recognises object paths and the graph already records
`object` nodes (`tools.py:3244`), so the precondition exists in the codebase; only the wiring does
not.

---

## Cross-cutting: reachability RE-MEASURED, not inherited

The prior lane's classification was re-derived rather than trusted. For each of the seven, every
non-test reference in `agent/`, `ui/` and `scripts/`:

| engine | references outside tests | any dispatch site? |
|---|---|---|
| `run_external_surface` | `tools.py:220` registry, `tools.py:461` schema, `tools.py:553` a comment about itself | **no** |
| `run_metadata` | `tools.py:203` registry, `tools.py:920` schema, `agent.py:103` `_AUTO_STORE_TOOLS` membership | **no** |
| `run_dirsearch` | `tools.py:206` registry, `tools.py:938` schema | **no** |
| `run_ferox` | `tools.py:205` registry, `tools.py:934` schema | **no** |
| `run_gobuster` | `tools.py:207` registry, `tools.py:942` schema | **no** |
| `run_workflow` | `tools.py:234` registry, `tools.py:1058` schema, its own returns, two `asvs_model` comments | **no** |
| `enumerate_ids` | registry + schema + `workflow.py:18` handler map + `packs.py:64` + `agent.py:3885` dedup-exemption list + `agent.py:144` system prompt | **no** (the handler map is driven only by `run_workflow`; the dedup list and prompt are not dispatchers) |

**No island was falsified.** All seven stand. `agent.py:103` and `agent.py:3885` are membership lists,
and `agent.py:144` is prompt text -- naming an engine in a list is a declaration, having a dispatch
site is a fact.

## Cross-cutting: what "wire it" would actually cost

Ranked by requests added per target, so the sweep-budget argument is quantitative:

| engine | requests per target per call | notes |
|---|---|---|
| `run_external_surface` | 2-5 | at most 2 to the target; permutation is offline; CT gated off |
| `run_metadata` | 1 per file | but nothing selects the files; unbounded on a media-heavy target |
| `enumerate_ids` | <= 52 | hard cap `lo+50` plus the baseline |
| `run_workflow` | sum of <= 20 steps | today's worst single step is `enumerate_ids` at 52 |
| `run_ferox` / `run_gobuster` | 0 as shipped (binary absent); ~4,700 with SecLists `common.txt` | vs `run_content_discovery`'s `max_paths=120` |
| `run_dirsearch` | 0 as shipped | dirsearch's own default wordlist is larger still |

For scale: the browser tier already costs 33 HTTP targets per browser target, and the sweep is 92% of
dispatches. Only `run_external_surface` is free enough to wire without a budget conversation -- and it
is the one with nothing downstream to consume it.

## Cross-cutting: the recurring shape is a DESCRIPTION that outruns the CODE

Four of the seven carry a claim that a reader (or the model, which reads `CLAUDE_TOOLS`) would act on
and the code does not support. This is one defect class, not four coincidences, and it is the reason
static reading was never going to settle these verdicts:

| where | the claim | the code |
|---|---|---|
| `tools.py:935` | "Recursive content discovery via feroxbuster" | `--no-recursion` hardcoded at `tools.py:1483`, binary absent |
| `tools.py:920` | run_metadata extracts "EXIF GPS" | exiftool absent; the native branch matches ASCII `b"GPS"`, which real EXIF never contains |
| `tools.py:3186` | "Confirmed findings still come from the confirm_* steps inside it" | `workflow.run` never reads `res.findings` |
| `tools.py:2475` vs `:220` | docstring says PASSIVE | registered ACTIVE, and it does fetch the target's favicon (ACTIVE is right, the docstring is wrong) |

A reachability gate cannot catch any of these, because each engine is present, registered and
implemented. Only running them does.

---

## THE UNKNOWNS, each with the experiment that closes it

Per the ticket: an UNKNOWN with a named measurement is a finished verdict, not a gap. There are two,
and neither blocks its engine's verdict.

**U-1. Does `_bin_discovery`'s parser fit gobuster's and dirsearch's output at all?**
Its only extractor is `re.findall(r"https?://[^\s\"']+", out)`. `feroxbuster --silent` prints bare
URLs; `gobuster dir -q` and `dirsearch -q` print status-prefixed PATHS. If that holds, both parse to
zero and report success with 0 findings on a target full of discoverable content -- a silent
false-clean. **This lane did not install the binaries, so this is UNVERIFIED, recorded as a
hypothesis.**
*Experiment:* in a throwaway container, install each binary, run it against `http://juice-shop:3000/`
with a 20-line wordlist, capture the REAL stdout to a file, and assert
`len(re.findall(r"https?://[^\s\"']+", stdout)) > 0` per binary. The captured stdout is the only
legitimate fixture; inventing the output shape is the defect class that has bitten this project three
times.
*Does it change the verdict?* **No.** DELETE is already the recommendation on five independent
grounds. U-1 only decides whether the deletion also removes a latent false-clean or merely dead code.

**U-2. Would `run_metadata` detect the GPS with exiftool installed?**
The engine has two extraction paths and only the absent one is capable. MEASURED: the native fallback
returns `{}` on a file whose GPS IFD this lane decoded. The exiftool path is untested because the
binary is not in the image.
*Experiment:* `docker run --rm --network apolaki_default <image-with-exiftool>` -- install `exiftool`,
mount the agent, re-run this lane's driver against
`http://juice-shop:3000/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg`, and check
for a lead with a `gps`-containing key.
*What each outcome means:* if it fires, the fix is one `agent/Dockerfile` line plus a binary EXIF
reader in `upload_tool.py`, and the verdict becomes SOUND-with-caveat. If it does not, the engine is
dead regardless of the binary and should be deleted like the trio. **Either way the native path needs
a binary EXIF IFD reader before it can be called a fallback -- today it reads XMP, PDF info dicts and
an ASCII string, none of which is EXIF.**

## WHAT THIS LANE RECOMMENDS, in dependency order

Nothing below was applied here. Every item names its owning file.

1. **Delete the three content-discovery adapters** (`tools.py`). Start with the `CLAUDE_TOOLS`
   removal alone -- purely subtractive, needs no oracle argument, and stops the product advertising a
   capability it cannot perform. **Highest value, lowest risk item in this lane.**
2. **Fix the `run_workflow` finding sink as ONE commit** across `workflow.py`, `tools.py:3202` and
   `agent.py:95`. Any subset is invisible. `agent/tests/test_island_soundness.py` already holds the
   failing test and the half-fix tripwire.
3. **Do not wire `run_workflow` before (2).** Wiring it first spends real requests on real attacks and
   reports nothing.
4. **`run_metadata`: run U-2 before deciding.** Do not wire it either way until it detects the one
   proven positive case in the labs.
5. **`enumerate_ids`: sound, and its gap is a caller, not an oracle.** If wanted deterministically,
   give it its own dispatch site keyed on an observed numeric-id endpoint
   (`authz_matrix.is_object_path` and the graph's `object` nodes already supply the precondition).
   **Do not route it through `run_workflow`** -- that puts a sound lead engine behind a proven sink.
6. **`run_external_surface`: build the consumer before wiring the producer.** It is safe and cheap and
   currently pointless; the promotion-on-live-check step its own docstring describes is the missing
   half.
7. **Fix the four description/code disagreements** listed above. They are cheap and they are what made
   this diagnosis take a lane.

---

## QA record

Full suite, rule 8c -- an isolated snapshot of committed HEAD (`b49ce80`) plus this lane's files, in a
throwaway container:

```
docker run --rm --network apolaki_default -v <snapshot>/agent:/app -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider
-> tests=2672  failures=0  errors=0   (2650 passed, 11 skipped, 11 xfailed)
```

Re-baselined against the coordinator's 2641 passed / 11 skipped / 9 xfailed: this lane adds exactly
**+9 passed and +2 xfailed**, and moves nothing else.

Both new xfails were confirmed to fail on the intended assertion (`--runxfail`):

```
E  AssertionError: workflow.run returned no findings although its only step emitted one
E  AssertionError: extract_metadata returned {} for a file carrying a GPS IFD
```

The two lab-gated metadata tests were re-run with `--network none` and SKIP cleanly -- they do not
error, and a skip inside the strict xfail does not trip the marker.

**All live measurements in this document were re-run against the committed HEAD snapshot and
reproduce identically.** The first pass had used the working tree, which carried another lane's 79
uncommitted lines in `agent/tools.py`; every number here is from HEAD, not from unlanded code.

## Lane state

**COMPLETE.** Seven verdicts, all measured. Commits: `4818f0d` (trio), `1ca3842`
(`run_external_surface` + `run_metadata`), `d725c01` (`run_workflow` + `enumerate_ids`), `b49ce80`
(`agent/tests/test_island_soundness.py`), plus this file.

This lane wired nothing and edited no product module, which was the point: the verdicts are usable by
whichever lane picks up the recommendations, and none of them had to be trusted to a lane that also
had an interest in the answer.
