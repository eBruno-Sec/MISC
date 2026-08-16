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
| `run_external_surface` | no (emits `[]`) | n/a | **SOUND** (and it is not a detector) | cannot produce a finding of any kind; seeds UNVERIFIED graph candidates, and nothing reads its output either |
| `run_metadata` | no (lead only) | `exposure` | **UNSOUND as shipped** | 0 false positives on 14 negative controls, but MEASURED clean on a file proven to carry EXIF GPS |
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

## Method / status of the remaining engines

| engine | status |
|---|---|
| `run_workflow` | in progress |
| `enumerate_ids` | in progress |
