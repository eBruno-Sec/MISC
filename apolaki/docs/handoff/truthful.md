# Truthful-engines lane — Q-054 / Q-055 / Q-055b

Three engines whose CODE is fine and whose REPORT is false. Same family as the 626 stored findings
printing a control claim that never ran, and the four engines advertising capability their code
does not have.

Status legend: **MEASURED** = command + real output pasted below. **UNVERIFIED** = not proven here.

Lab: local `apolaki_default` docker network, `apolaki-juice-shop-1` up 3 days. Tests run against an
isolated snapshot of HEAD plus only this lane's files (Rule 8c), never the shared tree.

---

## Q-054 — `run_workflow` was a finding sink, two sinks deep. FIXED.

### Reproduction, MEASURED (pristine HEAD, live target, same engine down two paths)

```
$ docker run --rm --network apolaki_default -v <HEAD-snapshot>/agent:/app -w /app \
    apolaki-agent python _repro054.py
DIRECT  success=True findings=1
  DIRECT finding: family=idor confidence=lead title=Enumerable objects by id (8 in 1..8)
WORKFLOW keys=['asserted', 'log', 'produced', 'ran', 'variables']
WORKFLOW findings=None
WORKFLOW log=[{"step": 0, "do": "enumerate_ids", "ok": true}]
TOOLRESULT success=True findings=0
```

`enumerate_ids` over `http://juice-shop:3000/api/Products/{id}` (ids 1..8) emits a `family=idor`
lead on a direct call and **nothing** through `workflow.run`. The returned dict had no field a
finding could travel in.

### The flagship case, MEASURED — worse than a dropped lead

The `idor_read` pack (`packs.py:14`) acquires two REAL Juice Shop identities and proves a cross-user
basket read. Run on pristine HEAD through `run_workflow`:

```
$ docker run --rm --network apolaki_default -v <HEAD-snapshot>/agent:/app -w /app \
    apolaki-agent python _repro054b.py
OUTPUT: {"ran": true, "asserted": true,
         "log": [{"step": 0, "do": "acquire_session", "ok": true},
                 {"step": 1, "do": "acquire_session", "ok": true},
                 {"step": 2, "do": "confirm_idor", "ok": true}],
         "variables": {}, "produced": ["foreign_object_read"]}
FINDINGS: 0
```

Two logins happened. The cross-user read happened. The oracle CONFIRMED it (`asserted: true`) and
the capability `foreign_object_read` was produced. **The confirmed CWE-639 finding was discarded.**
That is the false-clean shape: the mission paid for the requests and reported nothing, and the
clean result would have been read as evidence.

### Diagnosis

Two sinks in series, so repairing either alone changes nothing observable:

| # | site | defect |
|---|---|---|
| 1 | `workflow.py` `run()` | read `res.output` / `res.success` / `res.error`, never `res.findings`; return dict had no findings field |
| 2 | `tools.py` `_run_workflow` | hardcoded `[]` for its own `ToolResult.findings` |
| 3 | `agent.py:95` `_AUTO_STORE_TOOLS` | `run_workflow` absent — **NOT THIS LANE'S FILE, see handoff below** |

`_run_workflow`'s own docstring claimed the opposite ("Confirmed findings still come from the
confirm_* steps inside it").

### Fix (this lane's files only)

* `agent/workflow.py` — new `_step_findings(res)`; `run()` returns a `findings` aggregate in step
  order and stamps each log entry with its own step's findings. `findings` is **always present**
  (possibly `[]`) on every return path including the missing-prerequisite early return — a caller
  must never have to tell "no key" from "found nothing" (the `x or DEFAULT` shape that has bitten
  this codebase four times).
* `agent/tools.py` `_run_workflow` — forwards `res["findings"]` onto its `ToolResult`, and the
  docstring now describes what the code does. The full dicts travel in `ToolResult.findings`, NOT in
  `output`: `output` is truncated at 4000 chars and full finding dicts would have pushed the step log
  out of the window — a fix that hid the evidence of itself. The display copy keeps per-step counts.

`_step_findings` uses `getattr(res, "findings", None)`, not `res.findings`. Every real producer is a
`ToolResult` whose `findings` is a dataclass default and therefore always present, so this cannot
mask a real engine's output; it exists for the duck-typed step stand-ins in
`tests/test_workflow_headers.py`.

Non-dict entries are forwarded UNCHANGED. Several engines put raw URLs/scalars in `findings`;
dropping or coercing them here would be this ticket's own defect one layer up.

### Proof the fix works END TO END, MEASURED (live, same pack, same target)

```
$ docker run --rm --network apolaki_default -v <snapshot+fix>/agent:/app -w /app \
    apolaki-agent python _repro054b.py
OUTPUT: {"ran": true, "asserted": true,
         "log": [{"step": 0, "do": "acquire_session", "ok": true},
                 {"step": 1, "do": "acquire_session", "ok": true},
                 {"step": 2, "do": "confirm_idor", "ok": true, "findings": 1}],
         "produced": ["foreign_object_read"], "findings": 1}
FINDINGS: 1
{
 "title": "IDOR / BOLA — cross-user object access confirmed",
 "family": "idor",
 "cwe": "CWE-639",
 "confidence": "confirmed",
 "severity": "high",
 "engine": "confirm_idor",
 "target": "http://juice-shop:3000/rest/basket/1",
 "evidence": "owner GET http://juice-shop:3000/rest/basket/1 -> 200 (1310b)\nattacker (different
             identity) GET http://juice-shop:3000/rest/basket/1 -> 200 (1310b); owner/attacker
             similarity 1.0 (>=0.9 = same object)"
}
```

Inputs: `login_url=http://juice-shop:3000/rest/user/login`,
victim `admin@juice-sh.op` / `admin123`, attacker `mc.safesearch@juice-sh.op` / `Mr. N00dles`,
`target_url=http://juice-shop:3000/rest/basket/1`. Both real Juice Shop accounts, both real logins.

**0 findings before, 1 confirmed CWE-639 after, identical command.** Provenance survives: the
finding says `engine: confirm_idor`, not `run_workflow` — `ToolResult.__post_init__` stamps only
when unset, so attribution names who FOUND it, not who last carried it.

The live `enumerate_ids` lead also survives now (`findings=1` at all three layers, was `None` /
`0`).

### Tests — `agent/tests/test_truthful_workflow_findings.py` (14)

Fixtures copied from the two live runs above; nothing invented.

FAILED BEFORE THE FIX, MEASURED — same file against pristine HEAD:

```
$ docker run --rm -v <HEAD+testfile>/agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_truthful_workflow_findings.py -p no:cacheprovider
12 failed, 2 passed in 2.94s
```

The 2 that passed are the negative control (the stub really does emit a finding — assert the input
to the experiment before the output) and the unknown-pack case.

Negative controls included: a step that finds nothing yields `[]` and stamps no log entry; a blocked
prerequisite still carries the key; an unknown step invents no finding; a finding-free
`_run_workflow` reports `0`; scalars pass through untouched.

### Mutation testing, MEASURED — and one mutant that silently FAILED TO APPLY

First attempt used a host `python - <<PY` heredoc. **`python` is not on this Windows host**, so the
mutation never applied and the suite reported `14 passed` — a meaningless "survived" of exactly the
kind the house rules warn about. Caught by grep-verifying the mutated line before trusting the run.
Both mutants below were verified applied by `grep` first.

| mutant | line | result |
|---|---|---|
| M1 — `step_findings = []` (restore sink 1) | `workflow.py:162` verified | **KILLED** — 8 failed, 6 passed |
| M2 — `findings = []` (restore sink 2) | `tools.py` `_run_workflow` verified | **KILLED** — 3 failed, 11 passed |

M1 kills tests on both halves (a dead sink 1 starves sink 2); M2 kills exactly the three
`_run_workflow`-boundary tests, so the two halves are independently pinned.

### WIRING IS EXPLICITLY NOT DONE

`run_workflow` remains an island with no dispatch site. It was NOT wired into anything: a separate
lane judged it UNSOUND as a finding path, and wiring it before the sink was fixed would have spent
real requests on real attacks and reported nothing. Fixing the sink was the ticket.

---

## HANDOFF — two files this lane may not write

### 1. `agent/agent.py:95` — the THIRD sink (Coordinator / agent.py owner)

`agent.py:627` auto-stores a dispatched tool's findings only when the tool name is in
`_AUTO_STORE_TOOLS`; `run_workflow` is not in that set. Sinks 1 and 2 are now fixed, so this is the
last one. One line, in the "investigative + exploitation tools" group:

```diff
     "run_dir_harvest", "confirm_idor", "run_metadata", "run_sourcemap", "test_numeric_abuse",
     "run_cloud_probe",   # public-bucket listing is confirmed-by-oracle; auto-store it (#13, was an island)
+    # Q-054: workflow.run + _run_workflow now FORWARD their steps' findings (measured: a confirmed
+    # CWE-639 survives the live idor_read pack end to end). Without this line a deterministic
+    # mission drops them again at dispatch and the run looks clean.
+    "run_workflow",
```

**Routing is already correct for this** and needs no other change: `_is_confirmed` keys off
`f["confidence"]` BEFORE falling back to the tool name, so a forwarded `confirm_idor` finding
(`confidence=confirmed` + evidence) goes to `/findings`, and a forwarded `enumerate_ids` lead
(`confidence=lead`) goes to Leads. Verified by reading `agent.py:694-712`; not executed by this lane.

This is safe to apply **before** any wiring, and pointless to apply after wiring is forgotten.

### 2. `agent/tests/test_island_soundness.py` — THREE RED TESTS, BY DESIGN (islands lane)

**This is the one thing blocking a fully green tree, and it is not a defect — it is the islands
lane's pins firing because both defects they pinned are now fixed.** Their own docstrings mandate the
update ("STRICT: the day it lands this XPASSes", "If someone fixes tools.py:3202 this test fails and
must be updated in the same commit"). This lane was instructed not to write that file, so the patch
is here instead.

MEASURED — full suite on an isolated snapshot of HEAD plus this lane's Q-054 + Q-055 files:

```
3 failed, 2725 passed, 11 skipped, 9 xfailed in 591.36s
FAILED tests/test_island_soundness.py::test_workflow_carries_its_steps_findings_out
        (strict xfail XPASSED -- the Q-054 fix landed)
FAILED tests/test_island_soundness.py::test_run_workflow_tool_result_carries_them_too
        AssertionError: tools.py:3202 no longer hardcodes []; retire the xfail on
        test_workflow_carries_its_steps_findings_out in the same commit
        assert [{'title': 'Enumerable objects by id (8 in 1..8)', ... 'family': 'idor'}] == []
FAILED tests/test_island_soundness.py::test_native_metadata_reader_sees_binary_exif_gps
        (strict xfail XPASSED -- the Q-055 fix landed)
```

Every other test in the suite is green. `xfailed` fell 11 -> 9 because two strict xfails now XPASS.

Patch:

1. **Delete the `@pytest.mark.xfail(...)` decorator** on
   `test_workflow_carries_its_steps_findings_out` (lines 84-94). The test body already asserts the
   fixed behaviour and passes as written — no body change.
2. In `test_run_workflow_tool_result_carries_them_too`, invert the pinned contract:
   ```diff
   -    assert res.findings == [], (
   -        "tools.py:3202 no longer hardcodes []; retire the xfail on "
   -        "test_workflow_carries_its_steps_findings_out in the same commit")
   +    assert len(res.findings) == 1, "tools._run_workflow stopped forwarding workflow.run's findings"
   +    assert res.findings[0]["family"] == "idor"
   +    assert res.findings[0]["engine"] == "enumerate_ids"   # provenance names the inner producer
   ```
   and update its docstring, which still describes the defect as live.
3. **Delete the `@pytest.mark.xfail(...)` decorator** on
   `test_native_metadata_reader_sees_binary_exif_gps` (lines 249-258). Its body already asserts the
   fixed behaviour and passes as written. Its reason text describes both causes as live; both are
   fixed (`upload_tool.read_exif`, and `libimage-exiftool-perl` in the Dockerfile — the latter needs
   a rebake before `shutil.which("exiftool")` becomes true in a running image, which does not affect
   this test because the native reader now carries the capability alone).
4. `test_wiring_run_workflow_without_auto_store_would_still_drop_everything` (line 126) asserts
   `"run_workflow" not in _AUTO_STORE_TOOLS`. It is **still green today** and must be updated in the
   same commit as handoff item 1 above, not before.

None of these weakens anything: (1), (2) and (3) convert a pin on a DEFECT into a pin on the FIX,
which is what the file was built to do.

### 3. `agent/asvs_model.py:308` — comment now stale (asvs owner)

```
# Q-048: dropped run_workflow. It returns ToolResult(..., []) by design -- its own docstring says
```

`_run_workflow` no longer returns `[]` by design. The Q-048 *decision* (keep `run_workflow` out of
the ASVS attempted-engines set) may still be right — it is still an island with no dispatch site —
but the *reason given* is now false. Re-justify or re-open; this lane did not touch the file.

---

## Q-055 — `run_metadata` reported CLEAN on a photo proven to leak GPS. FIXED.

### Reproduction, MEASURED inside the shipped `apolaki-agent` image

```
$ docker run --rm --network apolaki_default -v <HEAD-snapshot>/agent:/app -w /app \
    apolaki-agent python _repro055.py
exiftool on PATH: None
status=200 bytes=107952 jpeg=True
b'GPS' in data      : False   <-- the fallback's ONLY JPEG branch
b'GPS' in data[:64k]: False
IFD0 tags: ['0x100','0x101','0x10f','0x110','0x11a','0x11b','0x128','0x131','0x132','0x213',
            '0x8769','0x8825']   GPS IFD pointer 0x8825 present: True
extract_metadata(): {}
run_metadata -> output='No sensitive metadata (native)' findings=0
```

Target: `http://juice-shop:3000/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg`.

**Both causes confirmed, and they compose** — fixing either alone leaves the engine broken:

1. `exiftool` is not on PATH in the image, so `shutil.which("exiftool")` is always false and the
   engine ALWAYS takes the native fallback.
2. The fallback's only JPEG branch was `b"GPS" in data[:65536]` — an ASCII substring. Real EXIF
   stores GPS as the BINARY IFD-pointer tag `0x8825`; the characters "GPS" never appear. Measured
   on the file that HAS GPS: `b"GPS" in data == False`.

### Fix

**`agent/upload_tool.py` — a real binary EXIF reader**, `read_exif(data)`:

* `_jpeg_exif_block` WALKS the JPEG segment table to find the APP1 `Exif\x00\x00` segment. It does
  not `data.find(b"Exif\x00\x00")` — that can match inside compressed image data and hand the parser
  a bogus TIFF base. Bare TIFF files are handled too.
* `_read_ifd` parses IFD entries per TIFF 6.0: both byte orders, the 4-byte inline/offset rule,
  per-type component sizes, and follows the ExifIFD (`0x8769`) and GPS IFD (`0x8825`) pointers.
  **Every read is bounds-checked**, so truncated or hostile input yields fewer tags rather than an
  exception — a raise here would be caught upstream and become an invisible false negative for the
  whole engine, which is this ticket's own defect class. Nothing can raise, so nothing needs a
  swallow.
* `_dms` converts rationals to DMS + decimal. A **missing hemisphere ref is a real input**: the
  coordinate is ambiguous and is labelled `(no hemisphere ref)` rather than silently defaulted to
  North/East. Out-of-range values report nothing rather than nonsense.
* The ASCII `b"GPS"` branch is **deleted**, not kept alongside. It was a guaranteed false negative on
  real EXIF *and* a false-positive surface on any JPEG whose comment contains the letters "GPS". A
  parser supersedes it in both directions. Where the GPS IFD pointer is present but no coordinate
  decodes, the reader says exactly that (`EXIF:GPSIFDPresent`), keyed on the binary tag observed.
* EXIF keys are namespaced `EXIF:` and merged LAST, so XMP and binary EXIF can no longer hide each
  other. The old code suppressed its EXIF branch whenever XMP had already produced a `GPSLatitude`.

**`agent/Dockerfile` — `libimage-exiftool-perl` added.** The exiftool question, decided explicitly:

* **MEASURED cost: +67.2 MB** filesystem delta including apt lists (the build's `rm -rf` reclaims
  those; net ~64 MB), i.e. **+2.3% on the 2.81 GB image**. It pulls `perl`, `perl-modules-5.36`,
  `libperl5.36`, `libgdbm-compat4`. Installed version 12.57.
* **Why buy it:** `run_metadata`'s docstring has always advertised "exiftool or native" while the
  image did not have it — an engine advertising capability its container does not have, which is
  this lane's whole theme. exiftool also covers containers the native reader genuinely cannot: PNG
  eXIf/tEXt, WebP, HEIC, MP4/MOV `moov` GPS, office documents.
* **It is an addition, not a dependency.** `read_exif` carries JPEG/TIFF EXIF alone, so a failed apt
  leaves the GPS capability intact instead of reinstating the false negative. The apt line is
  best-effort by design and stays that way.
* **NEEDS A REBAKE.** These measurements were taken by installing the identical Debian package into
  a throwaway container at runtime, not by rebuilding the image. The Dockerfile line does nothing
  until `apolaki-agent` is rebuilt (Coordinator's bake step).

### Proof, MEASURED (live, same URL)

```
== POSITIVE CONTROL ==
  output='metadata extracted (native)' findings=1
  severity=medium family=exposure conf=lead
  evidence:
    EXIF:Make: Google
    EXIF:Model: Pixel 3 XL
    EXIF:Software: paint.net 4.2
    EXIF:GPSLatitude: 59 deg 25' 16.17" N
    EXIF:GPSLongitude: 24 deg 48' 4.32" E
    EXIF:GPSPosition: 59.421158, 24.8012
    EXIF:GPSDateStamp: 2019:10:22
```

Character-for-character the coordinates the islands lane decoded by hand out of the GPS IFD:
**59 deg 25' 16.17" N, 24 deg 48' 4.32" E**. Was `findings=0`, "No sensitive metadata".

**Independent cross-validation.** The same script run with exiftool 12.57 installed reports
`GPSLatitude 59.4211583333333`, `GPSLongitude 24.8012`; the native reader reports `59.421158`,
`24.8012` — two independent implementations agreeing to 6 dp. exiftool additionally surfaces
GPSAltitude 71.4, GPSTimeStamp 14:12:15, GPSDOP 60.421 and ProfileCreator GOOG, which is the extra
coverage the +64 MB buys.

### THE NEGATIVE CONTROL, RE-MEASURED — the FP record is intact

The engine scored 0 false positives on 14 negative controls before this change. Re-measured after it
on **17** (the documented 14 plus three more real uploaded images), on both code paths:

```
native path:   negative controls: 17, findings on them: 0
exiftool path: negative controls: 17, findings on them: 0
```

10 product images (jpg/jpeg/png), a PDF, the SPA index, the `/api/Products` JSON, a soft-404, a
Markdown file, and two more uploads. **No false positive was traded for the false-negative fix.**

### Tests — `agent/tests/test_truthful_metadata.py` (39)

FAILED BEFORE THE FIX, MEASURED: `33 failed, 6 passed` against pristine HEAD, including
`test_the_engine_now_reports_the_leak_end_to_end` with the literal
`AssertionError: No sensitive metadata (native)`.

Positive/negative-control tests are LAB-GATED, following `test_island_soundness.py`: the only honest
fixture for the positive case is the file the target actually serves, and this lane will not invent a
JPEG carrying GPS. A skip is an ABSENT measurement, never a pass. The parser-robustness tests are
lab-independent and DO construct byte strings — legitimately, since the property under test is
"malformed input must not raise" and malformed input has no real-world original.

Mutation testing, all verified applied by grep first:

| mutant | result |
|---|---|
| M3 — GPS IFD pointer never followed (the false negative, reinstated) | **KILLED** — 3 failed |
| M4 — hemisphere ref ignored (S/W lose their sign) | **KILLED** — 2 failed |
| M5 — segment walk replaced by `data.find(b"Exif\x00\x00")` | **KILLED** — 1 failed, by the exact intended assertion |

M5's first attempt was applied with `sed`, which turned `\x00` into a literal NUL and corrupted the
file; the run reported `1 error`, not a pass. Re-applied through a Python mutator and re-verified.

---

## Q-055b — the bfla mirror. UNVERIFIED on arrival; **REPRODUCED**, and worse than suspected. FIXED.

### Established AT THE WIRE first, on pristine HEAD

Patching `tools._target_client` — BELOW `_http_send` — because `_run_bfla` builds its own client and
never calls `_http_send`, so every existing authz test (which patches `_http_send`) leaves the line
under test unexecuted. Registry constructed WITH a mission session:

```
registry session_headers: {'Cookie': 'session=MISSION-IDENTITY'}

requests actually sent (9):
  GET     http://target.tld/api/admin/users/1           identity=ANONYMOUS
  GET     http://target.tld/api/admin/users/1           identity=ANONYMOUS
  POST    http://target.tld/api/admin/users/1           identity=ANONYMOUS
  POST    http://target.tld/api/admin/users/1           identity=ANONYMOUS
  PUT     http://target.tld/api/admin/users/1           identity=ANONYMOUS
  PUT     http://target.tld/api/admin/users/1           identity=ANONYMOUS
  PATCH   http://target.tld/api/admin/users/1           identity=ANONYMOUS
  PATCH   http://target.tld/api/admin/users/1           identity=ANONYMOUS
  GET     et.tld/api/admin/users/bbh-nonexistent-de7fdc identity=ANONYMOUS

distinct identities on the wire: {'[]'}
findings: 0 -> []
```

**CONFIRMED.** `test_headers = dict(inp.get("headers") or {})` fed `c.request` directly, bypassing
`_merge_identity`, so the AUTHENTICATED row was anonymous — the exact mirror of the Q-032 defect.

### It is worse than a wrong row: the oracle was VACUOUS

`authz.analyze_methods` skips any method whose ANONYMOUS row is also 2xx (`# already public — not an
authz gap for this token`). With two byte-identical rows that guard fires on every method, so the
BFLA oracle **could not emit a finding on any target, ever**. Not a degraded oracle — a disabled one.

And no production caller supplies headers: `agent.py:977` and `agent.py:3193` both dispatch
`{"url": ...}`. `agent.py:970` gates the dispatch on `has_session = bool(self.tools.session_headers)`,
**discards that session**, and on the empty result records the literal evidence string
`"privileged control correctly denied the low-priv session"` — a claim about a control that was never
tested, produced by an oracle that never ran. Same shape as the 626 stored findings printing a
control claim that never ran.

### Fix (`agent/tools.py::_run_bfla`)

* Identity now goes through `_merge_identity`, the one place a request's identity is decided: a named
  `session=` persona wins, then explicit `headers`, and with neither the authenticated row inherits
  the mission session — which IS the low-privilege identity `agent.py:970` gated on.
* The control row is an explicit `Identity()`, so it is anonymous **by construction** rather than by
  accident. Fixing the authenticated row must not authenticate the control row; that is the very
  defect this one mirrors.
* **When no identity exists anywhere the engine SAYS SO** instead of reporting a clean sweep. An
  empty header dict is a real input: the two rows would be the same request and the differential
  proves nothing, so `analyze_methods` is suppressed and the output reads `BFLA method differential
  NOT RUN — no identity available`. Reporting `0 authorization signal(s)` there is indistinguishable
  from a real clean sweep, which is exactly this lane's theme.
* The side-channel oracle (`analyze_side_channel`, CWE-204) still runs when the differential is
  vacuous — it needs no authed/anon comparison, and suppressing it too would be a second false
  negative.
* **Three bare `except Exception: pass` handlers replaced with `self._swallow`.** A dropped row
  removes a method from the sweep and produces output byte-identical to "the token could not reach
  it".

### A SECOND defect, found by this ticket's own test

`test_an_unknown_persona_degrades_to_anonymous_not_to_the_mission` failed on the FIXED code. Cause:
`_resolve_headers` returns an `Identity` only when `role in self._sessions`; a role that was **named
but never minted** falls through as a plain dict and therefore inherits the mission session at
`_merge_identity`. `_identity`'s own docstring states the opposite contract ("An unknown role returns
`Identity()` = anonymous, never the mission session") — but `_resolve_headers` never calls it on that
path. Naming a role IS expressing an identity opinion.

Fixed locally in `_run_bfla`, where the oracle's soundness depends on it.

**HANDOFF (sessions lane / Q-032 owner): the same hole is in `_resolve_headers` itself**
(`tools.py:1698`), shared by ~40 engines. Any engine that names a persona which failed to mint
silently runs as the mission instead of as nobody. It was NOT fixed globally here: `_resolve_headers`
has many callers whose fallback expectations this lane has not measured, and a blind change there is
the kind of wide-blast-radius edit that needs its own negative controls.

### Proof, MEASURED at the wire after the fix

```
requests actually sent (9):
  GET     .../api/admin/users/1   identity={'Cookie': 'session=MISSION-IDENTITY'}
  GET     .../api/admin/users/1   identity=ANONYMOUS
  POST    .../api/admin/users/1   identity={'Cookie': 'session=MISSION-IDENTITY'}
  POST    .../api/admin/users/1   identity=ANONYMOUS
  ... PUT, PATCH, and the nonexistent-id probe as the authenticated identity ...
distinct identities on the wire: {'[]', "[('cookie', 'session=MISSION-IDENTITY')]"}

=== named persona (session=lowpriv) ===
  GET  identity={'Authorization': 'Bearer LOWPRIV-TOKEN'}      <-- no mission Cookie bleed
  GET  identity=ANONYMOUS

=== NO identity anywhere ===
  output: 0 authorization signal(s); BFLA method differential NOT RUN — no identity available
          (no session= role, no headers, no mission session), so the 'authorized' and 'anonymous'
          rows would be the same request
```

### Tests — `agent/tests/test_truthful_bfla_identity.py` (15)

FAILED BEFORE THE FIX, MEASURED: `11 failed, 4 passed` against pristine HEAD.

Includes `test_a_real_bfla_is_now_emitted_which_was_impossible_before` (a privileged endpoint that
200s to a token and 401s to nobody now yields CWE-285 findings) and its negative control
`test_a_genuinely_public_endpoint_still_emits_no_bfla` (200 to both rows still emits nothing — fixing
a false negative must not buy a false positive on every public API).

Mutation testing, all verified applied by grep first:

| mutant | result |
|---|---|
| M6 — identity reverted to the raw caller dict (the original defect) | **KILLED** — 8 failed |
| M7 — control row becomes the authenticated row (the Q-032 shape mirrored back) | **KILLED** — 6 failed |
| M8 — `vacuous = False` (a differential that cannot run reported as clean) | **KILLED** — 3 failed |

### A BEHAVIOUR CHANGE WORTH NAMING

`_run_bfla`'s POST/PUT/PATCH probes now carry an identity where before they went out anonymous. That
is the engine finally doing what its own docstring and `authz_tool`'s method sweep always described —
"send write methods with a token that SHOULD NOT be authorized" — and it is what makes the oracle
non-vacuous. It stays inside the existing guards: `run_bfla` is `PermissionLevel.INTRUSIVE`, so it
cannot fire without the HITL approval or `auto_approve`, scope is enforced inside `execute()`, and
DELETE remains opt-in (`test_delete_stays_opt_in` pins that, because the identity change is exactly
what would make a DELETE reach real state). Bodies are still the inert `{}`.

### HANDOFF — `agent/agent.py:970` (Coordinator / agent.py owner)

Two lines in the `fam == "bfla"` validator branch, both now wrong in a way this lane cannot fix:

1. It computes `has_session = bool(self.tools.session_headers) or ...`, then dispatches
   `{"url": ...}` — **discarding the very session it just gated on**. That now resolves correctly by
   accident (the mission session is inherited inside `_run_bfla`), but the intent should be explicit:
   pass the low-privilege persona through, e.g. `{"url": ..., "session": "<lowpriv role>"}` once one
   is minted, so the row under test is the LOW-PRIVILEGE identity rather than whatever the mission
   currently holds.
2. On `r.findings == []` it records `"privileged control correctly denied the low-priv session"`.
   `_run_bfla` now distinguishes "ran and found nothing" from "could not run the comparison", and
   says so in `r.output` (`BFLA method differential NOT RUN — no identity available`). That branch
   should read `r.output` and record BLOCKED rather than DISMISSED when the differential did not run;
   otherwise it keeps printing a control claim for a control that was never tested.
