# Builder lane - recall gaps (defect 1) and falsy credential-probe target (defect 2)

Lane: BUILDER. Written as I go. Every row is MEASURED (command + real output) or UNVERIFIED.
Source of the two defects: `docs/handoff/breaker-v16.md` sections 6.2 and 4.1, mission `bed9ffcd`,
target `http://mutillidae` (compose hostname, reachable only from inside the apolaki docker network).

Write set for this lane: this file, `agent/agent.py`, `agent/exposure_tool.py`,
`agent/tests/test_autoindex_discovery.py`, `agent/tests/test_credential_probe_target.py`.

STATUS: in progress.

## 0. Plan

1. Reproduce defect 1 (recall gap on `/passwords/accounts.txt`) and MEASURE which of the three
   candidate causes is the real one.
2. Reproduce defect 2 (falsy default at `agent/agent.py` ~1928).
3. Fix, mutation-test both fixes plus both over-correction mutants.

---

## 1. DEFECT 1 - REPRODUCED. Root cause MEASURED, and it is NOT what I would have guessed.

Every step of the harvest chain ALREADY WORKS. The engine has a browsable-directory harvester
(`tools.py::_run_dir_harvest` -> `exposure_tool.looks_like_listing` / `parse_listing` /
`is_harvestable` / `_SENSITIVE_SIG`). Fed the listing by hand, it does the right thing at every
stage. It was never fed the listing.

Command (read-only, inside the shared container):

```
MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
import sys; sys.path.insert(0,'/app')
import httpx, exposure_tool as exp
c = httpx.Client(timeout=25, follow_redirects=True)
r = c.get("http://mutillidae/passwords/?C=N;O=D")
print("GET /passwords/?C=N;O=D ->", r.status_code, "len=%d" % len(r.text))
print("looks_like_listing:", exp.looks_like_listing(r.text))
print("parse_listing     :", exp.parse_listing(r.text))
for fp in exp.parse_listing(r.text):
    print("   is_harvestable(%r) = %s" % (fp, exp.is_harvestable(fp)))
f = c.get("http://mutillidae/passwords/accounts.txt")
print("GET accounts.txt ->", f.status_code, "len=%d" % len(f.text))
print("_SENSITIVE_SIG match:", bool(exp._SENSITIVE_SIG.search(f.text)))
print("DIR_CANDIDATES     :", exp.DIR_CANDIDATES)
print("'passwords' in it  :", "passwords" in exp.DIR_CANDIDATES)
print(".txt in _HARVEST_EXT:", ".txt" in exp._HARVEST_EXT)
PY
```

Real output:

```
GET /passwords/?C=N;O=D -> 200 len=946
looks_like_listing: True
parse_listing     : ['accounts.txt']
   is_harvestable('accounts.txt') = True
GET accounts.txt -> 200 len=929
_SENSITIVE_SIG match: True
DIR_CANDIDATES     : ['ftp', 'uploads', 'upload', 'files', 'file', 'backup', 'backups', 'download',
                      'downloads', 'data', 'public', 'static', 'encryptionkeys', 'attachments',
                      'documents', 'media']
'passwords' in it  : False
.txt in _HARVEST_EXT: True
```

### 1.1 The three candidate causes, adjudicated

| Candidate cause from the brief | Verdict | Deciding measurement |
|---|---|---|
| "content discovery only tries a fixed wordlist and never follows links found in an autoindex listing" | **CONFIRMED - this is the cause** | `_run_dir_harvest` iterates `exp.DIR_CANDIDATES[:20]` and nothing else. 16 hardcoded names; `passwords` is not one. The observed listing is never an input to the engine. |
| "the exposure engine only flags a fixed set of filenames" | TRUE of the *other* engine, NOT the cause here | `EXPOSURE_CHECKS` is 15 fixed paths (`.git/HEAD`, `.env`, ...). But `_run_dir_harvest` is already content-driven and does not use that list, so this is not what suppressed the file. |
| "a static-extension filter that skips `.txt`" | **DISPROVED** | `.txt in _HARVEST_EXT` -> `True`. `is_harvestable('accounts.txt')` -> `True`. `.txt` was never filtered. |

### 1.2 The mission HAD the listing. Measured from its own database.

```
MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
import sqlite3
c=sqlite3.connect('file:/app/data/bbh.db?mode=ro', uri=True)
n=0
for row in c.execute("SELECT * FROM exchanges WHERE mission_id='bed9ffcd'"):
    if "/passwords" in str(row): n+=1
print("exchange rows mentioning /passwords:", n)
PY
```

```
exchange rows mentioning /passwords: 3
   HIT: ... '{"url": "http://mutillidae/passwords/?C", ...
   HIT: ... '{"url": "http://mutillidae/passwords/?C", ...
   HIT: ... '{"url": "http://mutillidae/passwords/?C=N;O=D", ...
```

So the fetch happened three times. Every downstream stage would have said yes. The engine's only
source of directories to harvest is a 16-word list written by hand, so a directory the crawler
actually walked is invisible to it. **A directory listing we already fetched is a list of real
files, and the harvester never sees it.**

### 1.3 A SECOND, independent defect found while measuring: the content oracle is unsound BOTH ways

`_SENSITIVE_SIG` is a substring regex (`password|passwd|secret|api[_-]?key|...`). Measured on four
real bodies across three labs:

```
  mutillidae/passwords/accounts.txt              SENSITIVE=True  match='password'
  mutillidae/robots.txt                          SENSITIVE=True  match='password'
  bwapp/robots.txt                               SENSITIVE=True  match='password'
  dvwa/robots.txt                                SENSITIVE=False match=''
```

- **False positive:** `robots.txt` on two of three labs matches, because it contains
  `Disallow: /passwords/`. A robots file is not a credential exposure. Had `passwords` merely been
  added to the wordlist, the engine would have shipped `robots.txt` as a HIGH "Exposed sensitive
  file" on two labs.
- **The true positive is luck.** The only reason `accounts.txt` matched is that ten of its rows
  contain a password whose literal value is the word `password`
  (`4,jeremy,password,d1373 1337 speak,Admin`). A credential dump using real passwords would not
  contain the substring `password` anywhere and would be silently skipped.

So "add `passwords` to the wordlist" is not only a benchmark-specific signature (forbidden), it
would also have been wrong. The file has to be judged on the STRUCTURE of its content.

(fix + mutation results below)

---

## 2. DEFECT 2 - REPRODUCED, and the stated mechanism is DISPROVED

The Breaker's hypothesis (breaker-v16.md 4.1b) was:

> `_discover_login_url` returned falsy for mutillidae [...] and the `or` fell through to a guessed
> `/login`.

**That is not what happens.** MEASURED:

```
MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
import sys; sys.path.insert(0,'/app')
import agent as A, httpx
class FakeIntel:
    def get(self, kind): return []
class FakeTools:
    urls = []                      # the mutillidae case: nothing login-ish was harvested
    intel = FakeIntel()
class FakeScope:
    def validate(self, u): return (True, "")
o = object.__new__(A.BBHAgent); o.tools = FakeTools(); o.scope = FakeScope()
d = A.BBHAgent._discover_login_url(o, "http://mutillidae")
print("  _discover_login_url ->", repr(d))
print("  is it falsy? ->", not bool(d))
print("  did the trailing `or base+'/login'` fire? ->", d is None)
c = httpx.Client(timeout=20, follow_redirects=False)
for u in ["http://mutillidae/login", "http://mutillidae/index.php?page=login.php"]:
    r = c.get(u); b = r.text or ""
    print("  %-46s HTTP %s len=%-6d <form=%d password-input=%d"
          % (u, r.status_code, len(b), b.lower().count("<form"), b.lower().count('type="password"')))
PY
```

Real output:

```
  _discover_login_url -> 'http://mutillidae/login'
  is it falsy? -> False
  did the trailing `or base+'/login'` fire? -> False

  http://mutillidae/login                        HTTP 404 len=278    <form=0 password-input=0
  http://mutillidae/index.php?page=login.php     HTTP 200 len=54989  <form=2 password-input=1
```

**`_discover_login_url` returned the guessed `/login` itself.** The falsy default lives INSIDE that
function (`agent.py:3110`, `cands.append(base.rstrip("/") + "/login")`, docstring: "else a common
default"), not at line 1928. The `or base.rstrip("/") + "/login"` at 1928 is DEAD CODE on this path -
it can only fire if the base is out of scope, in which case nothing runs anyway.

This matters: the patch proposed in breaker-v16.md (delete the trailing `or` at 1928 and
`return events`) **would have changed nothing.** Both halves of the fix have to be checked.

### 2.1 WHY discovery came up empty - a second, general defect

The mission DID see the real login. MEASURED from its own exchanges:

```
distinct URLs in mission exchanges: 534
login-ish URLs the mission ACTUALLY saw: 3
    http://mutillidae/includes/index.php?page=login.php
    http://mutillidae/includes/pop-up-help-context-generator.php?pagename=login.php
    http://mutillidae/index.php?page=login.php?do&popUpNotificationCode

would the CURRENT regex r"/(login|signin|sign-in|session|auth)\b" match them?
   match=False http://mutillidae/includes/index.php?page=login.php
   match=False http://mutillidae/includes/pop-up-help-context-generator.php?pagename=login.php
   match=False http://mutillidae/index.php?page=login.php?do&popUpNotificationCode
```

The discovery regex requires a `/` immediately before the keyword, so a **query-routed** login
(`?page=login.php`, `?action=login`) is invisible to it. That is general: query-routed pages are the
normal shape for a large family of PHP applications.

### 2.2 But broadening the regex is NOT sufficient either - MEASURED

I checked whether the three URLs the crawler actually recorded are usable login surfaces:

```
http://mutillidae/index.php?page=login.php?do&popUpNotificationC  HTTP 200 len=44935 <form=1 password-input=0
http://mutillidae/includes/index.php?page=login.php               HTTP 404 len=291   <form=0 password-input=0
```

Neither is. The first has a doubled `?` so `page` resolves to `login.php?do`, which renders a page
with no password input; the second is a 404. Only the clean
`http://mutillidae/index.php?page=login.php` (which the crawler never recorded) carries the password
input.

**So a name-shaped login URL is not a login endpoint, in exactly the same way a name-shaped
`accounts.txt` is not a credential file.** Both defects have the same shape: a decision made on the
STRING instead of on what the response actually contains. The fix is symmetric - verify the
candidate is a real login surface (reachable AND carrying a password input) before probing it, and
if none is, report NOT TESTED.

---

## 3. WHAT CHANGED

### 3.1 Defect 1 - `agent/exposure_tool.py` (three defects, any one sufficient)

1. **Discovery.** New `observed_directories()` / `directory_candidates()`. Candidates now come
   from the URL surface the engagement actually walked (facts) before `DIR_CANDIDATES` (guesses).
   Same-origin only; a path without a trailing slash contributes only its parents, so
   `/.git/logs/HEAD` yields `.git` and `.git/logs` and never a `HEAD/` request. With no observed
   surface it returns exactly today's list, so it cannot make an existing run worse.
2. **Resolution.** `parse_listing(html, base_url="")`. Hrefs now resolve against the listing's own
   final URL. Omitting `base_url` preserves the old contract exactly.
3. **Judgement.** `classify_content()` replaces the substring oracle with structural detectors:
   key material, SQL dump, credential-table shape, secret assignment, documentary marker.
   `_SENSITIVE_SIG` is now a duck-typed object exposing `.search()`, so the corrected judgement
   reaches the live harvest path through the existing call site in `tools.py` **without editing a
   file this lane does not own**. `harvest_finding()` grades, titles and CWEs from what was proven,
   and evidence is the redacted STRUCTURE - it used to be `snippet[:300]`, i.e. the raw body, which
   for a credential dump copies every plaintext password into the finding, the report and the DB.

### 3.2 Defect 2 - `agent/agent.py`

- `_discover_login_url(base, allow_guess=True)`. Default unchanged, so the two other callers keep
  their behaviour; the credential probe passes `allow_guess=False`.
- New `_login_surface(url)`. Excludes only on POSITIVE evidence: a 404/410, or a page that
  rendered fine (2xx/3xx HTML) and is not a login form. An error status is not evidence of
  absence, because a GET is not the method an API login answers - MEASURED, juice-shop's real
  login answers a GET with `HTTP 500 Error: Unexpected path: /rest/user/login`.
- With no such URL, no probe is fired. The finding records
  `credential_verification="not_tested"`, its text claims nothing about the credential, and
  `target` is a URL that was actually used rather than a guess.

### 3.3 THE WIRING I DO NOT OWN - `agent/tools.py::_run_dir_harvest`

The judgement half lands through the existing `_SENSITIVE_SIG.search()` call. The DISCOVERY and
RESOLUTION halves need two lines in `tools.py`, which another lane owns. Until this is applied the
recall gap stays open in production, because `accounts.txt` is never fetched:

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ async def _run_dir_harvest(self, inp: dict) -> ToolResult:
-            for d in exp.DIR_CANDIDATES[:20]:
+            # A directory the crawler already walked is a FACT; DIR_CANDIDATES is a guess list.
+            for d in exp.directory_candidates(origin, getattr(self, "urls", None))[:40]:
                 if harvested >= 60:
                     break
                 r = await get(origin + "/" + d)
                 if r is None or r.status_code != 200 or not exp.looks_like_listing(r.text):
                     continue
-                for fp in exp.parse_listing(r.text):
+                # Resolve against the listing's OWN final URL: Apache mod_autoindex emits bare
+                # file names, and joining those to the origin requests the web root.
+                for fp in exp.parse_listing(r.text, str(r.url)):
```

Both new signatures are backward compatible, so this diff is safe to apply at any time.

### 3.4 MEASURED end-to-end, replaying the real harvest loop against the live labs

```
=== BEFORE: shipping behaviour (guessed dirs, origin-join) ===
### DIR_CANDIDATES + parse_listing(html)             -> 0 finding(s)

=== AFTER: observed dirs first + listing-relative resolution ===
### directory_candidates + parse_listing(html,url)   -> 1 finding(s)
      Exposed credential store: accounts.txt | high | credential_exposure | CWE-522
      target  : http://mutillidae/passwords/accounts.txt
      evidence: credential-table shape: 23 rows, ','-delimited, column 1 is a near-unique
                identifier (distinct ratio 0.957) and column 2 an adjacent whitespace-free token
      plaintext secrets in evidence: NONE

RECALL GAP CLOSED: True

=== NO REGRESSION on juice-shop (the one target that already worked) ===
### juice-shop BEFORE -> 1 finding(s)      ### juice-shop AFTER -> 1 finding(s)
```

Classification across 4 labs on live bodies: **11/11 correct, 0 false positives.**
`_login_surface` across 4 labs: **7/7 correct** - rejects the guessed `/login` (404) and both
unprobeable crawled URLs, accepts mutillidae's real login, juice-shop's API login, dvwa and bwapp.

---

## 4. MUTATION RESULTS - all four mutants KILLED

Run against a COPY of the tree in a throwaway container (`cp -r /app /work`), never the shared
tree. Baseline green before and after every mutant.

| # | Mutant | Result | Test that killed it (the INTENDED assertion) |
|---|---|---|---|
| M1 | defect-1 core: "ignore files named by a directory listing" (`observed_directories` returns `[]`) | **KILLED** | `test_observed_directory_becomes_a_harvest_candidate` (+2 more) |
| M2 | defect-2 core: "restore the falsy default" (`cands.append(base + "/login")` unconditionally) | **KILLED** | `test_discovery_without_a_guess_returns_nothing_when_nothing_was_seen` |
| M3 | over-correction 1: "treat every .txt as a credential exposure" | **KILLED** | `test_robots_txt_is_not_a_credential_exposure` (+3 more) |
| M4 | over-correction 2: "probe anything even without a real login URL" | **KILLED** | `test_over_correction_probe_anything_is_rejected` (+5 more) |

Verbatim, per mutant:

```
M1 ignore listing-named files:
      FAILED test_observed_directory_becomes_a_harvest_candidate
      FAILED test_a_url_without_a_trailing_slash_does_not_invent_a_directory
      FAILED test_another_hosts_directory_is_not_this_hosts_surface

M3 every file is a credential exposure:
      FAILED test_robots_txt_is_not_a_credential_exposure
      FAILED test_a_plain_text_file_is_not_sensitive_by_virtue_of_being_text
      FAILED test_documentation_of_a_default_password_is_not_a_leaked_config
      FAILED test_a_decode_artefact_never_reaches_the_evidence_string

M2 restore the falsy default:
      FAILED test_discovery_without_a_guess_returns_nothing_when_nothing_was_seen

M4 probe anything:
      FAILED test_an_empty_url_is_never_a_login_surface
      FAILED test_an_out_of_scope_url_is_never_probed
      FAILED test_a_transport_failure_is_not_treated_as_a_login_surface
      FAILED test_over_correction_probe_anything_is_rejected
```

### 4.1 The flood M3 would have caused, QUANTIFIED across 4 labs

A fix that floods the report is a different defect, so this was measured rather than asserted:

```
=== FIX ===                        === M3 OVER-CORRECTION ===
  mutillidae        2                mutillidae        3
  juice-shop        1                juice-shop        5
  dvwa              0                dvwa              0
  bwapp             0                bwapp             0
  TOTAL:            3                TOTAL:            8
```

2.7x the volume, and every M3 row is MIS-TITLED "Exposed credential store" - including
`legal.md` (lorem ipsum), `announcement_encrypted.md` and `premium.key`. That is the Host-header
failure mode from breaker-v16.md section 3.1 repeating in a new engine.

---

## 5. HONEST LIMITS / open items

1. **The recall gap is not closed in production until the `tools.py` diff in 3.3 is applied.** The
   judgement half is live now; the discovery and resolution halves are not.
2. **`premium.key` is still missed** (`http://juice-shop:3000/encryptionkeys/premium.key`, body
   `1337133713371337.EA99A61D92D2955B1E9285B55BF2AD42`). MEASURED: the OLD oracle missed it too,
   so this is not a regression. A "whole file is one high-entropy hex/base64 token" detector would
   catch it, but it would also fire on every checksum file, so I did not add one under time
   pressure. Recorded as a known gap rather than guessed at.
3. **New true positive found by the fix:** `http://mutillidae/documentation/Mutillidae-Test-Scripts.txt`
   classifies as `secret_assignment` on a documented `--password=samurai` command line. Real, but
   it is documentation rather than config - a reviewer may want it graded below a leaked config.
4. **The mangled `root<U+FFFD>` username itself is NOT fixed.** Its cause is in
   `agent/intel.py::harvest_credentials`, which this lane does not own; breaker-v16.md 8.2 records
   it as UNVERIFIED. Defect 2's fix removes the false TARGET, not the false username. I did fix
   the same U+FFFD shape where it was about to reappear in my own evidence builder.

## 6. Commits

```
98f4def  Q-173 reproduction: the listing was fetched three times and never harvested
23f5545  Q-174 reproduction: the falsy default is not where the report said it was
07ae496  Q-173 fix: a directory listing we already fetched is a list of real files
8e25e3e  Q-174 fix: an absent login URL means NOT TESTED, not a probe against a 404
3379dd2  Q-173: a decode artefact must never reach a report as observed text
```

STATUS: COMPLETE. 31 new tests; scoped suite 266 passed, 1 opt-in skip
(`test_whole_product_reach.py`, run separately with `APOLAKI_LIVE_LAB=1`: 7 passed).
No filename, path or lab id is hardcoded in either fix.
