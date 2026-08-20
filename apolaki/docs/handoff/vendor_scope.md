# Q-083 — the code-assisted lane confirms a MEDIUM inside a vendored minified bundle

Lane: **vendor-scope** (Builder). Owns `agent/codeintel.py`, new tests under `agent/tests/`, this file.

The ticket is **"reports a finding it cannot justify at that confidence, in code the client does not
own"** — NOT "false positive". Whether that `Math.random()` feeds a security-relevant value is
UNKNOWN and nothing below claims otherwise. Proving it false means binding the value's use (the
Q-042 discipline) and that work is not done here either.

---

## 1. Apparatus — POSITIVE CONTROL

The findings DB is in the named volume `apolaki_bbh_data`, mounted at `/app/data` in
`apolaki-agent-1` (`docker-compose.yml`, `bbh_data:/app/data`). A throwaway container that mounts
only `agent:/app` sees an empty `/app/data` and every count returns 0.

```
$ docker run --rm -v apolaki_bbh_data:/data -v <scratch>:/work -w /work apolaki-agent \
    python /work/measure.py
POSITIVE CONTROL: findings=1773 missions=114
source-derived=716
source-derived by mission: [('2fb87a3a', 716)]
```

**Matches the brief exactly: 1773 findings / 114 missions / 716 source-derived, all from `2fb87a3a`.**
The apparatus was looking; every zero below is a measured zero.

---

## 2. BLAST RADIUS — MEASURED BEFORE ANY CHANGE

### 2.1 On the stored corpus (all 716 source-derived findings)

```
distinct source-derived targets: 562
findings by target extension: [('.java', 715), ('.js', 1)]
NON-.java targets (file, findings): [('webapp/js/jquery.min.js', 1)]
findings by top-level segment: [('java', 715), ('webapp', 1)]
```

**1 finding of 716 = 0.141%.** One file of 562.

### 2.2 The mission tree, re-run at HEAD — the baseline reproduces exactly

Tree pulled from the lab container, the documented reproduction path (it is not vendored in the repo):

```
$ docker cp apolaki-owaspbench-1:/owasp/BenchmarkJava/src/main ./benchmain
$ docker run --rm -v <HEAD-snapshot>/agent:/app -v ./benchmain:/tree:ro apolaki-agent \
    python /work/baseline.py
files_scanned=2766 findings=716 error=''
by_cwe: [('CWE-327', 261), ('CWE-328', 153), ('CWE-330', 219), ('CWE-501', 83)]
SCANNED files by ext: [('.java', 2763), ('.js', 3)]
non-.java finding files: [('webapp/js/jquery.min.js', 1)]
scanned *.min.js files: ['webapp/js/jquery.min.js']
```

2766 files and 716 findings, identical to the mission. **The baseline is a real baseline, not a
recollection.** `baseline.json` (file list + every finding's file/cwe) is the diff target for any
change.

### 2.3 What that number means, and what it does NOT

The blast radius on the corpus that produced the ticket is **one row**. That is a real measurement of
a **biased corpus**: mission `2fb87a3a` scanned a Java benchmark suite that happens to carry exactly
one stray vendored bundle. It says almost nothing about what the same heuristic does to a real
JavaScript application, so §3 measures that separately rather than generalising from 1/716.

---

## 3. Real trees — where the heuristic would actually bite

Corpora **copied from reality** (running lab containers), never invented.

### 3.1 Juice Shop, realistic layout (`frontend/dist` intact + first-party `routes/lib/models/data`)

```
juiceshop-realistic(dist intact)       files=115   findings=11
          5  routes/captcha.ts
          4  data/datacreator.ts
          2  lib/insecurity.ts
```

**11 findings, 11 first-party, 0 in a bundle.** `_SKIP_DIRS` already contains `dist`, so on an app
that keeps its build output in a conventionally-named directory the lane is *already* clean. This is
the positive control for "the existing skip list is not useless".

### 3.2 The specimens — what a bundle actually looks like

Two REAL minified files, and they do not share a naming convention:

```
$ head -c 200 benchmain/webapp/js/jquery.min.js
/*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Foundation, Inc. | jquery.org/license */
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?...

$ head -c 200 js_dist/frontend/main.js
import{a as jp,c as qp,d as Gp,e as Wp,f as Qp,i as $p,j as Or,k as Ua}from"./chunk-5K74DZ2F.js";...
```

**Juice Shop's 35 bundle files are named `main.js`, `polyfills.js`, `scripts.js`,
`chunk-<HASH>.js`, `about.component-<HASH>.js`. Not one ends in `.min.js`.**

That is a measured refutation of the obvious fix: **a `*.min.js` filename rule catches the jQuery
specimen and misses every modern bundler output** (esbuild/webpack/Vite/Angular). A filename rule
alone is not a vendor heuristic, it is a heuristic for one 2015 naming convention.

### 3.3 The cost, measured per file

Per-file timing of `codereview.summarize_units` + `review_source` on the real bundles:

```
    1.04s    88954 B     15 lines   54499 maxline   0 finds  frontend/about.component-NNIY6N42.js
   19.97s   484924 B      5 lines  219830 maxline   1 finds  frontend/chunk-BDIM6GZO.js
   21.54s   517955 B     25 lines  163024 maxline   3 finds  frontend/chunk-IWJKTZIN.js
    3.20s   138859 B     38 lines   92536 maxline   0 finds  frontend/chunk-NWDAIMF4.js
    0.46s    96238 B    532 lines   29867 maxline   0 finds  frontend/chunk-OKA37M7B.js
```

**~20 seconds per half-megabyte bundle**, to produce findings reported at a line number that is the
whole file. The first attempt to measure this corpus was killed by a 120s tool timeout — the bundles
alone outran it.

---

*(§4 onward: the immutability check, the heuristic, and the negative control — appended as measured.)*

---

# RUN 2 — the code run 1 landed, the tests it never wrote, and the number it never re-measured

Run 1 was killed **after committing the implementation** (`9dba899`) but **before writing §4 up**.
So the state run 2 inherited was not "no fix": it was `codeintel.not_maintained_source` +
`_mark_not_maintained` live in `review_source_tree`, with **zero tests and zero measured
verification**. Run 2's first job was therefore not to design a heuristic but to find out whether
the one already shipping is safe, and then to nail it down.

Inventory at HEAD, measured:

```
$ grep -rn "not_maintained\|source_kind\|vendor_scope" agent/ docs/ ui/ | grep -v "agent/codeintel.py:"
(no output)
```

**No test, and no consumer outside the function that writes it.** The fixtures were checked in; the
tests that were supposed to use them were not.

## 4. BENCHMARK IMMUTABILITY — the heuristic DOES touch that tree, so it is re-measured, not assumed

The brief's rule is that a filter which excludes benchmark files moves a scored number by hiding
cases. Run 1's heuristic is not a filter, but it **is** load-bearing on exactly the same axis, and
this is the part run 1 never got to:

`owasp_bench._detected` (line 379) credits a case **only** when a finding's confidence is not in
`_UNPROVEN`, and `_UNPROVEN` contains `"lead"` — which is precisely what `_mark_not_maintained`
assigns. **Any benchmark test-case file that the classifier touches silently becomes a miss.** That
is a real mechanism, not a hypothetical, so it gets measured.

### 4.1 Every file the walk reads, classified

```
$ docker run --rm -v <HEAD-snapshot>/agent:/app -v ./benchmain:/tree:ro apolaki-agent \
    python /work/baseline.py
WALK-SCANNED files          : 2766
CLASSIFIED not-maintained   : 2
   webapp/js/jquery.min.js      third-party  preserved licence banner: /*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Fou
   webapp/js/js.cookie.js       third-party  preserved licence banner: /*! js-cookie v2.1.3 | MIT */
```

**2 of 2766.** Both are real vendored bundles; `webapp/js/testsuiteutils.js` — OWASP's own
first-party file, which also opens with a `/*!` banner — is **not** classified. The rule that
separates them (a licence claim AND a version token) survives contact with the real tree.

Note `not_maintained_files=2` but `not_maintained_findings=1`: `js.cookie.js` is correctly
identified as a dependency and simply contains nothing the rules fire on. Classification is over
FILES, demotion is over FINDINGS, and the two counts are not meant to match.

### 4.2 The mission baseline, re-run at HEAD with the change in place

```
files_scanned=2766 findings=716 error=''
by_cwe: [('CWE-327', 261), ('CWE-328', 153), ('CWE-330', 219), ('CWE-501', 83)]
DEMOTED findings: 1
   webapp/js/jquery.min.js:2 cwe=CWE-330 conf='lead' kind=third-party
confidence distribution: [('confirmed', 715), ('lead', 1)]
```

**2766 / 716 / 261-153-219-83 — every number identical to the before.** Not one finding was
dropped and no CWE bucket moved, so the per-CWE breakdown cannot be hiding a swap inside a stable
total. The single intended change is visible as one row moving `confirmed` -> `lead`.

### 4.3 The scored number, end to end, with an apparatus control

Counting rows is not the same as scoring, so the actual suite score was re-run — `scan_source`
against the live `owaspbench:8443` plus `score` against the official
`expectedresults-1.2.csv` (2740 rows), the documented path:

```
=== AS HEAD BEHAVES ===
  crypto    TPR=100.0% FPR=  0.0%  (tp=130 fn=0 fp=0 tn=116)
  hash      TPR=100.0% FPR=  0.0%  (tp=129 fn=0 fp=0 tn=107)
  weakrand  TPR=100.0% FPR=  0.0%  (tp=218 fn=0 fp=0 tn=275)

=== APPARATUS CONTROL: every finding forced conf='lead' ===
  crypto    TPR=  0.0%   hash  TPR=  0.0%   weakrand  TPR=  0.0%
```

**100/100/100 holds.** The second block is the control that makes the first block mean something:
forcing every row to the demoted confidence collapses all three categories to zero, which proves
the scorer really does read `confidence` and would have shown the damage if the heuristic had
caused any. A 100% measured by an instrument that cannot move is not a measurement.

The structural reason it cannot move: the scorer keys on the file's stem, and

```
demoted stems           : ['jquery.min']
BenchmarkTest stems     : 2740
INTERSECTION (must be 0): []
```

**No benchmark path, ID or filename is special-cased anywhere in the heuristic.** It is evidence-only;
it simply finds no evidence in 2763 hand-written Java test cases, which is the correct answer.

---

# RUN 3 — the brief was one walk out of date, and the other walk was 175x worse

Run 3 opened on the instruction *"the tests exist, the product change does not — land it"*. That is
not what is at HEAD, and the first job was to find out rather than build a second copy of a shipped
fix.

```
$ grep -n "not_maintained\|_tag_not_maintained" agent/codeintel.py | head
373:def not_maintained_source(rel: str, text: str) -> tuple:
412:def _mark_not_maintained(f: dict, kind: str, evidence: str) -> None:
485:        kind, evidence = not_maintained_source(rel, text)
491:                _mark_not_maintained(f, kind, evidence)
503:            "not_maintained_files": not_maintained,
```

**The product change exists.** Run 1 landed it in `9dba899`, run 2 tested and measured it. All four
of the brief's requirements were already met by `review_source_tree`: evidence-based classification,
a negative control, the baseline diff, and benchmark immutability re-measured with an apparatus
control. Building it again would have produced a duplicate, and "the lane shipped the same fix
twice" is a worse outcome than "the lane pushed back".

So the question became: **is `review_source_tree` the only walk that had this blind spot?** It is
not.

## 5. THE SECOND WALK — `codeintel.review()`

`agent/codeintel.py` contains **two** independent tree walks:

| | `review_source_tree` (l. 434) | `review` (l. 507) |
|---|---|---|
| entry point | `POST /engage` source lane, `owasp_bench` | `GET /codereview`, UI "Code Review" tab |
| rows | findings, `confidence: confirmed` | leads (`rule`/`technique`/`severity`/`confirm`) |
| Q-083 fix at HEAD | **yes** (run 1) | **no** |

Only the first was fixed. The second has the same `_SKIP_DIRS` prune, reads the same file types,
and said nothing about ownership.

### 5.1 MEASURED on a real tree, before writing any code

DVWA pulled from the running lab (`docker cp apolaki-dvwa-1:/var/www/html`), 585 files:

```
TREE dvwa           root=/work/trees/dvwa
  review()  scanned=358 findings=57
  leads in NOT-MAINTAINED files : 14 of 57  (24.6%)
  does the lead row say so?     : ['NO -- no marker key on any row']
       2  third-party vulnerabilities/javascript/source/high_unobfuscated.js  {code_exec_sink}
       2  third-party external/phpids/0.6/lib/IDS/vendors/htmlpurifier/HTMLPurifier/Config.php  {weak_crypto}
       1  third-party external/phpids/0.6/lib/IDS/Caching/Database.php  {unsafe_deser}
       ... 12 distinct not-maintained files with leads
  evidence[vulnerabilities/javascript/source/high_unobfuscated.js]
        = 'licence pragma in file header: * @license MIT'
```

**24.6%, against the 0.141% that raised the ticket — 175x the blast radius, in the walk nobody
looked at.** The same run on the benchmark tree returns `0 of 500`, which is the control that stops
24.6% being read as "the classifier fires everywhere": it fires where dependencies actually are.

### 5.2 The lead that proves EVIDENCE was the right rule

`vulnerabilities/javascript/source/high_unobfuscated.js` is not DVWA's code:

```
$ head -8 dvwa/vulnerabilities/javascript/source/high_unobfuscated.js
/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.9.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
```

A verbatim copy of js-sha256 v0.9.0, filed under DVWA's own `vulnerabilities/` challenge tree under
a hand-written-looking name. **`vendor/`, `node_modules/`, `external/` and `*.min.js` all miss it.**
It is caught only because the file says what it is. §3.2 refuted the filename rule on the grounds
that it misses modern bundles; this is the second, independent refutation — it also misses vendored
code that was never bundled at all.

### 5.3 NEGATIVE CONTROL on the real tree — 114 first-party files read and left alone

239 of DVWA's 358 read files classify not-maintained. A number that large is only acceptable if the
239 really are vendored, so every file was classified and the result inspected by directory:

```
CLASSIFICATION BY TOP-LEVEL DIRECTORY (dvwa)
   <root>         FIRST-PARTY       9
   config         FIRST-PARTY       1
   dvwa           FIRST-PARTY       6
   external       FIRST-PARTY       3      <- DVWA's own additions inside external/, NOT stamped
   external       generated         1
   external       third-party     236      <- phpids 0.6 + bundled HTMLPurifier
   hackable       FIRST-PARTY       1
   vulnerabilities FIRST-PARTY     99
   vulnerabilities generated         1
   vulnerabilities third-party       1

POSITIVE CONTROL for that zero: DVWA first-party files READ and left alone = 114
   their extensions: {'.php': 112, '.js': 5, '.xml': 2}

EVIDENCE SPREAD over the classified set:
     218  dependency directory
      19  licence pragma in file header
       2  minified geometry
```

**114 of DVWA's own files were read and none was marked.** The zero is not vacuous — the apparatus
read 112 PHP files including all 99 `vulnerabilities/**` challenge sources. The three FIRST-PARTY
rows inside `external/` matter too: the classifier does not blanket-stamp a directory it has no
evidence about.

Exactly two rows under `vulnerabilities/` are classified, and both were checked by hand:

* `high_unobfuscated.js` → third-party. **Correct** (§5.2, js-sha256 v0.9.0).
* `high.js` → generated, *"minified geometry: longest line 10417 chars, mean 10418 over 1 line"*.
  **Correct** — it is the obfuscated build of that same library, and the maintained source is the
  file next to it.

## 6. THE CHANGE, and the two decisions the measurements forced

### 6.1 MARK, do not filter and do not demote — and DVWA is why

The brief asked the lane to decide deliberately whether the fix is a filter at all. For this walk
the answer came from the tree, not from taste: **`vulnerabilities/javascript/source/high.js` IS the
DVWA JavaScript challenge.** Attacking that obfuscated client-side code is the exercise. A filter
would have deleted the target; a confidence demotion would have told the operator to look away from
it. Marking costs no signal and adds the one fact worth having.

So `review()` rows get `source_kind`, `source_kind_evidence` and `tags` — and **no `confidence`**.
Two reasons, the second load-bearing:

1. A `review()` row has no `confidence` key at all; its contract is that *every* hit is a lead. There
   is no claim here to retract.
2. Writing `confidence` onto the marked subset **alone** would make the key's ABSENCE on every other
   row mean something it does not. That is the falsy-default shape that has bitten this codebase
   before, and `test_the_obfuscated_challenge_is_flagged_and_NOT_filtered_or_demoted` asserts the
   key stays off every row.

`_mark_not_maintained` was split so both walks write the marker through one function,
`_tag_not_maintained`; the tree walk adds the retraction (`confidence` + `proof_gap`) on top. The
summary keys are the SAME two names `review_source_tree` already returns — a second private name for
"this is a dependency" is how the original bug shipped.

### 6.2 EAGER classification — the cheap-looking option lost on measurement

Classifying only files that produced a lead keeps the recon path cheap and was the obvious design.
Measured instead of assumed:

```
dvwa         review()=4.29s over 358 files, 57 leads
   EAGER classify all   358 read files : 0.003s  (0.1% of review) -> 239 not-maintained
   LAZY  classify    37 lead-files     : 0.001s  (0.0% of review) -> 12 not-maintained
   inventory LOST by going lazy: 227 files
benchmain    review()=44.95s over 5484 files, 500 leads
   EAGER classify all  5519 read files : 0.218s  (0.5% of review) -> 2 not-maintained
   inventory LOST by going lazy: 2 files
js_app       review()=2.53s over 38 files, 3 leads
   EAGER classify all    38 read files : 0.030s  (1.2% of review) -> 19 not-maintained
   inventory LOST by going lazy: 18 files
```

**0.1%–1.2% of runtime to keep 227 of 239 dependency files in the inventory.** The bytes are already
in memory and the regexes are not what makes the walk slow. `test_the_inventory_covers_files_that_
produced_no_lead` is the tripwire, and it uses a real one-line 10417-char bundle that yields no lead
because `review()` skips lines over 600 chars — precisely the file a lazy implementation loses.

### 6.3 The tests, and the five mutants that prove they are not vacuous

Four new fixtures, all real DVWA files (`Munge.php` / `impossible.php` / `high.js` whole; the
js-sha256 one a byte-identical 90-line prefix, verified with `cmp`). The section turns on a
**matched pair**: `HTMLPurifier/URIFilter/Munge.php:49` `sha1($this->secretKey . ':' . $string)` and
`vulnerabilities/weak_id/source/impossible.php:6` `sha1(mt_rand() . time() . "Impossible")`. Same
call, same `weak_crypto` rule, opposite ownership.

```
n1  review() marks nothing (the pre-fix behaviour)   -> 5 tests fail
n2  LAZY: classify only lead-bearing files           -> the_inventory_covers_files_that_produced_no_lead
n3  every .js/.php called third-party                -> the sha1 negative control + 8 of run 2's tests
n4  reuse the DEMOTING marker in the leads walk      -> the_obfuscated_challenge_is_flagged_and_NOT_...
n5  drop the row instead of marking it (THE FILTER)  -> positive control + both marking tests
```

n4 is the one worth reading: reusing `_mark_not_maintained` in `review()` is a one-word
simplification that looks like *more* consistency, and exactly one test objects — the one that says
the DVWA challenge must not be demoted. n5 is the filter the brief warns against, and it fails the
positive control first, because it deletes the rows the control counts.

Every mutant was diffed against the original before its verdict was read; a mutant that does not
change the file proves nothing (run 2's lesson).

### 6.4 The mission baseline, re-run AFTER the change — no movement

`_mark_not_maintained` was split, so the walk that produces the scored number was edited. That is
exactly the case the brief says must be re-measured rather than argued. Same tree, same script,
same immutable diff target:

```
$ docker run --rm -v <run3-snapshot>/agent:/app -v ./benchmain:/tree:ro apolaki-agent \
    python /work/baseline.py
files_scanned=2766 findings=716 error=''
by_cwe: [('CWE-327', 261), ('CWE-328', 153), ('CWE-330', 219), ('CWE-501', 83)]
not_maintained_files: ['webapp/js/jquery.min.js', 'webapp/js/js.cookie.js']
not_maintained_findings: 1
confidence distribution: [('confirmed', 715), ('lead', 1)]
   DEMOTED webapp/js/jquery.min.js:2 cwe=CWE-330 conf='lead' kind=third-party
BASELINE IDENTICAL TO MISSION 2fb87a3a: True
```

**2766 / 716 / 261-153-219-83 — every number identical, and the per-CWE breakdown is checked
category by category so a swap cannot hide inside a stable total.** The one intended row is still
the one intended row. No benchmark path, ID or filename is named anywhere in this change either;
`review()` is not on the scored path at all, and `review_source_tree`'s behaviour is unchanged.

---

## 7. ANTI-IDLE — run 1's unfinished question: does the DAST side have the same blind spot?

**Yes. Thirteen rows, one engine, and one of them is the same jQuery bundle that raised this
ticket.** Not in `codeintel.py`, so this lane reports it rather than fixing it.

The question needed sharpening first. "A finding against a third-party asset" is not by itself a
defect on the DAST side: a served bundle IS the client's attack surface even when they did not
write it, and telling them their AngularJS is end-of-life is the product working. The ticket's
actual complaint transfers as: **does a runtime finding point the operator at a LOCATION they
cannot act on, in code they do not maintain, without saying so?**

### 7.1 Apparatus

```
POSITIVE CONTROL findings=1773 missions=154 tool_call=29945
provenance: [('<none>', 1057), ('source-derived', 716)]
runtime findings=1057, of which carry a target=1054
```

Matches the brief's control exactly. Every count below is a measured count.

### 7.2 The first number was wrong, and the correction is the interesting part

A text search for vendored-asset names across all runtime fields returned **112 of 1057 (10.6%)**.
That number does not survive inspection: 46 of the 112 are `CRLF / response-header injection on
'category'`, whose target is `https://ginandjuice.shop/catalog?category=...` — a first-party
endpoint. The asset name appears only because the *response body* references a script. The regex
matched the page, not the finding's location.

Re-measured on the field that actually points the operator somewhere (`url` / `target`):

```
RUNTIME findings whose OWN target/url IS a vendored script: 69 of 1057 (6.5%)
   of those, SCA / 'vulnerable component' rows (correct by design) : 56
   of those, NOT SCA -- a finding LOCATED in code the client does
                       not maintain, with no marker                : 13
```

The 56 are `Vulnerable component: angular@1.7.7 (CVE-2023-26118, +3 more)` and friends, tagged
`['sca','dependency','angular']`. Those are the product working.

### 7.3 The 13

```
--- the NOT-SCA rows, by title + cwe + confidence ---
    13  Credential exposed in a source comment     CWE-615   confirmed

--- the assets they point at, and the LINE they cite ---
   ginandjuice.shop/resources/js/angular_1-7-7.js          line=101  sev=high  tags=['secrets','comment','source-disclosure']
   ginandjuice.shop/resources/js/react-dom.development.js  line=23   sev=high  ...
   owaspbench:8443/benchmark/js/jquery.min.js              line=4    sev=high  ...   (x6)
   juice-shop:3000/chunk-QDZ6R7S6.js                       line=4    sev=high  ...
```

**One engine, `agent/codereview.py:1493` (`scan_comment_secrets` inside `review()`).** All 13 are
HIGH and hardcoded `"confidence": "confirmed"` — and that hardcode is notable in context, because
the three sibling scanners in the very same function (`scan_secrets`, `scan_sinks`,
`scan_weak_crypto`) all emit `"candidate"`. It is the one row in that function that claims
certainty, and it is the one landing on minified bundles.

`owaspbench:8443/benchmark/js/jquery.min.js` at **line 4** is the same jQuery bundle as
`webapp/js/jquery.min.js:2`. **Q-083 was filed from the SAST side; the DAST side was reporting the
same file the whole time and nobody looked.**

### 7.4 Two claims about those rows, stated at the confidence each deserves

MEASURED, and checkable from the row's own text: the finding says *"comment at line 101"*, and the
bytes it quotes from line 101 of `angular_1-7-7.js` are
`"},\n post:ja(wc),put:ja(wc),patch:ja(wc)},xsrfCookieName:"XSRF-TOKEN",...` — **minified library
source, not a comment.** For `jquery.min.js` it cites line 4 of a four-line minified file. The
row's stated basis is contradicted by the row's own evidence field.

NOT CLAIMED: that these are false positives. Nobody has bound what those values do, exactly as with
the `Math.random()` that started this. The defect that IS established is the ticket's, verbatim:
**a confidence asserted without basis, at a location the operator cannot act on, in code they do
not maintain.**

### 7.5 The vocabulary split, which is why this will happen again

```
--- does ANY runtime finding carry codeintel's marker vocabulary? ---
   source_kind key            : 0
   'not-maintained-source' tag: 0
   'dependency'/'sca' tag     : 56
```

**Zero of 1057 runtime findings carry the marker this lane built.** The DAST side is not silent
about dependencies — it has 56 rows tagged `dependency`/`sca` — it just says it with a different
word, in a different engine, and only for the SCA class. `codeintel.not_maintained_source` is a
pure function over `(rel, text)` and a fetched script body is exactly that input, so the classifier
already generalises; nothing consumes it outside `codeintel.py`.

**Recommended ticket (not filed here — `docs/QUEUE.md` belongs to another lane):** run
`scan_comment_secrets`' 13 rows through `codeintel.not_maintained_source(url_path, body)` and mark
them, and separately explain why one scanner in `codereview.review()` hardcodes `confirmed` while
its three siblings hardcode `candidate`.

### 7.6 One measured zero worth naming as a limit, not a result

```
B. runtime findings naming a third-party CDN HOST : 0 of 1057
```

Zero — but every corpus in that DB is a self-hosted lab (`ginandjuice.shop`, `juice-shop:3000`,
`owaspbench:8443`), so no scan has ever met a CDN-hosted asset. **That zero is a property of the
corpus, not evidence that the cross-origin case is handled.** It is untested, not clean.

---

## 8. THE REAL EXECUTION PATH — driven over HTTP, not asserted from a unit test

A passing test proves the function; it does not prove the endpoint returns what the function
computed. `uvicorn main:app` in a THROWAWAY container (`apolaki-agent-1` untouched, never
`docker cp`'d into, never restarted), DVWA mounted at `/tree`:

```
$ curl -s "http://127.0.0.1:18099/codereview?path=/tree"
top-level keys        : ['by_rule', 'by_severity', 'by_technique', 'exposed_dot_git',
                         'files_scanned', 'findings', 'not_maintained_files',
                         'not_maintained_findings', 'total']
files_scanned=358 total=57 exposed_dot_git=False
not_maintained_files  : 239
not_maintained_findings: 14
marked lead rows      : 14 of 57      kinds: {'third-party': 14}

SAMPLE MARKED ROW: {"rule": "code_exec_sink", ..., "file": "external/phpids/0.6/lib/IDS/vendors/
  htmlpurifier/HTMLPurifier/ConfigSchema/InterchangeBuilder.php", "line": 140,
  "snippet": "return eval('return array('. $contents .');');", ...}

UNMARKED (first-party) leads still reported: 43
     {"rule": "code_exec_sink", "file": "dvwa/js/dvwaPage.js", "line": 7, "severity": "critical"}
     {"rule": "code_exec_sink", "file": "security.php", "line": 121, "severity": "critical"}
     {"rule": "code_exec_sink", "file": "vulnerabilities/view_help.php", "line": 15, ...}
any row carrying a confidence key? : False
```

**Exactly the 14 of 57 that §5.1 measured going unmarked are now marked, over the wire.** The 43
first-party leads are still reported and still unmarked — the negative control holds end to end,
on DVWA's own `dvwaPage.js`, `security.php` and `view_help.php`. No row carries a `confidence`
key, so the §6.1 decision survives serialisation.

### 8.1 THE LAST MILE IS NOT DONE, and this lane cannot do it

`ui/index.html:2668 renderCodeReview()` draws a fixed row:

```js
<span class="cr-sev">${f.severity}</span>
<span class="cr-loc">${f.file}:${f.line}</span>
<span class="cr-tech">${f.technique}</span>
<div class="cr-snip">${f.snippet}</div> <div class="cr-why">${f.why}</div>
<div class="cr-conf"><b>Confirm:</b> ${f.confirm}</div>
```

**`source_kind`, `source_kind_evidence` and `not_maintained_files` are not among them.** The API
tells the truth and the Code Review tab does not yet show it. `ui/` belongs to another lane, so
this is reported rather than fixed: an operator reading the JSON or the report sees the marker; an
operator reading that tab still cannot tell that
`external/phpids/.../InterchangeBuilder.php:140` is HTMLPurifier and not theirs.

---

## 9. AN ATTEMPT TO BREAK THE CHANGE — the new surface it drags in

The two walks do not read the same files, and wiring the classifier into `review()` widened what it
sees. That is a real risk the change introduces and it was hunted rather than hoped about:

```
review_source_tree exts : ['.cjs','.java','.js','.jsx','.mjs','.py','.pyw','.ts','.tsx']
review()._EXTS          : the above PLUS
                          ['.conf','.config','.cs','.env','.go','.json','.php','.rb','.sql',
                           '.xml','.yaml','.yml']
```

**Twelve extensions the classifier had never been pointed at.** Its banner and geometry rules were
calibrated on JavaScript (§3.3, `_MINIFIED_MAX_LINE` / `_MINIFIED_MEAN_LINE`). A one-line SQL dump
or a packed JSON blob is exactly the shape that could be miscalled `generated`.

Every non-JS file the rule fires on across DVWA + Juice Shop, with evidence:

```
   .json    generated        1  <-- NON-JS CLASSIFIED
   .php     third-party    235  <-- NON-JS CLASSIFIED
   .php     -              112
   .xml     -                2
   .json    -                2
   .ts      -                1

   .json  generated   external/phpids/0.6/lib/IDS/default_filter.json
            minified geometry: longest line 16360 chars, mean 16360 over 1 line(s)
   .php   third-party external/phpids/0.6/lib/IDS/Converter.php   (+ 234 more)
            licence pragma in file header: * @license  http://www.gnu.org/licenses/lgpl.html
```

**No misfire found.** All 235 `.php` hits are PHPIDS, caught because `@license` is a documented
PHPDoc tag as well as a JS build pragma — the rule transferred to a second language without being
told about it. The one `.json` is a 16KB single-line filter table shipped *inside* that library.
The 112 first-party `.php` files and both `.xml` files were read and left alone.

### 9.1 Two things this does NOT establish

* **`.sql`, `.env`, `.yml`, `.yaml`, `.conf`, `.config`, `.go`, `.rb`, `.cs` were never exercised** —
  no such file exists in the trees available. Those extensions are UNTESTED, not clean. The
  geometry rule on a single-line SQL dump is the specific case a future run should go looking for.
* **`@license` in a first-party header would misclassify.** A project that tags its OWN files
  `@license MIT` gets called third-party. DVWA does not, Juice Shop does not, OWASP Benchmark does
  not — measured on all three — but the rule cannot tell "I ship this licence" from "I vendored
  something under this licence". The blast radius is asymmetric, and that asymmetry is the reason
  to leave it alone rather than tighten it on a hypothesis: in `review()` the consequence is a
  marker and no signal is lost, while in `review_source_tree` it is a confidence demotion. **The
  exposure is concentrated in the walk run 1 shipped, not the one added here.** Tightening a rule
  that shows zero observed errors across three real trees would trade a measured result for a
  guess.
