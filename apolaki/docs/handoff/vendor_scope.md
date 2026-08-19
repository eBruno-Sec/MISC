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
