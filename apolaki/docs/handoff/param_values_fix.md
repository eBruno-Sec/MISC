# Q-095 — Param mining yields NAMES, not VALUES

Lane file. Written as I go; if this lane dies, this file is the contribution.

Baseline at start: ship gate GREEN `3604 passed / 11 skipped / 12 xfailed / 0 failed` at `ca475ae`.

---

## 0. What the ticket already proved (do not re-derive)

- `?q` and `?q=` both return **16578 bytes** (unfiltered product list); `?q=apple` returns **921**.
- sqlmap: `?q` -> "not injectable"; `?q=apple` -> boolean-based + time-based blind, SQLite.
- Corpus: **9873 / 12156 (81.2%)** query-bearing dispatches valueless.
- Q-092 A/B'd the **value-overwriting** engines and found them identical on both sides.

## 1. Deliverable 1 — the classification (IN PROGRESS)

Axis, per the ticket: **does the engine need a working BASELINE to compare against?**

Reading the code shows the axis is really **three** cells, not two, and the third one matters
because it is where most of the 9873 live:

| Class | Definition | Effect of a blank value |
|---|---|---|
| **A. BASELINE-DEPENDENT** | fetches the URL **as given** and uses that response as the comparison term for a differential oracle | **BROKEN.** The blank-value baseline is a *different page* (the unfiltered one), so the differential is measured against the wrong reference. |
| **B. VALUE-OVERWRITING** | replaces the value with its payload; oracle is self-contained (canary present / breakout escaped / timing delta / header appeared) | **Unaffected.** Confirmed by Q-092's A/B. |
| **C. NO-DIFFERENTIAL** | single fetch, oracle is a pattern match on one response; never manipulates the value | **Unaffected in the Q-095 sense** — there is no baseline to corrupt. (It reads a *different page*, but that is a coverage question, not a false-negative-on-a-vulnerable-field question.) |

A fourth mechanism rides on class A and is worth naming separately because it is a *second*
independent breakage in the same call:

- **A2. VALUE-DERIVED PAYLOAD** — the engine builds its payload as `orig + "'"` / `orig + " AND 1=1"`.
  With `orig == ""` the payload changes *shape*, not just the baseline.

### Per-engine classification

(filled in below as each is read — evidence = the line that decides it)

Method: read every `_run_*` engine the planner dispatches with `_ex(ep)` (a *parameterized*
endpoint URL) — `planner.py:826-975` — plus every engine the ticket's corpus named. Evidence per
row is the line that decides the class: the **baseline fetch** and the **oracle call** it feeds.

#### Class A — BASELINE-DEPENDENT. A blank value BREAKS these.

| Engine | Baseline fetch | Oracle fed by it | Ticket volume |
|---|---|---|---|
| `_run_sqli` `tools.py:8488` | `base_r, _ = await get(c, url)` `:8515` | `sqli.analyze_boolean(base_body, rt, rf, …)` `:8571` | **863 valueless (75%)** |
| `_run_cmdi` `:9038` | `base_r, _ = await get(c, url)` `:9066` | `cmdi.analyze_output(base_body, r.text)` `:9074` | — |
| `_run_nosqli` `:8924` | `base_r = await get(c, url)` `:8952` | `ns.analyze_boolean(base_body, op, ctl, miss)` `:8985` | — |
| `_run_web_probes` `:7431` | `baseline = await self._http(url, capture=True)` `:7456` | `ws.analyze_traversal_pair(baseline, r, …)`, `ws.analyze_idor_pair(baseline, r, …)` | — |
| `_run_injection_probes` `:7667` | `base_body = base.text` `:7675` | `ws.analyze_ssti(base_body, sr.text)` **only** | **863 valueless (75%)** |
| `_run_xpath` `:5446` | `base = await _body(url)` | `xp.evaluate(base, probe_body)` | — |
| `_run_ldap` `:5547` | `base = await _body(url)` | `lp.evaluate(base, probe_body)` | — |
| `_run_sqli_structural` `:9821` | `base = await _body(url)` | `sq.structural_confirmed(base, ok, bad)` | — |
| `run_sqlmap` `:11148` | EXTERNAL — sqlmap's own dynamicity/stability check | its own | **58/58 valueless (100%)** |

`_run_injection_probes` is **MIXED and must not be treated as class A wholesale**: CORS,
host-header, open-redirect and CRLF are all self-contained oracles (class B). Only the SSTI
branch reads `base_body`. Fixing the whole engine as if it were baseline-dependent would be the
"applied where it was never needed" error the ticket warns about.

**Sub-split by ORACLE, because not every class-A oracle dies the same way:**

- **A-diff** — similarity / containment / status differential (`analyze_boolean`,
  `analyze_ssti`, `analyze_traversal_pair`, `analyze_idor_pair`, `quote_break_recovers`,
  `structural_confirmed`, xpath/ldap `evaluate`). **FALSE NEGATIVE.** The blank-value baseline is
  the unfiltered page; the TRUE payload returns the filtered page; TRUE fails to track the
  baseline; the oracle declines on a genuinely vulnerable field.
- **A-err** — signature *present in probe, absent from baseline* (`sqli.error_signatures`,
  `ns.error_signatures`). **SURVIVES.** A wrong baseline is still an error-free baseline, so the
  "absent from baseline" half still holds. If anything this is *more* permissive — a small FP
  risk, never a false negative. **A fix must not claim to have rescued these.**

**A2 — VALUE-DERIVED PAYLOAD**, a *second, independent* breakage riding on class A:
`orig = qvals.get(p, "1")` (`_run_sqli:8529`, `_run_cmdi:9068`). The `"1"` default fires only when
the key is ABSENT; a key present with a blank value yields `orig = ""`, so
`sqli.boolean_payloads("")` emits `' AND '1'='1` instead of `apple' AND '1'='1`. This is the
recorded falsy-default shape (`x or DEFAULT` where the empty value is a real input) in `.get`
clothing. It compounds A-diff; it is not the primary killer.

**A3 — VALUE-GATED**, where a blank value stops the engine before it selects anything:
`_run_deserialization:8181` calls `deser.find_serialized_inputs(query, cookies)`, which selects a
parameter only when its **VALUE** looks like a serialized blob. A blank value can never match, so
the engine returns `"No serialized objects found in query params, cookies or form fields"` and
tests nothing. Not a wrong answer — a **vacuous** one that prints as clean.

#### Class B — VALUE-OVERWRITING. Unaffected. (Q-092 A/B'd these; the code says why.)

| Engine | The overwrite | The self-contained oracle | Ticket volume |
|---|---|---|---|
| `_run_xss` `:5160` | `xt.set_param(url, p, xt.CANARY)` `:5172` | canary reflected + `xt.breakout_index(rb.text, ctx) != -1` | **1059 valueless (77%)** |
| `_run_dom_audit` `:6301` | `dom.build_probes` → `_add_query(url, pn, payload)` | `Object.prototype[PP_KEY] == MARK`, dialog fired, navigation to `EVIL` | **474 valueless (94%)** |
| `_run_ssrf` `:8031` | `ssrf.set_param(url, param, value)` `:8049` | metadata content match; open-vs-closed port pair (**probe vs probe**); OOB callback | **23/23 (100%)** |
| `_run_ssi` `:5647` | query rewrite | `si.evaluate(body, token)` — a live DATE between unique markers | — |
| `run_dalfox` `:11113` | EXTERNAL; dalfox substitutes and verifies reflection | its own | *UNVERIFIED — classified by mechanism, not A/B'd here* |

`_run_xss` alone is **1059 of the 9873**, and it is harmless. That single row is why "fix all
9873" is the wrong instruction.

#### Class C — NO-DIFFERENTIAL. No baseline exists to corrupt.

| Engine | Why | Ticket volume |
|---|---|---|
| `_run_anomaly_scan` `:5908` | one GET, regex sweep over that one body (`_ANOMALY_RX`, `_LEAK_HEADERS`) | **731 valueless (94%)** |
| `_run_bfla` `:7846` | differential is **identity** (token vs `Identity()`), not value | — |
| `_run_xxe` `:8311` | payload rides in the POST **body**; the query value is never read | — |

These read a *different page* than they would with a value — a coverage question — but they cannot
produce the Q-095 failure (clean report on a vulnerable field), because they have no baseline.

#### Class D — SELF-BASELINING. The blank value is on BOTH sides and cancels.

| Engine | Why it cancels |
|---|---|
| `_run_param_mine` `:5947` | builds its own control `?<random>=<canary>` on the SAME url `:5969`; the blank `q` rides on the baseline *and* every probe. **56/56 valueless and harmless by construction.** |
| `_run_path_sqli` `:10530` | injects into the PATH segment; the query string is byte-identical on both sides |
| `_run_deserialization` `:8181` | `base = c.get(q_url(name, orig))` vs `probe = c.get(q_url(name, bad))` — both carry the original value (but see **A3**: it never gets that far) |

### The arithmetic this classification produces

Of the ticket's five worst-by-volume rows, **three are harmless**:

```
run_xss           1059 valueless  ->  class B  HARMLESS
run_dom_audit      474            ->  class B  HARMLESS
run_anomaly_scan   731            ->  class C  HARMLESS
run_param_mine      56 (100%)     ->  class D  HARMLESS
run_ssrf            23 (100%)     ->  class B  HARMLESS
                   ----
                   2343 of the 9873 provably need NO fix
run_sqli           863            ->  class A  BROKEN  (A-diff + A2)
run_injection_probes 863          ->  class A  BROKEN  in ONE branch (SSTI) of five
run_sqlmap          58 (100%)     ->  class A  BROKEN  (proven in the ticket)
```

That is the deliverable: **the blast radius is the class-A rows, not the 81.2%.**

---

## 2. MEASURED: where the value is thrown away

`observed_param_values` **already recovers the real value correctly**. `merge_observed_params`
**then discards it.** MEASURED, container `apolaki-agent`, `planner` + `surface` at `ca475ae`:

```
urls = ["http://juice-shop:3000/rest/products/search?q",
        "http://juice-shop:3000/rest/products/search?q=apple"]

observed_param_values ->  {('juice-shop:3000', '/rest/products/search'): {'q': 'apple'}}
inventory example     ->  http://juice-shop:3000/rest/products/search?q      params: ['q']
merge_observed_params ->  http://juice-shop:3000/rest/products/search?q

VERDICT: the observed value 'apple' is DISCARDED

reversed crawl order  ->  http://juice-shop:3000/rest/products/search?q=apple
```

**The last line is the sharpest form of the defect: whether the whole mission probes a working URL
or a dead one is decided by which URL the crawl happened to see first.**

Mechanism, `planner.py:293 merge_observed_params`:

```python
pairs = parse_qsl(p.query, keep_blank_values=True)   # [('q', '')]
have  = {k for k, _ in pairs}                        # {'q'}
extra = [(k, values[k]) for k in sorted(values) if k not in have]   # []  <- 'apple' dropped
```

A parameter present with a **blank** value counts as "already have it". `observed_param_values`
itself already runs the opposite rule internally — *"first observation wins, but a real value beats
a blank one"* (`planner.py:286`) — so the fix is to make the two helpers agree, not to invent a
new policy. **Nothing is synthesized: `values[k]` comes only from `observed_param_values(urls)`,
which reads real crawled URLs and nothing else. A parameter never observed with a value stays
blank.**

### The second source, NOT fixed here — warm-start memory

`memory.py:164` stores endpoints as `host/path?` + `"&".join(params)` — **names joined by `&`,
no `=` at all**, which is the ticket's verbatim corpus shape (`?key&name`,
`?callback&format&key`, `?EIO&sid&t&transport`). The comment says so outright: *"Keep the param
NAMES on the stored endpoint (not values)"*. A warm start therefore re-seeds the surface
valueless **by construction**, and no in-mission merge can recover a value that was never stored.
Left alone in this lane: it changes a persisted format, and the in-mission fix above is
independently correct and testable. **Filed here so it is not lost.**

## 3. Two hypotheses of mine, MEASURED and DISPROVED

Recorded because a disproved hypothesis shrinks the real blast radius, and because both would
have produced a gate that lies.

**DISPROVED #1 — "`_run_sqli` reports clean on juice-shop's search when handed `?q`".** It does
not. MEASURED end-to-end against the live lab, `ToolRegistry._run_sqli`, both URLs:

```
.../rest/products/search?q         0.5s  findings=2 confirmed=2   error-based + union-extraction
.../rest/products/search?q=apple   0.4s  findings=2 confirmed=2   error-based + union-extraction
```

Why: `sqli.ERROR_PROBES` is `["'", '"', "')", '"))', '`']`, and `?q=')` raises `SQLITE_ERROR`
**even with a blank value**. My earlier single-payload measurement (`?q='` -> 200/30 bytes, no
signature) tested one probe and I generalised from it. A mechanism reproduced is not a cause
proven.

**DISPROVED #2 — "the boolean oracle discriminates on this endpoint".** It does not, in either
direction. MEASURED, all four contexts, both `orig` values:

```
orig=''       string-quote true=30 false=30 base=16572 -> analyze_boolean=False
              string-comment true=942 false=942        -> False   (numeric, paren-quote: False)
orig='apple'  string-quote true=30 false=30 base=  921 -> analyze_boolean=False
              string-comment true=942 false=942        -> False   (numeric, paren-quote: False)
```

Juice-shop concatenates as `%'||q||'%`, so a boolean payload breaks the statement outright and
both arms return the same 30-byte error object. **`/rest/products/search` is not a valid fixture
for a boolean-oracle gate at all**, with or without a value.

**What survives both disproofs:** the ticket's own sqlmap proof, which is about sqlmap's
*dynamicity check* bailing before it injects — a mechanism internal to sqlmap that neither of the
above touches. And this correction to my own classification:

> **CORRECTION to the A-err row in section 1.** I wrote that the error oracle "SURVIVES" a blank
> value. That is true of the *baseline* half (a wrong baseline is still an error-free baseline),
> but **not** of the **A2 value-derived payload** half: `?q='` returns 200/30 bytes while
> `?q=apple'` returns 500 with `SQLITE_ERROR`. Whether A-err survives is decided per endpoint by
> whether *some* probe in `ERROR_PROBES` happens to break the statement with an empty prefix.
> On juice-shop `')` does, so it survives **there**. That is a coincidence of this endpoint, not
> a property of the oracle. **A-err is UNRELIABLE under a blank value, not immune.**

## 4. My own sqlmap A/B — MEASURED, identical flags on both sides

The ticket's proof used different `--level`/`--risk` on the two arms. This run holds every flag
constant, so the only variable is the value. Container `apolaki-agent`, `--network apolaki_default`:

```
sqlmap -u 'http://juice-shop:3000/rest/products/search?q'       --batch --level 3 --risk 2 \
       --flush-session --random-agent --technique=BEUST
  [WARNING] heuristic (basic) test shows that parameter 'User-Agent' might not be injectable
  [WARNING] heuristic (basic) test shows that parameter 'Referer'    might not be injectable
  [ERROR]   all tested parameters do not appear to be injectable.

sqlmap -u 'http://juice-shop:3000/rest/products/search?q=apple' --batch --level 3 --risk 2 \
       --flush-session --random-agent --technique=BEUST
  [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be injectable
  [INFO]    heuristic (extended) test shows that the back-end DBMS could be 'SQLite'
  GET parameter 'q' is vulnerable.
  Parameter: q (GET)
      Type: boolean-based blind   Title: AND boolean-based blind - WHERE or HAVING clause
      Type: time-based blind      Title: SQLite > 2.0 AND time-based blind (heavy query)
  back-end DBMS: SQLite
```

**Note which parameters the valueless run tested: `User-Agent` and `Referer`. Never `q`.** The
dynamicity check dropped the parameter the whole dispatch existed to test, and the run still
printed a confident negative. That is the Q-095 shape exactly: a dispatch that opened its
transport, carried input incapable of proving anything, and reported a clean bill of health.

## 5. THE FIX — `planner.merge_observed_params`, one call site

`planner.py:293`. `have` counted a blank-valued parameter as "already have it":

```python
-   have  = {k for k, _ in pairs}
-   extra = [(k, values[k]) for k in sorted(values) if k not in have]
-   if not extra:
-       return url
-   return urlunparse(p._replace(query=urlencode(pairs + extra, doseq=True)))
+   upgraded = [(k, values[k]) if (not v and values.get(k)) else (k, v) for k, v in pairs]
+   have  = {k for k, _ in pairs}
+   extra = [(k, values[k]) for k in sorted(values) if k not in have]
+   if upgraded == pairs and not extra:
+       return url                      # a no-op must be a no-op -- see below
+   return urlunparse(p._replace(query=urlencode(upgraded + extra, doseq=True)))
```

**Single production call site: `planner.py:627`, inside `_ex(ep)`.** Every per-endpoint engine the
phase-E loop dispatches takes its URL from there, so class A is fixed at one point and class B is
carried along unchanged (its probe is byte-identical either way — that is the definition of the
class, and the gate asserts it).

**The byte-for-byte no-op branch is load-bearing, not tidiness.** Re-encoding unconditionally
rewrites `?q` as `?q=` — the same request on the wire (MEASURED: both 16572 bytes) but a different
STRING — on all 9873 valueless dispatches, churning every dedup key, step key and cached result for
endpoints this fix does not help. `test_a_parameter_never_observed_with_a_value_stays_blank` caught
that in the first draft.

**Nothing is synthesized.** `values` comes only from `observed_param_values(urls)`. A parameter
never observed with a value keeps its blank, and `test_every_value_on_every_probe_url_was_observed_
on_that_endpoint` asserts the general form.

## 6. THE GATE — `agent/tests/test_observed_param_value_delivery.py`

Committed RED (`02d66dc`) before the fix. **MEASURED before: 3 failed / 8 passed. After: 11 passed.**

| Test | Before | After | Role |
|---|---|---|---|
| `test_merge_observed_params_upgrades_a_blank_value_to_the_observed_one` | **RED** | green | the defect, at the helper |
| `test_a_baseline_dependent_engine_is_handed_the_observed_value_not_a_blank` | **RED** | green | the defect, at all 5 class-A engines the planner dispatches here |
| `test_the_probe_url_does_not_depend_on_the_order_the_crawl_saw_the_urls_in` | **RED** | green | crawl order decided the answer |
| `test_a_value_overwriting_engine_is_unaffected_in_both_directions` (x3) | green | green | **the non-vacuity control** — class B unaffected in BOTH directions |
| `test_the_two_classes_are_actually_distinguishable_on_this_fixture` | green | green | negative control *for the control*: if the two URLs produced the same baseline too, "class B unaffected" would be vacuous |
| `test_a_parameter_never_observed_with_a_value_stays_blank` | green | green | never synthesize |
| `test_every_value_on_every_probe_url_was_observed_on_that_endpoint` | green | green | never synthesize, general form |
| `test_a_real_value_is_never_churned_by_the_upgrade` | green | green | no churn on endpoints that were never broken |
| `test_live_a_blank_value_returns_a_different_page_than_the_observed_value` | green | green | the raw-byte fixture on the live lab |

**Why the executable gate sits at the planner boundary rather than on a class-A engine
end-to-end:** both candidate engine-level fixtures were measured and disproved (section 3), and the
one surviving class-A proof is sqlmap, a several-minute external run unfit for a unit suite. The
gate therefore asserts the thing the fix changes and the thing every class-A engine depends on —
that the probe URL carries the value the crawl observed — with the sqlmap A/B of section 4 as the
recorded end-to-end evidence that the URL choice decides the verdict.

The class-B control is deliberately NOT "the URL handed to `run_xss` is unchanged" — after the fix
it *does* change, because every engine takes the same `_ex(ep)`. It is "the PROBE `run_xss` puts on
the wire is byte-identical either way", which is what "unaffected" actually means for class B and
is true before and after.
