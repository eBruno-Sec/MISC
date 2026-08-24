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
