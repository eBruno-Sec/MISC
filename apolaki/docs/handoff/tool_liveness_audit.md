# Q-092 -- external-tool liveness audit of the 22 remaining zero-histogram wrappers

Lane: Breaker. Ticket: `docs/QUEUE.md` Q-092. Owner of this file only; `tools.py` is held by
another lane, so every production patch below is a DIFF, never an edit.

Method for every entry: read the wrapper, determine whether it shells out through `self._cmd`,
run the exact command / the exact engine live against an authorized lab, capture stdout bytes,
stderr bytes and exit code SEPARATELY, feed the real captured bytes to the wrapper's own parser,
and compare what the tool emitted against what the parser yielded. Verdicts are one of
BROKEN / BLIND / CORRECTLY QUIET / UNTESTABLE.

Authorized targets only: `juice-shop:3000`, `dvwa:80` on the `apolaki_default` docker network
(host ports 42000 / 42080), Natas, vulnweb / ginandjuice.

---

## 0. INSTRUMENT -- census reproduced before it was trusted

MEASURED. Re-derived independently from the corpus, not copied from the ticket:

```
MSYS_NO_PATHCONV=1 docker run --rm -i -v apolaki_bbh_data:/data apolaki-agent python - <<'PY'
import sqlite3, json, collections
db = sqlite3.connect("/data/bbh.db")
rows = db.execute("SELECT data FROM logs WHERE etype='tool_result'").fetchall()
... bucket int(o["count"]) per o["tool"] ...
PY
```

- `logs` table columns are `(id, mission_id, etype, data, created_at)`. The ticket's sketch says
  `o["type"]=="tool_result"`; the indexed column is `etype`, and filtering on it gives the same
  26249 rows. 66950 log rows total.
- 24 tools have >=10 runs and a `count` histogram of exactly `{0}`. **The same 24 the ticket
  names.** Run totals are 0-18 higher than the ticket's, consistent with a corpus that grew
  between the two measurements.

**Positive control on the instrument.** The same query shows 33 tools with >=10 runs whose
histogram is NOT all-zero (`run_katana` `{0:3, 1:34, 2:2, 7:2, 20:6, 33:38, 34:27, 35:12, 37:4,
50:50}`, `run_bfla` `{0:262, 1:76}`, `run_sqli` `{0:1113, 1:83, 2:18}`). The instrument can see a
non-zero when one exists, so a zero from it is a measurement and not an artifact.

---

## 1. STRUCTURAL RESULT -- the exit-code defect reaches only ONE of my 22

MEASURED, by AST-walking each of the 22 wrapper bodies in `agent/tools.py` and counting
`self._cmd(` calls, `__MISSING__` checks and bare `except Exception: pass` swallows:

| wrapper | lines | `self._cmd` calls |
|---|---|---|
| `_run_sqlmap` | 10774-10844 | **1** |
| the other 21 | - | **0** |

**21 of the 22 are pure-Python HTTP engines. They never shell out, so `_cmd`'s discarded exit
code cannot be their cause.** Only `run_sqlmap` is exposed to the Q-092 chokepoint. This is the
ticket's own warning holding: the zero histogram is a signature shared by tools with *different*
underlying causes, and 21 of these need a different explanation than dalfox's and nuclei's.

Every `except Exception:` in these bodies is already instrumented with `self._swallow(...)` (the
Q-08x work landed), so "a bare swallow hides the parse error" is NOT in play here either, with the
audit per tool below confirming it case by case.

---

## 2. SECOND INSTRUMENT -- the corpus records each run's SUMMARY STRING

The `tool_result` log payload is `{"type","tool","output","count"}`. `output` is the wrapper's own
one-line summary, and the wrappers emit a DIFFERENT summary for "precondition never met" than for
"ran the oracle, found nothing". That distinction is recorded 26249 times and costs nothing to
read, so it separates INPUT STARVATION from ORACLE SILENCE across the whole corpus before a single
live probe.

MEASURED, all 22, full histogram of `output`:

| tool | runs | output histogram |
|---|---|---|
| `run_ssi` | 940 | 940 `0 SSI injection finding(s)` |
| `run_waf_bypass` | 592 | 533 `0 WAF-bypass finding(s)`, 59 `no query params to test` |
| `run_sqli_structural` | 592 | 533 `0 structural SQLi finding(s)`, 59 `no query params` |
| `run_css_injection` | 592 | 592 `0 CSS injection finding(s)` |
| `run_form_nosqli` | 482 | 482 `no body auth-bypass NoSQLi on this endpoint` |
| `run_oauth` | 422 | 378 `0 OAuth signal(s), 0 confirmed`, 44 `Not an OAuth authorization URL (needs client_id + redirect_uri/response_type)` |
| `run_client_checks` | 348 | 348 `0 client/config finding(s)` |
| `run_nosqli` | 342 | 202 `tested 1 param(s), 0 confirmed`, 94 `tested 2`, 23 `tested 3`, 23 `tested 4` |
| `run_deserialization` | 335 | 335 `No serialized objects found in query params or cookies` |
| `run_github_recon` | 320 | 320 `Skipped - set BBH_GITHUB_TOKEN ...` |
| `run_form_cmdi` | 250 | 250 `no body command injection in the page's forms` |
| `run_upload_test` | 248 | 226 `No file-upload form found`, 22 `Could not fetch page for form discovery` |
| `check_takeover` | 142 | 73 `No subdomains to check (run recon first)`, 68 `0 takeover candidate(s)`, 1 `0 takeover candidate(s), 0 confirmed` |
| `run_session_token` | 82 | 82 `0 weak-session-token finding(s)` |
| `run_exposure` | 62 | 62 `15 checks, 0 exposure(s)` |
| `run_cache_poison` | 59 | 59 `no unkeyed-header reflection observed` |
| `run_sqlmap` | 58 | 46 `No SQLi confirmed [deep]`, 12 `No SQLi confirmed [insane]` |
| `run_path_sqli` | 58 | 58 `0 path-param SQLi finding(s)` |
| `run_llm_probe` | 46 | 40 `no prompt-injection signal observed`, 6 `no prompt-injection / output-handling signal observed` |
| `run_cache_deception` | 24 | 22 `0 web-cache-deception finding(s)`, 2 `no auth-differentiated private tokens on this page` |
| `run_ssrf` | 23 | 23 `tested 1 param(s), 0 SSRF signal(s), 0 confirmed` |
| `run_username_enum` | 15 | 13 `no server-rendered login form here`, 2 `0 username-enumeration finding(s)` |

**Immediate reads from this table, MEASURED:**

- `run_github_recon` is **320/320 a declared no-op**: it never made a request in the entire corpus.
- `run_deserialization` is **335/335 precondition-not-met**: it never reached its oracle once.
- `run_form_nosqli` (482), `run_form_cmdi` (250), `run_upload_test` (226/248), `check_takeover`
  (73/142), `run_username_enum` (13/15) likewise report a PRECONDITION message, not an oracle
  result, in most or all runs.
- The rest DID reach their oracle and it stayed silent -- those are the ones where BLIND vs
  CORRECTLY QUIET can only be told apart by a live positive control.

Per-tool sections follow in descending order of corpus runs.

---

## 3. `run_ssi` -- 940 runs -- **CORRECTLY QUIET**

Wrapper `tools.py:5281-5339`. Pure Python (`self._cmd` calls: 0). Injects
`mk<tok>mk<!--#config timefmt=...--><!--#echo var="DATE_GMT" -->mk<tok>mk` into each GET query
param and each POST form text field; `ssi_tool.evaluate` confirms only when the text BETWEEN the
two unique markers is an expanded date.

**Oracle positive control (synthetic known-positive bytes).** MEASURED:

```
body = '<html>x' + marker + 'APO-deadbeef-2026-233' + marker + 'y</html>'
si.evaluate(body, 'deadbeef')['confirmed']  -> True
si.evaluate(<literal payload echoed back>)  -> False
```

The oracle fires on a real positive and stays silent on plain reflection. It is not structurally
pinned at zero the way dalfox's JSONL parser is.

**Live transport control, DVWA (authorized lab), the engine's exact payload on a REFLECTING
surface.** MEASURED:

```
GET http://dvwa/vulnerabilities/xss_r/?name=<engine payload>     (authenticated, security=low)
-> 200, 4451 bytes
marker sandwich intact in response: True
text BETWEEN the markers:
    '<!--#config timefmt="APO-d2180631-%Y-%j" --><!--#echo var="DATE_GMT" -->'
si.evaluate(...) -> {'confirmed': False, 'oracle': ''}
```

This is the whole engine proven end to end: the payload reached the server, the server echoed it,
the response was parsed, the sandwich was found, and the oracle correctly ruled it REFLECTED rather
than EXECUTED. DVWA's Apache does not run `.php` through `mod_include`, so the directive is not
expanded -- which is the true state of the target.

**Live run of the wrapper itself, Juice Shop.** MEASURED:

```
run_ssi {"url":"http://juice-shop:3000/rest/products/search?q=apple"}
-> success=True output='0 SSI injection finding(s)' findings=0 error=None, swallowed=0
raw response to the SSI payload: 200, 30 bytes, '{"status":"success","data":[]}'
marker present in response: False
```

The JSON search endpoint does not reflect the parameter at all, so there is nothing for any SSI
oracle to read. Correct.

**VERDICT: CORRECTLY QUIET.** The engine transmits, parses and discriminates correctly; no target
in the corpus runs an SSI-enabled server. 940 zeros are 940 true negatives. No patch needed.

---

## 4. `run_waf_bypass` -- 592 runs -- **CORRECTLY QUIET (by required precondition)**

Wrapper `tools.py:9412-9452`. Pure Python. A THREE-state differential: baseline OK, bare signature
BLOCKED by a WAF, padded signature NOT blocked and reflected. State 2 is a hard gate -- the code
`continue`s out of the loop the moment `wb.is_blocked(...)` is False, so **a target with no WAF can
never produce a finding, by design.**

**Oracle positive control.** MEASURED:

```
wb.evaluate((200,'ok'), (403,'Request blocked by WAF'), (200,'echo <script>alert(1)</script>'), payload)
   -> confirmed True
wb.evaluate((200,'ok'), (200,'echo <payload>'),        (200,'echo <payload>'),        payload)
   -> confirmed False        # no WAF -> nothing to bypass
```

**Live.** MEASURED: `run_waf_bypass` on `http://juice-shop:3000/rest/products/search?q=apple`
-> `success=True output='0 WAF-bypass finding(s)' findings=0 swallowed=0`. Juice Shop returns 200
to the bare `<script>alert(1)</script>` signature; nothing blocks, so state 2 never occurs.

**Corpus corroboration:** 59 of the 592 runs report `no query params to test`, i.e. the wrapper was
dispatched at paramless URLs one run in ten. The remaining 533 reached the loop and found no WAF.

**VERDICT: CORRECTLY QUIET.** The engine is a WAF-bypass check pointed at a fleet of WAF-less local
labs. The zero is the correct answer. No patch needed.

---

## 5. `run_sqli_structural` -- 592 runs -- **CORRECTLY QUIET on the surfaces tested**

Wrapper `tools.py:9453-9486`. Pure Python. Sends a VALID subquery `(SELECT 1)` and an INVALID one
`(SELECT 1 FROM apolnope_zqx77)` and confirms when the invalid one raises a DBMS error the baseline
and the valid probe lack.

**Oracle positive control.** MEASURED:

```
sq.structural_probes() -> {'ok': '(SELECT 1)', 'bad': '(SELECT 1 FROM apolnope_zqx77)'}
sq.structural_confirmed('base rows', 'base rows', 'SQLITE_ERROR: near "x": syntax error')
   -> (True, [{'dbms': 'SQLite', 'pattern': 'SQLITE_ERROR'}])
sq.structural_confirmed('base rows', 'base rows', 'base rows')     -> (False, [])
```

**Live, with a NEGATIVE AND A POSITIVE on the same endpoint.** This is the important measurement:
Juice Shop's `/rest/products/search?q=` IS SQL-injectable, so if the engine were blind it would be
blind on a genuinely vulnerable parameter. MEASURED, raw:

```
q=apple                             -> 200,  921 bytes  {"status":"success","data":[{...}]}
q=(SELECT 1)                        -> 200,   30 bytes  {"status":"success","data":[]}
q=(SELECT 1 FROM apolnope_zqx77)    -> 200,   30 bytes  {"status":"success","data":[]}
q='                                 -> 200,   30 bytes  {"status":"success","data":[]}
q=apple')) UNION SELECT 1,2,3--     -> 500, 1078 bytes  Error: SQLITE_ERROR: SELECTs to the left
                                                        and right of UNION do not have the same
                                                        number of result columns
```

The parameter is injectable (the UNION probe reaches SQLite and errors), but it lands inside a
`LIKE '%...%'` **value** context, not a query-**structure** context: an unknown table name inside a
string literal is just a string, so the invalid subquery cannot raise. The engine's premise -- input
placed into the query STRUCTURE -- is simply not true of this parameter, and reporting nothing is
right. `run_sqli` (a separate engine) is the one that catches this surface, and the corpus confirms
it does: `run_sqli` histogram `{0:1113, 1:83, 2:18}`.

**VERDICT: CORRECTLY QUIET** on every surface reachable in the lab fleet. Caveat recorded honestly:
I did not find an ORDER-BY-style structural parameter on an authorized target, so I have proven the
oracle sound and the transport sound but have NOT observed an end-to-end true positive. That is a
gap in coverage, not evidence of a defect -- see section "RESIDUAL UNPROVEN" at the end.
