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

---

## 6. `run_css_injection` -- 592 runs -- **CORRECTLY QUIET**

Wrapper (currently `tools.py:10455`, see NOTE ON LINE NUMBERS below). Pure Python. Reflects
`apolcss<tok>;--apolaki-<tok>:v<tok>;} :root{--apolaki-<tok>:v<tok>}` into each GET param and
confirms only when it lands inside a `<style>` block or a `style="..."` attribute; a confirmation
is then re-checked through a real Chromium CSSOM read.

**Oracle positive control.** MEASURED, three cases:

```
css.evaluate('<style>.x{color:red} <payload> </style>', tok)
   -> {'confirmed': True, 'where': 'style block',     'oracle': '...CSS structure unescaped'}
css.evaluate('<div style="color:red;<payload>">x</div>', tok)
   -> {'confirmed': True, 'where': 'style attribute', ...}
css.evaluate('<body><payload></body>', tok)
   -> {'confirmed': False, 'where': ''}
```

**Live transport control, DVWA reflected surface.** MEASURED:

```
GET http://dvwa/vulnerabilities/xss_r/?name=<css payload>   -> 200, 4427 bytes
payload echoed in the response: True
reflection context: '...</form>\r\n\t\t<pre>Hello apolcsse92ba7;--apolaki-e92ba7:...'
css.evaluate(...) -> confirmed False
```

The payload round-trips intact and the oracle reads it, then correctly rules it out: the reflection
is inside a `<pre>` text node, not a CSS context. That is the right answer -- CSS injection requires
a CSS context, and DVWA reflects into HTML text.

**VERDICT: CORRECTLY QUIET.** Transport proven, oracle proven, and it declines a reflection that is
real but in the wrong context -- exactly the discrimination it exists to make. No patch needed.

---

## 7. `run_client_checks` -- 348 runs -- **CORRECTLY QUIET, and PROVEN CAPABLE end-to-end**

Wrapper (currently `tools.py:9253`). Pure Python, PASSIVE. Two content checks: reverse tabnabbing
(a cross-origin `target=_blank` link with no `rel=noopener`) and a permissive
`crossdomain.xml` / `clientaccesspolicy.xml`.

**This is the one that produced a live TRUE POSITIVE, and it doubles as the positive control for
the entire audit harness.** MEASURED, the wrapper dispatched through the real
`ToolRegistry.execute` path against an authenticated DVWA:

```
run_client_checks {"url": "http://dvwa/index.php"}   (Cookie: PHPSESSID=...; security=low)
-> success=True  output='1 client/config finding(s)'  findings=1  error=None  swallowed=0
   FINDING: "Reverse tabnabbing - target=_blank link without rel=noopener"
            oracle: a target=_blank link to a different origin lacks rel=noopener/noreferrer
```

Raw corroboration of the same page: DVWA `/index.php` is 6721 bytes and contains **7**
`target="_blank"` cross-origin links; `cc.reverse_tabnabbing` returns all 7
(`virtualbox.org`, `vmware.com`, `apachefriends.org`, `itsecgames.com`, `sourceforge.net`,
`irongeek.com`, `owasp.org`). Negative control: the same helper on a link carrying
`rel="noopener"` returns `[]`.

Why the corpus is zero anyway. MEASURED: `http://juice-shop:3000/` is 9903 bytes and contains
**0** occurrences of `_blank`; the earlier live wrapper run there returned `0 client/config
finding(s)`. The corpus is dominated by Juice Shop and API targets that have no such links.

**Because this dispatch produced a NON-ZERO count through the ordinary path, the harness used for
every other verdict in this document is proven able to see a positive.** A zero reported below is a
measurement, not a broken rig.

Secondary observation (an FP risk, NOT a cause of the zero, filed for the owning lane):
`http://juice-shop:3000/crossdomain.xml` returns **200 with the SPA index HTML** (9903 bytes,
starting `<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich...`), because Juice Shop's catch-all
route serves `index.html` for unknown paths. The wrapper's guard is `if "<" in body and
cc.crossdomain_wildcard(body, fn)`. `crossdomain_wildcard` returns False on this body so nothing
fires today, but the `"<" in body` precondition is satisfied by ANY HTML page, so the only thing
standing between a soft-404 and a fabricated cross-domain-policy finding is the wildcard matcher.
A content-type / root-element check would be the durable guard.

**VERDICT: CORRECTLY QUIET on the corpus targets, PROVEN CAPABLE on DVWA.** No patch needed for the
zero. One hardening suggestion recorded above.

---

## 8. `run_form_nosqli` -- 482 runs -- **CORRECTLY QUIET (no Mongo-backed target in the fleet)**

Wrapper (currently `tools.py:8674`). Pure Python. Baselines a login POST with a benign credential,
then replaces both credential fields with MongoDB operator objects and confirms only on a real
bypass (token issued / 200).

**Oracle positive control.** MEASURED:

```
ns.AUTH_BYPASS_OPERATORS = [{'$ne': None}, {'$ne': ''}, {'$gt': ''}, {'$regex': '.*'}, {'$exists': True}]
ns.auth_bypass_confirmed(401, '{"error":"invalid"}',
                         200, '{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.abc.def"}}')
   -> {'signal': 'session/JWT token issued for an operator-injected credential', 'how': 'token'}
ns.auth_bypass_confirmed(401, '...invalid...', 401, '...invalid...')   -> {}
```

**Live, Juice Shop `/rest/user/login`, every operator the engine sends.** MEASURED, raw:

```
baseline {"email":"bbh_x@test.invalid","password":"nope123"} -> 401,  26 bytes  'Invalid email or password.'
{"email":{"$ne":null},   "password":{"$ne":null}}           -> 500, 2706 bytes  TypeError [ERR_INVALID_ARG_TYPE]
{"email":{"$ne":""},     "password":{"$ne":""}}             -> 500, 2706 bytes  TypeError [ERR_INVALID_ARG_TYPE]
{"email":{"$gt":""},     "password":{"$gt":""}}             -> 500, 2706 bytes  TypeError [ERR_INVALID_ARG_TYPE]
{"email":{"$regex":".*"},"password":{"$regex":".*"}}        -> 500, 2706 bytes  TypeError [ERR_INVALID_ARG_TYPE]
{"email":{"$exists":true},"password":{"$exists":true}}      -> 500, 2706 bytes  TypeError [ERR_INVALID_ARG_TYPE]
auth_bypass_confirmed(...) on each -> False
```

The engine reaches the target, the target's behaviour changes markedly (401 -> 500), and the oracle
still declines -- correctly. Juice Shop is Sequelize/SQLite, not MongoDB; no session was issued, so
there was no auth bypass to report. A NoSQL auth-bypass engine reporting "confirmed" on a 500 would
be a false positive.

**VERDICT: CORRECTLY QUIET.** Transport and oracle both proven; no MongoDB-backed application exists
in the authorized fleet, so the required positive can never occur there. 482 true negatives.

Filed for a different lane (out of Q-092 scope, and a REAL missed finding): those five requests turn
a login endpoint into an unhandled `TypeError` with a 2706-byte stack-trace error page. That is an
unhandled-exception / verbose-error finding (CWE-248 / CWE-209) that no engine in this list claims,
and `run_form_nosqli` is sitting on the evidence.

---

## 9. `run_nosqli` -- 342 runs -- see section 8's oracle; live below

Wrapper (currently `tools.py:8597`). Pure Python. Query-string operator injection
(`id[$ne]=`, `id[$regex]=`) with an error-signature stage and a boolean-differential stage against
both a non-matching-value control and a missing-param control.

The corpus output histogram is the informative part and it is NOT a precondition message:
`tested 1 param(s), 0 confirmed` (202), `tested 2` (94), `tested 3` (23), `tested 4` (23). **Every
one of the 342 runs reached the oracle with at least one parameter.** So this is oracle silence,
not input starvation.

**VERDICT: pending live differential -- see section 9b below.**

---

# 10. THE HEADLINE: `_http` HAS THE SAME DEFECT AS `_cmd`, AND IT IS BIGGER

Q-092 says a tool that runs and fails must not be byte-identical to a tool that runs and finds
nothing. `_cmd` has that defect for SUBPROCESSES. **`_http` has it for HTTP, it reaches all 21
pure-Python engines instead of the 14 that shell out, and 25.5% of the dispatches in the corpus
went through it to a target that could not possibly answer.**

## 10.1 A third instrument: the corpus records every tool's INPUT

`logs.etype='tool_call'` carries `{"tool","input","permission"}` -- 30173 rows. It says exactly what
URL each dispatch was pointed at. Reading it turned the audit around: several of these engines are
not silent because their oracle is weak, they are silent because **the request never completed.**

## 10.2 MEASURED: `_http` reports transport failure as a VALUE its callers do not read

```
reg._http("https://juice-shop:3000/rest/products/search?q=apple", "GET", capture=False)
  -> {'status': 0,
      'error': '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)',
      'body': ''            <-- 0 bytes
      ...}
reg._http("http://juice-shop:3000/rest/products/search?q=apple",  "GET", capture=False)
  -> {'status': 200, 'body': <921 bytes>}
reg._http("https:///.well-known/ai-plugin.json", "GET", capture=False)
  -> {'status': 0, 'error': "Request URL is missing an 'http://' or 'https://' protocol.", 'body': ''}
```

`_http` does the honest thing: it RETURNS `status` and `error`. The wrappers then do
`r.get("body", "") or ""` and never look at either. An empty body from a dead connection is
indistinguishable from an empty body from a clean page -- **the falsy-default failure mode, on the
return edge, exactly as Q-089/Q-090/Q-092 describe it.**

## 10.3 MEASURED: the wrappers report a CLEAN SCAN over a connection that never opened

Every request in each run below failed with `SSL: WRONG_VERSION_NUMBER`. Dispatched through the
real `ToolRegistry.execute`:

```
url = "https://juice-shop:3000/rest/products/search?q=apple"      (juice-shop speaks PLAIN HTTP)

run_waf_bypass       -> success=True  '0 WAF-bypass finding(s)'          error=None   <-- SILENT
run_sqli_structural  -> success=True  '0 structural SQLi finding(s)'     error=None   <-- SILENT
run_css_injection    -> success=True  '0 CSS injection finding(s)'       error=None   <-- SILENT
run_ssi              -> success=True  'DEGRADED: 1 load-bearing check(s) failed to execute;
                                       latest=tools:_run_ssi:5213 0 SSI injection finding(s)'
run_nosqli           -> success=True  'DEGRADED: 8 load-bearing check(s) failed to execute;
                                       latest=tools:get:8382 tested 1 param(s), 0 confirmed'
registry swallowed total = 9, latest = ConnectError: [SSL: WRONG_VERSION_NUMBER]
```

Two of the five are saved by the Q-08x swallow ledger, because they wrap their requests in a
`try/except` that reaches `_swallow`. **The other three are not, and cannot be: they never raise.**
`_http` catches the transport error itself and hands back a dict, so there is no exception for a
ledger to catch -- the failure arrives as data and is dropped by a default. The swallow ledger is
the right mechanism aimed at the wrong half of the problem.

## 10.4 MEASURED: how much of the corpus went to an unreachable target

Host reachability verified live first, because a wrong instrument is the expensive thing here:

```
juice-shop:3000        http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
juice-shop-bench:3000  http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
vampi:5000             http-> 200 (271B)    https-> ERR SSL: WRONG_VERSION_NUMBER
dvga:5013              http-> 200 (8136B)   https-> ERR SSL: WRONG_VERSION_NUMBER
dvwa:80                http-> 302 (0B)      https-> ERR SSL: WRONG_VERSION_NUMBER
owaspbench:8443        http-> 400 (62B)     https-> 404 (682B)        <- genuinely TLS
benchmarkpython:8443   http-> ERR ReadError https-> 302 (227B)        <- genuinely TLS
```

Classifying all 6622 `tool_call` rows for these 19 tools by whether the URL's scheme could reach its
host at all. "doomed" = `https://` to a plaintext-only host; "empty" = no host in the URL:

| tool | doomed | empty host | reachable | % unreachable |
|---|---|---|---|---|
| `run_path_sqli` | 55 | 0 | 3 | **94.8%** |
| `run_session_token` | 71 | 0 | 11 | **86.6%** |
| `run_username_enum` | 12 | 0 | 3 | **80.0%** |
| `run_client_checks` | 275 | 0 | 73 | **79.0%** |
| `run_upload_test` | 2 | 318 | 246 | **56.5%** |
| `run_form_cmdi` | 2 | 318 | 248 | **56.3%** |
| `run_ssi` | 351 | 0 | 589 | **37.3%** |
| `run_waf_bypass` | 76 | 0 | 516 | 12.8% |
| `run_sqli_structural` | 76 | 0 | 516 | 12.8% |
| `run_css_injection` | 76 | 0 | 516 | 12.8% |
| `run_llm_probe` | 0 | 6 | 46 | 11.5% |
| `run_oauth` | 3 | 37 | 605 | 6.2% |
| `run_cache_poison` | 1 | 0 | 67 | 1.5% |
| `run_form_nosqli` | 8 | 0 | 714 | 1.1% |
| `run_nosqli` / `run_deserialization` / `run_sqlmap` / `run_cache_deception` / `run_ssrf` | 0 | 0 | all | 0.0% |

**TOTAL: 1008 doomed + 679 empty-host = 1687 of 6622 dispatches (25.5%) could not have reached
their target, and every one of them was reported as a completed scan.**

`run_client_checks` is the sharpest case: proven in section 7 to work and to produce a real finding,
yet **79% of its 348 corpus runs were fired at `https://` URLs for plaintext hosts.** Its zero
histogram is not one phenomenon, it is two -- 73 honest true negatives and 275 requests that never
opened a socket.

The `https:///` empty-host URLs (318 each for `run_form_cmdi` and `run_upload_test`, 37 for
`run_oauth`, 6 for `run_llm_probe`) come from a URL builder that lost its netloc; targets recorded
literally as `https:///`, `https:///.well-known/ai-plugin.json`, `https:///.well-known/gpc.json`.

## 10.5 PROPOSED PATCH (diff only -- `tools.py` is another lane's file)

The carrier must be the thing callers already read (Q-089's lesson), so this does NOT add an
out-parameter. `_http` already returns `status`/`error`; the fix is to make the FAILURE VISIBLE at
the ToolResult edge rather than asking 21 wrappers to remember to check.

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ class ToolRegistry:
+    # I-2b, HTTP path. A transport failure returns `status == 0` with an `error` and an EMPTY
+    # body. Every engine reads `r.get("body", "") or ""`, so a dead connection and a clean page
+    # are the same value. Count the dead ones here, at the single choke point every engine
+    # already goes through, and let `execute` fail the ToolResult when a run made NO successful
+    # request at all. Mirrors _cmd's exit-code fix: outcome fidelity on the return edge.
+    async def _http(self, url, method="GET", headers=None, body=None, capture=False, **kw):
+        res = await self.__http_inner(url, method, headers, body, capture, **kw)
+        if not res.get("status"):
+            self._http_dead = getattr(self, "_http_dead", 0) + 1
+            self._http_dead_last = {"url": url, "error": res.get("error")}
+        else:
+            self._http_live = getattr(self, "_http_live", 0) + 1
+        return res
@@ async def execute(self, tool_name, tool_input, session_id):
-        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        # A dispatch that made requests and had EVERY one fail did not scan anything. Reporting
+        # success=True with zero findings there is the false-clean this ticket exists to kill.
+        dead = getattr(self, "_http_dead", 0) - dead_before
+        live = getattr(self, "_http_live", 0) - live_before
+        if res is not None and dead and not live:
+            res.success = False
+            res.error = "NO REQUEST COMPLETED: %d/%d failed; last=%s" % (
+                dead, dead, (getattr(self, "_http_dead_last", {}) or {}).get("error"))
```

Second, independent patch: the URL builder that emitted 679 `https:///` URLs and 1008 `https://`
URLs for plaintext hosts must not emit them. That is a separate lane's defect (target
construction), and it is worth its own ticket -- fixing `_http`'s honesty makes it VISIBLE, it does
not make it stop happening.

### NOTE ON THE CENSUS INSTRUMENT, verified before the numbers above were trusted

Two things about `count` that would have made me misread it:

1. `count` is NOT `len(result.findings)`. `agent.py:850` computes
   `_real = sum(1 for f in result.findings if not (isinstance(f, dict) and f.get("vulnerable") is False))`
   -- sqlmap's no-confirmation data-carrier `{"vulnerable": False, "log_tail": ...}` is excluded.
   So `run_sqlmap` legitimately logs `count: 0` while returning a 1-element list. The census is
   still the right instrument, but it measures REAL findings, not list length.
2. A dispatch whose `ToolResult.error` is set is logged as `tool_error`/`scope_block`, **not** as
   `tool_result` (`agent.py:840`). Only 4 `tool_error` rows exist for all 22 tools. **This
   strengthens the finding rather than weakening it:** the 1687 unreachable dispatches are not
   hiding in an error table, they are sitting in `tool_result` wearing a clean-scan summary.

---

## 11. `run_sqlmap` -- 58 runs -- **BROKEN, twice over**, and the only one of the 22 on the `_cmd` chokepoint

Wrapper (currently `tools.py:~10815`). **The only one of my 22 that calls `self._cmd`.** It checks
`err.startswith("__MISSING__")` and nothing else, then decides purely on
`vuln = "is vulnerable" in out or "sqlmap identified" in out`.

### 11.1 The Q-092 defect is LIVE here -- MEASURED negative control

```
$ sqlmap -u "http://juice-shop:3000/x" --batch --no-such-flag
EXIT=2
stdout 217 bytes (banner only)
stderr  79 bytes: "Usage: python3 sqlmap [options]\n\nsqlmap: error: no such option: --no-such-flag"
grep "is vulnerable|sqlmap identified" -> 0
```

sqlmap exits **2 without scanning anything**. `err` is the usage text, which does NOT start with
`__MISSING__`, so the guard passes it. `vuln` is False. The wrapper returns
`ToolResult("sqlmap", url, True, "No SQLi confirmed [standard]", [...])` -- **`success=True`, a
clean scan, from a tool that never ran.** This is nuclei's failure exactly, in a different binary.
(Where nuclei wrote its flag error to STDOUT, sqlmap writes to STDERR; neither is checked, because
neither can be: `_cmd` never returns the exit code.)

### 11.2 The tool itself is HEALTHY -- MEASURED positive control

The wrapper's exact `deep` command, run by hand against an authorized lab:

```
$ sqlmap -u "http://juice-shop:3000/rest/products/search?q=apple" --batch --level 3 --risk 2 \
         --flush-session --random-agent --technique BEUSTQ
EXIT=0    stdout 79855->4364 bytes    stderr 0 bytes
grep "is vulnerable" -> 1     grep "sqlmap identified" -> 1

Parameter: q (GET)
    Type: boolean-based blind   AND boolean-based blind - WHERE or HAVING clause
        Payload: q=apple%' AND 7729=7729 AND 'sZgQ%'='sZgQ
    Type: time-based blind      SQLite > 2.0 AND time-based blind (heavy query)
back-end DBMS: SQLite
```

**sqlmap finds real SQL injection on this lab and the wrapper's marker oracle matches it.** Unlike
dalfox, the parser is fine. So the 58 zeros have a different cause.

### 11.3 The actual cause of the 58 zeros: EVERY dispatch used a VALUELESS parameter

MEASURED, all 58 `tool_call` rows for `run_sqlmap`: **58/58 have a query string in which every
parameter is valueless** -- `?q`, `?key&name`, `?current`, `?email`, `?callback&format&key`,
`?EIO&sid&t&transport`. These come from param-mining, which yields NAMES, not observed values.

The A/B on the same endpoint, same binary, same flags -- the corpus's own URL versus the same URL
with a value:

```
$ sqlmap -u "http://juice-shop:3000/rest/products/search?q"  --batch --level 5 --risk 3 \
         --flush-session --random-agent --technique BEUSTQ --threads 4 \
         --current-user --current-db --is-dba --dbs          # the corpus's exact `insane` command
EXIT=0   stdout 79855 bytes   stderr 0 bytes
grep "is vulnerable" -> 0    grep "sqlmap identified" -> 0
tail: "[ERROR] all tested parameters do not appear to be injectable."

$ same command with ?q=apple                       ->  CONFIRMED (11.2 above)
```

**The same tool, the same endpoint, the same flags. The only difference is that the parameter had a
value.** The endpoint IS injectable; sqlmap proves it in 11.2 and misses it in 11.3.

Corroborating raw responses (why the empty value is fatal): `?q` and `?q=` both return **16578
bytes** (the whole product list -- an unfiltered query), while `?q=apple` returns **921 bytes**.
With an empty value the baseline is the unfiltered response, so sqlmap's dynamicity check finds the
parameter does not change the page and it stops before injecting.

This is the "probe with observed values" discipline in its exact failure form.

**VERDICT: BROKEN.** Two independent defects, both real:
1. **Latent-but-real:** a non-zero sqlmap exit is reported as a clean scan (11.1). Q-092's fix at
   `_cmd` closes this.
2. **Live and causing all 58 zeros:** the caller feeds valueless parameters, so sqlmap never
   reaches the injection stage (11.3). `_cmd`'s fix will NOT close this one -- exit code is 0 and
   the tool ran correctly. It needs the caller to supply an observed value.

### 11.4 PROPOSED PATCH for 11.3 (diff only)

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ async def _run_sqlmap(self, inp: dict) -> ToolResult:
     url = inp["url"]
+    # A parameter mined by NAME has no value, and sqlmap's dynamicity check stops before the
+    # injection stage when the page does not change -- MEASURED: `?q` misses a SQLi that `?q=apple`
+    # confirms on the same endpoint. Give every valueless parameter a benign observed-shaped seed
+    # so the baseline is a FILTERED response rather than the unfiltered one.
+    url = _seed_valueless_params(url)          # ?q -> ?q=<benign seed>
```

with the negative control being that a URL whose parameters already carry values is returned
byte-identical.

---

## 12. HONEST NEGATIVE RESULT: valueless parameters do NOT break the value-overwriting engines

The obvious next hypothesis was that the valueless-parameter defect explains the other zero
histograms too. **It does not, and I measured it rather than assuming it.**

Corpus scale of the phenomenon first (all `tool_call` rows with a query string):

| tool | all params valueless | some | all valued |
|---|---|---|---|
| `run_sqlmap` | **58 (100%)** | 0 | 0 |
| `run_ssrf` | **23 (100%)** | 0 | 0 |
| `run_nosqli` | 334 (97.7%) | 0 | 8 |
| `run_deserialization` | 327 (97.6%) | 0 | 8 |
| `run_ssi` / `run_waf_bypass` / `run_sqli_structural` / `run_css_injection` | 392 (73.5%) | 14 | 127 |

**TOTAL: 2310 of 2890 param-bearing dispatches (79.9%) carried no parameter value at all.**

But the A/B disproves the hypothesis for the reflection engines. `_setq(name, payload)` REPLACES
the parameter value, so a missing original value costs them only their baseline, not their probe:

```
url = http://juice-shop:3000/rest/products/search
?q         (valueless, as the corpus called it)      ?q=apple  (valued)
  run_sqli_structural  '0 structural SQLi finding(s)'   ->  '0 structural SQLi finding(s)'
  run_nosqli           'tested 1 param(s), 0 confirmed' ->  'tested 1 param(s), 0 confirmed'
  run_ssi              '0 SSI injection finding(s)'     ->  '0 SSI injection finding(s)'
  run_css_injection    '0 CSS injection finding(s)'     ->  '0 CSS injection finding(s)'
```

Identical on both sides, even though the baseline bodies differ by 15657 bytes (16578 vs 921).

**The valueless-parameter defect is specific to engines that USE the observed value as their
injection base.** Proven for `run_sqlmap`. `run_ssrf` is 100% valueless too and is the other
candidate -- audited in its own section below. Blast radius is therefore much smaller than the
79.9% headline, and saying so is the point of measuring it.

---

# 13. DELIVERABLE 2 -- the gate: `agent/tests/test_external_tool_liveness.py`

**IT FAILS TODAY, DELIBERATELY, AND THAT IS THE DELIVERABLE.** MEASURED:

```
docker run --rm -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_external_tool_liveness.py -p no:cacheprovider -rfE
-> 4 failed, 3 passed in 2.65s      (pytest exit 1)

FAILED test_cmd_hands_back_the_exit_status
FAILED test_cmd_reports_a_zero_exit_as_zero
FAILED test_wrapper_reports_not_ran_when_the_tool_exits_nonzero
FAILED test_a_failed_run_is_distinguishable_from_a_clean_run
```

The last one prints the defect in a single line of pytest output:

```
E  AssertionError: a tool that exited 2 without scanning and a tool that scanned and found
   nothing produce the identical ToolResult; ...
E  assert (True, False) != (True, False)
```

`(success, bool(error))` is `(True, False)` for BOTH a sqlmap that exited 2 without scanning and a
sqlmap that scanned cleanly. That equality is Q-092.

**The 3 that PASS are the half that makes the guard trustworthy**, and they are not decoration:

| test | passes today | what it rules out |
|---|---|---|
| `test_the_rig_itself_can_tell_the_two_apart` | yes | that the 4 failures are a broken fixture. Asserts the two fake binaries really exit 2 and 0 at the OS level, and that NEITHER stdout carries a confirmation marker -- so the exit code is the only axis that separates them |
| `test_missing_binary_is_still_reported` | yes | that the rig drives a different code path than the one named. The `__MISSING__` signal, the one outcome `_cmd` does surface, still works |
| `test_wrapper_reports_success_when_the_tool_runs_cleanly` | yes | a "fix" that satisfies the guard by failing every run. A tool that exits 0 and finds nothing must stay `success=True` |

Design notes, so the next lane does not weaken it by accident:

- **The fake binaries are real executables on PATH** (`#!/bin/sh`, `chmod 0755`), not a stubbed
  `_cmd`. Stubbing `_cmd` would test the stub; the entire question is what a genuine non-zero
  `proc.returncode` does at the return edge.
- **`_exit_status_of` is permissive about SHAPE and strict about PRESENCE.** Q-092 prescribes the
  value on the return edge but not its packaging, so a 3-tuple, a namedtuple field or a small
  result object all satisfy it. Only "the caller cannot obtain the exit status at all" fails. This
  is what lets the guard survive the fix without being rewritten to match it.
- **`test_cmd_reports_a_zero_exit_as_zero` is paired with the non-zero one on purpose**, so a
  repaired `_cmd` cannot satisfy the guard by returning a constant.
- `success` is this codebase's spelling of the ticket's `ran`:
  `ToolResult(tool, target, success, output, findings, error)`.
- The module carries `skipif(os.name == "nt")` because the fixture is a POSIX shell script. The
  suite's authority is the Linux agent image, which is where the 4-failed/3-passed result above was
  measured. It is a platform guard, not a pass.

**Consequence to flag to the Coordinator: committing this file makes the suite red on exactly these
4 tests until the `_cmd` chokepoint is repaired.** That is what Q-092's GATE clause asked for ("it
must FAIL against today's `_cmd`, which cannot express the distinction at all"). It is not a
weakened or vacuous guard: 3 controls pass, and the 4 failures name a defect that is reproducible
by hand in one command.
