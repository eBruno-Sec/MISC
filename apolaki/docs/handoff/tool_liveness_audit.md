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

## SUMMARY -- all 22, classified, with the evidence that decided each

| tool | runs | verdict | what decided it |
|---|---|---|---|
| `run_ssi` | 940 | CORRECTLY QUIET | payload round-trips on DVWA, oracle rules it reflected-not-executed; no SSI server in the fleet |
| `run_waf_bypass` | 592 | CORRECTLY QUIET | requires a WAF to block the bare signature; no lab has one |
| `run_sqli_structural` | 592 | CORRECTLY QUIET | param is a `LIKE` value context, not a query-structure context |
| `run_css_injection` | 592 | CORRECTLY QUIET | payload reflects into a `<pre>`, not a CSS context; oracle correctly declines |
| `run_form_nosqli` | 482 | CORRECTLY QUIET | all 5 operators sent live; Juice Shop is SQLite, no Mongo in the fleet |
| `run_oauth` | 422 | CORRECTLY QUIET / positive UNTESTABLE | no OAuth authorization server on any authorized target |
| **`run_client_checks`** | 348 | **73 QUIET + 275 NEVER RAN** | **live TRUE POSITIVE on DVWA; 275/348 fired at `https://` plaintext hosts** |
| `run_nosqli` | 342 | CORRECTLY QUIET | reached its oracle every run; no Mongo-backed target exists |
| `run_deserialization` | 335 | CORRECTLY QUIET | fires on a serialized blob when given one; no target passes serialized objects |
| `run_github_recon` | 320 | **UNTESTABLE (disabled)** | 320/320 `Skipped - set BBH_GITHUB_TOKEN`; never made a request |
| `run_form_cmdi` | 250 | CORRECTLY QUIET, PROVEN CAPABLE | live CONFIRMED cmdi on DVWA; 318/568 dispatches had NO HOST |
| `run_upload_test` | 248 | CORRECTLY QUIET, PROVEN CAPABLE | live finding on DVWA upload; 318/566 dispatches had NO HOST |
| `check_takeover` | 142 | CORRECTLY QUIET / positive UNTESTABLE | all 142 called with `{}`; no dangling CNAME exists in the fleet |
| `run_session_token` | 82 | CORRECTLY QUIET | DVWA/VAmPI tokens are random; 71/82 unreachable by scheme |
| `run_exposure` | 62 | CORRECTLY QUIET, PROVEN CAPABLE | live "Exposed phpinfo()" on DVWA |
| `run_cache_poison` | 59 | CORRECTLY QUIET | no unkeyed-header reflection, no cache in front of the labs |
| **`run_sqlmap`** | 58 | **BROKEN (x2)** | **exit 2 reported clean; 58/58 used valueless params and missed a SQLi the same command confirms with a value** |
| **`run_path_sqli`** | 58 | **BROKEN BY TRANSPORT** | **finds a REAL CWE-89 on VAmPI; 55/58 fired at `https://` on a plaintext host** |
| `run_llm_probe` | 46 | CORRECTLY QUIET (uninformative) | never exchanged a message with an LLM; both corpus paths are a soft-404 and a 500 |
| `run_cache_deception` | 24 | CORRECTLY QUIET | ran the full variant sweep with a real session; no caching layer exists |
| `run_ssrf` | 23 | CORRECTLY QUIET (uninformative) | 23/23 to one mangled URL, all params valueless; never saw a URL-fetching param |
| `run_username_enum` | 15 | PRECONDITION NEVER MET | needs a known-good account; none supplied. 12/15 unreachable. Capability UNPROVEN |

**Tally: 2 BROKEN, 1 split (73 quiet / 275 never ran), 1 UNTESTABLE-by-config, 1 precondition-never-met, 17 CORRECTLY QUIET.**

**Zero BLIND.** Not one of the 22 has dalfox's defect -- a parser that can never yield a finding no
matter what the tool emits. Every oracle I tested fired on a synthetic positive and stayed silent
on a negative. **The dalfox/nuclei shape did not generalise, and that is a real result: it shrinks
the suspected blast radius of Q-091/Q-092's parser class from 24 tools to the 2 already known.**

**What DID generalise is a different defect**: 6 of the 22 are demonstrably working engines
(`run_client_checks`, `run_form_cmdi`, `run_upload_test`, `run_exposure`, `run_deserialization`,
`run_path_sqli` all produced live findings) whose zeros are dominated by dispatches that never
reached a target. That is section 10 / proposed ticket Q-093.

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

**VERDICT: CORRECTLY QUIET on the 73 runs that reached a target; the other 275 NEVER RAN.** See
7b -- this tool is the case that proves the two phenomena are distinct.

### 7b. `run_client_checks` is the whole argument in one experiment

This engine is the sharpest evidence in the audit because it is **provably working** and its zero
histogram is **two different phenomena wearing one number**.

Exact corpus split of all 348 dispatches, by scheme and host:

```
DOOMED  (https:// to a host that speaks only plaintext) = 275
    https://vampi:5000              167
    https://juice-shop:3000          96
    https://juice-shop-bench:3000    12
REACHABLE                                                =  73
    https://ginandjuice.shop         36
    https://owaspbench:8443          24
    http://vampi:5000                13
```

**The A/B, live, dispatched through the real `ToolRegistry.execute`.** Same engine, same page, one
reachable scheme and one that cannot open a socket:

```
https://vampi:5000/        success=True  '0 client/config finding(s)'  n=0  error=None
http://vampi:5000/         success=True  '0 client/config finding(s)'  n=0  error=None
    raw http://vampi:5000/ -> 200, 271 B, _blank count = 0, reverse_tabnabbing() = []

https://juice-shop:3000/   success=True  '0 client/config finding(s)'  n=0  error=None
http://juice-shop:3000/    success=True  '0 client/config finding(s)'  n=0  error=None
    raw http://juice-shop:3000/ -> 200, 9903 B, _blank count = 0, reverse_tabnabbing() = []
```

**The two ToolResults are byte-identical, and one of them never opened a socket.**

Put beside the DVWA run from section 7, the engine has exactly three real states and the reporting
collapses two of them:

| state | live evidence | what the operator sees |
|---|---|---|
| reachable + finding present | DVWA `/index.php`, 7 unprotected `target=_blank` links | `1 client/config finding(s)` |
| reachable + genuinely clean | vampi 271 B / juice-shop 9903 B, 0 `_blank` | `0 client/config finding(s)` |
| **UNREACHABLE** | `https://` to a plaintext host, `SSL: WRONG_VERSION_NUMBER`, 0 bytes | `0 client/config finding(s)` |

Rows 2 and 3 are indistinguishable to every consumer -- the operator, the report, the ledger and
the corpus census alike. **79.0% of this engine's history (275/348) is row 3 being read as row 2.**

This also settles the question the census alone could not answer. `run_client_checks` is not weakly
oracled and not badly targeted in the "wrong page" sense: it works, it found a real finding on the
first authorized target that actually had one, and its 73 reachable runs are honest true negatives
on pages measured to contain nothing for it to find. Its zero is 73 true negatives plus 275
non-events.

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

**TOTAL, DENOMINATOR = the 19 url-bearing tools of this audit: 1008 doomed + 679 empty-host = 1687
of 6622 dispatches (25.5%) could not have reached their target, and every one of them was reported
as a completed scan.**

### STATE THE DENOMINATOR -- two true numbers, two populations

The Coordinator independently reproduced this over ALL tools rather than my 19, and got a larger
absolute count on a larger base:

| population | empty host | https to plaintext host | unreachable | of | rate |
|---|---|---|---|---|---|
| **my 19 audited url-bearing tools** | 679 | 1008 | **1687** | 6622 | **25.5%** |
| **corpus-wide, all tools** (Coordinator) | 1495 | 1746 | **3241** | 27222 | **11.9%** |

**These do not conflict -- they are different denominators.** 25.5% is the rate among the tools in
this audit; 11.9% is the rate across every url/target dispatch in the corpus. The absolute
corpus-wide count is nearly double what this section measured, so the blast radius is BIGGER than
my scope, not smaller. Quote either, but always with its denominator attached: an unlabelled
percentage here is the kind of number that gets challenged and deserves to be.

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

---

# 14. PROPOSED TICKET Q-093 -- ready to file verbatim into `docs/QUEUE.md`

Coordinator owns `docs/QUEUE.md`; the text below is written to be pasted in as-is.

<!-- ================= BEGIN Q-093 TICKET TEXT ================= -->

### Q-093 - `_http` drops the transport outcome the same way `_cmd` drops the exit code, and 3241 dispatches never reached a target - **READY** - **CRITICAL**

**This is Q-092 in the HTTP path.** Q-092 is about 14 wrappers that shell out. `_http` is the
transport for **all 21 pure-Python engines**, and it has the identical defect with a wider blast
radius. Found while auditing Q-092's 22 remaining zero-histogram tools
(`docs/handoff/tool_liveness_audit.md`).

**MEASURED, live, on `apolaki_default`:**

```
reg._http("https://juice-shop:3000/rest/products/search?q=apple", "GET", capture=False)
  -> {'status': 0, 'error': '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)',
      'body': ''}                       # 0 bytes
reg._http("http://juice-shop:3000/rest/products/search?q=apple", "GET", capture=False)
  -> {'status': 200, 'body': <921 bytes>}
reg._http("https:///.well-known/ai-plugin.json", "GET", capture=False)
  -> {'status': 0, 'error': "Request URL is missing an 'http://' or 'https://' protocol.", 'body': ''}
```

`_http` is honest -- it RETURNS `status` and `error`. **The callers never read either.** Every
engine does `r.get("body", "") or ""`, so an empty body from a dead connection is the same value as
an empty body from a clean page. This is the falsy-default failure mode on the return edge, the
same invariant `FindingWriteId` (Q-089) and `FindingUpdateResult` (Q-090) exist to satisfy.

**MEASURED: the wrappers report a completed scan over a connection that never opened.** Every
request in each run below failed with `SSL: WRONG_VERSION_NUMBER`, dispatched through the real
`ToolRegistry.execute`, url = `https://juice-shop:3000/rest/products/search?q=apple`:

```
run_waf_bypass       -> success=True  '0 WAF-bypass finding(s)'       error=None   <-- SILENT
run_sqli_structural  -> success=True  '0 structural SQLi finding(s)'  error=None   <-- SILENT
run_css_injection    -> success=True  '0 CSS injection finding(s)'    error=None   <-- SILENT
run_ssi              -> success=True  'DEGRADED: 1 load-bearing check(s) failed ...'
run_nosqli           -> success=True  'DEGRADED: 8 load-bearing check(s) failed ...'
```

**The Q-08x swallow ledger cannot close this.** It catches two of the five, because those two wrap
their requests in a `try/except` that reaches `_swallow`. The other three never raise: `_http`
catches the transport error itself and returns a dict, so the failure arrives **as data** and is
dropped by a default. There is no exception for a ledger to catch. The ledger is the right
mechanism aimed at the wrong half of the problem.

**SCALE, two populations, both stated with their denominator:**

| population | empty host | https to plaintext host | unreachable | of | rate |
|---|---|---|---|---|---|
| the 19 url-bearing tools of the Q-092 audit | 679 | 1008 | **1687** | 6622 | **25.5%** |
| corpus-wide, all tools | 1495 | 1746 | **3241** | 27222 | **11.9%** |

Host reachability was verified live before the classification was trusted:

```
juice-shop:3000        http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
juice-shop-bench:3000  http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
vampi:5000             http-> 200 (271B)    https-> ERR SSL: WRONG_VERSION_NUMBER
dvga:5013              http-> 200 (8136B)   https-> ERR SSL: WRONG_VERSION_NUMBER
dvwa:80                http-> 302 (0B)      https-> ERR SSL: WRONG_VERSION_NUMBER
owaspbench:8443        http-> 400 (62B)     https-> 404 (682B)      <- genuinely TLS
benchmarkpython:8443   http-> ERR ReadError https-> 302 (227B)      <- genuinely TLS
```

**These dispatches are NOT hiding in an error table.** `agent.py:840` logs a `ToolResult` with an
`error` as `tool_error`/`scope_block` and everything else as `tool_result`. There are 4
`tool_error` rows for all 22 audited tools. The 1687 unreachable dispatches sit in `tool_result`
wearing a clean-scan summary.

**THE CASE THAT MAKES IT CONCRETE -- `run_client_checks`.** A tool proven to work, whose single
zero histogram is two different phenomena:

```
corpus split of its 348 dispatches:
    DOOMED    275   https://vampi:5000 (167), https://juice-shop:3000 (96),
                    https://juice-shop-bench:3000 (12)
    REACHABLE  73   https://ginandjuice.shop (36), https://owaspbench:8443 (24),
                    http://vampi:5000 (13)

live A/B, same engine, same page, one reachable scheme and one that cannot open a socket:
    https://vampi:5000/       success=True  '0 client/config finding(s)'  error=None
    http://vampi:5000/        success=True  '0 client/config finding(s)'  error=None
    https://juice-shop:3000/  success=True  '0 client/config finding(s)'  error=None
    http://juice-shop:3000/   success=True  '0 client/config finding(s)'  error=None

the same engine on a target that DOES have the defect:
    run_client_checks {"url": "http://dvwa/index.php"} (authenticated)
      -> success=True  '1 client/config finding(s)'  n=1
         "Reverse tabnabbing - target=_blank link without rel=noopener"
         (DVWA /index.php carries 7 unprotected cross-origin target=_blank links)
```

The engine has three real states -- reachable+finding, reachable+clean, unreachable -- and the last
two produce byte-identical results. **79.0% of this tool's history is "never ran" being read as
"clean".**

**TWO ROOT CAUSES, TWO FIXES. They are independent and must not be conflated.**

**(A) `_http` does not carry the transport outcome to the ToolResult edge.** Fix at the chokepoint,
not in 21 engines. The carrier must be the thing callers already read (Q-089's lesson), so this
adds no out-parameter callers can ignore:

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ class ToolRegistry:
+    # I-2b, HTTP path. A transport failure returns `status == 0` with an `error` and an EMPTY
+    # body. Every engine reads `r.get("body", "") or ""`, so a dead connection and a clean page
+    # are the same value. Count the dead ones at the single choke point every engine already
+    # goes through, and let `execute` fail the ToolResult when a dispatch made NO successful
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
+        dead_before = getattr(self, "_http_dead", 0)
+        live_before = getattr(self, "_http_live", 0)
...
-        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        # A dispatch that made requests and had EVERY one fail did not scan anything. Reporting
+        # success=True with zero findings there is the false-clean this ticket exists to kill.
+        dead = getattr(self, "_http_dead", 0) - dead_before
+        live = getattr(self, "_http_live", 0) - live_before
+        if res is not None and dead and not live:
+            res.success = False
+            res.error = "NO REQUEST COMPLETED: %d request(s) failed; last=%s" % (
+                dead, (getattr(self, "_http_dead_last", {}) or {}).get("error"))
```

Note the `dead and not live` condition: a dispatch where SOME requests failed is degraded, not
dead, and the existing `DEGRADED:` line already covers it. Only "made requests, every one failed"
becomes `success=False`. A dispatch that made no requests at all is untouched.

**(B) The target builder emits URLs that cannot be requested.** This is a SEPARATE root cause with
a separate fix, and (A) only makes it visible -- it does not stop it happening.

Two distinct malformations, both MEASURED in `logs.etype='tool_call'`:

1. **Scheme mismatch -- 1746 corpus-wide.** `https://` is attached to lab hosts that serve only
   plaintext (`vampi:5000`, `juice-shop:3000`, `juice-shop-bench:3000`, `dvga:5013`, `dvwa`). The
   builder is upgrading or defaulting the scheme without regard to what the host answers on.
2. **Lost netloc -- 1495 corpus-wide.** URLs recorded literally as `https:///`,
   `https:///.well-known/ai-plugin.json`, `https:///.well-known/assetlinks.json`,
   `https:///.well-known/gpc.json`. A builder joined a path onto an origin that was the empty
   string, producing a URL with **no host at all**. httpx rejects these before any connection
   (`Request URL is missing an 'http://' or 'https://' protocol`). Worst hit:
   `run_form_cmdi` 318/568 and `run_upload_test` 318/566 -- **56% of both tools' entire history.**
   `run_oauth` 37, `run_llm_probe` 6.

   The empty-netloc case is the more dangerous of the two because it is unconditional: no target
   configuration can make `https:///` resolve, so those dispatches were never capable of doing
   anything, on any target, ever.

**GATE.** Three properties, each with the negative control that must fail before the fix:

1. A dispatch whose every request failed yields `success=False` with an `error`, not
   `success=True, "0 findings"`. Negative control: it must FAIL today -- measured above, today it
   is `success=True, error=None`.
2. A dispatch where some requests succeeded and some failed stays `success=True` and keeps its
   existing `DEGRADED:` line. This must PASS today and after, so the fix cannot be "fail
   everything".
3. No product code path constructs a URL with an empty netloc. Fact-checked against real builder
   output, not against a declaration -- this project has shipped guards that check declarations
   eleven times.

**RELATION TO Q-092.** Same invariant (I-2b, outcome fidelity on the return edge), different
transport. Q-092's `_cmd` fix does NOT touch this: `_http`'s failures never reach a subprocess.
Fixing one and calling the class closed would leave the larger half open.

<!-- ================== END Q-093 TICKET TEXT ================== -->

---

# 15. THE CONSEQUENCE, PROVEN: a REAL vulnerability an Apolaki engine detects, missed 55 times

`run_path_sqli` is the case that turns Q-093 from an integrity argument into a lost finding.

**MEASURED live.** The engine, dispatched through the real path against an authorized lab:

```
run_path_sqli {"url": "http://vampi:5000/users/v1/1"}
  -> success=True  '1 path-param SQLi finding(s)'  n=1
     title:      SQL injection (error-based) in 'path segment 3'
     severity:   high      cwe: CWE-89      confidence: confirmed
     evidence:   SQLite error triggered by "1'"
```

**Verified genuine by hand, with the balanced-quote negative control** (so this is an injection, not
a generic 500):

```
/users/v1/1               -> 404,    48 B  {"status":"fail","message":"User not found"}
/users/v1/1'              -> 500, 44654 B  sqlalchemy.exc.OperationalError:
                                           (sqlite3.OperationalError) unrecognized token:
/users/v1/1''             -> 404,    48 B  {"status":"fail","message":"User not found"}
/users/v1/1' AND '1'='1   -> 404,    48 B  {"status":"fail","message":"User not found"}
```

One quote breaks the query, two quotes restore it. That is a textbook error-based SQLi and the
finding is correct.

**And the corpus fired this engine at `https://vampi:5000/...` for 55 of its 58 runs (94.8%)** --
the same path, the same host, the scheme that cannot open a socket. `https://vampi:5000/users/v1/1`
was dispatched 13 times on its own.

**A high-severity SQL injection that Apolaki's own engine finds correctly, on a lab in the standing
fleet, was reported as a clean scan 55 times.** Not a hypothetical loss of fidelity: a lost
finding, with the engine, the target and the proof all still in place.

---

# 16. REMAINING VERDICTS

Four more engines produced live TRUE POSITIVES during this pass, which raises the count of
demonstrably-working engines in the audit to six.

## 16.1 `run_form_cmdi` -- 250 runs (568 dispatches) -- **CORRECTLY QUIET, PROVEN CAPABLE**

MEASURED, authenticated DVWA:

```
run_form_cmdi {"url": "http://dvwa/vulnerabilities/exec/"}
  -> success=True  'command injection CONFIRMED in the form body
                    (http://dvwa/vulnerabilities/exec/)'  n=1
     -> "OS command injection (output) in 'ip'"
```

The engine works and confirms a real OS command injection. Its corpus zero is targeting:
**318 of 568 dispatches (56.3%) went to `https:///` -- a URL with no host** -- and the remainder to
Juice Shop, which has no server-rendered command-executing form. Corpus summary was 250/250
`no body command injection in the page's forms`.

## 16.2 `run_upload_test` -- 248 runs (566 dispatches) -- **CORRECTLY QUIET, PROVEN CAPABLE**

MEASURED, authenticated DVWA:

```
run_upload_test {"url": "http://dvwa/vulnerabilities/upload/"}
  -> success=True  'no restriction observed on upload endpoint'  n=1
     -> "No file-extension restriction observed on upload endpoint"
```

Raw corroboration: `/vulnerabilities/upload/` is 4194 bytes and contains `type="file"`. Corpus:
226/248 `No file-upload form found`, 22 `Could not fetch page for form discovery` -- and **318 of
566 dispatches (56.5%) were the empty-host `https:///` form.** Juice Shop's upload is an SPA XHR,
not a server-rendered form, so "no form found" is honest there.

## 16.3 `run_exposure` -- 62 runs -- **CORRECTLY QUIET, PROVEN CAPABLE**

MEASURED, DVWA: `run_exposure {"base_url": "http://dvwa"}` -> `'15 checks, 1 exposure(s)'`, n=1,
finding **"Exposed phpinfo()"**. The 62 corpus runs all report `15 checks, 0 exposure(s)` against
Juice Shop / ginandjuice / VAmPI, none of which serve phpinfo. True negatives.

## 16.4 `run_deserialization` -- 335 runs -- **CORRECTLY QUIET, PROVEN CAPABLE**

Corpus: 335/335 `No serialized objects found in query params or cookies` -- the precondition was
never met, not once. MEASURED that the precondition is real and the engine fires when it IS met:

```
run_deserialization {"url": ".../search?q=rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcg"}   (java stream magic)
  -> success=True  '1 serialized input(s), 1 signal(s), 0 confirmed'  n=1
run_deserialization {"url": "http://dvwa/vulnerabilities/exec/"}
  -> 'No serialized objects found in query params, cookies or form fields'  n=0
```

The engine detects a serialized blob when one is present. No target in the fleet passes serialized
objects in params or cookies, so 335 true negatives.

## 16.5 `run_path_sqli` -- 58 runs -- **BROKEN BY TRANSPORT** (section 15)

Engine correct and proven; **55/58 (94.8%) unreachable by scheme.** The only entry in this audit
where a confirmed real vulnerability was demonstrably missed. Fixed by Q-093(B), not by Q-092.

## 16.6 `run_nosqli` -- 342 runs -- **CORRECTLY QUIET**

Corpus reached the oracle every time (`tested N param(s), 0 confirmed`, N = 1..4) -- oracle silence,
not input starvation. Oracle proven in section 8. MEASURED live on Juice Shop and VAmPI
(`/books/v1/1?id=1`): `tested 1 param(s), 0 confirmed`. **No MongoDB-backed application exists in
the authorized fleet**, so the required positive cannot occur. True negatives.

## 16.7 `run_ssrf` -- 23 runs -- **CORRECTLY QUIET, with a targeting caveat**

MEASURED live: `run_ssrf` on `http://juice-shop:3000/rest/products/search?q=apple`
-> `tested 1 param(s), 0 SSRF signal(s), 0 confirmed`. The parameter is a product search string; it
does not fetch a URL, so there is nothing to make server-side.

Caveat worth recording: **all 23 corpus dispatches went to ONE mangled URL**,
`http://juice-shop:3000//api.ipinfodb.com/v3/ip-country/?callback&format&key` (a JS-harvested
absolute URL pasted onto the lab origin), and **23/23 had every parameter valueless.** The engine
has never been pointed at a genuine URL-fetching parameter, so its zero is uninformative rather
than wrong.

## 16.8 `run_oauth` -- 422 runs (645 dispatches) -- **CORRECTLY QUIET / UNTESTABLE for a positive**

`oauth_tool.parse_authorize` is a pure string check made BEFORE any request, so the 44
`Not an OAuth authorization URL` runs are correct refusals for URLs like
`https://ginandjuice.shop/oauth/authorize` carrying no `client_id`. Oracle proven:

```
parse_authorize("...?client_id=abc&redirect_uri=http://x/cb&response_type=code&state=s1")
   -> is_oauth True, state 's1'
parse_authorize(".../rest/products/search?q=apple")   -> is_oauth False
```

MEASURED live with a well-formed authorize URL on Juice Shop -> `0 OAuth signal(s), 0 confirmed`:
the endpoint does not exist, every redirect variant 404s, and `analyze_redirect_response` correctly
declines. **UNTESTABLE for a true positive: there is no OAuth authorization server in the
authorized fleet.** 37 dispatches also used the empty-host `https:///` form.

## 16.9 `check_takeover` -- 142 runs -- **CORRECTLY QUIET / UNTESTABLE for a positive**

**All 142 dispatches passed input `{}`** -- no subdomain list is ever handed in; the engine reads
mission recon state. 73 report `No subdomains to check (run recon first)`, which is an
ORCHESTRATION ORDERING fact: half its invocations happened before recon produced anything. The
other 68 had subdomains and found no takeover candidate. MEASURED live: `check_takeover {}` ->
`'No subdomains to check (run recon first)'`. A takeover needs a dangling CNAME to a claimable
provider; **no lab host has one**, so a positive is not constructible on an authorized target.

## 16.10 `run_session_token` -- 82 runs -- **CORRECTLY QUIET**

MEASURED live on DVWA `/login.php` and VAmPI `/users/v1/login`: `0 weak-session-token finding(s)`.
DVWA issues a PHP `PHPSESSID` and VAmPI a JWT -- neither is sequential nor decodes to user/role
data, so the oracle correctly declines. Note **71/82 (86.6%) of corpus dispatches were unreachable
by scheme**, so only 11 of the 82 zeros are informative.

## 16.11 `run_username_enum` -- 15 runs -- **PRECONDITION NEVER MET**

Corpus: 13 `no server-rendered login form here`, 2 `0 username-enumeration finding(s)`.
MEASURED live a THIRD precondition message the corpus never produced:

```
run_username_enum {"url": "http://dvwa/login.php"}       -> 'no known account to differential against'
run_username_enum {"url": "http://vampi:5000/users/v1/login"} -> 'no known account to differential against'
```

The engine needs a KNOWN-GOOD username to differentiate against, and nothing supplies one. Combined
with **12/15 (80%) unreachable by scheme**, this engine has never once run its comparison. Not
broken code -- an unmet precondition plus a transport defect. Its true capability is UNPROVEN.

## 16.12 `run_cache_poison` -- 59 runs -- **CORRECTLY QUIET**

MEASURED live on DVWA `/` -> `no unkeyed-header reflection observed`. Neither lab reflects an
unkeyed request header into a cacheable response; there is no cache in front of either. True
negatives.

## 16.13 `run_cache_deception` -- 24 runs -- **CORRECTLY QUIET**

Corpus: 22 `0 web-cache-deception finding(s)`, 2 `no auth-differentiated private tokens on this
page`. MEASURED live with a real authenticated DVWA session -> `0 web-cache-deception finding(s)`:
it found private tokens, built path-confusion variants and none routed to the private page. Correct
-- there is no caching layer in front of the labs.

## 16.14 `run_llm_probe` -- 46 runs -- **CORRECTLY QUIET, never reached an LLM**

MEASURED live, and the targeting is the story:

```
run_llm_probe {"url": "http://dvwa/"}                      -> 'URL does not look like a chat/AI endpoint - skipped'
run_llm_probe {"url": ".../rest/chatbot/respond"}          -> 'no prompt-injection / output-handling signal observed'
run_llm_probe {"url": ".../chatbot/conversation"}          -> 'no prompt-injection / output-handling signal observed'

raw GET probes of every chat path involved:
  /chatbot/conversation   -> 200, 9903 B   the SPA index (soft 404 -- this path does not exist)
  /rest/chat              -> 500, 2420 B   Error: Unexpect...
  /rest/chatbot/respond   -> 500, 2442 B   Error: Unexpect...
  /rest/chatbot/status    -> 500, 2440 B   Error: Unexpect...
```

The corpus only ever used `/chatbot/conversation` and `/rest/chat`. The first is a soft 404 serving
the SPA index; the second is a 500. Juice Shop's real chatbot requires **POST with an authenticated
token**, which the engine never performs. **The engine has never exchanged a message with an LLM**,
so "no prompt-injection signal observed" is a statement about nothing. Correctly quiet in the sense
that it invents no finding, but its 46 zeros carry no information about the target's LLM.

## 16.15 `run_github_recon` -- 320 runs -- **UNTESTABLE (disabled by configuration)**

**320/320 corpus runs report `Skipped - set BBH_GITHUB_TOKEN (your own read-only GitHub PAT) to
enable`.** It has never made a request. This is a DECLARED no-op, not a silent failure -- the
summary string says so plainly and honestly.

**UNTESTABLE, and deliberately left so:** enabling it requires supplying a GitHub personal access
token, and providing credentials is outside what this lane may do. It is also aimed at recon
targets that were themselves malformed (`hostmaster.hostmaster.hostmaster.juice-shop`, 22 runs),
which is a separate targeting defect worth noting for whoever owns subdomain recon.

**Recommendation:** a tool that is 100% skipped across 320 invocations should not be scheduled at
all, or the scheduler should surface "disabled" distinctly from "found nothing" -- it currently
inflates the tool ledger with 320 rows that scanned nothing.

---

# 17. RESIDUAL UNPROVEN -- what this audit did NOT establish

Recorded so nobody reads a verdict as stronger than its evidence.

1. **`run_sqli_structural` has no observed end-to-end true positive.** Oracle proven on synthetic
   bytes, transport proven live, but I found no ORDER-BY-style structural parameter on any
   authorized target. CORRECTLY QUIET is the right verdict for the surfaces tested; "this engine
   can catch a real structural SQLi" remains UNVERIFIED.
2. **`run_waf_bypass`, `check_takeover`, `run_oauth`, `run_cache_poison`, `run_cache_deception`
   have no constructible positive on an authorized target** -- they need, respectively, a WAF, a
   dangling CNAME, an OAuth authorization server, an unkeyed-header cache and a caching layer.
   None exists in the fleet. Their oracles are proven; their live capability is UNVERIFIED.
3. **`run_username_enum` capability is UNPROVEN.** It has never run its differential in the corpus
   or in this audit, because nothing supplies the known-good account it requires.
4. **`run_github_recon` is untested by choice.** Enabling it needs a GitHub PAT and supplying
   credentials is outside this lane's remit.
5. **`run_llm_probe` has never spoken to an LLM.** Its zeros are uninformative, not wrong. Proving
   it works needs a POST + authenticated exchange with Juice Shop's real chatbot, which I did not
   perform.
6. **`js-bench:3000` does not resolve today** (30 `run_sqlmap` dispatches, plus `run_form_cmdi` /
   `run_upload_test` traffic). It was presumably a live compose alias when those missions ran, so
   I classified those dispatches as "reachable scheme" and did NOT count them as unreachable. If
   the alias was already dead then, the unreachable totals in section 10.4 are UNDERSTATED. I
   cannot settle this retroactively and did not guess.
7. **The corpus is historical.** Every verdict about WHY a tool was zero in the corpus rests on
   `tool_call` inputs plus live reproduction of the same engine against the same host today. The
   labs are the same containers (8 days' uptime), but I did not re-run the original missions.
8. **`tools.py` changed under me mid-audit** (another lane added 42 lines of swallow-ledger
   plumbing at `_ACTIVE_REGISTRY`, verified orthogonal to all 22 wrappers by reading the diff).
   Line numbers cited in this document may drift; wrapper names will not.

---

# 18. WHAT THE OWNING LANES SHOULD TAKE FROM THIS

Ordered by value, each traceable to a measurement above:

1. **File Q-093** (section 14, verbatim). Two independent root causes: `_http` dropping the
   transport outcome, and a URL builder emitting `https:///` and wrong-scheme URLs. Bigger blast
   radius than Q-092 and it reaches all 21 pure-Python engines.
2. **Fix `_cmd` per Q-092.** `agent/tests/test_external_tool_liveness.py` is the gate and 4 of its
   7 tests fail today by design; the 3 controls that pass keep it honest.
3. **`run_sqlmap` needs a SECOND fix Q-092 does not provide** (section 11.4): seed valueless
   parameters with a benign observed-shaped value. Exit code 0 and the tool ran correctly, so no
   exit-code fix will reach it.
4. **Re-run the corpus after Q-093 lands.** Six engines are proven capable and were largely
   pointed at unreachable URLs; `run_path_sqli` alone has a confirmed high-severity CWE-89 waiting
   on VAmPI. The zero histogram should be re-measured after the fix, and any tool still at zero is
   then a genuine lead rather than a signature.
5. **`run_form_nosqli` is sitting on an unreported finding** (section 8): five operator payloads
   turn Juice Shop's login into an unhandled `TypeError` with a 2706-byte stack trace
   (CWE-248 / CWE-209). No engine in this list claims it.
6. **`run_client_checks` crossdomain check has an FP risk** (section 7): its `"<" in body`
   precondition is satisfied by any HTML soft-404, and Juice Shop serves the SPA index at
   `/crossdomain.xml` with HTTP 200. Only the wildcard matcher currently prevents a fabricated
   finding; a content-type / root-element check would be the durable guard.
7. **`run_github_recon` should not be scheduled while disabled** -- 320 ledger rows that scanned
   nothing.

---

# 19. SUITE STATE AT HEAD -- attribution of every red test, measured not assumed

The Coordinator asked to be told which of my files is implicated if the suite came back red. It is
red, **8 tests across two files, and only 4 of them are mine.**

## 19.1 Mine: 4 failures, by design, in `tests/test_external_tool_liveness.py`

```
FAILED test_cmd_hands_back_the_exit_status
FAILED test_cmd_reports_a_zero_exit_as_zero
FAILED test_wrapper_reports_not_ran_when_the_tool_exits_nonzero
FAILED test_a_failed_run_is_distinguishable_from_a_clean_run
```

This is Q-092's GATE clause working as specified. They go green when `_cmd` returns the exit status.
The other 3 tests in the file pass. See section 13.

## 19.2 NOT mine: 4 failures in `tests/test_deadcode_gate.py`, all naming `tools._swallow`

`test_deadcode_gate.py` is a file this lane is forbidden to edit. **I did not assume the failures
were someone else's -- I ran the negative control.**

Two `git archive HEAD` snapshots (never `cp -r` of the working tree), identical except that one has
my test file deleted:

```
SNAP A  = git archive HEAD, WITH tests/test_external_tool_liveness.py   (314 test files)
SNAP B  = git archive HEAD, WITHOUT it                                  (313 test files)

pytest tests/test_deadcode_gate.py on SNAP A -> 4 failed, exit 1
pytest tests/test_deadcode_gate.py on SNAP B -> 4 failed, exit 1     <-- IDENTICAL
```

**The same four fail with my file and without it, so my file did not cause them.** The failures
also never mention it; every one of the four names the same symbol:

```
test_no_flagged_entry_is_unaccounted_for
    AssertionError: qualified dead-code count rose to 40 (baseline 37).
    assert ['tools._swallow'] == []
test_the_accounting_gate_catches_the_island_the_pinned_ratchet_swallows
    AssertionError: the real tree must be accounted for before the island is added
test_a_justification_written_for_one_module_does_not_excuse_another
    assert ['security.build_error_xml', 'tools._swallow'] == ['security.build_error_xml']
test_every_flagged_function_has_a_named_disposition
    AssertionError: ... ['tools._swallow']
```

`tools._swallow` is the module-level swallow recorder added to `tools.py` by the **I-5 lane** (the
`_ACTIVE_REGISTRY` change I read the diff of in section 1 and confirmed orthogonal to all 22
wrappers). It is now at HEAD, and the deadcode gate flags it as an unaccounted island: registered,
with no record of its disposition.

**Owner: the I-5 lane, not this one.** The fix is theirs -- an entry in `TESTS_ONLY` or
`RETAINED_PINNED_BY_TEST_CONTRACT`, or proof of a real caller. Worth noting that the gate is
behaving exactly as designed here: a recorder added to fix silent failures was itself added without
an accounted caller, and the guard caught it.

**Net: HEAD is red 8 for these two files -- 4 mine and intended, 4 the I-5 lane's and unrelated.**


