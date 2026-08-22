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
