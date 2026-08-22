# Q-093 — `_http` drops the transport outcome, and a URL builder that lost its netloc

Lane file. Written AS I GO. If this lane is killed, this file is the contribution.

Baseline: HEAD `2dd1f7a`, ship gate GREEN at **3562 passed / 11 skipped / 12 xfailed / 0 failed**.

Two root causes, tracked separately throughout. **Do not read a fix for (A) as a fix for (B).**

| | root cause | corpus dispatches | status |
|---|---|---|---|
| **A** | `_http` returns `{status:0, error, body:""}`; no caller reads `status`/`error`, so a dead connection == a clean page | 3241 unreachable of 27222 (11.9%) | IN PROGRESS |
| **B** | a URL builder emits `https:///` — scheme, no netloc | 1495 | NOT STARTED |

---

## 0. Read-in (MEASURED — from the filed evidence, not re-derived)

`agent/tools.py:3972 _http` is honest: on any transport exception it returns
`{"error": str(e), "status": 0, "headers": {}, "body": "", "length": 0, "final_url": url}`.
Every engine reads `r.get("body", "") or ""`. **The failure arrives as DATA, not as an exception**,
so the Q-08x swallow ledger structurally cannot see it — there is nothing to catch.

`agent/tools.py:79 CmdResult` is the Q-092 pattern to mirror: a 2-length `tuple` subclass so every
`out, err = await self._cmd(...)` unpack keeps working, with `exit_code` riding on the value the
caller already reads. `agent/tools.py:100 _cmd_failure` is the shared predicate, and its docstring
records the lesson this lane must not repeat:

> `parsed` is the caller's own answer to "did I actually get anything out of this run?" ...
> Defaulting `parsed` to None means the safe direction (report the failure) is the one you get by
> not thinking about it.

## 1. Sequencing decision

Per the Coordinator: **commit the gate that FAILS against today's code first**, then the fix. A
partial lane then leaves an executable statement of the defect rather than a description of one.

---

## 2. (A) GATE LANDED FIRST — `agent/tests/test_http_transport_outcome.py`

**MEASURED against HEAD `2dd1f7a`, before any product change:**

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_http_transport_outcome.py -p no:cacheprovider -rfE -q
FFF.....F                                                                [100%]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_waf_bypass-WAF-bypass]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_sqli_structural-structural SQLi]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_css_injection-CSS injection]
FAILED ...::test_a_dead_dispatch_does_not_poison_the_next_clean_one
EXIT=1        # captured off `docker run` directly, not off a pipeline
```

The failure text is the defect, verbatim from the run:

```
AssertionError: the dead dispatch stopped being reported: '0 WAF-bypass finding(s)'
 +  where True = ToolResult(tool='waf_bypass', target='http://juice-shop:3000/rest/products/search?q=apple',
                            success=True, output='0 WAF-bypass finding(s)', findings=[], error=None).success
```

**BOTH HALVES, which is the whole design.** 4 fail, and **5 PASS BEFORE THE FIX**:

| test | before | after | what it forbids |
|---|---|---|---|
| every request failed -> `success=False` + error naming the cause | **FAIL** | pass | the false-clean |
| a clean 200 page -> `success=True`, `error=None`, 0 findings | pass | pass | "fail everything" |
| some failed, some succeeded -> `success=True` | pass | pass | degraded read as dead |
| engine sent no requests at all -> untouched | pass | pass | "no evidence" == "failure" |
| dead dispatch then clean dispatch on the SAME registry | **FAIL** | pass | cross-attribution |

A test asserting "0 findings on a dead connection" passes against the broken code and proves
nothing. Every dead-transport assertion here is paired with a reachable-transport assertion on the
SAME engine over the SAME page.

Nothing touches the network: `tools._target_client` is replaced, so `_http`'s real body (including
its real `except Exception` branch) and the whole of `ToolRegistry.execute` are under test.
Substituting `_http` or `execute` itself would test nothing.

**Committed as `xfail(strict=True)`**, following this repo's own `_KNOWN_OPEN` convention in
`tests/test_outcome_fidelity.py`. `strict=True` means the marker XPASSes -> RED the instant the
chokepoint starts carrying the outcome, so it cannot outlive the defect. Suite stays green
(`xxx.....x`, EXIT=0), and the defect is on disk as an executable statement rather than prose.

