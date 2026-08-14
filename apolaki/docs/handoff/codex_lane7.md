# Codex Lane 7 Handoff: Q-023 ZAP Invocation

## Lease

- Branch: `codex/zap-invocation`
- Baseline: `6c9907a4a78426bb51bee461ca160f1ca7e63ccb`
- Worktree: `C:/Users/voice/Desktop/GitHub/MISC-codex-lane7`
- Owned production files: `agent/zap_client.py`, `agent/tools.py`, `agent/main.py`
- Owned tests: new `agent/tests/test_zap_*.py`

## Measured Baseline

Preflight on `http://localhost:8000/missions`: `running_missions=0`.

```text
MSYS_NO_PATHCONV=1 docker run --rm -v "C:/Users/voice/Desktop/GitHub/MISC-codex-lane7/apolaki/agent:/app" -w /app apolaki-agent python -m pytest tests/ -p no:cacheprovider -rx

2238 passed, 9 skipped, 9 warnings in 287.25s (0:04:47)
```

The count matches the coordinator's expected 2238. The worktree was clean at the exact requested SHA.

## Existing Measured Trace

Read `docs/research/INBOX.md` Line 1 in full before implementation. Its 150-mission / 25,619-call
audit is accepted as the historical baseline and was not repeated. Current-code tracing, fail-first
controls, real invocation evidence, benchmark identity, and final verification follow below.

## Fail Before Fix

The first six controls failed semantically against `6c9907a`: missing and `High` ZAP confidence
could enter the confirm-by-tool fallback, target-driving `access_url` ran without a verified daemon
rate rule, AJAX failure was swallowed, the active path did not drain passive scan work, an enabled
mission completed without a `run_zap` row, and no static driver-bypass guard existed. No
ImportError, collection error, fixture error, skip, or unrelated assertion was credited.

```text
6 failed, 1 passed, 3 warnings in 3.10s
```

The alert-attribution control was added after the first real mission exposed retained-daemon alert
contamination. Its semantic negative case contains one old alert, two current alerts, and one alert
with no message identity; only the two joined to post-cursor messages may survive.

## Implemented Production Contract

- `zap_client.alert_to_finding()` always emits `confidence: candidate`; ZAP's grade is preserved
  separately as `scanner_confidence`. A ZAP signature is a lead, never an Apolaki confirmation.
- `ZapClient.configure_target_safety()` installs and reads back an aggregate one-request-per-second
  rule for every scoped host and one worker per target-driving ZAP component before traffic starts.
- ZAP history responses feed the shared `TargetRatePolicy`; a 429/503 with `Retry-After` stops all
  ZAP producers and returns an environment failure with no clean or vulnerable verdict.
- Traditional/AJAX/active scan incompleteness is visible, AJAX exceptions are visible, and passive
  scan work is drained for passive and active policies.
- Alerts are joined to message IDs created after the pass cursor. Retained or unattributed alerts
  are excluded rather than claimed by a later mission.
- A mission with `enable_zap=true` cannot finish successfully unless its persisted log contains a
  `run_zap` `tool_call`. ZAP-off completion and logs are unchanged.
- The dead `recon["zap"]` write was removed. Targeted rescans were deliberately not changed because
  their planner key and deduplication are in the coordinator-owned planner.

## Focused Controls

After current-message alert attribution was added:

```text
docker run --rm -v "C:/Users/voice/Desktop/GitHub/MISC-codex-lane7/apolaki/agent:/app" -w /app apolaki-agent python -m pytest tests/test_zap_invocation.py tests/test_zap_rate_policy.py -p no:cacheprovider

.............                                                            [100%]
13 passed, 3 warnings in 4.51s
```

## Real No-DoS Observation

A disposable named target returned 429 plus `Retry-After: 2` to the first request. Real ZAP 2.17.0
stopped after exactly one target request; no second request began inside the cooldown window:

```json
{"error":"ZAP stopped on target rate limit: HTTP 429 at http://apolaki-zap-lane7-live:42888/; Retry-After 2.000s. No clean or vulnerability verdict was produced.","requests":1,"retry_remaining":1.0732480189981288,"returned_at":56904.685077672}
```

The configured rule was independently read back from the real daemon for every scoped host:

```json
{"descriptions":["apolaki-a8529d1e115d33eb","apolaki-34cd643f5a010e73"],"hosts":["domsource","juice-shop"],"requests_per_second":1.0}
```

## First Real Mission Observation

The first post-fix Full mission persisted exactly one production call row. It also exposed that
base-URL filtering imported retained alerts from earlier scans; this observation is retained here
as fail-before evidence for the subsequent message-cursor fix, not as the final acceptance run.

```json
{"mission_id":"05a27c3d","status":"complete","tool_call":{"input":{"aggression":"normal","policy":"passive","speed":"normal","url":"http://domsource:8080"},"permission":"intrusive","tool":"run_zap","ts":"2026-08-14T10:07:11.494621+00:00","type":"tool_call"},"tool_result":{"count":180,"output":"policy=passive; speed=n/a; aggression=n/a; target-rate<=1rps; 180 ZAP alert(s) [passive] (from 183 raw)","tool":"run_zap","ts":"2026-08-14T10:08:55.801659+00:00","type":"tool_result"}}
```

## Live Findings During Acceptance

The acceptance work found and fixed two defects not visible in mocked orchestration:

1. ZAP's global daemon retains alerts. A later mission querying only by base URL claimed earlier
   scans' alerts. Alerts are now joined to message IDs created after the pass cursor; alerts without
   that ownership fact are excluded.
2. A first version observed seed responses through global history. A delayed browser response from
   the previous pass arrived first and satisfied the same-host barrier, allowing the current spider
   to start before the current 429 was inspected. `core/sendRequest` returns the exact seed response,
   so seed cooldown decisions now use that direct result. Asynchronous spider/active traffic still
   uses history polling, and incomplete history rows retain their cursor until response headers exist.

The strict target remained unchanged throughout. Intermediate runs with two requests failed. The
final run saw exactly one tagged seed request and retained the shared cooldown after return:

```text
{"observations":[{"headers":{"Connection":"close","User-Agent":"Apolaki-ZAP/1","X-Apolaki-ZAP-Seed":"bbh-zap-rate-live-9d79-1","X-Scanner":"Apolaki-ZAP-authorized","host":"apolaki-zap-lane7-live:42888"},"index":1,"method":"GET","path":"/","started":58917.745407064}],"result_error":"ZAP stopped on target rate limit: HTTP 429 at http://apolaki-zap-lane7-live:42888/; Retry-After 2.000s. No clean or vulnerability verdict was produced."}
{"error":"ZAP stopped on target rate limit: HTTP 429 at http://apolaki-zap-lane7-live:42888/; Retry-After 2.000s. No clean or vulnerability verdict was produced.","requests":1,"retry_remaining":1.00290282300557,"returned_at":58917.966799}
1 passed, 3 warnings in 6.06s
```

The invalid `ajaxSpider.stopAllScans` / `removeAllScans` calls seen in real daemon logs were also
removed. `stop_all()` now calls and verifies the add-on's actual global `ajaxSpider.stop` action;
BAD_ACTION can no longer disappear behind a broad exception.

## Final Real Mission Proof

This is the post-attribution, post-no-DoS production acceptance row. The mission went through
`main.engage`, `main.run_mission`, normal agent/planner execution, and SQLite persistence. No ZAP
method was mocked and `_run_zap` was not called directly.

```json
{"mission_id":"49d413bb","status":"complete","tool_call":{"input":{"aggression":"normal","policy":"passive","speed":"normal","url":"http://domsource:8080"},"permission":"intrusive","tool":"run_zap","ts":"2026-08-14T10:55:14.748831+00:00","type":"tool_call"},"tool_result":{"count":0,"output":"policy=passive; speed=n/a; aggression=n/a; target-rate<=1rps; 0 ZAP alert(s) [passive] (from 0 current raw) [187 retained alert(s) excluded]","tool":"run_zap","ts":"2026-08-14T10:57:00.589375+00:00","type":"tool_result"}}
```

```text
1 passed, 3 warnings in 199.56s (0:03:19)
```

The zero is intentional: this already-used daemon held 187 matching alerts, but none were owned by
messages from this mission. Claiming those alerts would be cross-mission evidence contamination.
The row proves invocation; it does not fabricate a new alert.

## What A ZAP Alert Is Worth

A ZAP alert remains a lead. `risk` maps to severity and the raw scanner grade remains visible as
`scanner_confidence`, but Apolaki confidence is always `candidate`. A signature or scanner confidence
string is not a deterministic differential oracle and has no negative control. Independent Apolaki
tools may later confirm the underlying vulnerability; the ZAP finding itself cannot bypass that
proof step. The proof gate was not weakened.

## Semantic Mutation Ledger

Eight semantic mutants were killed by the exact intended assertion. Each source mutation was
restored before the next; SHA-256 checks after the final mutation matched the pre-mutation hashes for
all five mutated files.

| mutant | exact control | observed semantic failure | credited |
|---|---|---|---|
| `candidate -> confirmed` in ZAP mapping | `test_zap_alert_is_explicitly_lead_only_even_without_scanner_confidence` | expected `candidate`, got `confirmed` | yes |
| invert persisted-call `ran` guard | `test_enabled_mission_cannot_complete_without_persisted_run_zap_call` | mission became `complete`, expected `failed` | yes |
| fabricate a read-back rule when daemon returns none | `test_action_success_without_an_active_rule_fails_closed` | `DID NOT RAISE RuntimeError` | yes |
| invert seed cooldown branch | `test_target_retry_after_aborts_zap_before_the_next_driver` | result became successful and later drivers ran | yes |
| replace alert-ID intersection with truthy union | `test_alerts_are_attributed_only_to_messages_created_after_the_pass_cursor` | old and unattributed alerts entered output | yes |
| swallow AJAX exception again | `test_ajax_spider_failure_is_reported_and_active_path_drains_passive_queue` | required degradation text disappeared | yes |
| consume incomplete history row | `test_incomplete_zap_history_row_is_retried_not_consumed` | cursor advanced `0 -> 1` before response commit | yes |
| restore nonexistent AJAX `stopAllScans` action | `test_stop_all_has_no_silently_invalid_ajax_actions` | exact `ajaxSpider.stop` call absent | yes |

An initial read-back mutant disabled the guard but then crashed later on `None`. It was discarded and
is not counted; the non-crashing fabricated-rule mutant above is the credited version.

One additional fail-before control was added after review: an unobservable secondary seed used to be
caught as `seed degraded`, return success, and continue into the spider. The pre-fix assertion saw
`result.success is True`; after removing that catch, the same observation fails the pass before any
spider traffic. This is fail-before evidence for the actual old branch, not counted again as a mutant.

## Targeted Verification

Normal mode keeps the two foreign-daemon tests explicitly skipped; they were run separately above.

```text
docker run --rm -v "C:/Users/voice/Desktop/GitHub/MISC-codex-lane7/apolaki/agent:/app" -w /app apolaki-agent sh -lc "python -m pytest tests/test_zap_*.py -p no:cacheprovider"

..........ss........                                                     [100%]
18 passed, 2 skipped, 3 warnings in 8.43s
```

## Historical And Owned Boundaries

The four 2026-07-26 missions remain historically unexplained because their planner state and exact
code are unrecoverable. A recurrence is no longer silent: any opted-in mission without a persisted
`run_zap` call is terminally failed with a visible `tool_error`.

Targeted rescans remain unwired. The required change is in coordinator-owned `planner.py`: replace
the one-per-host dedup key `run_zap:{host}` with a state/version-aware key after newly discovered
routes or authenticated state, while preserving a bounded rescan budget. No planner file was touched.

Full-suite, Tier-3, benchmark-identity, and commit measurements are in progress.
