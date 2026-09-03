# Shopify engagement readiness gate

Authorized engagement: Shopify's public bug bounty programme. Scope below is the operator's own
Burp export, carried forward from mission `9e8653b8` unchanged: 15 in-scope entries, 7 exclusions.

**This file exists because "it feels ready" is how three false CRITICALs reached a live programme
report on 2026-09-01.** A false HIGH on a real programme costs Signal, and Signal costs invitations.
Every box below is a MEASUREMENT with a command behind it, not a judgement.

## A. The false-positive fixes that must be in the running image

Each of these fired, or would have fired, on an API-heavy real target. All were found this cycle.

| # | defect | why it matters on Shopify specifically |
|---|---|---|
| Q-160 | "Reflected XSS (html)" graded HIGH on a JSON response | Shopify is API-heavy. ANY endpoint echoing a bad parameter into a JSON error was a HIGH. A browser proved the payload cannot execute: `application/json` + `nosniff`. |
| SQLi error-recovery | `429 -> 502 -> 429` read as "the quote broke the query and escaping restored it" | partners.shopify.com rate-limits. 429 satisfied `< 500` twice. |
| SQLi time-blind | one unrepeated timing observation, responses discarded | a rate-limited 429 control against a served 200 was a confirmed CRITICAL |
| cmdi time-blind | character-identical to the SQLi bug, claiming RCE | never measured wrong in the field only because it had not yet been aimed at one |
| `_run_jwt` | CRITICAL "Forged JWT accepted" on ANY 2xx, no controls | fires on every unauthenticated endpoint in existence |
| passive_disclosure | docs page with a PEM -> CRITICAL; public JWKS with a nested `d` -> CRITICAL | `/.well-known/jwks.json` is public BY DESIGN and Shopify serves one |

## B. Coverage that did not exist before this cycle

Shopify's admin and partners surfaces are single-page applications, which Apolaki was structurally
blind to. `curl` sees 0 forms and 0 routes where a render sees the real surface.

- SPA route discovery, including routes reached by DRIVING the app's own controls (Q-157/Q-163)
- hash-route parameters probed, deduped and inventoried as real pages (Q-153/Q-159/Q-161)
- forms an SPA renders, driven in a browser with no `action`/`method`/`name` (Q-158)
- NoSQL operators in JSON request bodies, built from an OBSERVED body (Q-155)
- granular CSP, language-specific code injection, DOM sinks, passive disclosure, JWT (Q-145..Q-149)

## C. The gate itself

| check | command | required |
|---|---|---|
| full suite | `pytest tests/` against a snapshot of HEAD | 0 failed, 0 error |
| liveness | `python liveness_run.py` | no regression against the baseline |
| pinned ratchets | `scripts/gates.sh` | all hold |
| adversarial review | Breaker pass over anything landed this cycle | every finding triaged, none open at HIGH |
| image freshness | `docker exec apolaki-agent-1 grep -c <symbol> /app/<file>` | the running container carries the fixes, NOT just the repo |
| scope | 15 in-scope, 7 out-of-scope, loaded and echoed back | matches the operator's Burp export exactly |
| lab bench alive | `python scripts/labs_health.py` | 10/10 ALIVE before any shakedown is believed |
| engine reachability | `python scripts/tool_ledger.py` | nothing we rely on sits in ZERO-ONLY or NEVER |

### Added after the 2026-09-02 shakedown, because each of these had already produced a wrong belief

**The bench must be alive before its zeros mean anything.** mutillidae was serving `Database
Offline` and bwapp `Unknown database 'bWAPP'` -- both HTTP 200. Every injection engine aimed at them
returned zero CORRECTLY, and the cross-mission ledger then reported those engines as never having
produced anything. dalfox read as structurally broken at 207 runs / 0 results; against a revived
mutillidae, with its own unchanged command line, it returned verified XSS immediately. A dead lab
and a broken engine are the same observation.

**Reachability is a separate measurement from accuracy.** `run_cmdi` claims RCE and was dispatched
ZERO times in 175 missions -- its planner gate was exact-match against an 11-word parameter list,
selecting 1 of 792 endpoints. Its false-positive oracle was hardened twice by someone who never
checked that anything dispatches it. An engine's accuracy is worth nothing until its reachability
is a number.

**A tool can be installed, configured, and never have run.** nuclei passed `-json`, removed in v3;
the binary exits 2 on the unknown flag before loading any of its 13,619 templates. Every nuclei
dispatch in this platform's history was that. The defect was already named in this repo, in the
opening paragraph of `tests/test_external_tool_liveness.py` -- diagnosed, guarded at the class
level, never fixed at the instance. Root-causing and repairing are separate acts.

**Image freshness is on this list because it has already burned a run.** Mission `9e8653b8` scanned
Shopify from a container that predated every engine in section B, and nothing in the mission record
said so.

It burned a SECOND time on 2026-09-02, during the shakedown that was supposed to be checking for
exactly this. `/app` is BAKED into the agent image -- only `/app/ui` is bind-mounted -- so three
committed fixes were live in the throwaway test containers and absent from every mission. The
census I was reading as evidence about the platform was measuring the previous build. Verify with a
grep INSIDE the running container for a symbol only the new code contains; a green suite in a
mounted container proves nothing about what the missions run.

## D. Rules for the run itself

- Slow. The operator asked for `scan slow` and the previous run was rate-limited into 429s that the
  oracles then misread. Rate limiting is not a finding and must never become one.
- Monitor tools AND orchestration, not just findings: `scripts/tool_census.py <mission>` after the
  run, and the phase/heartbeat while it runs.
- NOTHING IS REPORTED TO THE PROGRAMME FROM THIS RUN WITHOUT A SECOND PAIR OF EYES. The three
  withdrawn findings from `9e8653b8` were all `confidence=confirmed`.
