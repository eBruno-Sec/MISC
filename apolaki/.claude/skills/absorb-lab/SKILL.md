---
name: absorb-lab
description: Run Apolaki's full vulnerable-app ABSORPTION CYCLE against an authorized lab/CTF target (OWASP Juice Shop, DVWA, PortSwigger Gin & Juice Shop, bWAPP, WebGoat, crAPI, Mutillidae, DVNA, Gruyere, Security Shepherd, PortSwigger Academy labs, etc.). Trigger when told to "absorb <target>", "knock out <lab>", "add <app> to the taxonomy/benchmark", "solve <vuln-app>", "expand lab coverage", "prove techniques on <lab>", or when a new intentionally-vulnerable application should become a validation fixture. The cycle: knock out as many challenges/vulns as possible (source-driven), formalize confirmed solvers into a reproducible pack, lift the TRANSFERABLE technique behind each into the Technique Registry, confirm cross-lab transferability (>=2 labs => generalized), verify orchestration, and QA the whole platform.
---

# Absorb a vulnerable app (the absorption cycle)

Turn an authorized intentionally-vulnerable application into permanent, reproducible, *generalized*
Apolaki capability. This is exactly how Juice Shop and DVWA were absorbed. Run the phases in order;
every phase ends with something committed and green.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`. Deploy = `docker cp <file> apolaki-agent-1:/app/<file>`
then `docker restart apolaki-agent-1` (module cache needs the restart). CI runs pytest on **Python 3.11**
(container is 3.12) so verify on 3.11 before pushing (no backslash inside f-string expressions).

## Phase 0 -- authorize + connect
- Confirm the target is authorized (a lab you run, or a public scan-me demo like ginandjuice.shop).
- Reach it from the agent container (compose service alias, or an external host). No-DoS, no credential
  brute-force -- knowledge-only for brute (single known values are fine, loops are not).
- If it has a scoreboard/oracle (Juice Shop `/api/Challenges`), snapshot the baseline count.

## Phase 1 -- knock out challenges, SOURCE-DRIVEN (never guess)
- If source is available, read the EXACT solve condition (`grep "solveIf(challenges." routes/*.ts`,
  `challenges.yml`, or the app's published vulnerability list). Guessing wastes runs; the source gives
  the precise request. For Gin & Juice, PortSwigger publishes the expected vulns/paths/difficulties.
- Craft the precise request/exploit. Use the right engine: HTTP for API/injection, the **browser engine**
  (`browser_engine.drive`, headless-chrome sidecar) for client-side-only challenges (DOM/CSP/Video XSS,
  hidden client routes) that HTTP cannot reach. Chain where needed (e.g. zip-slip -> stored XSS).
- Measure the scoreboard delta after each batch. Only count a solve the oracle confirms.
- Honest ceiling: skip DoS (rule), chatbot (needs a funded LLM), web3 (needs a chain). State the real
  reachable max and where you stop.

## Phase 2 -- absorb: formalize + generalize
- **Formalize** every confirmed solver into the lab's reproducible pack (e.g. `juiceshop_solvers.py`),
  wired into `solve()`, so the number TRAVELS in git (any machine reproduces it, not sticky state).
  Prove it on a FRESH instance: board 0 -> N via `labs.solve`.
- **Lift the transferable technique** behind each solve into `techniques.py` as a first-class technique
  (id / vuln_class / cwe / owasp / detect / exploit / oracle / try_it / maps_to). Only the
  target-agnostic METHODOLOGY is a technique; hardcoded creds/ids/flags stay tagged as lab fixtures.
- Add the app's expected-vuln CLASS manifest to `benchmark.py` MANIFESTS (a validation fixture).

## Phase 3 -- confirm transferable (the generalized bar)
- A technique is `generalized` ONLY when `validated_on` lists >= 2 independent labs. If this lab proves
  a technique already proven elsewhere, add this lab to its `validated_on` + `maps_to` -> it flips to
  generalized. Never fake it: the oracle must actually fire on this lab.
- Report the generalized count delta honestly.

## Phase 4 -- orchestration check (mandatory after ANY change)
Verify the new knowledge actually composes, no island of state:
- New techniques appear in `GET /techniques` and carry KEV/CAPEC enrichment.
- `technique_planner._PRECONDITIONS` has an entry for each new technique so the deterministic planner
  gates + ranks it from real recon evidence (`GET /plan/{session}` shows it when its observation holds).
- The advisor recommends it; recon/harvest/code-intel still feed the SAME observation model.
- Nothing new bypasses scope / HITL / no-DoS / no-brute.

## Phase 5 -- QA the whole platform (mandatory after ANY change)
- Full test suite on 3.11 (all green; note the exact passed/skipped count, never inflate).
- Endpoint sweep (health + every major GET/POST returns 200 with a real payload).
- If the UI changed: every nav tab renders, 0 console errors, the changed control works in the real
  browser (drive it, don't assume).
- Rebuild the agent image (`docker compose build agent`) so the change is BAKED, not just `docker cp`'d
  (a `compose up`/recreate discards cp'd files -> silently tests old code).

## Phase 6 -- commit + push, then update memory
- One focused commit per coherent unit, with the honest reproducible number + the Co-Authored-By trailer.
- Record the absorption in the optest-loop memory: what solved, the reproducible count, the new/generalized
  techniques, any target-specific gotcha, and the honest ceiling.

## Guardrails (always)
Deterministic-first + zero-token by default. No DoS. No credential brute-force loops. Scope + HITL stay
in front. Target-specific shortcuts stay tagged as test-fixture knowledge; only the transferable portion
enters the general Technique Registry. Report numbers you actually reproduced -- a solve the oracle
didn't confirm is not a solve.
