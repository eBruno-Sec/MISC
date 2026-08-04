---
name: apolaki-ship
description: The mandatory "definition of done" gate for ANY change to Apolaki (the web/API pentest platform at C:\Users\voice\Desktop\GitHub\MISC\apolaki) — a feature build, a bug fix, a new technique, or a lab absorption. Trigger it EVERY time before calling a change done, and whenever asked "did you check orchestration / absorption / the UI", "is it wired in", "run the checks", or "is this shippable". Runs five gates in order: (1) orchestration composition — the change composes into the ONE engagement state, no island; (2) absorption — every technique/trick used is distilled into the registry with validated_on updated per lab; (3) UI verification — drive the changed control in the REAL browser, not the engine room; (4) QA — full pytest green on the agent image (python:3.12; there is no CI) + endpoint sweep; (5) bake + commit + memory. This is the check that catches "wired the backend but never verified it composes / shows in the UI / got absorbed".
---

# Apolaki ship gate

Run this after ANY change to Apolaki, before you call it done — not only when absorbing a lab.
A feature that passes its own unit test but was never checked for orchestration, never distilled
into the registry, and never driven through the real UI is **not shipped**. Every gate below has
caught a real miss; skip none.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`. Deploy fast = `docker cp <f> apolaki-agent-1:/app/<f>`
+ `docker restart apolaki-agent-1`; ship = `docker compose build agent` (BAKE). There is **no CI**; the
agent image is **python:3.12** so pytest runs on 3.12 — that image IS the bar. Keep code 3.11-compatible
too (no backslash inside f-string expressions); a real 3.11 run is optional extra evidence, never claim
"3.11 CI parity" (there is no 3.11 CI).

## Gate 1 — Orchestration composition (no islands)
The north star: **one engagement state, every gathered signal feeds every phase.** A capability the
scan/planner/report doesn't actually consume is a dashboard island (this is exactly how the technique
planner, attack-chain, proxy, and mutation engine each started — built, then found unwired).

- The change appears where it should: `GET /techniques` + `/intel/techniques` (with KEV/CAPEC
  enrichment), `/plan/{s}`, `/graph/attack/{s}`, the report's Intelligence-Orchestration section, and
  the relevant UI tab.
- The consumers actually USE it — trace the chain end to end and prove each hop:
  recon/intel harvest → `technique_planner.derive_observations` adds the observation →
  `plan()` gates + ranks the technique → `technique_advisor` surfaces it → the autonomy loop records +
  re-plans it → the report renders it. A missing hop = an island; wire it, don't ship it.
- Nothing new bypasses **scope / HITL / no-DoS / no-credential-brute**.

## Gate 2 — Absorption (distill every trick, pass or fail)
- Every technique/trick used to solve or exploit anything in this change is a first-class entry in
  `agent/techniques.py` (id / vuln_class / cwe / owasp / detect / exploit / oracle / try_it / maps_to).
  Only the target-agnostic METHODOLOGY is the technique; hardcoded creds/ids/flags stay lab fixtures.
- For EACH lab whose ORACLE actually fired, add that lab to `validated_on` + `maps_to`. **A solve you
  didn't record is an absorption miss** (e.g. SSRF solved on Juice Shop but `ssrf.validated_on` left
  empty). `>=2` independent labs ⇒ `generalized`; never fake it — check the oracle really fired.
- A new vuln CLASS ⇒ add it to `agent/benchmark.py` MANIFESTS.
- Wire the planner so it's autonomous: add the technique's precondition to `technique_planner._PRECONDITIONS`
  and derive its observation, so a real scan reaches for it on its own.

## Gate 3 — UI verification (through the browser, NOT the engine room)
- Drive the CHANGED control in the REAL browser — launch the scan from Launch, click the button, open
  the tab — not `docker exec … python` / curl. Backend proof verifies the engine; it does not verify the
  layer the user touches.
- Confirm the change does what it claims, visibly: the finding lands in the Live Run feed, the tab
  renders, the value updates, the report shows the section. **0 console errors.** Supplement with API for
  depth; never substitute it for the UI pass.

## Gate 4 — QA
- Full `pytest` GREEN on the agent image (**python:3.12**) — note the exact passed count, never inflate.
  There is no CI, so the baked 3.12 image IS the bar; a separate 3.11 run is optional extra evidence
  (report it as "3.11" only if you actually ran 3.11, never as "CI parity").
- Endpoint sweep: `/health` + every major GET/POST returns 200 with a real payload (health, techniques,
  intel, plan, graph, benchmark, proxy, and whatever the change touched).

## Gate 5 — Bake + ship
- `docker compose build agent` then recreate — BAKE, don't just `docker cp` (a compose up/recreate
  discards cp'd files → silently tests old code).
- One focused commit + push; end the message with the Co-Authored-By trailer.
- Update the `apolaki-optest-loop` memory: what changed, the orchestration + absorption result, the UI
  verification, and the honest numbers (test count, generalized count, board %).

## Guardrails (always)
Deterministic-first + zero-token by default. No DoS. No credential brute-force loops (single known/
discovered values only). Scope + HITL stay in front. Report only numbers you actually reproduced.
