# Apolaki — Browser Intelligence Engine (BIE) — queued spec

**Status:** QUEUED (user-requested, not yet built). Captured verbatim-in-substance so nothing is lost to
summarization. Build only when the book-reading grind (#103) reaches a checkpoint or the user prioritizes it.

**One-line:** "Me not only *request* website. Me *become user inside* website and watch everything website
does." A first-class runtime viewpoint to complement Apolaki's current assets/requests/graph-facts model.

**Name it Browser Intelligence Engine (BIE)** — NOT "Chrome scanner."

---

## Why (the missing viewpoint)
Apolaki today reasons over assets, requests, and graph facts (static/HTTP truth). It lacks the **runtime**
viewpoint: what a real user/browser actually sees and does after JS executes. Chrome is explicitly building
DevTools *for agents* because agents need runtime/browser visibility, not source alone. BIE closes that gap.

## Tech choice
- **Playwright** for high-level control (click/type/navigate/login/multi-tab/iframe/popup/downloads).
- **Raw Chrome DevTools Protocol (CDP)** underneath for deep instrumentation (the same protocol Chrome
  DevTools itself uses): Network, DOM, Runtime, Storage, Debugger, Security, Target, Fetch, tracing, cookies,
  request/response bodies.
- **Do not reinvent Chrome automation.** Playwright on top, CDP for the deep hooks.

## Capabilities (authorized engagements only)
- **Browser control:** click, type, navigate, login, multi-tab, iframe, popup, downloads.
- **DevTools-level recon:** DOM, JS bundles, source maps, APIs, WebSockets, workers, CSP/security state.
- **Traffic analysis:** headers, POST bodies, responses, timing, redirects.
- **Auth/session analysis:** inspect cookies/storage/tokens; compare authorized personas. Mutations/replays
  stay **scope- + HITL-gated**.
- **Runtime JS analysis:** variables, framework state, errors, dynamically-generated endpoints.
- **Request interception:** Playwright/CDP `Fetch` can pause/modify **authorized** requests before they leave
  the browser.
- **Visual awareness:** screenshots + DOM/accessibility tree → planner knows what a human actually sees, not
  just HTTP HTML.
- **SPA support:** observe React/Vue/Angular *after* JS execution, not the initial HTML as truth.
- **User-flow recording:** login → dashboard → object → action becomes a graph-backed reproducible attack path.

---

## Architecture (NO ISLANDS — feeds Planner + Graph + Evidence + Report + Retest)
```
Apolaki Planner
      ↓
Browser Agent
      ↓
Playwright
      ↓
Chrome
      ↕
Raw CDP
      ↓
Network / DOM / Runtime / Storage / Security / Debugger
      ↓
Evidence Collector
      ↓
AssetGraph
      ↓
Oracle / Attack Planner / Replay
```
**Doctrine (from Apolaki.txt):** every engine MUST feed Planner + Graph + Evidence + Report + Retest. BIE is
not a dashboard island — trace each hop end to end and prove it before shipping (per apolaki-ship Gate 1).

## Controlled exploitation flow (not just recon)
```
Browser observes normal user action
  ↓ Graph learns request + state + persona
  ↓ Planner forms exploit hypothesis
  ↓ Browser/CDP mutates ONE variable
  ↓ Request executes
  ↓ Oracle compares baseline vs mutation
  ↓ Negative controls
  ↓ Confirmed / rejected
  ↓ Evidence + replay recipe
```
**Canonical example (real BOLA, not spray):** User A opens `/invoice/123`. Apolaki captures the exact browser
request, switches to **User B's authenticated browser context**, changes ONLY `123`, executes, and checks
whether B receives A's data. Far stronger than blindly spraying ids.

**Applies to:** IDOR/BOLA, role/permission bypass, hidden UI functionality, CSRF/workflow, parameter
tampering, JS-only-discovered API calls, WebSocket actions, multi-step business-logic abuse, session/cookie
behavior, client-side trust assumptions.

**Crown-jewel invariant (keep it):** the browser performs the *attempt*; the **oracle** decides truth.
"Browser successfully did weird shit" NEVER auto-equals a vulnerability. Deterministic confirmation +
negative controls remain the gate. (Matches Apolaki's confirmation-oracle philosophy.)

## Evidence-derived PoC bundle (big win)
On a **confirmed** finding, freeze the successful browser execution and generate the PoC bundle **from the
actual run** (not LLM-invented steps afterward). Reuse the existing `poc_bundle.py` contract (#111):
```
Confirmed vulnerability
  ↓ Freeze successful browser execution
  ↓ Generate PoC bundle
     ├── Human reproduction steps (1. Login as Persona B  2. Navigate…  3. Perform…  4. Observe unauthorized result)
     ├── Before/after screenshots
     ├── Browser trace (interactive)
     ├── Exact HTTP request
     ├── Mutated request
     ├── Response proving impact
     ├── HAR / network evidence
     ├── Console / DOM evidence (when relevant)
     ├── Negative-control result
     ├── Persona/session references [REDACTED]
     └── Replay script
```
This turns "deterministic replay > pretty report language" into something a client can **literally replay**.

## Guardrails (non-negotiable, inherit Apolaki's)
Scope + HITL in front of every mutation/replay; no DoS; no credential-brute loops (single known/discovered
values only); secrets/personas vaulted + redacted in evidence; CAPTCHA/MFA PAUSE never bypass; only
authorized in-scope targets; oracle+negative-control gates every "confirmed"; deterministic-first (browser is
an instrument, not the source of truth).

## Existing Apolaki pieces to reuse (avoid duplication — check first)
- CDP-headless collector (#29) + capture/HAR (#38) + mitmproxy intercept (#40) — BIE supersedes/absorbs these
  with a Playwright+raw-CDP core; verify what's already wired before rebuilding.
- Persona/auth artery + authz-matrix (#52-#57, #62) — BIE's per-persona browser contexts plug into this.
- Canonical AssetGraph (#58/#63) + attack-path ranking (#116) + retest loop (#117) + poc_bundle (#111).
- Findings write-gate + confirmation oracles + negative controls.

## Acceptance (ship-gate when built)
No-island trace proven (Planner→BIE→Graph→Evidence→Report→Retest); one real BOLA confirmed via persona-swap
browser contexts on a lab; PoC bundle generated from the actual run (screenshots+HAR+mutated req+negative
control); driven through the real UI, 0 console errors; full pytest green on the baked python:3.12 image;
bake + push; update `apolaki-optest-loop` memory.
