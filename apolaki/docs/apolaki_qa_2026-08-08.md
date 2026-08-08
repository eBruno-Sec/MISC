# Apolaki QA — Browser Intelligence Engine build (2026-08-08)

Scope of this pass: build + integrate the Browser Intelligence Engine (#124), then verify the whole
platform still composes. Everything below is a result that was actually executed; where something was not
proven, it says so.

---

## 1. What shipped

| # | Slice | Technique id | CWE | Commit |
|---|-------|--------------|-----|--------|
| 1 | Runtime persona-swap BOLA | `browser_persona_bola` | CWE-639 | 914b80b |
| 2 | Client-side control surface | `client_side_authz` | CWE-602 | 914b80b |
| 3 | Route-interception identity-param tamper | `client_supplied_identity_param` | CWE-639 | c248927 |

`agent/bie.py` (~1,000 lines), `agent/tests/test_bie.py` (41 tests). Playwright + chromium were already in
the agent image, so no new dependency.

## 2. Test results

| Check | Result |
|-------|--------|
| Full suite, baked `python:3.12` image | **1106 passed, 0 failed** |
| BIE unit tests | 43 passed |
| Orchestration audit | 41 gated + 28 always-on, **0 islands** |
| Technique registry | 70 techniques |
| Endpoint sweep (from OpenAPI, 113 routes / 72 GET) | 64 ok · 8 expected (need a caller-supplied id) · **0 defects** |

No CI exists for this repo; the baked agent image is the bar, per the ship gate.

## 3. Live proof (real execution path, not inspection)

**Mission e33c1c96** — authenticated deterministic scan of Juice Shop through the real API:

- The persona artery's step 5e fired BIE on its own proven persona pair.
- The candidate came from **observation**: persona A's browser fetched `/rest/basket/6`, persona B's
  fetched `/rest/basket/7`. The swap changed only the id — this is the spec's canonical example, not
  id-spraying.
- **1 cross-user read CONFIRMED**, and it was the mission's only confirmed finding.
- Negative controls at confirmation time: anonymous `401`, implausible-id returned a different body.

Verified hop by hop:

| Hop | Evidence |
|-----|----------|
| Planner → BIE | artery step 5e invoked `confirm_browser_persona_bola` on the proven pair |
| BIE → Graph/state | 5 runtime observations added as `runtime:*` capabilities |
| BIE → shared ledger | 263 entries recorded as `engine="browser"` (so they are in the one HAR) |
| BIE → Evidence | PoC bundle carries `browser_evidence` + steps + replay script + screenshots |
| BIE → Report | HTML renders "Browser runtime proof" with embedded before/after PNGs |
| BIE → UI | Assurance panel row renders live from `/report/{id}/json` |

## 4. Defects found and fixed during this pass

1. **Shared wire sink destroyed persona attribution.** All three browser contexts wrote to one request
   list, so "which persona's browser made this request" — the entire basis of the cross-user hypothesis —
   was lost. Fixed: per-persona sinks.
2. **Control surface enumerated an empty DOM.** Phase 1's screenshot capture navigated the attacker page to
   a raw JSON endpoint; phase 2 then read the control surface from a page with no controls and reported a
   silent zero. Fixed: controls are read while the personas are still on application pages, accumulated
   across routes.
3. **The platform's own proof gate demoted the strongest evidence.** The BIE finding omitted `impact`, so
   `proof_schema.demote_unproven` downgraded a `confirmed` cross-user read to a `lead` in the report while
   the database still said `confirmed`. This is the gate working correctly and the producer being wrong.
   Fixed in both producers, plus a regression test asserting every BIE confirmation satisfies the proof
   contract. **Generalisable lesson: any new access-control producer must satisfy `proof_schema` or its
   findings are invisible in the report.**
4. **Fixed sleeps.** Replaced with condition-based waits (see §6).
5. **Phase-3 trigger page.** Route interception could not see the app re-issue a request because the page
   had been parked on an API URL; now an application page is re-driven first.

### Regression proof for defect 3

**Mission d2a651ca**, run on the rebuilt image after the `impact` fix, end to end:

```
DB     -> confirmed   CWE-639   impact set: True
REPORT -> confirmed   CWE-639   proof_gap: None      (was "lead" before the fix)
ARTERY -> BIE ran, 1 confirmed, candidate from observation
UI     -> Findings posture: Confirmed 1              (was 0 before the fix)
```

UI driven in a real browser (load mission → Assurance panel), **0 console errors**.

## 5. Honest limitations

- `client_side_authz` and `client_supplied_identity_param` carry **`validated_on: []`**. Both are
  unit-proven and both execute live without error, but neither has been confirmed by a lab yet:
  - Juice Shop's Angular **removes** privileged controls from the DOM rather than hiding them, so there is
    nothing to enumerate and phase 2 correctly reports zero. Routes that exist only in the JS bundle are
    the static collectors' job; the two views compose and neither pretends to be the other.
  - Juice Shop identifies objects by **path** id, not by an identity query parameter, so phase 3 correctly
    finds zero candidates there.
  Confirming these needs a lab that hides a privileged control with CSS, and one that passes an identity
  parameter in the query string.
- Phase 3 records its own provenance honestly: `route-interception` when the app re-issued the request and
  it was rewritten in flight, `in-page-fetch` when it did not and the mutated request had to be issued from
  inside the page — a weaker claim, so it is named rather than blurred.
- Screenshots embed as base64 in the HTML report, which grows it (110 KB for one finding).

## 6. Determinism

The Playwright books call `wait_for_timeout` an anti-pattern; every fixed sleep is gone from `bie.py`.
Navigation registers `expect_response` for the app's real object request **before** navigating, then
settles on `networkidle`. The settle **reason** is recorded as evidence (`networkidle+object-response`)
instead of hiding a magic number.

Those books also devote chapters to AI/Copilot/MCP-driven test generation. Those are **rejected by policy**:
generation may involve a model, confirmation never does. The oracle stays deterministic.

## 7. Guardrails, unchanged

Only safe methods auto-fire (GET). State-changing controls become operator leads and are never auto-clicked.
Every URL passes the caller's scope gate. Session secrets stay server-side — evidence carries cookie and
storage **names** only, and `redact_headers` masks authorization material. No DoS, no credential-brute loops.
