# Competitor analysis — Hound / CyberHound (queued 2026-08-07)

Source: user's dig through Hound (CyberHound) + its current terms. This is a REAL Apolaki competitor whose
product philosophy overlaps heavily with Apolaki's direction — not a generic vuln scanner.

## What Hound claims (marketing + terms)
AI-driven automated web/API pentester that: logs in, completes MFA/CAPTCHA, operates across multiple approved
accounts, tests business logic, exercises browser attack paths, chains multi-step attacks. Plus:
- Authenticated/persona testing (multiple accounts + roles).
- Business-logic reasoning (headline).
- Attack chaining (multi-step, not isolated alerts).
- Browser-native testing (auth/CSRF/DOM/workflows).
- Independent verification (findings re-tested).
- Human review before delivery.
- Safety layer (every command passes multiple checks; destructive actions + actions vs unapproved accounts blocked).
- Retest evidence in the report UX.
- Engagement isolation (dedicated cloud infra destroyed afterward; per-app encrypted finding storage).
- Reporting: **Fix Now / Fix If / Strengthen** (not just Critical/High/Medium), conditional weaknesses,
  scope + test perspective, business impact, coverage/retest views.

## Where Apolaki is architecturally stronger (Hound shows no PUBLIC proof of these)
first-class technique registry · deterministic confirmation-oracle contracts · canonical AssetGraph ·
candidate→lead→confirmed lifecycle · WSTG coverage accounting · ASVS objective modeling · CWE/CAPEC ·
SARIF boundary · D3FEND remediation mapping · cloud/AD/OT frontier · **deterministic-first, AI optional**.
Hound's terms explicitly call it "AI-driven penetration testing using AI agents" — so Apolaki's
deterministic-first architecture is a real differentiator IF it works end-to-end.

## Where Hound is scarier: PRODUCTIZATION
Their story is dead simple: give Hound approved app/accounts → it behaves like an attacker → verifies →
human reviews → client gets a useful report. Apolaki risks becoming technologically monstrous while Hound
sells the simpler outcome. Don't chase feature-for-feature.

## Ideas to steal (mapped to Apolaki's current state)
1. Authenticated multi-persona workflows absolutely first-class — **Apolaki HAS** (auth artery: register→login→
   matrix→BOLA, proven live). Surface it harder in report/UI.
2. Business-logic testing as a HEADLINE capability — **partial** (business_logic technique + hypotheses as
   leads); make it a named, prominent capability + confirmations.
3. Independent verification/retest VISIBLE, not buried — **Apolaki HAS** (retest closure loop #117 + poc-bundle);
   surface retest evidence prominently in the report UX.
4. Beautiful Coverage view: tested / confirmed-safe / blocked / inconclusive / not-tested — **Apolaki HAS the
   data** (Coverage Engine #21, ASVS/WSTG accounting, candidate assurance rows); needs the polished VIEW.
5. **Fix Now / Fix If / Strengthen** remediation-priority layer ALONGSIDE CVSS (not replacing technical
   severity) — **NEW, buildable now**: a deterministic classifier over (confidence, severity, exploitability,
   reachability, standards-violated) → {fix_now | fix_if | strengthen}. Highest-ROI steal.
6. Engagement isolation/destruction + evidence security as EXPLICIT product features — **Apolaki HAS the
   mechanics** (--fresh-lab genuine isolation #70, encrypted identity vault, redacted refs, per-mission tenant
   isolation from the fix-pass #10); make them a named product surface.
7. Keep attack chains, but SHOW the evidence graph explaining WHY the chain is real — **Apolaki HAS**
   (canonical graph + attack_chain + poc-bundle); render the "why this chain is real" evidence path.

## The positioning / moat
Hound sells "AI pentester." Apolaki should sell **"evidence-backed autonomous pentesting."** The killer
answer: *"Here is exactly how we discovered it, the deterministic oracle that confirmed it, the negative
control, the attack path it enables, the standards it violates, the evidence bundle, and the replay that
proves the fix."* Apolaki already has every one of those primitives — the work is PRODUCTIZING them into that
single narrative per finding.

## Concrete next builds (roadmap, by ROI)
1. **Fix Now / Fix If / Strengthen** remediation-priority engine (deterministic, over existing finding fields)
   + render in report alongside CVSS. Testable, self-contained.
2. **"Evidence dossier" per finding** — unify the primitives Apolaki already emits (oracle + negative control
   + attack path + standards violated + poc-bundle + retest replay) into one narrative block in the report.
   This IS the moat, made visible.
3. **Coverage view** polish (tested/confirmed-safe/blocked/inconclusive/not-tested) — data exists; build the view.
4. Business-logic as a headline capability surface.
