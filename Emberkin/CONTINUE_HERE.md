# Emberkin — build status / handoff

**Last updated:** 2026-07-17 ~03:30 PDT
**Status:** ✅ COMPLETE and verified in-browser. Committed & pushed to `eBruno-Sec/MISC`.

If you are the scheduled 04:41 continuation: **the project is finished.** Do NOT rebuild it.
Your job is only a light verification/polish pass. See the checklist at the bottom.

Read `README.md` for the full original IP canon (names, elements, villain, regions, classes).

---

## What exists (all done)

| File | State |
| --- | --- |
| `README.md` | Original IP bible, controls, layout, honest scope notes. |
| `index.html` | Project hub / landing page (matches MISC gallery style). Links Play + Design Bible + README. |
| `play/index.html` | Game shell: importmap for three@0.161.0 (jsdelivr CDN), canvas, HUD, all menus. |
| `play/style.css` | HUD, menus, 3 themes, accessibility, CSS portraits, print. |
| `play/game.js` | The full game (~950 lines, core three.js only). All systems below. |
| `docs/index.html` | Phase-0 design bible (GDD, TDD, Mimic Orb state machine, multiplayer, child-safety, architecture, roadmap, risks). |
| `../index.html` | MISC gallery — Emberkin card added first under "Games & Interactive". |
| `../.claude/launch.json` | `misc-static` python http.server on port 8123 (for local preview). |

## Systems implemented & VERIFIED (via ?dev=1 QA harness + manual play)

- Title → sibling select (Wren/Cael) → permanent class select (5, with preview/stats) → opening
  cinematic → world. ✓
- Fully-3D world (lake, trees, mountains, Wardstones, camp, trial hoops), blocky humanoid
  characters (not stick figures), third-person follow camera with collision + drag/mouse look +
  arrow-key fallback. ✓
- Movement: WASD, sprint+stamina, jump. ✓
- Fishing at the lake → Tainer emerges → companion dialogue + objective progression. ✓
- Combat (class-specific melee/ranged) → non-graphic dissolve into motes of light → Emberlight
  tokens → Mimic Orb drop. ✓
- **Mimic Orb** full state machine, separate monster health, player health preserved exactly,
  manual eject (F) AND automatic eject at 0 monster-HP — both restore exact pre-transform health.
  **Verified precisely with HP 63 and 47.** ✓
- Stealth: guards ignore the disguised Mimic form; alert states shown only near the camp. ✓
- Elements: unlock at Wardstones, switch (Q / 1–5), Cinder melts the Rime wall puzzle. ✓
- Gliding: Windrider's Trial (updraft + hoops) grants the Windrider's Mark. ✓
- Progression: Emberlight + weapon upgrade. ✓
- Save/Load: JSON download + upload + localStorage autosave; validation rejects prototype
  pollution, future schema versions, non-objects, bad enums (exact message
  "Invalid or corrupted progress file"); round-trip restore verified. ✓
- Accessibility & themes: reduced motion, high-contrast, larger UI, camera speed, invert-Y,
  aim assist, volume — all wired and persisted. ✓
- No console errors across the whole flow. ✓

## Notes

- `?dev=1` on the play URL installs `window.__EMBER` QA hooks (spawnNear, killNearest, transform,
  eject, hurtMimic, setHp, save, loadObj, validate, unlockAll, state). Gated — absent in normal
  play. Keep it; it's how this build was verified and how you can re-verify.
- three.js loads from `https://cdn.jsdelivr.net/npm/three@0.161.0/build/three.module.js` via
  importmap. Confirmed loading in-browser. GitHub Pages serves ES modules fine.

---

## Verification-only checklist for the scheduled run

1. `git -C "C:\Users\Zabre\Desktop\2. ClaudeAI\Apps\MISC" log --oneline -3` — confirm the Emberkin
   commit is present and pushed (`git status` clean, `git log origin/main` includes it).
2. Optionally open the LIVE site once GitHub Pages has rebuilt:
   `https://ebruno-sec.github.io/MISC/Emberkin/` and `.../Emberkin/play/?dev=1`. Check the loading
   screen clears and the title screen appears (confirms the CDN importmap works on Pages).
3. If (and only if) something is actually broken, fix it, then commit & push. Otherwise do nothing —
   the project is complete. Do not rebuild or re-scope.

## Source brief (reference)
`C:\Users\Zabre\AppData\Local\Temp\claude\C--Users-Zabre-Desktop-2--ClaudeAI-Apps-MISC\6682e31d-3ff9-4d3c-bb18-a554514d1e15\scratchpad\zip_extract\Claude_Fable_Prompt_Package\MASTER_PROMPT.md`
(scratchpad — may be cleaned up; original zip in Downloads). `README.md` + this file are sufficient.
