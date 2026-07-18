# Emberkin — build status / handoff

**Last updated:** 2026-07-17 (survival-sandbox expansion underway)
**Status:** Adventure slice ✅ shipped & verified. Now expanding into a survival sandbox per an
audited, phased roadmap (below). If you are a scheduled continuation: verify the latest commit
pushed; only continue the CURRENT in-progress sandbox phase, never rebuild shipped systems.

## Survival-sandbox expansion (approved 2026-07-17)

Approved architecture decisions:
- **Hybrid terrain overlay** — heightfield stays authoritative; ground tiles voxelize on first
  dig (1 m³ cells, ~24 m depth cap). Full-voxel rewrite explicitly rejected.
- **Elements live in the hotbar** — unified 1–0 hotbar (weapons/tools/consumables/elements);
  Q still cycles elements.

Roadmap: A core framework → B inventory/hotbar UI → C gathering (trees/ores/plants, damage
numbers) → D dig & place (voxel overlay) → E crafting/forge/smelting → F building + elemental
traps → G combat depth + original elemental reactions → H exploration (minimap/fog/caves) →
I dragon endgame at depth → J polish/QoL.

**Phase A (core framework) — ✅ SHIPPED & verified** (commit ba13b45):
items.js registry (proto-guarded lookups), input.js action map, bag API, save v3 with
v1/v2 migration, deep-copied snapshots, reticle + ranged aim-dot, step() harness now runs
updateCamera/updateAim. Full old-suite regression passed.

**Phase B (inventory + hotbar) — ✅ SHIPPED & verified** (26c9aa9 + refinements 597562f):
unified 10-slot hotbar (keys 1–0; weapons show tier + equipped highlight, consumables show
counts), bag grid with tooltips + sort, full drag & drop (weapons, items, slot-to-slot moves),
auto-population (starter weapon + 2 Emberjam; found weapons auto-slot). Per user feedback,
ELEMENTS ARE NOT SLOTTED: Q cycles right, E cycles left (E is context-sensitive — interacts
when a prompt is showing), HUD element chip bottom-right live-syncs. Old element wheel removed.
Also: over-the-shoulder camera setting (right/left/center, default right).

**Survival-sandbox expansion COMPLETE — all phases C–J shipped & verified:**
- C gathering (trees/rock/ore/plants, magnet pickups, floating loot/damage text)
- D dig & place blocks + the underground Delve (Sunken Barrow → crystal cavern)
- E crafting/forge/smelting (recipes.js, in-inventory panel, Wardcharm +maxHP)
- F building + elemental traps (spike/frost/ember) + structure combat + damage numbers
- G combat depth: dash, double-jump, charged attack, crits, combo, heal-on-kill + 10 original
  elemental reactions (Steambloom, Thermal Shatter, Galvanize, …)
- H minimap + world map + fog of war
- I Vornrath the Deepwyrm endgame → unlocks Wellspring Transmute, legendary loot, Deepened mode
- J footsteps, menu fades, resource tracker, controls cheat-sheet, docs/README/hub/card updates

Modules: play/items.js, play/input.js, play/recipes.js + play/game.js (~3,500 lines). Save
schema v3 (bag/hotbar/build/underground/dragon/hardMode) with v1/v2/v3 migration. Dev harness
(?dev=1) exposes hooks + a deterministic step(sec) simulator; full regression passes with zero
console errors. User's save backups are gitignored (EMBERKIN_backup_*.json).

If resuming: the game is feature-complete against the survival brief. Verify only; don't rebuild.

`README.md` holds the full original IP canon (names, elements, villain, regions, classes, tiers).

---

## What exists (all done, all verified)

| Piece | Contents |
| --- | --- |
| `play/` | The full 3D game (~2,050-line game.js). Core loop **plus Phase-2**: 3 weapon tiers per class with Weapons & Gear panel (equip / compare / upgrade / dismantle w/ 2-step confirm), 4 elemental mechanisms (Rime freezes the lake deep-water zone, Loam raises steps+platforms, Tide floods the basin, Arc opens the boss gate), elemental Stonekin variants (resist own element ×0.25, counter ×1.75; Cinder↔Rime, Tide↔Arc), and the boss **Hush, the Hollow Warden** (320 HP, telegraphed slam, 2.6s weak window ×2 dmg, phase 2 at half HP spawns adds, defeat = +40 Emberlight + Tier-3 chest + "to be continued"). Save schema **v2** with v1→v2 migration. |
| `studio/` | **Emberkin Studio** (Phase-4 demonstrator): grid-snapped placement of 7 piece types, single-flag rule, occupied-square rejection, erase/undo(60)/clear, 200-piece limit, localStorage autosave, validated JSON save/load (type whitelist, bounds, pollution guard, limit check — generic error "Invalid or corrupted progress file"), instant playtest (kid spawns at flag, walks/jumps, Grumbles wander, chests pop, hoops spin) that restores exact editor context on exit. Local-only; no publishing. |
| `docs/` | Design codex updated: scope table rows for the new systems, UGC section links the Studio, roadmap marks Phase 2 (single-player parts) and Phase 4 (local sandbox) as shipped, villain section names Hush. |
| `index.html` | Hub: Studio action card + expanded checklist. |
| `../index.html` | Gallery card description covers boss + studio. |

## Verification evidence (dev harness, `?dev=1`)

Game (`window.__EMBER`, includes deterministic `step(seconds)` because background tabs throttle RAF):
- Weapons: grant/equip/dismantle; tier power math exact (sword 26/36; bow 30/39 at Lv2). UI flow
  clicked through: rows, +10 comparison, "Really dismantle?" confirm, +6 Emberlight, resume.
- Mechanisms: all four activate via hook AND via real melee strike; wrong element refused with
  sigil-labeled toast; projectiles carry element (Bow/Focus can trigger mechs and melt the ice wall).
- Deep water: unfrozen lake ejects walkers to the 8.4-radius ring (glide-over allowed above y2.5);
  frozen lake is walkable to the island chest.
- Boss: exactly one 24-dmg slam per cycle (damage log instrumented), weak window ×2 verified
  (10→20), phase 2 at <160 HP spawns exactly 2 adds, defeat flow grants +40/stage 6/Tier-3 chest.
- Saves: v2 round-trips all new fields; **v1 save migrates** (starter weapon granted, mechs/chests/
  boss defaulted); defeated-save rebuild spawns no boss but re-creates the reward chest ("Open
  chest" prompt → grants Tier-3).
- Fixed during this pass: sibling-select 260ms timer could stamp phase='class' over a running game
  (now guarded); ranged classes couldn't melt the ice wall (now can); new-game now fully resets the
  module-singleton G.
Studio (`window.__STUDIO`): all editor invariants + save validation + round-trip + autosave-across-
reload + click-to-place (switched to mouse events — same input path as the game) + visual playtest
walk (kid moved (6,6)→(9.2,9.1)) + context restore.
Zero console errors across all flows, local and live.

---

## Verification-only checklist for any scheduled run

1. `git -C "C:\Users\Zabre\Desktop\2. ClaudeAI\Apps\MISC" status` clean; latest Emberkin commit on
   origin/main.
2. Optionally: open `https://ebruno-sec.github.io/MISC/Emberkin/play/?dev=1` — loading clears to
   title, console clean. Same for `.../Emberkin/studio/`.
3. Fix only if actually broken; otherwise stop. Do not rebuild or re-scope.
