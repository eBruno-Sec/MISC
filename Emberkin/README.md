# Emberkin — *A Light Between Two*

An original, family-friendly, **fully-3D third-person** fantasy adventure — playable in the browser.
This is a **vertical slice** built from a complete production brief: it demonstrates the core game
loop (sibling & class selection, a floating companion, elemental powers, non-graphic combat, the
signature *Mimic Orb* transformation, and gliding) inside a small hand-built 3D world, plus a full
Phase-0 design codex.

> Built with [Three.js](https://threejs.org) (loaded via CDN import map). No build step, no backend —
> a self-contained static site that runs on GitHub Pages.

Live: `https://ebruno-sec.github.io/MISC/Emberkin/`

---

## Originality statement

Emberkin draws on broad action-adventure genre conventions but uses **only original** names,
characters, lore, regions, creatures, symbols, and systems. Nothing here copies characters, names,
companion designs, dialogue, story, map, creatures, UI, or code from any existing product. All
proper nouns below are original to this project.

---

## The original IP (canon reference)

| Element of the brief | Emberkin's original take |
| --- | --- |
| Title | **Emberkin** — *A Light Between Two* |
| World | The **Reach of Aldermere**; the slice takes place in **Willowmere Vale**, a bright lake-and-forest valley |
| The two siblings | **Wren** (sister) and **Cael** (brother). The player permanently chooses one; the unchosen becomes the **Lost Sibling** |
| The floating companion (working name "Tainer") | **Tainer**, a small floating light-being called a **Glimmer** — a stray spark of the world's first light, found tangled in the reeds and pulled from Willowmere's lake while fishing |
| The villain | **Mourne, the Stillard** — an ancient being who wants to *still* the world into a perfect, changeless silence. He believes change is suffering, so stillness is mercy. He cracked the **Wellspring** (the source of the elements) and scattered the siblings. His servants are the **Hollow Wardens** |
| The five elements (unlocked at statues) | **Loam** (earth), **Tide** (water), **Cinder** (fire), **Arc** (storm/electricity), **Rime** (ice). Each has an original name, sigil, and colour — never signalled by colour alone |
| The ancient statues | **Wardstones** — carved guardian stones that attune an element when touched |
| The signature transformation | The **Mimic Orb** (preserved from the brief). Defeated **Stonekin** sometimes leave a single-use **Mimic Mote**; absorbing it performs a **Mirrorstep** into that creature, with **separate monster health** and **automatic + manual ejection** back to your preserved health |
| The starting enemy family | The **Stonekin** — animated rock creatures (**Grumble**, **Boulderback**). On defeat they **dissolve into drifting motes of light** — no blood, gore, dismemberment, or corpse |
| The gliding mentor & test | **Skywright Pell** runs the **Windrider's Trial** (hoops + wind currents). Passing grants the **Windrider's Mark** (gliding licence) and a **windwing** glider |
| Currency / progression | **Emberlight** (tokens) earned from exploration and combat, spent to upgrade your class weapon |

### The five permanent classes

| Class | Tier 1 (start) | Tier 2 (lake hoard) | Tier 3 (boss reward) | Playstyle |
| --- | --- | --- | --- | --- |
| **Sword** | Vale Blade | Bramblefang | Dawnedge | Balanced close range, reliable, parry potential |
| **Bow** | Reed Bow | Galewhisper | Sunstring | Ranged precision, charged shots, weak points |
| **Greatsword** | Cragcleaver | Bouldersong | Titanroot | Slow, heavy, high stagger, breaks weak stone |
| **Dual Swords** | Twin Fangs | Skydancers | Emberfangs | Fast combos, high mobility, quick elemental build-up |
| **Psychic Focus** | Wander Rune | Lumen Coil | Starheart | A floating rune; telekinetic push/pull, shields, moving platforms |

The class is chosen once and is permanent for the save. All classes complete the slice. Weapons
are managed from the pause menu's **Weapons & Gear** panel: equip, compare power, upgrade with
Emberlight, or dismantle spares (two-step confirm; the equipped weapon is protected).

### The four elemental mechanisms & the boss

Carved trigger stones around the vale answer only to their own element (sigil + name shown, never
colour alone): **Rime** freezes the lake's deep water into a path to an island hoard, **Loam**
raises stone steps to a cliff-top chest, **Tide** floods a sealed basin so its hoard floats to the
rim, and **Arc** powers open the gate to a hollow where **Hush, the Hollow Warden** — Mourne's
first lieutenant — waits. Hush telegraphs a slam, exposes its back-crystal for bonus damage
afterward, and calls Stonekin at half health. Elemental Stonekin variants resist their own element
and take extra damage from its counter (Cinder ↔ Rime, Tide ↔ Arc).

---

## What the slice demonstrates (acceptance checklist)

Playable, end to end:

1. Launch a **3D** client in the browser
2. **Select** the brother or sister
3. **Choose** a permanent class (with preview + description)
4. View the **separation** sequence and the **fishing** interaction
5. **Pull Tainer** from the water and meet her
6. Complete **movement** tutorials (walk, run, jump)
7. **Fight** a Stonekin enemy
8. See a **non-graphic dissolve** effect on defeat
9. Receive a **Mimic Orb**, **transform**, use **monster abilities**, and see **separate monster health**
10. **Eject manually**, then reach **zero monster health** and **eject automatically** with original health preserved
11. **Infiltrate** a guarded camp that is only passable in a disguised (transformed) form
12. Unlock an **element** at a Wardstone and use it in an **environmental puzzle**
13. Earn **Emberlight** and **upgrade** your weapon
14. Pass the **Windrider's Trial** and unlock **gliding**
15. **Save** progress to JSON and **reload** it (with autosave to local storage; v1 saves migrate to v2)
16. Adjust **accessibility** settings (reduced motion, high-contrast, camera speed, larger UI, aim assist)
17. Strike all **four elemental mechanisms** and open their hoards
18. Defeat **Hush, the Hollow Warden** and claim the Tier-3 weapon
19. Build and **instantly playtest** your own glade in **Emberkin Studio**

---

## Controls

| Action | Keyboard / Mouse |
| --- | --- |
| Move | **W A S D** |
| Sprint | **Shift** (hold) |
| Jump | **Space** |
| Glide | **Space** in the air (after the Windrider's Mark) |
| Attack | **Left click** or **J** |
| Interact / fish / touch Wardstone | **E** |
| Cycle element | **Q** / **1–5** |
| Activate Mimic Orb | **F** (when an orb is held) |
| Eject from Mimic form | **F** |
| Camera | **Mouse** (click the canvas to look) |
| Pause / menu | **Esc** |

A full control list and accessibility options are available from the in-game pause menu. Every
control is also shown on the HUD, and prompts adapt to what you can currently do.

---

## Project layout

```
Emberkin/
  index.html          Project hub / landing page (matches the MISC gallery style)
  play/
    index.html        Game shell — canvas, HUD, menus, inventory, boss bar
    style.css         Game + HUD styling, themes, accessibility, print
    game.js           The game (Three.js): world, camera, combat, mimic, elements,
                      mechanisms, weapons, boss, gliding, save (v2 + migration)
  studio/
    index.html        Emberkin Studio shell — toolbar, palette, playtest UI
    studio.js         Creator sandbox: grid placement, erase/undo, limits,
                      validated save/load, instant playtest
  docs/
    index.html        Phase-0 design codex (GDD, TDD, systems, safety, architecture, roadmap)
  README.md           This file
  CONTINUE_HERE.md     Build-status / handoff notes
```

## Emberkin Studio (creator sandbox)

A kid-friendly, **local-only** creator: place trees, rocks, blooms, Grumbles, chests, hoops, and a
start flag on a snapped grid (max 200 pieces), erase and undo freely, then hit **Playtest** to walk
your own glade instantly — chests pop open, Grumbles wander, hoops spin. **Back to editing**
returns you to the exact camera, mode, and selection you left. Glades autosave to the browser and
export/import as validated `.json` (same defensive rules as game saves). Nothing can be published
or shared — which is exactly why it ships without the moderation pipeline the full platform
design requires.

## Running locally

It's a static site, but ES-module imports need to be served over HTTP (not `file://`):

```bash
cd Emberkin
python -m http.server 8000
# then open http://localhost:8000/
```

## Scope & honesty notes

This is a **front-end vertical slice and design package**, not the full shipped platform. The brief
describes a multiplayer, containerized, moderated live-service with user-generated content. Those
systems are **fully designed** in [`docs/`](docs/index.html) (networking model, server authority,
child-safety and moderation plans, container/Kubernetes/CI-CD architecture, Mimic Orb server-side
state machine, threat model) but are **not implemented** here — a browser slice can't be
server-authoritative against itself. Where the brief calls for server authority, the docs mark the
boundary clearly. Nothing in this slice is presented as production-ready multiplayer.

Save data here is **local only** (JSON download/upload + browser storage) and is explicitly *not*
authoritative — matching the brief's rule that client saves never govern real progression, currency,
or entitlements.
