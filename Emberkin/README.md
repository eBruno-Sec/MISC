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

Every weapon has its **own feel**. Faster weapons hit lighter and slower ones hit harder, so
damage-per-second stays comparable — the choice is style, never strength.

| Discipline | Weapon | Signature |
| --- | --- | --- |
| **Sword** | Vale Blade | Forgiving — a wider, more generous swing arc |
| | Bramblefang | Swift — quick strikes, shorter reach, combo builds **double** |
| | Dawnedge | Keen — long reach, **+10% crit** |
| **Bow** | Reed Bow | Quick draw — rapid, lighter shots |
| | Galewhisper | **Piercing** — arrows carry on through a second foe |
| | Sunstring | Heavy draw — slow, powerful shots |
| **Greatsword** | Cragcleaver | **Crushing** — heavy knockback |
| | Bouldersong | Sweeping — a far wider arc through crowds |
| | Titanroot | **Stonebane** — ×1.4 against the heavy Stonekin |
| **Dual Swords** | Twin Fangs | Relentless — fastest strikes, combo builds **double** |
| | Skydancers | **Windborne** — longer, more frequent dash |
| | Emberfangs | **Emberbound** — elemental reactions hit 35% harder |
| **Psychic Focus** | Wander Rune | Swift bolts — light, rapid casts |
| | Lumen Coil | **Chaining** — its light arcs on to a nearby foe |
| | Starheart | Starfall — slow, heavy, brilliant impact |

Weapons are held **in the hands** and swing with the arms, with a distinct animation per style —
a sword arc, a two-handed greatsword chop, a bow draw-and-loose, a floating spinning rune, and
**dual swords that alternate left and right** for a real combo rhythm.

### Mastery, not loot

You choose a **starting discipline** at the beginning — it's your opening story beat and begins one
Mastery rank ahead — but **every one of the 15 weapons is unlocked from the start**, usable by
anyone. All are *unique grade*: equal in power, and **nothing can be broken or dismantled**.
Equipping a weapon switches your whole combat style (pick up a bow and you shoot, even if you began
as a swordfighter).

Power comes from **Mastery**, bought with Emberlight in the inventory — one track per weapon type
(Sword, Bow, Greatsword, Dual, Focus), 10 ranks each. Chests and quests pay Emberlight rather than
weapons. **You invest in the discipline, not the object.**

> *Deliberate change from the original brief.* The brief specified a permanent class, class-locked
> weapon tiers, and dismantling spares for materials. This build keeps the permanent-choice **story
> beat** but replaces the loot treadmill with mastery — more freedom to try every playstyle, and no
> "destroy your gear" anxiety, which suits a family-friendly game better than a gear grind.

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
18. Defeat **Hush, the Hollow Warden** and claim a hoard of Emberlight for Mastery
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
| Cycle element | **Q** (next) / **E** (previous — when no interaction prompt is showing) |
| Hotbar (weapons, tools, consumables, blocks) | **1–0**, assignable by drag &amp; drop in the inventory |
| Gather / build / break / dig | **Attack** at a tree, rock, ore, placed block, or ground (a block on the hotbar places instead) |
| Dash | double-tap a movement key |
| Double jump | **Space** again in the air |
| Charged attack | hold **Attack** ~0.6s |
| World map | **M** · Inventory & crafting | **I** or the pause menu |
| Activate Mimic Orb | **F** (when an orb is held) |
| Eject from Mimic form | **F** |
| Camera | **Mouse** (click the canvas to capture it and look) |
| Zoom camera | **Scroll wheel** |
| Free the cursor / pause | **Esc** (one press does both; Resume re-captures the mouse) |

A full control list and accessibility options are available from the in-game pause menu. Every
control is also shown on the HUD, and prompts adapt to what you can currently do.

### Touch / mobile

On a phone or tablet the game shows an **on-screen control layer** the moment you first touch the
screen: a dynamic **movement joystick** (left thumb; push to the edge to sprint), a **drag-to-look**
camera (right thumb), and thumb-reach buttons for **Attack** (hold to charge), **Jump**, **Dash**,
**Interact**, **Mimic Orb**, **element ◀ / ▶**, **Map**, and **Menu**. The hotbar taps directly. The
controls appear only on touch input, so desktop play is completely unchanged. *(The separate
Emberkin Studio creator is still desktop-only.)*

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

## Story, quests & the Wayfarer's Journal

Emberkin has a **guided main story** you can follow beat by beat — and each beat teaches a real,
gentle life skill, so the hero grows in wisdom, not just in loot. The villain **Mourne** wants to
*freeze the world so nothing can ever be lost*; that's emotional avoidance dressed as mercy, and the
final boss **Vornrath** is buried grief grown huge in the dark. So the lessons aren't bolted on —
they're the story the game is already telling:

| Beat | Skill it teaches |
| --- | --- |
| The first cast · meeting Tainer | Beginning — the next small step |
| Attuning your first element | Emotional intelligence — naming feelings |
| Melting the ice wall | Problem-solving — patience over force |
| Slipping through the camp | Situational awareness — watch first |
| Besting Hush | Stoicism — the space between what happens and what you do |
| Sparking a reaction | Stoicism — the dichotomy of control |
| The Windrider's Trial | Courage — leaning into the wind |
| Descending the Delve | Growth — the precious things grow in the dark |
| Facing the Deepwyrm | Integration — meeting the pain turns it back to light |
| Understanding Mourne | Meaning — a life you can lose is worth living fully |

Alongside the story there are **12 Lessons** — wisdom the vale teaches by *doing* rather than by
telling. They complete on gameplay milestones and never expire:

| Lesson | Earned by | Skill it teaches |
| --- | --- | --- |
| Made, Not Found | craft anything | Creation — good things are built |
| Small Deposits | gather 50 | Compounding — small efforts add up |
| You Are Always Building | place 20 blocks | Habits — choose what you build |
| Steady Hands | 25 encounters | Composure — useful while rattled |
| Go and See | explore 60 tiles | Curiosity — look instead of guessing |
| Combinations | 8 reactions | Collaboration — two beats one |
| Turn the Soil | dig 15 | Persistence — the boring stretch pays |
| Depth Over Width | 5 mastery ranks | Deliberate practice over dabbling |
| Heat and Time | smelt 5 | Transformation needs discomfort *and* patience |
| Tend Yourself | 5 restoratives | Self-care isn't quitting |
| Before the Storm | 5 traps | Foresight — prepare in the calm |
| Curiosity Rewarded | 4 chests | Wonder is worth protecting |

### Insights are earned by play, but *sealed* by reading

That's the part that makes the wisdom stick. When a beat or lesson completes, the game pauses and
shows a **Reflection**: the story line, then the teaching and a practice to try. Tap **I've read it —
ask me** and it asks **one question** about what you just read. Answer correctly and the insight is
**sealed**. Answer wrong and it simply returns you to the teaching to read again — no penalty, no
lost progress, just another pass. Your **Wayfarer rank** (*Lost Traveller → Seeker → Wanderer →
Steady → Kindled → Sage → Lightbearer → Keeper of the Ember*, across all **22** insights) counts
**sealed** insights only, so reading *is* the progression.

Nothing traps you: every Reflection has a **Not now** button (in both the reading and the quiz view,
since phones have no Esc). Anything left unsealed waits in the **Insights** tab with a **Read & seal
this insight** button, and the Journal header tells you how many are still awaiting you.

**Daily** and **weekly quests** pair a game task with a small real-world **practice** ("name one
thing you can't control, and loosen your grip on it"). The Journal also holds a **How to Play** guide
covering every mechanic — movement, combat, elements, gather, craft, build, dig, and the Delve.

> **A note on the reflections:** they're gentle life-skills practice inspired by stoicism and
> emotional intelligence — *not* medical or mental-health advice. This is surfaced in the Journal
> itself. If something ever feels too heavy, the game says plainly: talk with someone you trust.

## Survival sandbox

Past the story slice, Emberkin is a full survival loop:

- **Gather** — chop trees for Timber, mine rock for Stone, and work ore veins for Iron, Gold, and
  Crystal. Ore needs a pick of the right tier; nodes regrow over time. Drops magnet to you.
- **Craft & forge** — an in-inventory recipe panel (with search) turns materials into tools,
  building blocks, elemental traps, and consumables. Place a **Forge** to smelt ore into ingots and
  craft iron gear; brew a **Wardcharm** to permanently raise max health.
- **Dig** — craft a **Stone Pick** (3 Stone + 2 Timber), press its **hotbar number** to hold it, then
  **attack open ground** to dig up Dirt, Stone and Clay. Holding a pick also mines rock and ore.
  Works for every class.
- **Build** — put a block on your hotbar and attack to **place** it (walls, platforms — enemies will
  attack your structures); attack a placed block while *not* holding a block to **break** it back
  into your bag. Lay **Spike / Frost / Ember** traps to defend a base.
- **Delve** — with an Iron Pick, descend the **Sunken Barrow** into a dark crystal cavern with ore,
  an underground lake, ruins, and a hidden hoard.
- **Fight deeper** — dash, double-jump, and charged strikes; a **combo** meter; crits and
  heal-on-kill; and **ten original elemental reactions** (hit with one element, then another) that
  splash bonus damage and status effects.
- **Explore** — a rotating **minimap** and a full **world map** with fog of war.
- **Endgame** — wake **Vornrath, the Deepwyrm** at the bottom of the Delve. Beating it unlocks the
  **Wellspring Transmute**, legendary loot, and an optional **Deepened** (harder) mode.

Everything is local and single-player; the survival systems all persist in the same versioned save.

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
