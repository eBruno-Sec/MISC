# 🚀 QuantumKids

A **Zero-to-Hero physics academy** for ages 8–15 that teaches Special Relativity,
Thermodynamics, Quantum Mechanics and more through **visual intuition and play** —
no heavy math prerequisites. Single self-contained `index.html`, no build step, runs
anywhere (and offline).

**Live:** https://ebruno-sec.github.io/MISC/quantumkids/index.html

## What's inside

The build implements the QuantumKids framework across four pillars:

| Pillar | Implementation |
| --- | --- |
| **I · Curriculum** | 6 tracks (Classical Mechanics, Electromagnetism, Thermodynamics, Special Relativity, Quantum Mechanics, Astrophysics), each with a story hook, an intuitive analogy anchor, core concepts, and a "Hero Leap." |
| **II · Sandbox engine** | Every lesson centers on a real, interactive HTML5-Canvas simulation. Kids drag dials (gravity, speed of light, temperature, star mass…) and see immediate consequences. Each mission has a 3-tier challenge: **Cadet** (visual proof) → **Specialist** (variable debugging, auto-verified against live sim state) → **Hero** (predictive multiple-choice). |
| **III · Print Lab Packs** | Ink-saver, black-on-white line-art blueprint worksheets built on demand (`window.print()`), plus a **"What Your Child Unlocked"** parental audit page that maps gameplay to formal academic benchmarks. |
| **IV · State persistence** | `Download Progress (.json)` serializes the full nested state tree to `QUANTUMKIDS_backup_[YYYY-MM-DD].json`. `Upload Progress (.json)` (file picker **or** drag-and-drop) runs `JSON.parse` + strict schema validation before hydrating — corrupt or foreign files are rejected with a clean `Invalid or corrupted progress file` banner. Progress also autosaves to `localStorage`. |

A **Parent Zone** surfaces live child metrics (badges, tracks mastered, XP, rank),
the benchmark audit trail, backup controls, and the premium **Hero Tracks** unlock flow.

## The six sandboxes

1. **Cosmic Trampoline** — launch a ball around a planet; find orbit vs. escape velocity.
2. **Dance-Floor Charges** — Coulomb field lines; opposites attract, like charges repel.
3. **Bumper-Car Entropy** — a gas of particles with a live entropy meter (the arrow of time).
4. **Twin Rockets** — time dilation with two digital clocks and a Lorentz factor readout.
5. **Quantum Coin** — superposition, measurement collapse, and entanglement.
6. **Stellar Pressure Cooker** — build a star; its mass decides white dwarf / neutron star / black hole.

## Tech

Vanilla JS + Canvas 2D, no dependencies or build tooling. Mobile-first ergonomics
(≥48px touch targets, bottom thumb-zone nav). Theme-aware for print. Fonts via Google
Fonts with system fallbacks.
