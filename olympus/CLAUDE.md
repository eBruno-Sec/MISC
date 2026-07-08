# CLAUDE.md — OLYMPUS working rules

**Read `HANDOFF.md` first.** It is the full project state (architecture, feature map,
constraints, gotchas, config). This file is just the rules of the road, loaded every
session.

## The flow (do this every change)
1. **Keep `HANDOFF.md` current.** When you make a non-trivial change (a feature, a fix
   with behavior impact, a new constraint/gotcha, a config knob), **update `HANDOFF.md`
   in the same change** — it's the portable memory that travels to Kali and fresh clones.
   Skip only for pure cosmetics (typos, formatting).
2. **Non-breaking is paramount.** Prefer additive changes. Small, focused commits.
3. **Ship path:** Erwin dev's on Windows (no local Node/Docker), commits + pushes to
   `main`; runs on Kali via `git pull origin main && docker compose up --build -d`. That
   `--build` runs the frontend `tsc && vite build` — it's the type-check gate. There is
   no local `tsc` on the dev box.
4. **Frontend caution:** can't compile on the dev box. Self-audit TS hard, or use a
   branch Erwin builds before merge. `npm run build` needs `npm install` first.
5. End commit messages with:
   `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## Hard constraints (details in HANDOFF.md)
- **`create_all` only, no migrations.** New tables OK; a **new column on an existing
  table breaks existing DBs** — put new mission-level flags in `mission.context` JSON.
- **Never hide findings.** METIS is advisory-only (annotates, never tags FP / deletes).
- **Scope safety** on every active probe (same-host; workbench refuses off-scope).
- **Strict TS** (`tsc` strict): no `number|null !== undefined` (TS2367), narrow
  `Map.get`/`.find` before use, inline `type` imports.
- **AI is optional** — single provider via `core/ai_client.complete()`; everything
  non-AI is deterministic.

## Verify
`docker compose exec backend python -m pytest tests/ -q` (poc, replay, surface, forms,
security). Frontend is verified by the Docker build.
