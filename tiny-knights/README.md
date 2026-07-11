# Tiny Knights — Times Table Quest ⚔️

A cozy math RPG for kids aged 6–11. Battle friendly monsters by answering
multiplication questions — spaced repetition dressed up as a knight's adventure.

**Play it:** https://ebruno-sec.github.io/MISC/tiny-knights/

## Features

- **Daily Quest** — an adaptive 12-question session that mixes weak facts,
  new material, and review using a spaced-repetition scheduler
- **Table Trainer, Boss Battles, Mistake Rescue, Speed Round** — focused modes
  for drilling one table, testing mastery, or low-pressure recovery practice
- **Mastery engine** — a fact counts as mastered only after repeated fast,
  correct answers across at least three separate sessions
- **Progression** — XP, coins, badges, cosmetic unlocks, a monster book, and a
  daily streak
- **Parent Dashboard** — mastery overview, weak/slow facts, session history,
  table range (1–10 or 1–12), and session length controls
- **No account, no ads** — all progress is saved in the browser via
  `localStorage`; includes dark mode, reduced motion, and sound toggles

## Stack

React 19 + TypeScript + Vite + Tailwind CSS 4. No backend.

## Development

```bash
npm install
npm run dev      # local dev server
npm run build    # type-check + production build to dist/
npm run lint
```

## Deployment

GitHub Pages builds this app in CI (see `.github/workflows/pages.yml`): the
workflow runs `npm ci && npm run build` and publishes `dist/` at
`/MISC/tiny-knights/`. Don't commit build output — pushing to `main` is enough.

A `Dockerfile` + `nginx.conf` are also included for self-hosting
(see `DOCKER_GUIDE.md`).
