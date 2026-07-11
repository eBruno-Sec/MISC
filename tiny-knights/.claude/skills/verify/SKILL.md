---
name: verify
description: Build, serve, and drive Tiny Knights end-to-end with Playwright to verify changes at the browser surface.
---

# Verifying Tiny Knights

## Build + serve

```bash
cd tiny-knights
npm install
npm run build                      # tsc -b && vite build -> dist/
npx vite preview --port 4173 &     # serves at http://localhost:4173/MISC/tiny-knights/
```

The base path is `/MISC/tiny-knights/` (set in vite.config.ts) — the root URL 404s.

## Drive it (Playwright)

Use `playwright-core` with the preinstalled browser:
`executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'`
(check `ls /opt/pw-browsers/` for the current version suffix).

Useful selectors / flows:
- Equation text: `div[aria-live="polite"]` filtered by `hasText: '×'`; textContent
  has **no spaces** (e.g. `3×4=?` or `?×4=12`). Compute the answer accordingly.
- Answer input: `button[aria-label="Number 3"]`, `button[aria-label="Submit answer"]`.
- A full Daily Quest is 12 questions; wait ~1s between submits (advance animations
  run 600–700ms). Victory screen shows `h1` "Quest Complete!".
- Multiple choice appears after 2 wrong answers on one question: buttons under
  `.grid.grid-cols-2`.
- Progress lives in `localStorage['tiny-knights-progress-v1']` as
  `{ version, data }` — seed `data.lastPlayedDate` / `data.dailyStreak` /
  `data.facts[key].isMastered` to reach specific states, then reload.

## Gotchas

- Google Fonts request fails in the sandbox (network policy) — harmless,
  fonts fall back; ignore that console error.
- Session results (`data.sessions[last]`) are the ground truth for scoring
  bugs: compare `questionsAnswered` against the number of submits you made.
