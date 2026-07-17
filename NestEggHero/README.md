# NestEggHero

NestEggHero is a static, dependency-free financial learning studio for GitHub Pages. It teaches source-labeled 2026 retirement facts, runs deterministic educational calculators, and keeps learning continuity on the user's device.

## Highlights

- Fact registry with effective year, jurisdiction, authority status, source URL, retrieval date, reviewer, and next-review date.
- Eight structured lessons with Kid Speak variants, quizzes, sources, risks, takeaways, and next steps.
- Nine calculators using pure functions: steady saving, compound growth, debt payoff, Roth vs Traditional Decision Lab, today's dollars, real return, present value, effective annual rate, and 2026 contribution limit helper.
- Premium responsive interface with a modern decision dashboard, source drawer, scenario presets, and richer calculator result panels.
- IndexedDB learning progress with localStorage only for low-risk preferences.
- JSON backup envelope with schema versioning, sha256-base64 checksum, size/depth/node/string guards, prototype-pollution rejection, preview, merge, and replace.
- Crawlable generated lesson, fact, and calculator index pages for GitHub Pages SEO.
- Print mode, reduced motion support, dark theme, larger text mode, service worker cache, sitemap, robots file, and tests.

## Run locally

```bash
npm run serve
```

Open http://127.0.0.1:4173/.

## Validate and generate static pages

```bash
npm run build
```

`build` generates static pages under `learn/`, `facts/`, and `tools/`, then runs the test suite.

## Hosted URL

https://ebruno-sec.github.io/MISC/NestEggHero/

## Content governance

Changing financial facts must be updated in `scripts/facts.js` and must include an effective year, jurisdiction, authority status, source URL, retrieval date, reviewer, and next-review date. This app is general education only and does not provide individualized tax, legal, fiduciary, or investment advice.
