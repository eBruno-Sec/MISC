# NestEggHero

NestEggHero is a static, GitHub-hostable financial education app for learning retirement basics, comparing simple projections, and exporting low-risk learning progress.

This first version was built from the fact-checked NestEggHero documentation package reviewed on 2026-07-16. It is educational only and does not provide individualized tax, legal, fiduciary, or investment advice.

## What is included

- Crawlable educational content with reviewed dates and official sources.
- A deterministic savings projection calculator with assumptions shown next to results.
- A 2026 retirement contribution limit helper using source-labeled federal figures.
- Kid Speak explanations that preserve the underlying financial meaning.
- IndexedDB learning progress, bookmarks, badges, and preferences.
- Schema-versioned JSON export/import with checksum validation.
- Print, reduced-motion, dark theme, and offline-support scaffolding.

## Local preview

Open `index.html` directly for the core app, or run a local static server to test offline behavior:

```bash
python -m http.server 4173
```

Then visit `http://localhost:4173`.

## GitHub Pages URL

Expected project URL after the MISC repo publishes from the branch root:

https://ebruno-sec.github.io/MISC/NestEggHero/

## Validation

```bash
npm test
```

The test suite covers the formula and contribution-limit domain module used by the app.

## Source authority

Changing financial facts must include an effective year, jurisdiction, authority status, source URL, retrieval date, reviewer, and next-review date before publication.
