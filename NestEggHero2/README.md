# NestEggHero 2

A financial learning studio built as a static, dependency-free web app. Eight short lessons, seven estimate calculators, and a fact registry where every changing 2026 figure carries its effective year, jurisdiction, authority status, and official source.

Built fresh from the fact-checked NestEggHero documentation package reviewed 2026-07-16 (included under `docs/`). General education only, never individualized tax, legal, fiduciary, or investment advice.

## What makes this build different

- **Fact registry engine.** No financial figure is hard-coded into prose. Articles embed `[[fact:id]]` tokens that resolve through `scripts/facts.js`; a record with `draft`, `expired`, or `disputed` status refuses to publish. The full registry is browsable in the app at `#/facts`.
- **Article engine.** Every lesson follows the content style guide order (learn, summary, explanation, example, activity, risks, takeaways, quiz, sources, next) with Kid Speak variants that simplify wording without dropping uncertainty or risk.
- **Calculator registry.** Seven deterministic tools (steady saving, compound growth, debt payoff, today's dollars, real return, present value, effective annual rate) defined as data plus pure functions; assumptions render beside every result and results are always labeled estimates.
- **Backup pipeline.** Exports follow the JSON backup spec: `NestEggHero_backup_YYYY-MM-DD.json` with a sha256-base64 checksum. Imports are treated as untrusted input: size, depth, node, and string caps, prototype-pollution rejection, checksum verification, preview, then an explicit merge-or-replace choice applied atomically.
- **State discipline.** Learning state lives in IndexedDB with schema versioning and debounced autosave; only low-risk display preferences use localStorage. Analytics counters never leave the device and are excluded from backups.

## Structure

```
index.html            App shell (hash-routed views render into it)
styles/main.css       Semantic tokens, light and dark themes, print mode
scripts/facts.js      Fact records: value, year, authority, source, review dates
scripts/articles.js   Lessons, glossary, quizzes
scripts/calculators.js Pure calculation engine and calculator definitions
scripts/storage.js    IndexedDB learning state, localStorage preferences
scripts/backup.js     Export envelope and hardened import pipeline
scripts/main.js       Router, views, components
docs/                 The fact-checked documentation package (source of truth)
tests/                Node test suites for calculators, backup, content integrity
```

## Run locally

```bash
npm run serve
```

Then open http://127.0.0.1:4180/. Any static server works; the service worker needs http(s) for offline testing.

## Test

```bash
npm test
```

Covers the calculation formulas (zero-rate branches, payment-versus-interest rejection, timing), the backup pipeline (checksum, tampering, unsafe keys, future versions, merge/replace), and content integrity (every fact token, next-lesson link, and quiz answer resolves).

## Hosted URL

https://ebruno-sec.github.io/MISC/NestEggHero2/

## Content governance

Changing figures publish only from `scripts/facts.js`, where each record carries claim, value, effective year, jurisdiction, authority status, source URL, retrieval date, reviewer, and next-review date. Facts were last reviewed 2026-07-16 against IRS and SSA primary sources; the next scheduled review is 2027-01-15.
