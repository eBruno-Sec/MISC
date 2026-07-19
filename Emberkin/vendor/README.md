# vendor/

`three.module.js` — Three.js **r161**, MIT licensed, © 2010–2023 Three.js Authors.

Vendored deliberately. It was previously loaded from `cdn.jsdelivr.net`, which
meant GitHub Pages could serve the game perfectly and it would still fail to
start if that CDN was unreachable. A local copy makes the game fully
self-contained and playable offline.

To update: download the matching build and repoint the import maps in
`play/index.html` and `studio/index.html` (both use `../vendor/three.module.js`).
Keep the version in sync across both.

## fonts/

The webfonts are vendored too, so there are now **zero external runtime
requests**. Nothing loads from `fonts.googleapis.com`. Files are the **latin
subset** woff2 pulled from Google Fonts (Open Font License):

- `baloo2-{500,600,700,800}.woff2`: Baloo 2 (display font: game + Studio)
- `nunito-{400,600,700,800}.woff2`: Nunito (body font, everywhere)
- `spacegrotesk-{500,700}.woff2`: Space Grotesk (display font: docs + hub;
  700 is the family's heaviest weight, so `font-weight:800` maps to it)

Each page declares these with `@font-face` rules (see `play/style.css` and the
inline `<style>` in `studio/`, `docs/`, and `index.html`). To add a weight or
subset, fetch the matching woff2 from Google Fonts and add an `@font-face` rule
next to the others. `.gitattributes` already marks `vendor/**` as binary.
