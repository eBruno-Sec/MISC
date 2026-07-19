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
inline `<style>` in `studio/`, `docs/`, and `index.html`). `.gitattributes`
already marks `vendor/**` as binary.

### Fetching these correctly (read before adding a weight)

Google's modern `css2` endpoint serves a **variable** font: it returns the same
file URL for every weight you ask for. Naively saving that response per weight
gives you N byte-identical copies, and the weights then collapse — the first
pass here shipped Nunito 600/700/800 all rendering identically at 728.91px, so
"bold" body text was not bold.

Request with a User-Agent that predates variable-font support and Google serves
genuine per-weight static files instead. Chrome 50 works and still gets woff2:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36
```

Pick the `@font-face` block whose `unicode-range` contains `U+0000-00FF` (that
is the plain latin subset; latin-ext does not cover it).

**Always verify after adding a weight** — checksum the files to confirm they
differ, then measure rendered width per weight in the browser and check the
numbers increase monotonically. Identical widths mean the weights collapsed.
