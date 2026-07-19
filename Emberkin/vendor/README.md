# vendor/

`three.module.js` — Three.js **r161**, MIT licensed, © 2010–2023 Three.js Authors.

Vendored deliberately. It was previously loaded from `cdn.jsdelivr.net`, which
meant GitHub Pages could serve the game perfectly and it would still fail to
start if that CDN was unreachable. This is the project's only third-party
dependency, so a local copy makes the game fully self-contained and playable
offline.

To update: download the matching build and repoint the import maps in
`play/index.html` and `studio/index.html` (both use `../vendor/three.module.js`).
Keep the version in sync across both.
