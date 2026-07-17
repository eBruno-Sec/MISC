// Offline support. Network first so facts stay current when online; the
// versioned cache answers when the network is gone. Bumping VERSION retires
// every older cache on activate, which also recovers from corrupted caches.

const VERSION = "nestegghero2-v1.0.0";
const CORE = [
  "./",
  "index.html",
  "styles/main.css",
  "scripts/main.js",
  "scripts/articles.js",
  "scripts/calculators.js",
  "scripts/facts.js",
  "scripts/storage.js",
  "scripts/backup.js",
  "images/egg.svg",
  "manifest.webmanifest"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((cache) => cache.addAll(CORE)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== VERSION).map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) {
    return;
  }
  event.respondWith((async () => {
    try {
      const fresh = await fetch(request);
      if (fresh.ok) {
        const cache = await caches.open(VERSION);
        cache.put(request, fresh.clone());
      }
      return fresh;
    } catch {
      const cached = await caches.match(request, { ignoreSearch: true });
      if (cached) {
        return cached;
      }
      const shell = await caches.match("index.html");
      if (shell) {
        return shell;
      }
      return new Response("Offline and not cached yet.", { status: 503, headers: { "Content-Type": "text/plain" } });
    }
  })());
});
