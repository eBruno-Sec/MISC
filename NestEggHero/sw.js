const CACHE_NAME = "nestegghero-v1.0.0";
const ASSETS = [
  "./",
  "./index.html",
  "./styles/main.css",
  "./scripts/app.js",
  "./scripts/facts.js",
  "./scripts/content.js",
  "./scripts/calculators.js",
  "./scripts/storage.js",
  "./scripts/backup.js",
  "./images/mark.svg",
  "./manifest.webmanifest",
  "./robots.txt",
  "./sitemap.xml"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))));
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith(caches.match(request).then((cached) => cached || fetch(request).then((response) => {
    if (response.ok) caches.open(CACHE_NAME).then((cache) => cache.put(request, response.clone()));
    return response;
  }).catch(() => caches.match("./index.html"))));
});
