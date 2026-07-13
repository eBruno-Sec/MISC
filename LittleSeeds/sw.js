// Little Seeds Service Worker
// Caches the app shell and the 3 free stories for offline reading.
// Premium stories (Day4–Day20) are network-only — they require auth anyway.

const CACHE = 'little-seeds-v1';

const PRECACHE = [
  './',
  './index.html',
  './styles.css',
  './manifest.json',
  './icon.svg',
  './Story/nav.js',
  './Story/Day1.html',
  './Story/Day2.html',
  './Story/Day3.html',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  // Only intercept same-origin GETs
  if (request.method !== 'GET' || url.origin !== location.origin) return;

  // Google Fonts — let fall through (network only, no caching complexity)
  if (url.hostname.includes('googleapis') || url.hostname.includes('gstatic')) return;

  // Premium story pages — network only (gate runs client-side via nav.js)
  const dayMatch = url.pathname.match(/Day(\d+)\.html$/i);
  if (dayMatch && parseInt(dayMatch[1]) > 3) return;

  // Cache-first for everything else in our scope
  e.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached;
      return fetch(request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE).then(c => c.put(request, clone));
        }
        return response;
      });
    })
  );
});
