// Find My Expense service worker: makes the app installable and loads instantly / offline.
const VERSION = 'fme-v11';
const SHELL = ['/', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png', '/icons/apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Never cache account / OTP calls
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return;

  // Pages: always try the network first so updates appear immediately; fall back to cache offline
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).then(res => { caches.open(VERSION).then(c => c.put('/', res.clone())); return res; })
      .catch(() => caches.match('/')));
    return;
  }

  // Own static files and Google Fonts: serve from cache, refresh in the background
  if (url.origin === location.origin || /fonts\.(googleapis|gstatic)\.com$/.test(url.hostname)) {
    e.respondWith(caches.open(VERSION).then(async c => {
      const hit = await c.match(req);
      const net = fetch(req).then(res => { if (res.ok || res.type === 'opaque') c.put(req, res.clone()); return res; }).catch(() => hit);
      return hit || net;
    }));
  }
});
