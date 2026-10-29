/* ZenLens service worker: caches the app shell only. API calls and their data are never cached.
 *
 * Web Share Target ("Redact before you share"): Android Chrome POSTs a shared image to /share-target.
 * We take it here, park it in a private Cache Storage inbox under a random id (on-device only, never
 * sent anywhere) and redirect to /share.html?id=..., which reads it, deletes it straight away and sends
 * it only to this server's /api/redact_image. Shared text/title are ignored on purpose.
 */
const CACHE = 'zenlens-shell-v2';
const INBOX = 'zenlens-share-inbox';
const SHELL = ['/', '/index.html', '/app.css', '/app.js', '/manifest.webmanifest',
  '/share.html', '/share.css', '/share.js',
  '/icons/icon.svg', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  // Drops old shells and any share-inbox leftovers (an inbox entry must never outlive its page).
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

const go = path => Response.redirect(new URL(path, self.location.origin).href, 303);

async function receiveShare(request) {
  try {
    const form = await request.formData();
    const files = form.getAll('image').filter(f => f && typeof f === 'object' && f.size > 0
      && (!f.type || f.type.startsWith('image/')));
    if (!files.length) return go('/share.html?error=nofile');
    const id = self.crypto.randomUUID ? self.crypto.randomUUID()
      : Array.from(self.crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    const inbox = await caches.open(INBOX);
    for (const k of await inbox.keys()) await inbox.delete(k);  // one share at a time; no backlog of originals
    await inbox.put(`/__share-inbox/${id}`, new Response(files[0], { headers: {
      'Content-Type': files[0].type || 'application/octet-stream', 'X-Share-Count': String(files.length),
      'X-Stashed-At': String(Date.now()) } }));
    return go(`/share.html?id=${id}`);
  } catch {
    return go('/share.html?error=read');
  }
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  if (e.request.method === 'POST' && url.pathname === '/share-target') {
    e.respondWith(receiveShare(e.request));
    return;
  }
  if (e.request.method !== 'GET' || url.pathname.startsWith('/api/')) return;
  if (!SHELL.includes(url.pathname)) return;
  // Network first so updates land immediately; fall back to the cached shell when offline.
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(url.pathname, copy)); }
    return r;
  }).catch(() => caches.match(url.pathname).then(r => r || caches.match('/index.html'))));
});
