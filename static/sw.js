const CACHE_NAME = 'fitness-app-cache-v6';

// Only pre-cache assets that don't require authentication
const STATIC_ASSETS = [
  '/fit',
  '/static/manifest.json',
  '/static/js/main.js',
  '/static/offline.html'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return Promise.allSettled(
        STATIC_ASSETS.map(url =>
          cache.add(url).catch(err => console.warn('SW: failed to cache', url, err))
        )
      );
    })
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET requests (POST login, sync, etc.)
  if (event.request.method !== 'GET') return;

  // Skip API/sync requests
  if (url.pathname === '/sync') return;

  if (event.request.mode === 'navigate') {
    // Navigation: network first, fallback to cache, then offline page
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Only cache successful (200) responses, NOT redirects (302)
          if (response.ok && !response.redirected) {
            const respClone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, respClone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(event.request)
            .then(cached => cached || caches.match('/static/offline.html'));
        })
    );
  } else {
    // Static assets: cache first, then network
    event.respondWith(
      caches.match(event.request).then(cachedResponse => {
        if (cachedResponse) return cachedResponse;
        return fetch(event.request).then(response => {
          if (response.ok) {
            const respClone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, respClone));
          }
          return response;
        }).catch(() => {
          return new Response('', { status: 408 });
        });
      })
    );
  }
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(name => name !== CACHE_NAME)
                  .map(name => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});
