const CACHE_NAME = 'fitness-app-cache-v2';
const STATIC_ASSETS = [
  '/fit',
  '/static/manifest.json',
  '/static/js/main.js',
  '/static/offline.html'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
});

self.addEventListener('fetch', event => {
  if (event.request.mode === 'navigate') {
    event.respondWith(
      Promise.race([
        fetch(event.request)
          .then(response => {
            const respClone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, respClone));
            return response;
          })
          .catch(() => caches.match(event.request)),
        new Promise(resolve =>
          setTimeout(() => resolve(caches.match(event.request)), 3000)
        )
      ]).then(resp => resp || caches.match('/static/offline.html'))
    );
  } else {
    event.respondWith(
      caches.match(event.request).then(cachedResponse => {
        return (
          cachedResponse ||
          fetch(event.request).catch(() => caches.match('/static/offline.html'))
        );
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
    })
  );
});
