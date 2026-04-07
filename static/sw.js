const CACHE_NAME = 'fitness-app-cache-v9';

// Only pre-cache assets that don't require authentication
const STATIC_ASSETS = [
  '/',
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

  // Skip sync endpoints
  if (url.pathname === '/sync' || url.pathname === '/sync_weights') return;

  if (event.request.mode === 'navigate') {
    // Navigation: network first, fallback to cache, then offline page
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Only cache successful (200) responses, NOT redirects (302)
          // Respect Cache-Control: no-store (auth pages)
          const cacheControl = response.headers.get('Cache-Control') || '';
          if (response.ok && !response.redirected && !cacheControl.includes('no-store')) {
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

// Clear authenticated pages from cache on logout
const STATIC_PATHS = new Set(STATIC_ASSETS.map(u => new URL(u, self.location.origin).pathname));

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'CLEAR_AUTH_CACHE') {
    event.waitUntil(
      caches.open(CACHE_NAME).then(cache => {
        return cache.keys().then(requests => {
          return Promise.all(
            requests.filter(req => {
              const path = new URL(req.url).pathname;
              // Keep only static assets, remove all cached pages
              return !path.startsWith('/static/') && path !== '/';
            }).map(req => cache.delete(req))
          );
        });
      })
    );
  }
});

// ============================================================
// Background Sync
// ============================================================

const DB_NAME = 'FitnessAppOffline';
const DB_VERSION = 1;

function openOfflineDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('offlineSessions')) {
        db.createObjectStore('offlineSessions', { keyPath: 'uuid' });
      }
      if (!db.objectStoreNames.contains('offlineWeights')) {
        db.createObjectStore('offlineWeights', { keyPath: 'uuid' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function getAllFromStore(storeName) {
  return openOfflineDB().then(db => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readonly');
      const req = tx.objectStore(storeName).getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  });
}

function deleteFromStore(storeName, uuids) {
  return openOfflineDB().then(db => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      uuids.forEach(uuid => store.delete(uuid));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  });
}

function doBackgroundSync(storeName, endpoint, payloadKey) {
  return getAllFromStore(storeName).then(entries => {
    if (!entries || entries.length === 0) return;
    return fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({ [payloadKey]: entries })
    })
    .then(r => r.json())
    .then(data => {
      if (data.status === 'success') {
        const uuids = data.synced_uuids || entries.map(e => e.uuid);
        return deleteFromStore(storeName, uuids);
      }
    });
  });
}

self.addEventListener('sync', event => {
  if (event.tag === 'sync-sessions') {
    event.waitUntil(doBackgroundSync('offlineSessions', '/sync', 'sessions'));
  }
  if (event.tag === 'sync-weights') {
    event.waitUntil(doBackgroundSync('offlineWeights', '/sync_weights', 'weights'));
  }
});
