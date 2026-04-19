const CACHE_NAME = 'aegis-portal-v1';
const STATIC_ASSETS = [
    '/',
    '/index.html',
];

// Install event - cache essential files
self.addEventListener('install', function(event) {
    console.log('[Service Worker] Installing Service Worker...', event);
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('[Service Worker] Caching app shell');
                return cache.addAll(STATIC_ASSETS);
            })
            .catch(function(err) {
                console.log('[Service Worker] Cache failed:', err);
            })
    );
    self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', function(event) {
    console.log('[Service Worker] Activating Service Worker...', event);
    event.waitUntil(
        caches.keys().then(function(keyList) {
            return Promise.all(keyList.map(function(key) {
                if (key !== CACHE_NAME) {
                    console.log('[Service Worker] Removing old cache:', key);
                    return caches.delete(key);
                }
            }));
        })
    );
    return self.clients.claim();
});

// Fetch event - network first, fallback to cache
self.addEventListener('fetch', function(event) {
    // Skip non-GET requests
    if (event.request.method !== 'GET') {
        return;
    }

    event.respondWith(
        fetch(event.request)
            .then(function(response) {
                // Clone the response before caching
                const responseToCache = response.clone();
                caches.open(CACHE_NAME)
                    .then(function(cache) {
                        cache.put(event.request, responseToCache);
                    });
                return response;
            })
            .catch(function() {
                // Network failed, try cache
                return caches.match(event.request);
            })
    );
});
