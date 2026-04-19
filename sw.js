self.addEventListener('install', function(event) {
    console.log('[Service Worker] Installing Service Worker ...', event);
});

self.addEventListener('activate', function(event) {
    console.log('[Service Worker] Activating Service Worker ....', event);
    return self.clients.claim();
});

self.addEventListener('fetch', function(event) {
    // Just a pass-through for Streamlit apps, allowing the Add to Home Screen prompt
    event.respondWith(fetch(event.request));
});
