// sw.js - Service Worker قوي للكاش الكامل
const CACHE_NAME = 'ps4-exploit-v1';
const urlsToCache = [
    '/',
    '/index.html',
    '/run_lapse.html',
    '/run_poops.html',
    '/chain_lapse.js',
    '/chain_poops.js',
    '/core.js',
    '/mem.js',
    '/int64.js',
    '/ps4_offsets.js',
    '/rpc_worker.js',
    '/logo_raw.png',
    '/payload.bin',
    '/patches/1100.bin',
    '/patches/1150.bin',
    '/patches/1200.bin',
    '/patches/1250.bin',
    '/patches/1300.bin',
    '/core.js?v=10'
];

// تثبيت Service Worker
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Caching files...');
                return cache.addAll(urlsToCache);
            })
            .then(() => self.skipWaiting())
    );
});

// تفعيل Service Worker
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// اعتراض جميع الطلبات
self.addEventListener('fetch', event => {
    // لا نعترض POST requests
    if (event.request.method !== 'GET') return;

    // استراتيجية Cache First ثم Network
    event.respondWith(
        caches.match(event.request)
            .then(cachedResponse => {
                // إذا وجد في الكاش، أرجعه فوراً
                if (cachedResponse) {
                    return cachedResponse;
                }

                // إذا لم يوجد في الكاش، اطلب من الشبكة
                return fetch(event.request)
                    .then(response => {
                        // لا نحفظ الطلبات غير الناجحة
                        if (!response || response.status !== 200) {
                            return response;
                        }

                        // نسخ الاستجابة للحفظ
                        const responseToCache = response.clone();

                        caches.open(CACHE_NAME)
                            .then(cache => {
                                cache.put(event.request, responseToCache);
                            });

                        return response;
                    })
                    .catch(() => {
                        // إذا فشل الاتصال بالشبكة، أعرض صفحة الأوفلاين
                        return caches.match('/index.html');
                    });
            })
    );
});