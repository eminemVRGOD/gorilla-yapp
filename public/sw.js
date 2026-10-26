// Gorilla Yapps app shell: lets the site install like an app, open on a flaky connection,
// and show notifications for DMs and pings even when it's closed.
const CACHE = "gy-shell-v2";
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(["/", "/icon-192.png"])).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin || new URL(req.url).pathname.startsWith("/api/")) return;
  if (req.mode === "navigate") {
    // always try the newest page first, fall back to the saved copy
    e.respondWith(fetch(req).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put("/", copy)); return r; }).catch(() => caches.match("/")));
  }
});
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { title: "Gorilla Yapps", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    // you're looking at Gorilla Yapps right now: the app already shows it
    if (list.some(c => c.focused && c.visibilityState === "visible")) return;
    return self.registration.showNotification(String(d.title || "Gorilla Yapps").slice(0, 80), {
      body: String(d.body || "").slice(0, 200), tag: String(d.tag || "gy"), renotify: true,
      icon: "/icon-192.png", badge: "/icon-192.png", data: { url: typeof d.url === "string" && d.url.startsWith("/") ? d.url : "/", k: d.tag || "" }
    });
  }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const data = e.notification.data || {}, url = new URL(data.url || "/", self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    const c = list.find(x => new URL(x.url).origin === self.location.origin);
    if (c) { c.postMessage({ type: "go", k: data.k }); return c.focus(); }
    return self.clients.openWindow(url);
  }));
});
