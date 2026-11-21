self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    if (self.registration.navigationPreload) await self.registration.navigationPreload.enable();
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate" || new URL(event.request.url).pathname.startsWith("/ui/oidc/")) return;
  event.respondWith((async () => {
    try {
      return (await event.preloadResponse) || (await fetch(event.request));
    } catch {
      return offline();
    }
  })());
});

function offline() {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Offline · gh-appauth</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px 16px; box-sizing: border-box;
  font: 14px/1.5 Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: Canvas; color: CanvasText; text-align: center; }
h1 { font-size: 20px; font-weight: 600; margin: 0 0 6px; }
p { margin: 0 0 20px; opacity: .7; }
button { padding: 8px 14px; border: 0; border-radius: 7px; background: CanvasText; color: Canvas; font: inherit; font-weight: 500; cursor: pointer; }
</style></head>
<body><main><h1>Can't reach the broker</h1><p>Check your connection or SSH tunnel, then try again.</p><button onclick="location.reload()">Retry</button></main></body></html>`;
  return new Response(html, {
    status: 503,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}
