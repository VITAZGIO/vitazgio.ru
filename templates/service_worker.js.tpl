
        // Версию поднимаем при КАЖДОЙ правке offline.html. Страница лежит в
        // кэше, и перекладывается она только при установке нового воркера —
        // а он считается новым, лишь когда меняется сам этот файл. Без смены
        // версии на телефоне так и осталась бы старая лиса.
        const CACHE = "vitazgio-offline-v2";
        const OFFLINE = "/static/offline.html";

        self.addEventListener("install", event => {
          event.waitUntil(
            caches.open(CACHE).then(c => c.add(new Request(OFFLINE, { cache: "reload" })))
                  .catch(() => {})
          );
          self.skipWaiting();
        });

        self.addEventListener("activate", event => {
          event.waitUntil((async () => {
            const names = await caches.keys();
            await Promise.all(names.map(n => {
              if (n !== CACHE && n !== "share-inbox") return caches.delete(n);
            }));
            await self.clients.claim();
          })());
        });

        self.addEventListener("fetch", event => {
          const url = new URL(event.request.url);

          // Переходы по страницам: всегда идём в сеть, а без неё показываем лису.
          if (event.request.mode === "navigate" && event.request.method === "GET") {
            event.respondWith((async () => {
              try {
                return await fetch(event.request);
              } catch (e) {
                const cached = await caches.match(OFFLINE);
                return cached || new Response("Нет связи", { status: 503 });
              }
            })());
            return;
          }

          if (event.request.method !== "POST" || url.pathname !== "/share-target") return;

          event.respondWith((async () => {
            try {
              const form = await event.request.formData();
              const cache = await caches.open("share-inbox");
              const files = form.getAll("files").filter(f => f && f.size);
              let index = 0;
              for (const file of files) {
                await cache.put(
                  new Request("/__shared/" + (index++) + "?t=" + Date.now()),
                  new Response(file, { headers: {
                    "X-Name": encodeURIComponent(file.name || "файл"),
                    "X-Type": file.type || "application/octet-stream",
                  }})
                );
              }
              const text = [form.get("title"), form.get("text"), form.get("url")]
                .filter(Boolean).join("\n").trim();
              if (text) {
                await cache.put(new Request("/__shared-text?t=" + Date.now()),
                                new Response(text));
              }
            } catch (e) {}
            return Response.redirect("/drop?shared=1", 303);
          })());
        });
        