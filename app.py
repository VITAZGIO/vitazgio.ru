from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Витрина сервисов vitazgio.ru">
      <title>vitazgio.ru — мои сервисы</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #0d1321;
          --surface: rgba(25, 32, 48, 0.82);
          --line: rgba(255, 255, 255, 0.1);
          --text: #f7f8fc;
          --muted: #989fb2;
        }

        * { box-sizing: border-box; }

        html { scroll-behavior: smooth; }

        body {
          margin: 0;
          min-width: 320px;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at 12% 8%, rgba(57, 126, 255, 0.24), transparent 32rem),
            radial-gradient(circle at 88% 78%, rgba(149, 65, 255, 0.2), transparent 34rem),
            var(--bg);
          color: var(--text);
        }

        body::before {
          content: "";
          position: fixed;
          inset: 0;
          pointer-events: none;
          opacity: 0.16;
          background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
          background-size: 44px 44px;
          mask-image: linear-gradient(to bottom, black, transparent 80%);
        }

        .page {
          min-height: 100svh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          padding: clamp(32px, 6vw, 76px) 0 28px;
          overflow: hidden;
        }

        .hero {
          width: min(1380px, calc(100% - 40px));
          margin: 0 auto clamp(34px, 5vw, 58px);
        }

        .eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 22px;
          color: #cdd2df;
          font-size: 0.76rem;
          font-weight: 700;
          letter-spacing: 0.16em;
          text-transform: uppercase;
        }

        .eyebrow::before {
          content: "";
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #64e6a5;
          box-shadow: 0 0 16px #64e6a5;
        }

        .sr-only {
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip: rect(0, 0, 0, 0);
          white-space: nowrap;
          border: 0;
        }

        .cyber-terminal {
          position: relative;
          min-height: 164px;
          display: flex;
          align-items: center;
          margin: 0;
          padding: 34px clamp(22px, 4vw, 54px);
          overflow: hidden;
          border: 1px solid rgba(54, 228, 255, .24);
          background: linear-gradient(110deg, rgba(12, 28, 43, .92), rgba(20, 17, 38, .82));
          clip-path: polygon(0 0, calc(100% - 25px) 0, 100% 25px, 100% 100%, 25px 100%, 0 calc(100% - 25px));
          box-shadow: inset 0 0 38px rgba(38, 211, 255, .06);
        }

        .cyber-terminal::before,
        .cyber-terminal::after {
          content: "";
          position: absolute;
          height: 2px;
          background: linear-gradient(90deg, transparent, #2de2ff, #ff3fa4, transparent);
          opacity: .72;
        }

        .cyber-terminal::before { top: 0; left: 4%; width: 42%; }
        .cyber-terminal::after { right: 5%; bottom: 0; width: 30%; }

        .terminal-prompt {
          margin-right: .35em;
          color: #ff3fa4;
          font-family: "Cascadia Code", Consolas, monospace;
          font-size: clamp(1.4rem, 5vw, 4.7rem);
          font-weight: 800;
          text-shadow: 0 0 16px rgba(255, 63, 164, .7);
        }

        .cyber-text {
          position: relative;
          display: inline-block;
          min-height: 1.1em;
          white-space: nowrap;
          color: #dffaff;
          font-family: "Cascadia Code", Consolas, "Courier New", monospace;
          font-size: clamp(1.15rem, 4.7vw, 4.4rem);
          font-weight: 800;
          letter-spacing: -.065em;
          line-height: 1;
          text-shadow: 2px 0 #ff3fa4, -2px 0 #21dcff, 0 0 20px rgba(33, 220, 255, .35);
        }

        .cyber-text::before,
        .cyber-text::after {
          content: attr(data-text);
          position: absolute;
          inset: 0;
          pointer-events: none;
          opacity: 0;
        }

        .cyber-text::before { color: #2de2ff; clip-path: inset(18% 0 57% 0); animation: glitch-top 4.2s infinite; }
        .cyber-text::after { color: #ff3fa4; clip-path: inset(62% 0 16% 0); animation: glitch-bottom 4.2s infinite; }

        .terminal-cursor {
          width: .12em;
          height: clamp(1.4rem, 4.7vw, 4.4rem);
          margin-left: .14em;
          background: #2de2ff;
          box-shadow: 0 0 14px #2de2ff;
          animation: cursor-blink .72s step-end infinite;
        }

        @keyframes cursor-blink { 50% { opacity: 0; } }
        @keyframes glitch-top {
          0%, 88%, 100% { opacity: 0; transform: translate(0); }
          89% { opacity: .9; transform: translate(5px, -1px); }
          91% { opacity: .65; transform: translate(-4px, 1px); }
          93% { opacity: 0; }
        }
        @keyframes glitch-bottom {
          0%, 91%, 100% { opacity: 0; transform: translate(0); }
          92% { opacity: .85; transform: translate(-6px, 1px); }
          94% { opacity: .6; transform: translate(3px, -1px); }
          96% { opacity: 0; }
        }

        .services-wrap {
          width: 100%;
          overflow-x: auto;
          padding: 14px max(20px, calc((100vw - 1380px) / 2)) 36px;
          scrollbar-width: thin;
          scrollbar-color: rgba(255,255,255,.22) transparent;
        }

        .services {
          display: grid;
          grid-template-columns: repeat(5, minmax(210px, 1fr));
          gap: 14px;
          min-width: 1110px;
          max-width: 1380px;
          margin: 0 auto;
        }

        .service {
          --accent: #6c8cff;
          --glow: rgba(108, 140, 255, 0.2);
          position: relative;
          isolation: isolate;
          min-height: 310px;
          display: flex;
          flex-direction: column;
          padding: 26px;
          overflow: hidden;
          color: inherit;
          text-decoration: none;
          background: linear-gradient(145deg, rgba(27, 33, 48, .9), var(--surface));
          border: 1px solid var(--line);
          border-radius: 26px;
          box-shadow: 0 20px 70px rgba(0, 0, 0, 0.25);
          transition: transform .3s ease, border-color .3s ease, box-shadow .3s ease;
        }

        .service::before {
          content: "";
          position: absolute;
          z-index: -1;
          width: 180px;
          height: 180px;
          top: -95px;
          right: -70px;
          border-radius: 50%;
          background: var(--accent);
          filter: blur(55px);
          opacity: .24;
          transition: opacity .3s ease, transform .3s ease;
        }

        .service:hover,
        .service:focus-visible {
          transform: translateY(-9px);
          border-color: color-mix(in srgb, var(--accent), white 18%);
          box-shadow: 0 28px 80px rgba(0,0,0,.4), 0 0 38px var(--glow);
          outline: none;
        }

        .service:hover::before { opacity: .42; transform: scale(1.15); }
        .service--ha { --accent: #41bdf5; --glow: rgba(65,189,245,.2); }
        .service--cloud { --accent: #1687d9; --glow: rgba(22,135,217,.22); }
        .service--jellyfin { --accent: #aa5cc3; --glow: rgba(170,92,195,.22); }
        .service--npm { --accent: #f04477; --glow: rgba(240,68,119,.2); }
        .service--mc { --accent: #7fbd58; --glow: rgba(127,189,88,.2); }

        .service-top { display: flex; align-items: flex-start; justify-content: space-between; }

        .logo {
          width: 62px;
          height: 62px;
          display: grid;
          place-items: center;
          border-radius: 18px;
          color: var(--accent);
          background: rgba(255,255,255,.055);
          border: 1px solid rgba(255,255,255,.09);
          box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
        }

        .logo svg,
        .logo img { width: 38px; height: 38px; object-fit: contain; }

        .arrow {
          width: 38px;
          height: 38px;
          display: grid;
          place-items: center;
          border-radius: 50%;
          color: #b9c0d0;
          background: rgba(255,255,255,.045);
          transition: color .25s ease, background .25s ease, transform .25s ease;
        }

        .service:hover .arrow { color: #fff; background: var(--accent); transform: rotate(45deg); }
        .arrow svg { width: 17px; }

        .service-copy { margin-top: auto; }
        .service h2 { margin: 0 0 8px; font-size: 1.42rem; letter-spacing: -.035em; }
        .service p { min-height: 44px; margin: 0 0 18px; color: var(--muted); line-height: 1.45; }
        .domain { color: var(--accent); font-size: .74rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }

        footer {
          width: min(1380px, calc(100% - 40px));
          display: flex;
          justify-content: space-between;
          gap: 20px;
          margin: auto auto 0;
          padding-top: 28px;
          color: #686f80;
          font-size: .82rem;
        }

        @media (max-width: 700px) {
          .page { justify-content: flex-start; }
          .hero { margin-bottom: 22px; }
          .cyber-terminal { min-height: 126px; padding-inline: 18px; }
          .terminal-prompt { margin-right: .2em; }
          .cyber-text { letter-spacing: -.08em; }
          .services { grid-template-columns: repeat(5, 78vw); min-width: max-content; }
          .service { min-height: 280px; scroll-snap-align: center; }
          .services-wrap { scroll-snap-type: x mandatory; }
          footer { flex-direction: column; }
        }

        @media (prefers-reduced-motion: reduce) {
          * { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
        }
      </style>
    </head>
    <body>
      <main class="page">
        <section class="hero" aria-labelledby="page-title">
          <div class="eyebrow">vitazgio.ru · мои домены</div>
          <h1 id="page-title" class="cyber-terminal" aria-label="Мои веб-сервисы, Vitazgio Network, Domain Control">
            <span class="terminal-prompt" aria-hidden="true">&gt;</span>
            <span id="cyber-text" class="cyber-text" data-text="МОИ ВЕБ-СЕРВИСЫ" aria-hidden="true">МОИ ВЕБ-СЕРВИСЫ</span>
            <span class="terminal-cursor" aria-hidden="true"></span>
          </h1>
        </section>

        <nav class="services-wrap" aria-label="Сервисы vitazgio.ru">
          <div class="services">
            <a class="service service--ha" href="https://ha.vitazgio.ru" aria-label="Открыть Home Assistant">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/home-assistant.png" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Home Assistant</h2><p>Умный дом и автоматизация</p><span class="domain">ha.vitazgio.ru</span></div>
            </a>

            <a class="service service--cloud" href="https://cloud.vitazgio.ru" aria-label="Открыть Nextcloud">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="9" stroke="currentColor" stroke-width="4"/><circle cx="7.5" cy="24" r="5.5" stroke="currentColor" stroke-width="4"/><circle cx="40.5" cy="24" r="5.5" stroke="currentColor" stroke-width="4"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Nextcloud</h2><p>Личное облачное хранилище</p><span class="domain">cloud.vitazgio.ru</span></div>
            </a>

            <a class="service service--jellyfin" href="https://jel.vitazgio.ru" aria-label="Открыть Jellyfin">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/jellyfin.svg" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Jellyfin</h2><p>Фильмы, сериалы и музыка</p><span class="domain">jel.vitazgio.ru</span></div>
            </a>

            <a class="service service--npm" href="https://npm.vitazgio.ru" aria-label="Открыть Nginx Proxy Manager">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/nginx-proxy-manager.svg" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Nginx Proxy</h2><p>Управление доменами и прокси</p><span class="domain">npm.vitazgio.ru</span></div>
            </a>

            <a class="service service--mc" href="https://mc.vitazgio.ru" aria-label="Открыть Minecraft сервер">
              <div class="service-top">
                <span class="logo" aria-hidden="true">
                  <svg viewBox="0 0 48 48" fill="none" shape-rendering="geometricPrecision">
                    <defs>
                      <linearGradient id="grass-top" x1="8" y1="9" x2="39" y2="23" gradientUnits="userSpaceOnUse"><stop stop-color="#a8db68"/><stop offset="1" stop-color="#6eae48"/></linearGradient>
                      <linearGradient id="dirt-left" x1="7" y1="17" x2="25" y2="42" gradientUnits="userSpaceOnUse"><stop stop-color="#b98253"/><stop offset="1" stop-color="#855333"/></linearGradient>
                      <linearGradient id="dirt-right" x1="24" y1="24" x2="41" y2="39" gradientUnits="userSpaceOnUse"><stop stop-color="#98623d"/><stop offset="1" stop-color="#6b4029"/></linearGradient>
                    </defs>
                    <path d="m24 5 18 9.5L24 24 6 14.5 24 5Z" fill="url(#grass-top)"/>
                    <path d="m6 14.5 18 9.5v19L6 33.5v-19Z" fill="url(#dirt-left)"/>
                    <path d="M42 14.5 24 24v19l18-9.5v-19Z" fill="url(#dirt-right)"/>
                    <path d="m6 14.5 18 9.5 18-9.5M24 24v19" stroke="#d6efa5" stroke-opacity=".42" stroke-width="1.2"/>
                    <path d="m6 14.5 18 9.5v4l-4-2.1v3.4l-4-2.1v-3.4l-4-2.1v3.4L6 22v-7.5Z" fill="#79b64d"/>
                    <path d="M42 14.5 24 24v4l4-2.1v3.4l4-2.1v-3.4l4-2.1v3.4l6-3.1v-7.5Z" fill="#659b40"/>
                    <path d="m10 27 4 2.1v4.2L10 31v-4Zm8 7.2 3 1.6v4.1l-3-1.6v-4.1Zm18-6.4 3-1.6v4.2L36 32v-4.2Zm-8 5.3 4-2.1v4.2l-4 2.1v-4.2Z" fill="#5b3523" fill-opacity=".68"/>
                  </svg>
                </span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Minecraft</h2><p>Игровой сервер для друзей</p><span class="domain">mc.vitazgio.ru</span></div>
            </a>
          </div>
        </nav>

        <footer><span>© 2026 vitazgio.ru · Основан 2:12 04.05.2026</span></footer>
      </main>
      <script>
        (() => {
          const output = document.getElementById("cyber-text");
          const phrases = ["МОИ ВЕБ-СЕРВИСЫ", "VITAZGIO NETWORK", "DOMAIN CONTROL"];
          const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
          const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
          const render = (text) => {
            output.textContent = text;
            output.dataset.text = text;
          };

          if (reduceMotion) {
            render(phrases[0]);
            return;
          }

          const runTerminal = async () => {
            let phraseIndex = 0;
            while (true) {
              const phrase = phrases[phraseIndex];
              render("");
              for (let index = 1; index <= phrase.length; index += 1) {
                render(phrase.slice(0, index));
                await wait(78);
              }
              await wait(1450);
              for (let index = phrase.length - 1; index >= 0; index -= 1) {
                render(phrase.slice(0, index));
                await wait(42);
              }
              await wait(260);
              phraseIndex = (phraseIndex + 1) % phrases.length;
            }
          };

          runTerminal();
        })();
      </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
