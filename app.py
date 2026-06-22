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
      <title>vitazgio.ru — витрина доменов</title>
      <style>
        body {
          margin: 0;
          font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: radial-gradient(circle at top, #1a1f33 0%, #0b0d14 45%);
          color: #f5f7ff;
        }
        .page {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 32px 16px;
          text-align: center;
        }
        .badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          font-size: 0.9rem;
          letter-spacing: 0.03em;
          padding: 0.65rem 1rem;
          border-radius: 999px;
          background: rgba(255,255,255,0.08);
          border: 1px solid rgba(255,255,255,0.12);
          margin-bottom: 1rem;
        }
        h1 {
          margin: 0;
          font-size: clamp(2.2rem, 4vw, 4rem);
          line-height: 1.05;
        }
        .intro {
          max-width: 620px;
          margin: 1rem auto 2rem;
          color: #d7dbf0;
          font-size: 1rem;
          line-height: 1.7;
        }
        .cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 18px;
          width: min(100%, 960px);
          margin-top: 1rem;
        }
        .card {
          background: rgba(18, 24, 48, 0.82);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 20px;
          padding: 24px;
          text-decoration: none;
          color: inherit;
          transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
          box-shadow: 0 18px 60px rgba(4, 10, 30, 0.25);
        }
        .card:hover,
        .card:focus-visible {
          transform: translateY(-6px);
          border-color: rgba(96, 165, 250, 0.35);
          box-shadow: 0 24px 70px rgba(4, 10, 30, 0.35);
        }
        .card-title {
          margin: 0 0 10px;
          font-size: 1.25rem;
          letter-spacing: -0.03em;
        }
        .card-subtitle {
          margin: 0;
          color: #a8b0d4;
          line-height: 1.6;
        }
        .footer {
          margin-top: 2.5rem;
          color: #8f98b5;
          font-size: 0.95rem;
        }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="badge">vitazgio.ru — витрина ваших поддоменов</div>
        <h1>Добро пожаловать на витрину доменов</h1>
        <p class="intro">Здесь собраны быстрые ссылки на ваши сервисы. Нажмите на карточку, чтобы перейти на нужный поддомен.</p>
        <div class="cards">
          <a class="card" href="https://ha.vitazgio.ru" target="_blank" rel="noopener noreferrer">
            <h2 class="card-title">ha.vitazgio.ru</h2>
            <p class="card-subtitle">Home Assistant — умный дом и автоматика.</p>
          </a>
          <a class="card" href="https://cloud.vitazgio.ru" target="_blank" rel="noopener noreferrer">
            <h2 class="card-title">cloud.vitazgio.ru</h2>
            <p class="card-subtitle">Nextcloud — личное облачное хранилище.</p>
          </a>
          <a class="card" href="https://jel.vitazgio.ru" target="_blank" rel="noopener noreferrer">
            <h2 class="card-title">jel.vitazgio.ru</h2>
            <p class="card-subtitle">Jellyfin — мультимедийный сервер.</p>
          </a>
          <a class="card" href="https://npm.vitazgio.ru" target="_blank" rel="noopener noreferrer">
            <h2 class="card-title">npm.vitazgio.ru</h2>
            <p class="card-subtitle">NPM — панель управления пакетами и прокси.</p>
          </a>
          <a class="card" href="https://mc.vitazgio.ru" target="_blank" rel="noopener noreferrer">
            <h2 class="card-title">mc.vitazgio.ru</h2>
            <p class="card-subtitle">Minecraft — сервер для игры и друзей.</p>
          </a>
        </div>
        <div class="footer">P.S. Основан 2:12 04.05.2026. Сделано для быстрой навигации по вашим сервисам.</div>
      </main>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
