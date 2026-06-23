# vitazgio.ru

Лендинг-витрина моих самохостед-сервисов + скрытый личный кабинет.

## Что это технически

- **Flask-приложение в один файл** — [app.py](app.py). Весь HTML/CSS/JS лежит inline прямо в python-строках (никаких шаблонов/templates, никакого фронтенд-билда). Статика (логотипы) — в [static/](static/).
- **Главная страница `/`** — публичная витрина с карточками-ссылками на сервисы: Home Assistant (ha.), Nextcloud (cloud.), Jellyfin (jel.), Nginx Proxy Manager (npm.), Minecraft (mc.) — все на поддоменах vitazgio.ru.
- **Скрытый вход в кабинет** — невидимая кнопка в правом нижнем углу главной страницы открывает модалку с паролем.
- **`/api/login`** — проверка пароля (PBKDF2-HMAC-SHA256, соль и хэш захардкожены в app.py), rate-limit 5 попыток / 5 минут на IP, кладёт флаг в Flask-сессию (cookie, HttpOnly).
- **`/cabinet`** (защищён `login_required`) — личный кабинет. Внутри — раскрывающийся список устройств **NetBird VPN** (это и есть скриншот, который ты прислал): имя устройства, его IP в mesh-сети, кнопка копирования IP и **онлайн/офлайн статус + пинг в мс**. Список устройств задаётся в `NETBIRD_DEVICES` в [app.py](app.py) (не тянется из NetBird API — это просто статичный список IP/имён).
- **Живой статус устройств**: фоновый поток `netbird_ping_loop` в app.py пингует каждый IP из `NETBIRD_DEVICES` раз в 10 секунд (системной командой `ping`, кроссплатформенно — есть ветка под Windows и под Linux) и кладёт результат (online + latency_ms) в `netbird_status`. Эндпоинт `GET /api/netbird/status` отдаёт это в JSON, страница `/cabinet` опрашивает его раз в 10 секунд и красит точку зелёным/красным.
- Нет базы данных, нет ORM, нет внешних API-вызовов (кроме локального `ping`) — всё в памяти процесса.

## Деплой

- [Dockerfile](Dockerfile) + [docker-compose.yml](docker-compose.yml) — `python:3.11-slim` + `iputils-ping` (нужен для пингов), ставит `requirements.txt` (там только `flask`), запускает `python app.py` на порту 5000.
- **Контейнер работает в `network_mode: host`** — это специально, иначе он не видит NetBird-интерфейс хоста и не может пинговать адреса 100.104.x.x. Из-за этого секция `ports` в docker-compose.yml не нужна (порт 5000 публикуется напрямую через сеть хоста).
- [.github/workflows/deploy.yml](.github/workflows/deploy.yml) — на пуш в `main` self-hosted runner делает `git fetch && git reset --hard origin/main` в `/opt/sites/vitazgio.ru` и `docker compose restart web`.

### Команды для ручного деплоя

```
cd C:\TRASH\NextCloud\Сервер\Programs\vitazgio.ru
git add .; git commit -m "..."; git push
```

Если упало на сервере:

```
cd /opt/sites/vitazgio.ru
git fetch origin
git reset --hard origin/main
docker compose up -d --build
docker logs vitazgio-site
```

## На что обратить внимание при правках

- Пароль захардкожен (PBKDF2-хэш) в [app.py](app.py). Список NetBird-устройств — в `NETBIRD_DEVICES` там же; при добавлении/смене устройства правится только этот список (HTML и API строятся из него автоматически), но счётчик "N устройств" в шапке кабинета остаётся текстом, который нужно поправить руками отдельно.
- `SESSION_COOKIE_SECURE` включается через env `SESSION_COOKIE_SECURE=true` (на проде за HTTPS должен быть `true`).
- Так как контейнер развёрнут в `network_mode: host`, он шарит сеть хоста полностью (меньше изоляции) — осознанный компромисс ради доступа к NetBird mesh.
