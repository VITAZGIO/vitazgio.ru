# vitazgio.ru

Лендинг-витрина моих самохостед-сервисов + скрытый личный кабинет.

## Что это технически

- **Flask-приложение в один файл** — [app.py](app.py). Весь HTML/CSS/JS лежит inline прямо в python-строках (никаких шаблонов/templates, никакого фронтенд-билда). Статика (логотипы) — в [static/](static/).
- **Главная страница `/`** — публичная витрина с карточками-ссылками на сервисы: Home Assistant (ha.), Nextcloud (cloud.), Jellyfin (jel.), Nginx Proxy Manager (npm.), Minecraft (mc.) — все на поддоменах vitazgio.ru.
- **Скрытый вход в кабинет** — невидимая кнопка в правом нижнем углу главной страницы открывает модалку с паролем.
- **`/api/login`** — проверка пароля (PBKDF2-HMAC-SHA256, соль и хэш захардкожены в app.py), rate-limit 5 попыток / 5 минут на IP, кладёт флаг в Flask-сессию (cookie, HttpOnly).
- **`/cabinet`** (защищён `login_required`) — личный кабинет. Внутри — раскрывающийся список устройств **NetBird VPN** (это и есть скриншот, который ты прислал): имя устройства, его IP в mesh-сети, кнопка копирования IP и **онлайн/офлайн статус + пинг в мс**. Список устройств задаётся в `NETBIRD_DEVICES` в [app.py](app.py) (не тянется из NetBird API — это просто статичный список IP/имён).
- **Живой статус устройств**: фоновый поток `netbird_ping_loop` в app.py пингует каждый IP из `NETBIRD_DEVICES` раз в 10 секунд (системной командой `ping`, кроссплатформенно — есть ветка под Windows и под Linux) и кладёт результат (online + latency_ms) в `netbird_status`. Эндпоинт `GET /api/netbird/status` отдаёт это в JSON, страница `/cabinet` опрашивает его раз в 10 секунд и красит точку зелёным/красным.
- **Веб-SSH-консоль**: у устройств с `"ssh_enabled": True` в `NETBIRD_DEVICES` (сейчас — orangepizero3, ubuntu-server, ubuntuvitaz1) в кабинете есть кнопка «Подключиться». Сервер сам ходит по SSH на эти машины через NetBird и стримит терминал в браузер через `xterm.js` + websocket (`flask-sock`, роут `/ws/console/<ip>`). **Логин/пароль для SSH не хранятся нигде** — при каждом подключении в браузере спрашивается имя пользователя и пароль заново, они уходят первым сообщением по уже открытому websocket и сразу используются для `paramiko`-коннекта (`look_for_keys=False`, `allow_agent=False` — только пароль, никаких ключей). Перед этим один раз за сессию спрашивается **второй пароль** поверх обычного входа в кабинет: `SSH_GATE_PASSWORD_PREFIX` (секрет из env) + день и месяц сегодняшней даты (`ДДММ` по Москве), пересчитывается каждую полночь — см. `console_password_today()` в app.py. Без 2FA, но с тем же rate-limit'ом (5 попыток/5 мин), что и у основного логина.
- Нет базы данных, нет ORM, нет внешних API-вызовов (кроме локального `ping` и SSH к своим же устройствам) — всё в памяти процесса.

## Деплой

- [Dockerfile](Dockerfile) + [docker-compose.yml](docker-compose.yml) — `python:3.11-slim` + `iputils-ping` (пинги) + `tzdata` (нужен для часового пояса Europe/Moscow в формуле пароля консоли), ставит `requirements.txt` (`flask`, `flask-sock`, `paramiko`), запускает `python app.py` на порту 5000.
- **`SSH_GATE_PASSWORD_PREFIX`** прокидывается в контейнер из `.env`-файла рядом с `docker-compose.yml` на сервере (`/opt/sites/vitazgio.ru/.env`, в git не попадает — см. `.gitignore`). Без этой переменной кнопка «Подключиться» работает, но `/api/console/login` отвечает 503 (фича выключена).
- **Контейнер работает в `network_mode: host`** — это специально, иначе он не видит NetBird-интерфейс хоста и не может пинговать адреса 100.104.x.x. Из-за этого секция `ports` в docker-compose.yml не нужна (порт 5000 публикуется напрямую через сеть хоста).
- [.github/workflows/deploy.yml](.github/workflows/deploy.yml) — на пуш в `main` self-hosted runner делает `git fetch && git reset --hard origin/main` в `/opt/sites/vitazgio.ru` и `docker compose up -d --build` (важно: именно `up -d --build`, а не `restart` — `restart` не пересобирает образ и не применяет изменения `docker-compose.yml`/`Dockerfile`, из-за этого один раз уже не подтянулись `network_mode: host` и `ping`).

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
- **`VITAZGIO_SESSION_SECRET` обязательно задать в `.env` на сервере.** Если его нет, `SECRET_KEY` Flask генерируется случайно при каждом старте процесса — а значит **любой передеплой/рестарт контейнера мгновенно разлогинивает всех**: страница кабинета остаётся открытой в браузере (она уже отрисована), но любой следующий запрос к серверу получает редирект на `/`, и фронтенд вместо понятной причины показывает "Сервер недоступен". Сгенерировать значение разово: `python3 -c "import secrets; print(secrets.token_hex(32))"`.
- Так как контейнер развёрнут в `network_mode: host`, он шарит сеть хоста полностью (меньше изоляции) — осознанный компромисс ради доступа к NetBird mesh.
- **Настройка после первого деплоя с SSH-консолью** — создать на сервере `/opt/sites/vitazgio.ru/.env` с двумя строками: `VITAZGIO_SESSION_SECRET=<случайная строка>` и `SSH_GATE_PASSWORD_PREFIX=<свой секрет>` (файл не коммитится), затем пересоздать контейнер (`docker compose up -d --build`). Логин/пароль к самим устройствам никуда заранее прописывать не нужно — их спрашивают в браузере при каждом подключении.
