# AI_MAP

Этот проект должен быть удобен прежде всего для Codex/Claude: правки должны
требовать чтения минимума файлов, новые фичи должны добавляться по одному
предсказуемому шаблону, а важные правила должны быть видны до погружения в код.

## Главная цель

Держать проект как AI-first modular monolith:

- один репозиторий;
- один Flask-сервер и один деплой;
- фичи изолированы по смыслу;
- новые разделы не раздувают `app.py`;
- нейросеть быстро находит нужный модуль, читает его карту и правит локально.

## Перед любой правкой

1. Прочитать `README.md`, если нужна общая картина.
2. Прочитать `CLAUDE.md`, если правка касается деплоя, инфраструктуры,
   исторических решений или ловушек.
3. Прочитать этот файл.
4. Найти фичу ниже и открыть только её файлы.
5. Если меняются маршруты, обновить `docs/routes-inventory.md`.
6. Если меняется JS в шаблонах, помнить ловушку: в python-строках `\n`
   превращается в реальный перенос, в шаблонах нужен `\\n`.

## Куда смотреть

### Вход и общая сборка

- `app.py` — создание Flask app, глобальные настройки, регистрация blueprints,
  старые общие хранилища и функции.
- `blueprints/` — серверные модули страниц/API.
- `templates/` — HTML/CSS/JS страниц.
- `static/` — статика, игры, иконки, vendor JS/CSS.
- `tests/` — pytest-покрытие сайта.

### Главная, кабинет, серверы, темы

- `blueprints/home.py`
- `templates/home.html`
- `templates/cabinet.html`
- `templates/themes.html`
- `templates/servers_unlock.html`
- тесты: `tests/test_servers.py`, `tests/test_auth.py`

### Дроп и публичные ссылки

- `blueprints/drop.py`
- `templates/drop.html`
- данные: `drop_data/`, индекс в `drop_data/index.json`
- тесты: `tests/test_drop.py`
- инварианты:
  - пользовательское имя файла не должно становиться путём на диске;
  - публичные файлы отдавать безопасно: attachment / sandbox CSP;
  - удаление сначала идёт в корзину, не сразу физически.

### Файлы устройств и SFTP

- `blueprints/files.py`
- `templates/files.html`
- тесты: `tests/test_files.py`, `tests/test_phone_files.py`

### Телефонный агент

- `blueprints/phone.py`
- `templates/phone.html`
- Android-клиент: `android/`
- ТЗ и этапы: `docs/phone-access-plan.md`, `docs/phone-tz/`
- тесты: `tests/test_phone.py`, `tests/test_phone_files.py`
- инварианты:
  - телефон сам подключается к сайту websocket-ом;
  - входящих подключений к телефону не предполагается;
  - токены не хранить в открытом виде, если можно хранить хэш.

### SSH/RDP/VNC/NetBird/Claude

- `blueprints/remote.py`
- `templates/netbird.html`
- `templates/claude.html`
- тесты частично в `tests/test_files.py`
- инварианты:
  - пароли машин не хранить на сервере;
  - логин/пароль идут только в текущем websocket-сеансе;
  - суточный пароль консоли проверяется отдельно от пароля кабинета.

### Музыка и плеер

- `blueprints/music.py`
- `templates/music.html`
- `templates/vg_player.js.tpl`
- данные: `data/music/`, `data/music.json`
- тесты: `tests/test_music.py`

### AI/Neuro/OpenRouter

- `blueprints/ai.py`
- `templates/ai.html`
- данные: `data/aichat.json`, `data/aichat_img/`
- тесты: `tests/test_ai.py`

### Долги

- `blueprints/debts.py`
- `templates/debts.html`
- данные: `data/debts.json`
- тесты: `tests/test_debts.py`
- осторожно: сейчас есть `password_plain` для отображения владельцу. Не
  усиливать эту схему без отдельного решения.

### DIY, блокнот, уведомления, бэкап

- DIY: `blueprints/diy.py`, `templates/diy.html`
- Блокнот: `blueprints/notebook.py`, `templates/notebook.html`
- Уведомления: `blueprints/remote.py`, `templates/notifications.html`,
  `tests/test_notifications.py`
- Бэкап/Себастьян: `blueprints/backup_sebastian.py`,
  `templates/backup.html`, `templates/sebastian.html`

### PWA

- `blueprints/pwa.py`
- `templates/service_worker.js.tpl`
- `static/offline.html`
- тесты: `tests/test_pwa.py`

### Desktop Windows app

- `desktop/`
- `desktop/package.json`
- тесты: `desktop/tests/*.cjs`, `tests/test_desktop.py`

### Android app

- `android/`
- workflow: `.github/workflows/android.yml`
- сайтовые API обновления APK: `blueprints/phone.py`, `blueprints/desktop.py`

## Что не читать без причины

- `static/vendor/*`
- `desktop/dist/*`
- `desktop/node_modules/*`
- `.venv-desktop/*`
- `data/*`
- `drop_data/*`
- `pytest-cache-files-*`
- `__pycache__/*`

Если задача не про сборку Android/Desktop, не читать большие артефакты сборки.

## Как добавлять новые фичи

Новая фича должна появляться отдельным модулем, а не кусками по всему проекту.

Желаемый будущий шаблон:

```text
features/<name>/
  FEATURE.md
  routes.py
  service.py
  storage.py
  templates/
  tests/
```

Пока проект живёт в текущей структуре, минимальный шаблон такой:

```text
blueprints/<name>.py
templates/<name>.html
tests/test_<name>.py
docs/routes-inventory.md
```

В `app.py` для новой фичи должна появляться только регистрация blueprint и
передача зависимостей. Не складывать туда HTML, бизнес-логику и большие helper
функции.

## Как писать модуль

Разделять уровни:

- `routes` принимает HTTP-запрос и возвращает HTTP-ответ;
- `service` решает, что должно произойти;
- `storage` читает и пишет данные;
- `security/auth` проверяет доступы, пароли, лимиты;
- шаблон содержит UI, но не должен требовать чтения всего backend-кода.

Не смешивать в одной функции request parsing, проверку прав, файловую систему,
бизнес-логику и сборку HTML.

## Правила для экономии токенов

- Перед правкой читать `FEATURE.md` фичи, если он есть.
- Если `FEATURE.md` нет, при крупной правке создать короткий.
- Держать файлы небольшими: лучше 3 файла по 250 строк, чем один на 900.
- Не делать широкие рефакторы вместе с фичей.
- Не менять соседние модули без явной причины.
- Не трогать документацию инфраструктуры, если задача не про инфраструктуру.
- Для новой фичи сразу добавлять тест, который показывает основной сценарий.

## Ближайшее направление рефакторинга

Не переписывать проект целиком. Двигаться постепенно:

1. Сделать `app.py` тоньше: оставить создание приложения, настройки и
   регистрацию модулей.
2. Вынести общие вещи в `core/`: config, auth, rate limit, json storage,
   notifications, background jobs.
3. Для крупных фичей завести локальные `FEATURE.md`.
4. Новые фичи писать уже по модульному шаблону.
5. Старые фичи переносить только когда их всё равно приходится менять.

## Короткое заявление о стиле проекта

Этот проект строится не под классическую командную разработку, а под работу
нейросетевых агентов. Главный критерий структуры: агент должен быстро понять
границы задачи, открыть мало файлов, внести локальную правку, запустить понятные
тесты и не сломать соседние части. Поэтому новые возможности добавляются как
изолированные модули с короткой картой, явными контрактами, тестом и минимумом
изменений в центральном `app.py`.
