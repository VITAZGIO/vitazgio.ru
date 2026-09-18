# AI_MAP — где что лежит

Навигация по проекту: тема → файлы. **Правил здесь нет** — они в
`CLAUDE.md` (он читается сам в начале каждой сессии). Этот файл нужен в
одном случае: не знаешь, в каком файле живёт нужная фича.

Порядок чтения: `CLAUDE.md` (правила, ловушки) → этот файл (найти фичу)
→ `blueprints/<name>.md` (карта фичи: точки входа, данные, инварианты,
какой тест гонять) → сам код. Раньше, чем понадобилось, ничего не
открывать.

## Структура (после задач 1-40, оба плана выполнены)

| Папка | Что там |
|---|---|
| `app.py` | тонкий вход: создание Flask-приложения, конфиг, регистрация blueprint'ов, фоновые задачи (метрики, пинг NetBird), свои роуты входа. ~1250 строк |
| `core/` | общая инфраструктура: `auth.py` (вход, доверенные устройства, суточный пароль консоли, ограничение попыток), `storage.py` (`DATA_DIR`, атомарная запись JSON, безопасные имена файлов), `templates.py` (`template()`) |
| `blueprints/` | по файлу на фичу + `<name>.md` — карта рядом с кодом |
| `templates/` | HTML/CSS/JS страниц, обычные текстовые файлы (без Jinja2) |
| `tests/` | pytest, гоняется в CI дважды |
| `scripts/` | `gen_routes.py` — генератор описи роутов |
| `android/`, `desktop/` | клиентские приложения, свои README |

## Фичи

| Тема | Файл | Карта |
|---|---|---|
| Главная, темы, серверы, аркада | `blueprints/home.py` | `home.md` |
| Кабинет, NetBird, SSH/RDP/VNC/Claude, уведомления | `blueprints/remote.py` | `remote.md` |
| Дроп и публичные ссылки | `blueprints/drop.py` | `drop.md` |
| Файлы машин и телефона (SFTP) | `blueprints/files.py` | `files.md` |
| Телефонный агент, экран, звук, управление | `blueprints/phone.py` | `phone.md` |
| Музыка и плеер | `blueprints/music.py` | `music.md` |
| Нейронки (/neuro, /ai), вкладка Claude | `blueprints/ai.py` | `ai.md` |
| Долги | `blueprints/debts.py` | `debts.md` |
| DIY | `blueprints/diy.py` | `diy.md` |
| Блокнот | `blueprints/notebook.py` | `notebook.md` |
| Вкладка «Приложения» | `blueprints/apps.py` | `apps.md` |
| Оболочка Windows, просмотр экрана ПК | `blueprints/desktop.py` | `desktop.md` |
| Бэкап и Себастьян | `blueprints/backup_sebastian.py` | `backup_sebastian.md` |
| Доверенные устройства | `blueprints/devices.py` | `devices.md` |
| Журнал входов | `blueprints/login_log.py` | `login_log.md` |
| PWA, иконки, «Поделиться» | `blueprints/pwa.py` | `pwa.md` |

Карты лежат рядом с кодом: `blueprints/<name>.md`.

## Полный список роутов

`docs/routes-inventory.md` — **генерируется** скриптом
`python3 scripts/gen_routes.py`, руками не редактировать (правки
потеряются, расхождение с кодом валит `tests/test_docs.py`).

## Что не читать без причины

`static/vendor/*`, `desktop/dist/*`, `desktop/node_modules/*`,
`android/app/build/*`, `data/*`, `drop_data/*`, `__pycache__/*`.
Это артефакты сборки и живые данные — в задачах про код они не нужны.

## Как добавить фичу

Правило целиком — в `CLAUDE.md`, раздел «Как добавлять новую фичу».
Коротко: `blueprints/<name>.py` (фича владеет своим состоянием сама,
общее берёт прямым импортом из `core/`, фабрика **без аргументов** —
эталон `blueprints/login_log.py` и `debts.py`) + `templates/<name>.html`
+ `tests/test_<name>.py` + `blueprints/<name>.md` + перегенерировать
опись роутов. В `app.py` — только строка регистрации.
