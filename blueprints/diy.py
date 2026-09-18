"""blueprints/diy.py — «Страна DIY» /diy: свои творения (задача 36,
docs/structure-plan.md).

Данные и вся логика — на модульном уровне здесь же, а не в `app.py`: файл
владеет своим состоянием сам, как блокнот (задача 35) и аркада (задача 36,
home.py). `diy_items`/`diy_lock`/`diy_load` по-прежнему читает и
`blueprints/backup_sebastian.py` (восстановление бэкапа перечитывает DIY
с диска) — импортированы в `app.py` из `blueprints.diy` для форварда,
как `notebook_data`/`notebook_lock` в задаче 35.

`safe_filename`/`clean_url` — общие с notebook.py хелперы, переехавшие
в `core/storage.py` в задаче 35 (обложка статьи и имя вложения не
пропускают путей и опасных символов; ссылка в шапке статьи получает
`https://`, если протокол не указан).
"""

import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from functools import wraps
from urllib.parse import quote

from flask import Blueprint, g, jsonify, request, send_file, session
from markupsafe import escape

from blueprints.pwa import ICON_LINKS
from core.auth import DEVICE_COOKIE, device_check, log_login
from core.storage import DATA_DIR, clean_url, safe_filename
from core.templates import template

# ---- Страна DIY: свои творения --------------------------------------------
# Записи ведёт хозяин сайта прямо со страницы, без правки кода. Обложки
# ужимаем при загрузке: портфолио листают, и тянуть в него исходные пять
# мегабайт с телефона незачем.
DIY_DIR = os.path.join(DATA_DIR, "diy")
DIY_INDEX_PATH = os.path.join(DATA_DIR, "diy.json")
DIY_MAX_IMAGE = 12 * 1024 * 1024
DIY_COVER_SIDE = 1280
DIY_LINK_LIMIT = 6

# Тематики. Раньше у записи был «вид» — программа, поделка, чертёж; полки из
# этого не выходило, всё лежало одной кучей. Теперь запись живёт в своей
# тематике, и у каждой свой цвет и свой значок. Листание — кладкой (masonry),
# один способ на все полки, переключателя между видами больше нет.
DIY_THEMES = (
    {"id": "программы",  "name": "Программы",  "color": "#2de2ff",
     "hint": "код, приложения и всё, что запускается"},
    {"id": "устройства", "name": "Устройства", "color": "#ffd84a",
     "hint": "ESP, платы, паяльник и провода"},
    {"id": "сервера",    "name": "Сервера",    "color": "#63f5ad",
     "hint": "машины, сети и то, что крутится круглосуточно"},
    {"id": "разное",     "name": "Разное",     "color": "#b57cff",
     "hint": "всё остальное"},
)
DIY_KINDS = tuple(t["id"] for t in DIY_THEMES)

# Старые названия видов — на новые полки. Записи, сделанные до тематик,
# сами переезжают при первом чтении.
DIY_KIND_MOVES = {
    "программа": "программы",
    "поделка": "устройства",
    "чертёж": "устройства",
    "разбор": "разное",
    "другое": "разное",
}

# Стартовые записи заводились ещё до полок, и по старому виду «поделка»
# панель мониторинга уехала бы к устройствам вместе с паяльником. Их
# раскладываем по названию — по одному разу, при первом чтении.
DIY_STARTERS = {
    "ssh_tunnel": "программы",
    "Себастьян": "программы",
    "Панель мониторинга": "сервера",
    "Корона": "устройства",
    "Магнитола": "устройства",
    "Реле под столом": "устройства",
}

diy_items: dict = {}
diy_lock = threading.Lock()
os.makedirs(DIY_DIR, exist_ok=True)


def _diy_cover_path(item_id):
    return os.path.join(DIY_DIR, f"{item_id}.jpg")


# Вложения статьи (фото и файлы) лежат в своей папке на запись. В самом
# коде статьи хозяин ссылается на них по имени через {{имя.jpg}} — страница
# статьи подставит настоящий адрес. Так в исходник сайта не попадает ни
# байта содержимого, и всё переживает деплой, как личный дроп.
DIY_ASSET_MAX = 25 * 1024 * 1024          # 25 МБ на одно вложение
DIY_ASSET_SIDE = 1600                     # фото ужимаем по большей стороне
DIY_ASSET_LIMIT = 40                      # сколько вложений на запись
DIY_BODY_MAX = 200_000                    # столько символов кода статьи
DIY_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}


def _diy_asset_dir(item_id):
    return os.path.join(DIY_DIR, item_id)


# safe_filename — теперь core.storage.safe_filename (общая с notebook.py,
# импортирована наверху файла под старым именем через `as`).


def _diy_asset_path(item_id, name):
    safe = safe_filename(name)
    if not safe:
        return None
    return os.path.join(_diy_asset_dir(item_id), safe)


def _diy_write_index():
    """Вызывать под diy_lock."""
    try:
        tmp = DIY_INDEX_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(diy_items, fh, ensure_ascii=False)
        os.replace(tmp, DIY_INDEX_PATH)
    except OSError:
        pass


def diy_load():
    try:
        with open(DIY_INDEX_PATH, encoding="utf-8") as fh:
            diy_items.update(json.load(fh) or {})
    except (OSError, ValueError):
        pass
    moved = False
    for work in diy_items.values():
        work.setdefault("links", [])
        work.setdefault("hidden", False)
        work.setdefault("pinned", False)
        work.setdefault("body", "")
        work.setdefault("assets", [])
        # Переезд со старых видов на тематики. Незнакомое кладём в «разное»,
        # чтобы запись не пропала из списка ни при каком раскладе.
        kind = work.get("kind") or ""
        if kind not in DIY_KINDS:
            work["kind"] = (DIY_STARTERS.get(work.get("title") or "")
                            or DIY_KIND_MOVES.get(kind, "разное"))
            moved = True
    if moved:
        try:
            _diy_write_index()
        except OSError:
            pass          # не смогли записать — переедем в следующий раз


diy_load()


# ---- Первое наполнение страны DIY -----------------------------------------
# Несколько записей заводятся сами при первом запуске: иначе раздел встречает
# пустотой, а расписывать каждую руками с телефона неудобно. Заготовки лежат
# рядом с кодом (static/seed), фотографии копируются во вложения записи.
# Каждая заготовка сеется ровно один раз: удалил — больше не вернётся.
DIY_SEED_FLAG = os.path.join(DATA_DIR, "diy_seeded.json")
DIY_SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "seed")

DIY_SEEDS = [
    {
        "key": "ssh_tunnel",
        "title": "ssh_tunnel",
        "kind": "программы",
        "assets": "ssh_tunnel",
        "body": """---
кратко: Учебный проект: как из штатного механизма SSH собрать рабочий локальный прокси. Один файл, без установки и без прав администратора — Windows, Linux и Android.
теги: Go, Kotlin, сети, SSH, SOCKS5
цвет: #2de2ff
обложка: главный-экран.png
ссылка: https://github.com/VITAZGIO/ssh_tunel
---

<p>У SSH есть штатная возможность — проброс TCP-соединений. Та самая, что стоит
за командой <code>ssh -D</code>. Мне стало интересно, что будет, если написать
её самому и довести до состояния программы, которой можно пользоваться каждый
день. Так появился <b>ssh_tunnel</b>: он поднимает соединение с моим же
сервером и разворачивает поверх него локальный прокси.</p>

<div class="note">Проект учебный. Он сделан, чтобы разобраться, как устроены
SOCKS, HTTP CONNECT, каналы SSH и как программа узнаёт, какое приложение
открыло соединение. Никакого сервиса тут нет: нужен сервер, к которому у тебя
и так есть доступ по SSH.</div>

<h2>Как выглядит</h2>

<div class="shots">
  <figure><img src="{{главный-экран.png}}" alt="Главный экран"><figcaption>Одна кнопка и живые цифры</figcaption></figure>
  <figure><img src="{{выбор-программ.png}}" alt="Разделение трафика"><figcaption>Какие программы вести через сервер</figcaption></figure>
  <figure><img src="{{настройки.png}}" alt="Настройки"><figcaption>Адрес, ключ и готовая команда</figcaption></figure>
</div>

<h2>Что происходит внутри</h2>

<p>Приложение думает, что говорит с обычным прокси на своей же машине.
Программа разбирает запрос, узнаёт адрес назначения и открывает до него канал
внутри SSH-соединения. Дальше всё решает сервер — включая DNS-запрос:</p>

<pre><code>  приложение
      │  SOCKS4/4a/5 (1080)   HTTP CONNECT (1081)
      ▼
  ssh_tunnel  ──── зашифрованный SSH (22) ────►  сервер  ──►  сеть</code></pre>

<p>Имя хоста разрешает сервер, а не твой компьютер. Это важная деталь: иначе
соединение выходило бы с адреса сервера, а запрос имени — с твоего.</p>

<h2>Что он умеет</h2>

<div class="cards">
  <div><b>Три протокола сразу</b><p>SOCKS5, SOCKS4/4a и HTTP CONNECT. Разные программы умеют разное — нужны все три.</p></div>
  <div><b>Разделение по программам</b><p>Через туннель идёт всё, только выбранные приложения или все кроме выбранных. Правила меняются на ходу.</p></div>
  <div><b>Локальная сеть напрямую</b><p>Роутер, NAS и Home Assistant остаются доступными: их адреса идут мимо туннеля. Mesh-сети тоже учтены.</p></div>
  <div><b>Переживает обрывы</b><p>Пул SSH-соединений с проверкой живости. Заснувший ноутбук не ломает туннель.</p></div>
  <div><b>Возвращает настройки</b><p>При любом закрытии, включая аварийное. Интернет после выхода не пропадает.</p></div>
  <div><b>Видно, кто ходит в сеть</b><p>Живой список программ и адресов, с пометкой, если DNS-запрос ушёл мимо туннеля.</p></div>
</div>

<h2>Три системы, один принцип</h2>

<table>
  <tr><th>Система</th><th>Как устроено</th><th>Что нужно настроить</th></tr>
  <tr><td><b>Windows</b></td><td>Окно с одной кнопкой, значок у часов</td><td>Адрес сервера и ключ</td></tr>
  <tr><td><b>Linux</b></td><td>Консоль плюс веб-интерфейс, служба systemd</td><td>Флаги или тот же конфиг</td></tr>
  <tr><td><b>Android</b></td><td>Системное подключение со своим сетевым стеком</td><td>Ничего: приложения просто ходят в сеть</td></tr>
</table>

<p>На компьютере программа поднимает прокси и прописывает переменные окружения
— иначе Node.js, Python и Go их бы не увидели, они системный прокси не читают.
На телефоне так нельзя, поэтому там приложение забирает у системы сырые
IP-пакеты и разбирает их само.</p>

<div class="warn">На Android нет UDP: через SSH он не проходит. Звонки и игры,
которым нужен UDP, надо выносить в исключения — они пойдут напрямую. Веб и
мессенджеры работают: приложение отбивает UDP сразу, и они за доли секунды
переключаются на TCP.</div>

<h2>Как начать</h2>

<ol class="steps">
  <li>Скачать один файл под свою систему — установщика нет.</li>
  <li>Открыть настройки и указать адрес сервера и пользователя.</li>
  <li>Если ключа ещё нет — нажать знак вопроса у поля с ключом: там готовая команда, которая создаст ключ и положит его на сервер.</li>
  <li>Нажать круглую кнопку. Всё.</li>
</ol>

<pre><code>curl -LO https://github.com/VITAZGIO/ssh_tunel/releases/latest/download/ssh_tunnel_linux
chmod +x ssh_tunnel_linux
./ssh_tunnel_linux -host ТВОЙ_СЕРВЕР -user tunnel -save
./ssh_tunnel_linux -web</code></pre>

<div class="ok">Ключ сервера проверяется при каждом подключении: подмена по
дороге не пройдёт незаметно. Для телефона стоит завести отдельный ключ — тогда
потеря одного устройства не тянет за собой второе.</div>

<h2>Чем пришлось заняться по дороге</h2>

<div class="chips">
  <span>разбор SOCKS4/4a/5</span><span>HTTP CONNECT</span><span>каналы direct-tcpip</span>
  <span>пул соединений</span><span>keepalive и переподключение</span><span>поиск процесса по сокету</span>
  <span>системный прокси Windows</span><span>переменные окружения</span><span>свой сетевой стек под Android</span>
  <span>тест скорости в несколько потоков</span>
</div>

<h2>Размер проекта</h2>

<table>
  <tr><th>Что</th><th>Сколько</th></tr>
  <tr><td>Код на Go</td><td>49 файлов, около 7 900 строк</td></tr>
  <tr><td>Android</td><td>Kotlin: сервис, плитка в шторке, выбор приложений</td></tr>
  <tr><td>Документация</td><td>архитектура, настройка сервера, безопасность, разбор ошибок</td></tr>
  <tr><td>Сборки</td><td>Windows, Linux amd64 и arm64, APK — собираются автоматически</td></tr>
</table>
""",
    },
    {
        "key": "korona",
        "title": "Корона",
        "kind": "устройства",
        "body": """---
кратко: ARGB-лента на пять метров под потолком. Zigbee-роутер на ESP32-H2, десять цветовых пресетов и пульт на кнопках через один провод.
теги: ESP32-H2, Zigbee, ARGB, MQTT
цвет: #b57cff
---

<p>Лента по периметру комнаты, которая слушается умного дома и не занимает
Wi-Fi: плата работает Zigbee-роутером, то есть заодно чинит сеть остальным
устройствам.</p>

<h2>Из чего собрано</h2>

<table>
  <tr><th>Узел</th><th>Что стоит</th></tr>
  <tr><td>Мозги</td><td>ESP32-H2 SuperMini, режим Zigbee Router</td></tr>
  <tr><td>Питание</td><td>12 В на ленту, понижайка на 5 В для платы</td></tr>
  <tr><td>Данные</td><td>Согласователь уровней 3.3 → 5 В и резистор на линии</td></tr>
  <tr><td>Пульт</td><td>Шесть кнопок на одном проводе — по сопротивлению</td></tr>
</table>

<div class="note">Кнопки собраны резисторной лесенкой: каждая даёт своё
напряжение, плата по нему и понимает, какую нажали. Один провод вместо шести.</div>

<h2>Что умеет</h2>

<div class="cards">
  <div><b>Десять пресетов</b><p>Отдельные каналы под каждый цвет — переключаются из умного дома одной кнопкой.</p></div>
  <div><b>Яркость шагами</b><p>Два канала «ярче» и «темнее» с автосбросом, чтобы удерживать нажатие.</p></div>
  <div><b>Чинит сеть</b><p>Питание от розетки, значит ретранслирует чужой трафик и укрепляет меш.</p></div>
</div>
""",
    },
    {
        "key": "magnitola",
        "title": "Магнитола",
        "kind": "устройства",
        "body": """---
кратко: Автомагнитола стала домашним усилителем. Управляется из умного дома через ИК-светодиод, вклеенный внутрь корпуса напротив штатного приёмника.
теги: ESP32-C3, MQTT, ИК, звук
цвет: #ffd84a
ссылка: https://github.com/VITAZGIO/magnitola
---

<p>Обычная автомагнитола, колонки и компьютерный блок питания на 12 вольт —
получился усилитель, который включается голосом и кнопкой в телефоне.</p>

<h2>Как ей управлять</h2>

<p>Пульт у магнитолы инфракрасный, поэтому светодиод поселился прямо внутри
корпуса — напротив штатного приёмника. Родной пульт при этом продолжает
работать, а соседние ИК-устройства команд не ловят.</p>

<div class="ok">Плата знает, включена ли магнитола: провод антенны даёт
+12 В при включении, и это напряжение через делитель читается платой.
Никаких догадок по последней команде.</div>

<h2>Что получилось</h2>

<div class="chips">
  <span>15 кнопок в умном доме</span><span>датчик «включена»</span>
  <span>появляется в доме сама</span><span>веб-настройка</span><span>без правки конфигов</span>
</div>

<h2>Что не сработало</h2>

<ol class="steps">
  <li>Управление по проводам руля через мультиплексор: магнитола забывала настройки после отключения питания.</li>
  <li>ИК через готовый хаб: команды ловили соседние устройства, а повторы давали двойные шаги громкости.</li>
</ol>

<p>Дальше — переезд на плату с Zigbee, чтобы всё жило в одной сети с остальным
домом.</p>
""",
    },
    {
        "key": "rele",
        "title": "Реле под столом",
        "kind": "устройства",
        "body": """---
кратко: Коробка под столешницей: два реле, шесть кнопок на одном проводе, термометр, управление вентилятором и питанием USB.
теги: ESP32-H2, Zigbee, реле, DS18B20
цвет: #63f5ad
---

<p>Всё, что раньше требовало тянуться под стол, теперь нажимается кнопкой
или командой из умного дома.</p>

<h2>Что внутри</h2>

<table>
  <tr><th>Выход</th><th>Зачем</th></tr>
  <tr><td>Два реле</td><td>Свет и розетка рабочего места</td></tr>
  <tr><td>Вентилятор</td><td>Плавные обороты, а не «вкл-выкл»</td></tr>
  <tr><td>Питание USB</td><td>Отдельный ключ: можно обесточить хабы разом</td></tr>
  <tr><td>Термометр</td><td>Температура под столом уходит в дом</td></tr>
</table>

<div class="note">Шестая кнопка — служебная: короткое нажатие открывает сеть
для новых устройств, длинное сбрасывает плату к заводскому состоянию.</div>
""",
    },
    {
        "key": "sebastian",
        "title": "Себастьян",
        "kind": "программы",
        "body": """---
кратко: Голосовой дворецкий целиком на домашней видеокарте: слышит, думает, управляет светом и отвечает своим голосом. Наружу не уходит ничего.
теги: LLM, Whisper, XTTS, MCP
цвет: #ff7a59
---

<p>Домашний голосовой помощник, собранный из открытых частей и связанный
своим кодом. Всё крутится на одной видеокарте в виртуалке — ни один запрос
не покидает квартиру.</p>

<h2>Путь одной фразы</h2>

<ol class="steps">
  <li>Микрофон отдаёт запись распознавалке речи.</li>
  <li>Текст уходит в языковую модель.</li>
  <li>Модель сама решает, дёрнуть ли инструмент: погода, время, состояние дома.</li>
  <li>Команда уходит в умный дом — только по белому списку устройств.</li>
  <li>Ответ озвучивается знакомым голосом.</li>
</ol>

<p>Полный круг «голос → голос» укладывается в 3.7–9 секунд.</p>

<div class="warn">Две большие модели на одной карте одновременно работать не
могут — скорость падает втрое. Поэтому этапы идут строго по очереди, а не
параллельно.</div>

<h2>Чему научился по дороге</h2>

<div class="chips">
  <span>белый список устройств прямо в схеме</span><span>слепок голоса считается один раз</span>
  <span>размер контекста важнее всего для памяти</span><span>инструменты — первым пунктом промпта</span>
</div>
""",
    },
    {
        "key": "panel",
        "title": "Панель мониторинга",
        "kind": "сервера",
        "body": """---
кратко: Настольная панель с экраном и двенадцатью кнопками: показывает сервер, дёргает реле и рулит подсветкой компьютера по радио.
теги: ESP32, TFT, RF433, MQTT
цвет: #35e0f0
---

<p>Маленький экран и ряд кнопок на столе: видно температуру и обороты, а
любую из двенадцати кнопок можно повесить на что угодно в умном доме.</p>

<h2>Что показывает</h2>

<div class="cards">
  <div><b>Сервер</b><p>Температура дисков, обороты вентиляторов, связь.</p></div>
  <div><b>Кнопки</b><p>Двенадцать событий — каждое ловится домом отдельно.</p></div>
  <div><b>Радио</b><p>Подсветка компьютера управляется по 433 МГц, без своей прошивки.</p></div>
</div>

<div class="note">Про сборку: среда разработки крепко держит старые флаги
компиляции. Если поменял настройки экрана, а цвета остались прежние — надо
чистить сборку целиком, иначе будешь искать ошибку в проводах.</div>
""",
    },
]


def _diy_seed():
    """Заводит стартовые записи страны DIY — по одному разу каждую.

    Всё внутри обёрнуто: заготовки — приятная мелочь, и если они почему-то
    не легли (нет места, странные имена файлов), сайт всё равно обязан
    подняться."""
    try:
        with open(DIY_SEED_FLAG, encoding="utf-8") as fh:
            done = json.load(fh) or {}
    except (OSError, ValueError):
        done = {}

    changed = False
    for spec in DIY_SEEDS:
        if done.get(spec["key"]):
            continue
        item_id = str(uuid.uuid4())
        now = time.time()
        with diy_lock:
            diy_items[item_id] = {
                "title": spec["title"],
                "summary": "",
                "kind": spec["kind"],
                "links": [],
                "body": spec["body"],
                "assets": [],
                "cover": False,
                "hidden": False,
                "pinned": False,
                "created": now,
                "updated": now,
            }
            # фотографии заготовки переносим во вложения записи
            src_dir = os.path.join(DIY_SEED_DIR, spec.get("assets") or "")
            if spec.get("assets") and os.path.isdir(src_dir):
                os.makedirs(_diy_asset_dir(item_id), exist_ok=True)
                for name in sorted(os.listdir(src_dir)):
                    safe = safe_filename(name)
                    if not safe:
                        continue
                    try:
                        shutil.copyfile(os.path.join(src_dir, name),
                                        os.path.join(_diy_asset_dir(item_id), safe))
                    except OSError:
                        continue
                    kind = ("image" if os.path.splitext(safe)[1].lower() in DIY_IMAGE_EXT
                            else "file")
                    size = os.path.getsize(os.path.join(_diy_asset_dir(item_id), safe))
                    diy_items[item_id]["assets"].append(
                        {"name": safe, "kind": kind, "size": size})
            _diy_write_index()
        done[spec["key"]] = True
        changed = True

    if changed:
        try:
            with open(DIY_SEED_FLAG, "w", encoding="utf-8") as fh:
                json.dump(done, fh, ensure_ascii=False)
        except OSError:
            pass


try:
    _diy_seed()
except Exception:                                    # noqa: BLE001
    logging.getLogger(__name__).exception(
        "Не удалось завести заготовки DIY — работаем без них")


def _diy_clean_links(raw):
    """Ссылки: подпись и адрес. Пускаем только http и https — иначе в
    портфолио можно вписать javascript: и получить чужой скрипт на сайте."""
    out = []
    for entry in (raw or [])[:DIY_LINK_LIMIT]:
        if not isinstance(entry, dict):
            continue
        url = (entry.get("url") or "").strip()[:400]
        if not url:
            continue
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url.lstrip("/")
        label = (entry.get("label") or "").strip()[:40] or "ссылка"
        out.append({"label": label, "url": url})
    return out


def _diy_head(body):
    """Разбирает «шапку» кода статьи: пары «ключ: значение» между строками из
    трёх дефисов в самом начале. Так вся карточка описывается тем же кодом,
    что и статья, и руками в форме ничего заполнять не нужно.

        ---
        кратко: Свой прокси через SSH под три системы
        теги: Go, Android, сети
        цвет: #2de2ff
        обложка: главный-экран.png
        ссылка: https://github.com/…
        ---

    Возвращает (словарь шапки, остаток кода)."""
    text = (body or "").lstrip("﻿ \t\r\n")
    if not text.startswith("---"):
        return {}, body or ""
    lines = text.split("\n")
    out, rest_at = {}, None
    for i, raw in enumerate(lines[1:], start=1):
        line = raw.strip()
        if line.startswith("---"):
            rest_at = i + 1
            break
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip().lower()] = value.strip()
    if rest_at is None:                     # закрывающих дефисов нет — не шапка
        return {}, body or ""
    return out, "\n".join(lines[rest_at:])


def _diy_card(work):
    """Что показать на короткой карточке. Всё берём из шапки кода, а если её
    нет — из старых полей записи, чтобы прежние записи не осыпались."""
    head, _ = _diy_head(work.get("body", ""))
    tags = [t.strip() for t in (head.get("теги") or head.get("tags") or "").split(",")]
    accent = (head.get("цвет") or head.get("color") or "").strip()
    if not re.match(r"^#[0-9a-fA-F]{6}$", accent):
        accent = ""
    return {
        "summary": (head.get("кратко") or head.get("summary")
                    or work.get("summary", ""))[:400],
        "tags": [t for t in tags if t][:6],
        "accent": accent,
        "shot": safe_filename(head.get("обложка") or head.get("cover") or ""),
        "link": clean_url(head.get("ссылка") or head.get("link") or ""),
    }


def _diy_public(item_id, work, can_edit):
    card = _diy_card(work)
    row = {
        "id": item_id,
        "title": work.get("title", ""),
        "summary": card["summary"],
        "tags": card["tags"],
        "accent": card["accent"],
        "shot": card["shot"],
        "link": card["link"],
        "kind": work.get("kind", "другое"),
        "links": work.get("links", []),
        "cover": bool(work.get("cover")),
        "created": work.get("created", 0),
        "updated": work.get("updated", 0),
        "pinned": bool(work.get("pinned")),
        "assets": [dict(a) for a in work.get("assets", [])],
        "has_body": bool((work.get("body") or "").strip()),
    }
    if can_edit:
        row["hidden"] = bool(work.get("hidden"))
        row["body"] = work.get("body", "")
    return row


def _diy_sorted(can_edit):
    """Закреплённые сверху, дальше по свежести. Скрытые видит только хозяин.
    Вызывать под diy_lock."""
    rows = [(k, v) for k, v in diy_items.items()
            if can_edit or not v.get("hidden")]
    rows.sort(key=lambda kv: (not kv[1].get("pinned"), -kv[1].get("created", 0)))
    return rows


def diy_editor_required(view):
    """Правит только хозяин. Проверка та же, что у кабинета: живая сессия или
    помеченное доверенным устройство — тогда режим правки включается сам,
    без лишнего ввода пароля."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


def _diy_can_edit():
    """Пустил бы редактор этого гостя. Отдельно от декоратора: страница
    спрашивает об этом, ничего не меняя."""
    if session.get("authenticated"):
        return True
    fresh = device_check(request.cookies.get(DEVICE_COOKIE))
    if fresh:
        session["authenticated"] = True
        g.new_device_cookie = fresh
        log_login("доверенное устройство")
        return True
    return False


def create_diy_blueprint():
    diy_bp = Blueprint("diy", __name__)

    def diy_render_body(item_id, body):
        """Подставляет в код статьи адреса вложений: {{имя.jpg}} превращается в
        ссылку на /diy/asset/<id>/имя.jpg. Больше ничего не трогаем — остальное
        хозяин пишет как обычный HTML."""
        def swap(match):
            name = safe_filename(match.group(1))
            if not name:
                return match.group(0)
            return "/diy/asset/" + item_id + "/" + quote(name)

        return re.sub(r"\{\{\s*([^{}]+?)\s*\}\}", swap, body or "")

    @diy_bp.get("/api/diy")
    def diy_list_api():
        can_edit = _diy_can_edit()
        with diy_lock:
            works = [_diy_public(k, v, can_edit) for k, v in _diy_sorted(can_edit)]
        return jsonify(works=works, can_edit=can_edit, kinds=list(DIY_KINDS),
                       themes=[dict(t) for t in DIY_THEMES])

    @diy_bp.post("/api/diy")
    @diy_editor_required
    def diy_create_api():
        payload = request.get_json(silent=True) or {}
        title = (payload.get("title") or "").strip()[:80]
        if not title:
            return jsonify(error="Без названия не сохранить."), 400
        kind = payload.get("kind") if payload.get("kind") in DIY_KINDS else "разное"
        item_id = str(uuid.uuid4())
        now = time.time()
        with diy_lock:
            diy_items[item_id] = {
                "title": title,
                "summary": (payload.get("summary") or "").strip()[:600],
                "kind": kind,
                "links": _diy_clean_links(payload.get("links")),
                "body": (payload.get("body") or "")[:DIY_BODY_MAX],
                "assets": [],
                "cover": False,
                "hidden": bool(payload.get("hidden")),
                "pinned": bool(payload.get("pinned")),
                "created": now,
                "updated": now,
            }
            _diy_write_index()
        return jsonify(id=item_id)

    @diy_bp.patch("/api/diy/<item_id>")
    @diy_editor_required
    def diy_update_api(item_id):
        payload = request.get_json(silent=True) or {}
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            if "title" in payload:
                title = (payload.get("title") or "").strip()[:80]
                if not title:
                    return jsonify(error="Без названия не сохранить."), 400
                work["title"] = title
            if "summary" in payload:
                work["summary"] = (payload.get("summary") or "").strip()[:600]
            if "body" in payload:
                work["body"] = (payload.get("body") or "")[:DIY_BODY_MAX]
            if "kind" in payload and payload["kind"] in DIY_KINDS:
                work["kind"] = payload["kind"]
            if "links" in payload:
                work["links"] = _diy_clean_links(payload.get("links"))
            for flag in ("hidden", "pinned"):
                if flag in payload:
                    work[flag] = bool(payload[flag])
            work["updated"] = time.time()
            _diy_write_index()
        return jsonify(ok=True)

    @diy_bp.delete("/api/diy/<item_id>")
    @diy_editor_required
    def diy_delete_api(item_id):
        with diy_lock:
            work = diy_items.pop(item_id, None)
            if work:
                _diy_write_index()
        if work:
            try:
                os.remove(_diy_cover_path(item_id))
            except OSError:
                pass
            shutil.rmtree(_diy_asset_dir(item_id), ignore_errors=True)
        return jsonify(ok=True)

    @diy_bp.post("/api/diy/<item_id>/asset")
    @diy_editor_required
    def diy_asset_upload_api(item_id):
        """Фото или файл к статье. Картинки ужимаем, прочее кладём как есть.
        Имя сохраняем узнаваемым — по нему хозяин ссылается в коде статьи."""
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            if len(work.get("assets", [])) >= DIY_ASSET_LIMIT:
                return jsonify(error=f"Больше {DIY_ASSET_LIMIT} вложений на запись нельзя."), 400
        upload = request.files.get("file")
        if not upload:
            return jsonify(error="Файл не выбран."), 400
        if request.content_length and request.content_length > DIY_ASSET_MAX + 8192:
            return jsonify(error="Вложение больше 25 МБ."), 413
        name = safe_filename(upload.filename)
        if not name:
            return jsonify(error="Не разобрать имя файла."), 400
        os.makedirs(_diy_asset_dir(item_id), exist_ok=True)
        dest = _diy_asset_path(item_id, name)
        ext = os.path.splitext(name)[1].lower()
        is_image = ext in DIY_IMAGE_EXT
        try:
            if is_image and ext != ".gif":
                # GIF мог бы быть анимацией — её не трогаем; остальное ужимаем.
                from PIL import Image

                Image.MAX_IMAGE_PIXELS = 80_000_000
                with Image.open(upload.stream) as image:
                    keep_alpha = ext in (".png", ".webp")
                    image = image.convert("RGBA" if keep_alpha else "RGB")
                    image.thumbnail((DIY_ASSET_SIDE, DIY_ASSET_SIDE))
                    if ext == ".png":
                        image.save(dest, "PNG", optimize=True)
                    elif ext == ".webp":
                        image.save(dest, "WEBP", quality=85, method=4)
                    else:
                        image.save(dest, "JPEG", quality=84, optimize=True)
            else:
                upload.save(dest)
                if os.path.getsize(dest) > DIY_ASSET_MAX:
                    os.remove(dest)
                    return jsonify(error="Вложение больше 25 МБ."), 413
        except Exception:
            try:
                os.remove(dest)
            except OSError:
                pass
            return jsonify(error="Не вышло сохранить вложение."), 415
        size = os.path.getsize(dest)
        kind = "image" if is_image else "file"
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                os.remove(dest)
                return jsonify(error="Запись не найдена."), 404
            assets = [a for a in work.get("assets", []) if a.get("name") != name]
            assets.append({"name": name, "kind": kind, "size": size})
            work["assets"] = assets
            work["updated"] = time.time()
            _diy_write_index()
        return jsonify(ok=True, name=name, kind=kind, size=size)

    @diy_bp.delete("/api/diy/<item_id>/asset/<path:name>")
    @diy_editor_required
    def diy_asset_delete_api(item_id, name):
        safe = safe_filename(name)
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            work["assets"] = [a for a in work.get("assets", []) if a.get("name") != safe]
            work["updated"] = time.time()
            _diy_write_index()
        path = _diy_asset_path(item_id, safe)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
        return jsonify(ok=True)

    @diy_bp.get("/diy/asset/<item_id>/<path:name>")
    def diy_asset_api(item_id, name):
        """Вложение статьи. Открыто всем, как и обложка — статью смотрит любой.
        У скрытой записи вложения видит только хозяин."""
        with diy_lock:
            work = diy_items.get(item_id)
            hidden = bool(work and work.get("hidden"))
            known = {a.get("name") for a in (work.get("assets", []) if work else [])}
        if not work:
            return "", 404
        if hidden and not _diy_can_edit():
            return "", 404
        safe = safe_filename(name)
        if safe not in known:
            return "", 404
        path = _diy_asset_path(item_id, safe)
        if not path or not os.path.exists(path):
            return "", 404
        response = send_file(path, conditional=True)
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    @diy_bp.post("/api/diy/<item_id>/cover")
    @diy_editor_required
    def diy_cover_upload_api(item_id):
        with diy_lock:
            if item_id not in diy_items:
                return jsonify(error="Запись не найдена."), 404
        picture = request.files.get("file")
        if not picture:
            return jsonify(error="Файл не выбран."), 400
        if request.content_length and request.content_length > DIY_MAX_IMAGE + 8192:
            return jsonify(error="Картинка больше 12 МБ."), 413
        try:
            from PIL import Image

            Image.MAX_IMAGE_PIXELS = 80_000_000   # защита от «бомб» с диким разрешением
            with Image.open(picture.stream) as image:
                image.draft("RGB", (DIY_COVER_SIDE, DIY_COVER_SIDE))
                image = image.convert("RGB")
                image.thumbnail((DIY_COVER_SIDE, DIY_COVER_SIDE))
                image.save(_diy_cover_path(item_id), "JPEG", quality=82, optimize=True)
        except Exception:
            return jsonify(error="Это не похоже на картинку."), 415
        with diy_lock:
            work = diy_items.get(item_id)
            if work:
                work["cover"] = True
                work["updated"] = time.time()
                _diy_write_index()
        return jsonify(ok=True, size=os.path.getsize(_diy_cover_path(item_id)))

    @diy_bp.delete("/api/diy/<item_id>/cover")
    @diy_editor_required
    def diy_cover_delete_api(item_id):
        with diy_lock:
            work = diy_items.get(item_id)
            if work:
                work["cover"] = False
                work["updated"] = time.time()
                _diy_write_index()
        try:
            os.remove(_diy_cover_path(item_id))
        except OSError:
            pass
        return jsonify(ok=True)

    @diy_bp.get("/diy/cover/<item_id>")
    def diy_cover_api(item_id):
        """Обложка. Открыта всем: страница со списком тоже открыта."""
        with diy_lock:
            work = diy_items.get(item_id)
            hidden = bool(work and work.get("hidden"))
        if not work or not work.get("cover"):
            return "", 404
        if hidden and not _diy_can_edit():
            return "", 404
        path = _diy_cover_path(item_id)
        if not os.path.exists(path):
            return "", 404
        response = send_file(path, mimetype="image/jpeg", conditional=True)
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    @diy_bp.get("/diy/a/<item_id>")
    def diy_article_page(item_id):
        """Отдельная страница одного творения: полная статья, что открывается из
        короткой карточки в новом окне. Содержимое — код, написанный хозяином;
        вложения он подставляет по имени через {{…}}."""
        with diy_lock:
            work = diy_items.get(item_id)
            if not work or (work.get("hidden") and not _diy_can_edit()):
                snapshot = None
            else:
                card = _diy_card(work)
                _, text = _diy_head(work.get("body", ""))     # шапку в текст не пускаем
                snapshot = {
                    "title": work.get("title", ""),
                    "summary": card["summary"],
                    "tags": card["tags"],
                    "accent": card["accent"] or "#2de2ff",
                    "link": card["link"],
                    "kind": work.get("kind", ""),
                    "body": text,
                    "links": list(work.get("links", [])),
                    "cover": bool(work.get("cover")),
                    "hidden": bool(work.get("hidden")),
                }
        if snapshot is None:
            return "Творение не найдено", 404

        body_html = diy_render_body(item_id, snapshot["body"])
        if not body_html.strip():
            # Кода статьи ещё нет — показываем хотя бы название и описание,
            # чтобы страница не выглядела сломанной.
            body_html = ("<p class=\"lead\">" + str(escape(snapshot["summary"])) + "</p>"
                         if snapshot["summary"] else
                         "<p class=\"lead\">Статья ещё пишется.</p>")
        links_html = ""
        if snapshot["links"]:
            chips = "".join(
                f'<a href="{escape(l["url"])}" target="_blank" rel="noopener">{escape(l["label"])}</a>'
                for l in snapshot["links"])
            links_html = f'<div class="links">{chips}</div>'
        draft = ('<span class="draft">черновик</span>' if snapshot["hidden"] else "")

        html = template("diy_article.html")
        summary_html = (f'<p class="summary">{escape(snapshot["summary"])}</p>'
                        if snapshot["summary"] else "")
        tags = "".join([
            f'<span class="kind">{escape(snapshot["kind"])}</span>' if snapshot["kind"] else "",
            "".join(f'<span class="tag">{escape(t)}</span>' for t in snapshot["tags"]),
            draft,
        ])
        src_html = ""
        if snapshot["link"]:
            src_html = (
                '<div class="srcline"><a href="' + str(escape(snapshot["link"])) + '" target="_blank" rel="noopener">'
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M21 3l-9 9"/>'
                '<path d="M10 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/></svg>'
                'Исходники и сборки</a></div>')
        return (html.replace("__ICONLINKS__", ICON_LINKS)
                    .replace("__ACCENT__", snapshot["accent"])
                    .replace("__DESC__", str(escape(snapshot["summary"] or snapshot["title"])))
                    .replace("__TAGS__", tags)
                    .replace("__SUMMARY__", summary_html)
                    .replace("__SRC__", src_html)
                    .replace("__LINKS__", links_html)
                    .replace("__TITLE__", str(escape(snapshot["title"])))
                    .replace("__BODY__", body_html))

    @diy_bp.get("/diy")
    def diy_page():
        """Страна DIY: витрина своих творений.

        Смотреть может кто угодно, добавлять — хозяин. Отдельного входа не просим:
        если сайт уже помнит устройство по кабинету, режим правки включается сам."""
        html = template("diy.html")
        return html.replace("__ICONLINKS__", ICON_LINKS)

    return diy_bp
