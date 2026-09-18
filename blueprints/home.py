"""blueprints/home.py — главная страница `/`, витрина `/themes`, страница
`/servers`, рекорды аркады (задача 36, docs/structure-plan.md).

Рекорды аркады — своя, ничем не разделяемая с другими фичами подсистема
(данные, лок, ограничение частоты попыток): переехала сюда целиком, как
блокнот в задаче 35. `SERVERS_PASSWORD` тоже больше не приходит из
`app.py` — файл сам читает свою переменную окружения, это не общий
секрет с чем-либо ещё.

`game_icons` (пиксель-арт для главной и, отдельно, для аватарки
Себастьяна) и `netbird_devices` (список машин, общий для нескольких
фич) остались фабричными аргументами: первое — 350+ строк литералов не
столько «инфраструктура», сколько статические данные, второе — общая
конфигурация, которую забирать себе одной фиче не с руки. Переедут вместе
со своими задачами (Себастьян/устройства), не здесь.
"""

import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Blueprint, jsonify, redirect, request, session

from blueprints.pwa import ICON_LINKS
from core.auth import (
    CONSOLE_LOGIN_MAX_ATTEMPTS,
    CONSOLE_LOGIN_WINDOW_SECONDS,
    SSH_GATE_PASSWORD_PREFIX,
    client_ip,
    console_login_attempts,
    console_login_attempts_lock,
    console_password_today,
    log_login,
    login_required,
    rate_blocked,
    rate_clear,
    rate_hit,
)
from core.storage import DATA_DIR, atomic_write_json
from core.templates import template

SERVERS_PASSWORD = os.environ.get("SERVERS_PASSWORD", "1224")

# ---- Рекорды аркады ---------------------------------------------------------
# Лежат на сервере, а не в localStorage: браузер чистят, телефон меняют, а
# таблица должна пережить и то, и другое, и перезагрузку сервера.
#
# Аркада открыта без пароля — значит, результат может прислать кто угодно.
# Проверить «честно ли набрано» из браузера нельзя в принципе, поэтому здесь
# только санитария: потолок значения, ограничение частоты и длины имени.
# Удаление же закрыто суточным паролем — это единственное действие, где
# ошибиться нельзя.
ARCADE_SCORES_PATH = os.path.join(DATA_DIR, "arcade_scores.json")
ARCADE_TOP = 3               # столько мест показываем
ARCADE_KEEP = 10             # столько храним: снёс хама — поднялся следующий
ARCADE_NAME_MAX = 12
ARCADE_VALUE_MAX = 10_000_000
ARCADE_SUBMIT_WINDOW = 300
ARCADE_SUBMIT_MAX = 40       # результатов с одного адреса за пять минут

# epoch поднимается, когда правила меняются так, что старые рекорды больше
# не сравнимы с новыми, — например, в DOOM добавили уровень и время
# прохождения выросло у всех. Записи прошлой эпохи отваливаются сами при
# первой же загрузке файла.
# lo/hi — границы правдоподобного результата. Считает очки браузер, подделать
# запрос может кто угодно, но хотя бы заведомая чушь в таблицу не попадёт:
# человек не печатает тысячу знаков в минуту и не проходит DOOM за пять секунд.
# Рулетки тут намеренно нет: колесо — генератор случайных чисел, место в
# такой таблице говорит про везение, а не про игрока. Свой лучший результат
# она по-прежнему помнит, но только на устройстве.
ARCADE_GAMES = {
    "snake":    {"title": "Змейка",  "order": "max", "unit": "score", "epoch": 1,
                 "lo": 10, "hi": 20_000},
    "tetris":   {"title": "Тетрис",  "order": "max", "unit": "score", "epoch": 1,
                 "lo": 10, "hi": 2_000_000},
    # epoch 2: уровней стало пять вместо двух, старые времена несравнимы
    "doom":     {"title": "DOOM",    "order": "min", "unit": "time",  "epoch": 2,
                 "lo": 40, "hi": 7_200},
    "tanks":    {"title": "Танчики", "order": "max", "unit": "score", "epoch": 1,
                 "lo": 100, "hi": 500_000},
    "arkanoid": {"title": "Арканоид", "order": "max", "unit": "score", "epoch": 1,
                 "lo": 50, "hi": 500_000},
    "wolf":     {"title": "Ну, погоди!", "order": "max", "unit": "score", "epoch": 1,
                 "lo": 1, "hi": 100_000},
    # У шахмат в рейтинге серия побед подряд, и только на сложном уровне.
    "chess":    {"title": "Шахматы", "order": "max", "unit": "score", "epoch": 1,
                 "lo": 1, "hi": 1_000},
    # Печать меряется чистой скоростью: знаков в минуту за вычетом опечаток.
    # Мировые рекорды слепой печати — около 900 зн/мин, потолок с запасом.
    "typing":   {"title": "Печать",  "order": "max", "unit": "cpm",   "epoch": 1,
                 "lo": 30, "hi": 1_500},
}

arcade_scores: dict = {}
arcade_lock = threading.Lock()
arcade_submit_attempts = defaultdict(deque)
arcade_submit_lock = threading.Lock()

# Управляющие символы, нулевой ширины и переключатели направления письма:
# ими можно нарисовать ник, который ломает таблицу или притворяется чужим.
ARCADE_NAME_BAD = re.compile("[\x00-\x1f\x7f​-‏ -‮⁦-⁩]")


def _arcade_clean_name(raw):
    """Ник в таблицу. Пустой или из одних пробелов — значит подписываться
    не захотели: в аркадах такого зовут NoName, так и запишем."""
    name = ARCADE_NAME_BAD.sub("", raw if isinstance(raw, str) else "")
    name = re.sub(r"\s+", " ", name).strip()
    return name[:ARCADE_NAME_MAX] or "NoName"


def _arcade_sort(game, rows):
    reverse = ARCADE_GAMES[game]["order"] == "max"
    # При равном результате выше тот, кто добрался до него раньше.
    return sorted(rows, key=lambda r: (-r["value"] if reverse else r["value"],
                                       r.get("at", 0)))


def _arcade_save():
    """Вызывать под arcade_lock."""
    try:
        atomic_write_json(ARCADE_SCORES_PATH, arcade_scores)
    except OSError:
        pass


def _arcade_load():
    try:
        with open(ARCADE_SCORES_PATH, encoding="utf-8") as fh:
            stored = json.load(fh)
    except (OSError, ValueError):
        stored = {}
    for game, meta in ARCADE_GAMES.items():
        rows = stored.get(game) or []
        if not isinstance(rows, list):
            rows = []
        clean = []
        for row in rows:
            try:
                if int(row.get("epoch", 0)) != meta["epoch"]:
                    continue        # рекорд по старым правилам — не сравним
                clean.append({
                    "id": str(row["id"]),
                    "name": _arcade_clean_name(row.get("name")),
                    "value": int(row["value"]),
                    "at": float(row.get("at", 0)),
                    "epoch": meta["epoch"],
                })
            except (KeyError, TypeError, ValueError):
                continue
        arcade_scores[game] = _arcade_sort(game, clean)[:ARCADE_KEEP]


def _arcade_public():
    """Вызывать под arcade_lock."""
    return {game: [{"id": r["id"], "name": r["name"], "value": r["value"], "at": r["at"]}
                   for r in rows[:ARCADE_TOP]]
            for game, rows in arcade_scores.items()}


_arcade_load()


def create_home_blueprint(*, game_icons, netbird_devices):
    home_bp = Blueprint("home", __name__)

    # ---- Рекорды аркады: без пароля, аркада ведь тоже открыта ---------------
    @home_bp.get("/api/arcade/scores")
    def arcade_scores_api():
        with arcade_lock:
            return jsonify(
                scores=_arcade_public(),
                games={g: {"title": m["title"], "order": m["order"], "unit": m["unit"]}
                       for g, m in ARCADE_GAMES.items()},
            )

    @home_bp.post("/api/arcade/scores")
    def arcade_score_add():
        client = client_ip()
        if rate_blocked(arcade_submit_attempts, arcade_submit_lock, client,
                        ARCADE_SUBMIT_WINDOW, ARCADE_SUBMIT_MAX):
            return jsonify(error="Слишком часто. Попробуйте позже."), 429
        rate_hit(arcade_submit_attempts, arcade_submit_lock, client)

        payload = request.get_json(silent=True) or {}
        game = payload.get("game")
        if game not in ARCADE_GAMES:
            return jsonify(error="Неизвестная игра."), 400
        try:
            value = int(payload.get("value"))
        except (TypeError, ValueError):
            return jsonify(error="Плохой результат."), 400
        meta = ARCADE_GAMES[game]
        if not meta.get("lo", 0) <= value <= min(meta.get("hi", ARCADE_VALUE_MAX),
                                                 ARCADE_VALUE_MAX):
            return jsonify(error="Результат вне правдоподобных границ."), 400

        row = {
            "id": secrets.token_urlsafe(6),
            "name": _arcade_clean_name(payload.get("name")),
            "value": value,
            "at": time.time(),
            "epoch": meta["epoch"],
        }
        with arcade_lock:
            rows = _arcade_sort(game, arcade_scores.get(game, []) + [row])[:ARCADE_KEEP]
            arcade_scores[game] = rows
            _arcade_save()
            place = next((i for i, r in enumerate(rows) if r["id"] == row["id"]), None)
            return jsonify(
                # place — место в таблице (0 — первое) или null, если не пролез
                place=place if place is not None and place < ARCADE_TOP else None,
                scores=_arcade_public(),
            )

    @home_bp.post("/api/arcade/scores/delete")
    def arcade_score_delete():
        """Чистка таблицы от неприличных ников. Пускаем по тому же суточному
        паролю, что и в консоль, — заводить ради этого отдельный секрет незачем."""
        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
            log_login("лимит попыток (рекорды)", kind="block")
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not SSH_GATE_PASSWORD_PREFIX or not isinstance(password, str) or \
                not hmac.compare_digest(password.encode(), console_password_today().encode()):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            log_login("неверный суточный пароль (рекорды)", kind="fail")
            return jsonify(error="Неверный суточный пароль."), 401
        rate_clear(console_login_attempts, console_login_attempts_lock, client)

        game = payload.get("game")
        if game not in ARCADE_GAMES:
            return jsonify(error="Неизвестная игра."), 400
        target = str(payload.get("id", ""))
        with arcade_lock:
            rows = arcade_scores.get(game, [])
            kept = [r for r in rows if r["id"] != target]
            if len(kept) != len(rows):
                arcade_scores[game] = kept
                _arcade_save()
            return jsonify(scores=_arcade_public())

    @home_bp.get("/themes")
    @login_required
    def themes_page():
        """Витрина оформления: разделы кабинета как органы и импланты киборга.
        Своего бэкенда нет — данные берутся из уже существующих эндпоинтов."""
        organs = ["ЛОБНАЯ ДОЛЯ", "ТЕМЕННАЯ ДОЛЯ", "ЗАТЫЛОЧНАЯ ДОЛЯ", "ВИСОЧНАЯ ДОЛЯ",
                  "МОЗЖЕЧОК", "СТВОЛ МОЗГА", "ТАЛАМУС", "ГИПОФИЗ"]
        cols, rows = [60, 330, 600, 870], [250, 420]
        cards = []
        for i, device in enumerate(netbird_devices[:8]):
            left, top = cols[i % 4], rows[i // 4]
            kind = ("SSH" if device.get("ssh_enabled") else
                    "RDP" if device.get("rdp_enabled") else
                    "VNC" if device.get("vnc_enabled") else "—")
            cards.append(
                f'<g class="ncard" style="--i:{i}">'
                f'<path class="ncard-plate" d="M{left} {top + 12} L{left + 12} {top} L{left + 246} {top} '
                f'L{left + 246} {top + 68} L{left + 234} {top + 80} L{left} {top + 80} Z"/>'
                f'<text class="ncard-organ" x="{left + 84}" y="{top + 20}">{organs[i]}</text>'
                f'<text class="ncard-name" x="{left + 84}" y="{top + 38}">{device["name"]}</text>'
                f'<text class="ncard-ip" x="{left + 84}" y="{top + 54}">{device["ip"]}</text>'
                f'<text class="ncard-ping" x="{left + 236}" y="{top + 22}" text-anchor="end" '
                f'data-ping="{device["ip"]}">— — —</text>'
                f'<g class="ncard-btn"><rect x="{left + 84}" y="{top + 60}" width="100" height="16" rx="1"/>'
                f'<text x="{left + 134}" y="{top + 72}" text-anchor="middle">ПОДКЛЮЧИТЬСЯ</text></g>'
                f'<text class="ncard-ip" x="{left + 236}" y="{top + 72}" text-anchor="end">{kind}</text>'
                f'</g>'
            )

        html = template("themes.html")
        return html.replace("__NODES__", "".join(cards)) \
                   .replace("__ICONLINKS__", ICON_LINKS)

    def servers_unlock_page(error=""):
        html = template("servers_unlock.html")
        return html.replace("__ICONLINKS__", ICON_LINKS).replace("__ERROR__", error)

    @home_bp.get("/servers")
    def servers_page():
        """Хозяйство: три машины, их роли и что на них крутится.

        Страница открыта всем, поэтому наружу не выносим ни публичный адрес VPS,
        ни адреса mesh-сети — только домашние 192.168.x, которые одинаковы у
        половины страны и ничего не выдают."""
        if not session.get("servers_authenticated"):
            return servers_unlock_page()
        html = template("servers.html")
        return html.replace("__ICONLINKS__", ICON_LINKS)

    @home_bp.post("/servers/unlock")
    def servers_unlock():
        password = request.form.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), SERVERS_PASSWORD.encode()
        ):
            return servers_unlock_page("Неверный пароль."), 401
        session["servers_authenticated"] = True
        return redirect("/servers")

    @home_bp.route("/")
    def home():
        html = template("home.html")
        for name, svg in game_icons.items():
            html = html.replace("__ICON_%s__" % name.upper(), svg)
        html = html.replace("__ICONLINKS__", ICON_LINKS)
        return html

    return home_bp
