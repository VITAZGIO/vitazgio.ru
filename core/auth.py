"""core/auth.py — вход в кабинет: пароль кабинета, доверенные устройства,
журнал входов, `login_required`, суточный пароль консоли, ограничение
частоты попыток (задачи 34-36).

`password_matches` (задача 36) нужна и `app.py` (свой `/api/login`), и
`blueprints/debts.py` (не даёт завести должника с паролем владельца) —
классический признак того, что место — в core, а не в одном из двух.

Перенесено из `app.py` дословно (то же поведение, те же имена данных —
`docs/structure-plan.md` запрещает менять семантику в рамках этого
разреза). Публичные имена здесь — без ведущего подчёркивания: раньше это
были приватные функции `app.py`, а теперь их напрямую импортируют и
`app.py` (под старыми именами, через `as`, чтобы не трогать полторы сотни
мест, где они уже вызываются), и blueprints (`devices.py` уже берёт их
отсюда напрямую; `debts.py`, `home.py`, `remote.py` пока получают их же
через фабрику из `app.py` — после миграции этих файлов возьмут те же
имена прямо отсюда).

`login_required` — единственный guard, переехавший сюда целиком: он
общий для всего сайта. Более специфичные guard'ы (`debts_owner_required`,
`diy_editor_required`, `music_editor_required` и т.п.) остаются в
`app.py` — они опираются на `device_check`/`DEVICE_COOKIE`/`log_login`
отсюда, но несут свою, ещё не переехавшую сюда логику (свои полки
разблокировки, свои сообщения об ошибке).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

from flask import g, redirect, request, session, url_for

from core.storage import DATA_DIR, atomic_write_json

# ---- Пароль кабинета ---------------------------------------------------------
# Репозиторий публичный, поэтому соль и хэш живут только в .env. Запасных
# значений в коде нет намеренно: раньше они тут лежали, и любой желающий мог
# скачать их вместе с исходниками и спокойно подбирать пароль у себя дома,
# без всяких ограничений на число попыток. Нет переменных — приложение не
# поднимается вовсе; это лучше, чем молча работать с всем известным паролем.
def _password_secret(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(
            f"Не задана переменная {name}. Соль и хэш пароля кабинета хранятся "
            "только в .env — в публичный репозиторий им нельзя. Как получить "
            "новую пару, написано в README, раздел «Пароль кабинета»."
        )
    try:
        return base64.b64decode(raw)
    except (ValueError, TypeError) as e:
        raise SystemExit(f"Переменная {name} не читается как base64: {e}")


PASSWORD_SALT = _password_secret("CABINET_PASSWORD_SALT")
PASSWORD_HASH = _password_secret("CABINET_PASSWORD_HASH")
PASSWORD_ITERATIONS = 600_000


def password_matches(password):
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), PASSWORD_SALT, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(candidate, PASSWORD_HASH)


# ---- Доверенные устройства («запомнить это устройство») ---------------------
# Кука содержит "селектор.валидатор". На сервере лежит только SHA-256 валидатора,
# поэтому утечка файла войти не позволяет. Валидатор периодически перевыпускается
# (не на каждый запрос — см. DEVICE_ROTATE_AFTER): если украденной кукой
# воспользуются, у настоящего устройства токен перестанет подходить — по этому
# признаку запись сносится целиком (с коротким окном прощения на случай, если
# это не кража, а просто несколько параллельных запросов браузера успели
# разъехаться по старой и новой куке — см. DEVICE_GRACE_SECONDS).
DEVICES_PATH = os.path.join(DATA_DIR, "devices.json")
DEVICE_COOKIE = "vitazgio_device"
DEVICE_TTL_DAYS = 90
DEVICE_ROTATE_AFTER = 6 * 3600
DEVICE_GRACE_SECONDS = 60

trusted_devices: dict = {}
devices_lock = threading.Lock()


def client_ip():
    """Реальный адрес клиента.

    Разбором X-Forwarded-For занимается ProxyFix в app.py, и это
    принципиально: раньше здесь бралась левая запись заголовка, а её
    клиент присылает сам — NPM свою дописывает следом, не затирая чужую.
    Так в журнал входов можно было записать любой выдуманный адрес.
    """
    return request.remote_addr or "unknown"


def devices_write():
    """Вызывать под devices_lock."""
    atomic_write_json(DEVICES_PATH, trusted_devices)


def devices_prune_expired():
    """Вызывать под devices_lock. Возвращает число удалённых."""
    now = time.time()
    dead = [s for s, d in trusted_devices.items() if d.get("expires", 0) < now]
    for selector in dead:
        trusted_devices.pop(selector, None)
    return len(dead)


def _devices_load():
    try:
        with open(DEVICES_PATH, encoding="utf-8") as fh:
            trusted_devices.update(json.load(fh))
    except (OSError, ValueError):
        pass
    devices_prune_expired()


def device_label(ua):
    """Имя по User-Agent: точнее браузер не скажет, зато потом можно переименовать."""
    ua = ua or ""
    system = next((name for key, name in (
        ("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iPhone"),
        ("iPad", "iPad"), ("Macintosh", "Mac"), ("Linux", "Linux"),
    ) if key in ua), "Устройство")
    browser = next((name for key, name in (
        ("YaBrowser", "Яндекс"), ("Edg/", "Edge"), ("OPR/", "Opera"),
        ("Firefox", "Firefox"), ("Chrome", "Chrome"), ("Safari", "Safari"),
    ) if key in ua), "браузер")
    return f"{system} · {browser}"


def unique_label(base):
    """Вызывать под devices_lock."""
    taken = {d["label"] for d in trusted_devices.values()}
    if base not in taken:
        return base
    number = 2
    while f"{base} {number}" in taken:
        number += 1
    return f"{base} {number}"


def device_issue(label, ua, ip, selector=None):
    """Выдаёт или продлевает токен (с ротацией валидатора). Вызывать под devices_lock."""
    selector = selector or secrets.token_urlsafe(12)
    validator = secrets.token_urlsafe(32)
    now = time.time()
    previous = trusted_devices.get(selector, {})
    entry = {
        "hash": hashlib.sha256(validator.encode()).hexdigest(),
        "label": previous.get("label") or label,
        "ua": (ua or "")[:160],
        "created": previous.get("created", now),
        "last_used": now,
        "last_ip": ip,
        "expires": now + DEVICE_TTL_DAYS * 86400,
        "rotated": now,
    }
    if previous.get("hash"):
        # Старая кука ещё может лететь к другим параллельным запросам того
        # же браузера (открытие кабинета дёргает сразу несколько ручек) —
        # даём ей недолго прожить, иначе такой запрос выглядел бы как кража.
        entry["prev_hash"] = previous["hash"]
        entry["prev_hash_until"] = now + DEVICE_GRACE_SECONDS
    trusted_devices[selector] = entry
    devices_write()
    return f"{selector}.{validator}"


def device_check(raw):
    """Проверяет куку. При успехе возвращает свежую куку, иначе None."""
    if not raw or "." not in raw:
        return None
    selector, validator = raw.split(".", 1)
    now = time.time()
    with devices_lock:
        record = trusted_devices.get(selector)
        if not record or record.get("expires", 0) < now:
            return None
        expected = hashlib.sha256(validator.encode()).hexdigest()
        if hmac.compare_digest(record["hash"], expected):
            if now - record.get("rotated", record.get("created", now)) < DEVICE_ROTATE_AFTER:
                # Кука свежая — не ротируем валидатор на каждый запрос.
                # Страница кабинета дёргает сразу несколько ручек одной и той
                # же (ещё не обновлённой браузером) кукой; ротация на каждую
                # роняла бы устройство «по кражи» на втором же запросе.
                record["last_used"] = now
                record["last_ip"] = client_ip()
                record["expires"] = now + DEVICE_TTL_DAYS * 86400
                devices_write()
                return raw
            return device_issue(record["label"], record.get("ua", ""), client_ip(), selector)
        prev_hash = record.get("prev_hash")
        if prev_hash and now < record.get("prev_hash_until", 0) and hmac.compare_digest(prev_hash, expected):
            # Параллельный запрос со старой кукой в окне прощения после
            # ротации — не кража, просто ещё не долетевший Set-Cookie.
            return raw
        # Селектор есть, а валидатор чужой — похоже на кражу токена.
        # Сносим запись: оба устройства пойдут вводить пароль заново.
        trusted_devices.pop(selector, None)
        devices_write()
        return None


def device_forget(selector):
    with devices_lock:
        dropped = trusted_devices.pop(selector, None)
        if dropped:
            devices_write()
    return dropped is not None


_devices_load()


# ---- Журнал входов -----------------------------------------------------------
LOGIN_LOG_PATH = os.path.join(DATA_DIR, "login_log.json")
LOGIN_LOG_DAYS = 14          # с запасом: просили хранить не меньше недели
LOGIN_LOG_MAX = 500          # потолок, чтобы файл не рос бесконечно
LOGIN_LOG_MAX_FAIL = 200     # отдельный потолок для неудачных попыток

login_log: list = []
login_log_lock = threading.Lock()


def login_log_trim():
    """Вызывать под login_log_lock: режет старьё по возрасту и по количеству.

    Успехи и провалы урезаются по отдельности. Иначе достаточно было бы
    подолбиться неверным паролем пятьсот раз, чтобы вытеснить из журнала все
    настоящие входы — то есть заодно стереть следы того, что искал.
    """
    edge = time.time() - LOGIN_LOG_DAYS * 86400
    rows = [row for row in login_log if row.get("at", 0) >= edge]
    good = [row for row in rows if row.get("kind", "ok") == "ok"][-LOGIN_LOG_MAX:]
    bad = [row for row in rows if row.get("kind", "ok") != "ok"][-LOGIN_LOG_MAX_FAIL:]
    login_log[:] = sorted(good + bad, key=lambda row: row.get("at", 0))


def _login_log_save():
    """Вызывать под login_log_lock."""
    try:
        atomic_write_json(LOGIN_LOG_PATH, login_log)
    except OSError:
        pass


def _login_log_load():
    try:
        with open(LOGIN_LOG_PATH, encoding="utf-8") as fh:
            login_log.extend(json.load(fh))
    except (OSError, ValueError):
        return
    login_log_trim()


def log_login(note="", kind="ok"):
    """kind: ok — вошли, fail — пароль не подошёл, block — упёрлись в лимит."""
    with login_log_lock:
        ua = request.headers.get("User-Agent", "")[:100]
        login_log.append({
            "at": time.time(),
            "ip": client_ip(),
            "ts": datetime.now(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M:%S"),
            "ua": f"{ua} · {note}" if note else ua,
            "kind": kind,
        })
        login_log_trim()
        _login_log_save()


_login_log_load()


# ---- Guard ---------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            # Пароль не вводили — но устройство могло быть помечено доверенным.
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return redirect(url_for("home.home"))
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


# ---- Ограничение частоты попыток (общая утилита) -----------------------------
# Используется и здесь (нигде выше — счётчик самого пароля кабинета
# остался в app.py, ему core не нужен), и суточным паролем консоли ниже, и
# blueprints (devices.py, debts.py, home.py, remote.py — рекорды аркады,
# доверие устройству, вход в консоль).

def rate_blocked(store, lock, key, window, limit):
    """Не пора ли притормозить этот адрес. Заодно чистит остывшие записи,
    чтобы словарь не рос по одной строке на каждый заглянувший IP."""
    now = time.monotonic()
    with lock:
        for stale, hits in [(k, v) for k, v in store.items() if k != key]:
            if not hits or now - hits[-1] > window:
                store.pop(stale, None)
        attempts = store[key]
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        return len(attempts) >= limit


def rate_hit(store, lock, key):
    with lock:
        store[key].append(time.monotonic())


def rate_clear(store, lock, key):
    with lock:
        store.pop(key, None)


# ---- Суточный пароль консоли -------------------------------------------------
# Второй, независимый от пароля кабинета секрет: открывает SSH-консоль,
# RDP/VNC-оверлеи, файлы по SFTP и (тем же паролем) доверие устройству и
# рекорды аркады — везде, где нужен уровень строже, чем просто «вошёл в
# кабинет». Меняется раз в сутки сам, без .env — только префикс в нём.
SSH_GATE_PASSWORD_PREFIX = os.environ.get("SSH_GATE_PASSWORD_PREFIX")
CONSOLE_LOGIN_WINDOW_SECONDS = 300
CONSOLE_LOGIN_MAX_ATTEMPTS = 5
console_login_attempts = defaultdict(deque)
console_login_attempts_lock = threading.Lock()


def console_password_today():
    now = datetime.now(ZoneInfo("Europe/Moscow"))
    return f"{SSH_GATE_PASSWORD_PREFIX}{now:%d%m}"
