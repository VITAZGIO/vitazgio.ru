import base64
import codecs
import hashlib
import hmac
import io
import json
import math
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

import paramiko
from flask import Flask, Response, g, jsonify, redirect, request, send_file, session, url_for
from flask_sock import Sock
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("VITAZGIO_SESSION_SECRET", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

# Трафик доходит до приложения только через реверс-прокси, поэтому без этой
# обёртки request.remote_addr — всегда адрес прокси: счётчик попыток входа
# получался общим на всех, а схема в ссылках дропа — http вместо https.
# ProxyFix берёт из X-Forwarded-For запись, которую поставил наш собственный
# прокси (крайнюю справа), — снаружи её подделать нельзя, в отличие от левых.
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=TRUSTED_PROXY_HOPS,
    x_proto=TRUSTED_PROXY_HOPS,
    x_host=TRUSTED_PROXY_HOPS,
)

sock = Sock(app)

# Репозиторий публичный, поэтому соль и хэш берём из .env: иначе их можно
# просто скачать и подбирать пароль офлайн. Значения ниже — запасные, на случай
# если переменные не заданы.
PASSWORD_SALT = base64.b64decode(
    os.environ.get("CABINET_PASSWORD_SALT") or "vLsGUQ/owFhcITf4A6CVjw=="
)
PASSWORD_HASH = base64.b64decode(
    os.environ.get("CABINET_PASSWORD_HASH") or "T+E27QxamfCbhsdxJ1JlEXo4yuBwfwQFtw9ODFkA+kg="
)
PASSWORD_ITERATIONS = 600_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
login_attempts = defaultdict(deque)
login_attempts_lock = threading.Lock()

NETBIRD_DEVICES = [
    {"ip": "100.104.18.182", "name": "VitazNout", "rdp_enabled": True},
    {"ip": "100.104.140.4", "name": "VitazComp", "rdp_enabled": True, "wol_mac": "d8:bb:c1:a6:d4:81"},
    {"ip": "100.104.1.172", "name": "windows10proxmox", "rdp_enabled": True},
    {"ip": "100.104.67.89", "name": "orangepizero3", "ssh_enabled": True},
    {"ip": "100.104.221.91", "name": "ubuntu-server", "ssh_enabled": True},
    {"ip": "100.104.160.121", "name": "windows10V", "rdp_enabled": True},
    {"ip": "100.104.111.39", "name": "ubuntuvitaz1", "ssh_enabled": True},
    {"ip": "100.104.86.103", "name": "MOBILA", "vnc_enabled": True},
]
PING_INTERVAL_SECONDS = 10
PING_TIMEOUT_SECONDS = 1
PING_LATENCY_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)

netbird_status = {device["ip"]: {"online": False, "latency_ms": None} for device in NETBIRD_DEVICES}
netbird_status_lock = threading.Lock()
ssh_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("ssh_enabled")}

SSH_GATE_PASSWORD_PREFIX = os.environ.get("SSH_GATE_PASSWORD_PREFIX")

# Дома guacd рядом (127.0.0.1). Если сайт крутится на VPS — сюда
# подставляется Netbird-адрес домашнего сервера.
GUACD_HOST = os.environ.get("GUACD_HOST", "127.0.0.1")
GUACD_PORT = int(os.environ.get("GUACD_PORT", "4822"))
CONSOLE_LOGIN_WINDOW_SECONDS = 300
CONSOLE_LOGIN_MAX_ATTEMPTS = 5
console_login_attempts = defaultdict(deque)
console_login_attempts_lock = threading.Lock()

login_log: list = []
login_log_lock = threading.Lock()
LOGIN_LOG_DAYS = 14          # с запасом: просили хранить не меньше недели
LOGIN_LOG_MAX = 500          # потолок, чтобы файл не рос бесконечно
LOGIN_LOG_MAX_FAIL = 200     # отдельный потолок для неудачных попыток

# Машины для сбора метрик. Первая — та, на которой крутится сам сайт: до неё
# ходить по SSH не нужно, /proc читается локально (контейнер живёт в
# network_mode: host, поэтому видит память и аптайм самого сервера).
METRICS_TARGETS = [
    {
        "ip": "local",
        "name": "vps-amsterdam",
        "local": True,
    },
    {
        "ip": "100.104.67.89",
        "name": "orangepizero3",
        "user_env": "METRICS_ORANGEPI_USER",
        "pass_env": "METRICS_ORANGEPI_PASS",
    },
    {
        "ip": "100.104.221.91",
        "name": "ubuntu-server",
        "user_env": "METRICS_UBUNTUSERVER_USER",
        "pass_env": "METRICS_UBUNTUSERVER_PASS",
    },
]
# ubuntuvitaz1 из сбора метрик убрана намеренно: в Netbird она осталась и
# по SSH к ней по-прежнему ходим, просто датчики по ней больше не снимаем.
METRICS_INTERVAL = 30
METRICS_CPU_SAMPLE = 1  # пауза между двумя замерами /proc/stat, секунды
metrics_data: dict = {t["ip"]: None for t in METRICS_TARGETS}
metrics_lock = threading.Lock()

# Сбор метрик: CPU-строка, пауза, CPU-строка ещё раз, RAM%, disk%, uptime, temp.
# Два замера /proc/stat обязательны: там лежат счётчики, накопленные с момента
# загрузки, и одно их деление даёт среднюю загрузку за весь аптайм — цифру,
# которая почти не двигается. Настоящая загрузка — это разница между замерами.
_METRICS_CMD = (
    "grep '^cpu ' /proc/stat; "
    f"sleep {METRICS_CPU_SAMPLE}; "
    "grep '^cpu ' /proc/stat; "
    "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0)printf \"%.1f\\n\",(t-a)/t*100;else print 0}' /proc/meminfo; "
    "df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %'; "
    "awk '{printf \"%.0f\\n\",$1}' /proc/uptime; "
    # Температура есть не везде; печатаем 0 вместо пустоты, иначе съезжает
    # нумерация строк и disk с uptime подставляются не туда.
    "{ cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0; } "
    "| awk '{printf \"%.1f\\n\",$1/1000}'"
)


def _cpu_busy_total(cpu_line: str):
    """Из строки «cpu user nice system idle iowait …» — (занято, всего) тиков."""
    fields = [float(x) for x in cpu_line.split()[1:] if x.replace(".", "", 1).isdigit()]
    if len(fields) < 4:
        return None
    total = sum(fields)
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
    return total - idle, total


def _cpu_percent(first_line: str, second_line: str):
    """Загрузка между двумя замерами. None, если замеры непригодны."""
    first, second = _cpu_busy_total(first_line), _cpu_busy_total(second_line)
    if not first or not second:
        return None
    busy_delta, total_delta = second[0] - first[0], second[1] - first[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, busy_delta / total_delta * 100)), 1)


def _parse_metrics(lines: list) -> dict:
    """Разбирает вывод _METRICS_CMD. Каждое поле независимо: если конкретная
    машина чего-то не отдала, остальные цифры всё равно доезжают."""

    def at(index):
        return lines[index].strip() if len(lines) > index else ""

    def as_float(text):
        try:
            return float(text)
        except ValueError:
            return None

    temp = as_float(at(5))
    return {
        "cpu": _cpu_percent(at(0), at(1)),
        "ram": as_float(at(2)),
        "disk": int(at(3)) if at(3).isdigit() else None,
        "uptime": int(at(4)) if at(4).isdigit() else None,
        "temp": temp if temp else None,  # 0.0 — это «датчика нет»
        "ts": time.time(),
    }


def _collect_metrics_local() -> dict | None:
    """Метрики машины, на которой работает само приложение."""
    try:
        with open("/proc/stat") as fh:
            first = fh.readline()
        time.sleep(METRICS_CPU_SAMPLE)
        with open("/proc/stat") as fh:
            second = fh.readline()

        meminfo = {}
        with open("/proc/meminfo") as fh:
            for row in fh:
                key, _, rest = row.partition(":")
                meminfo[key] = float(rest.split()[0]) if rest.split() else 0.0
        total, available = meminfo.get("MemTotal", 0), meminfo.get("MemAvailable", 0)

        # Диск смотрим по каталогу приложения: он проброшен с хоста, значит
        # покажет реальный раздел сервера, а не оверлей контейнера.
        usage = shutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
        with open("/proc/uptime") as fh:
            uptime = int(float(fh.read().split()[0]))

        return {
            "cpu": _cpu_percent(first, second),
            "ram": round((total - available) / total * 100, 1) if total else None,
            "disk": round(usage.used / usage.total * 100) if usage.total else None,
            "uptime": uptime,
            "temp": None,
            "ts": time.time(),
        }
    except (OSError, ValueError, ZeroDivisionError):
        return None


def _collect_metrics_for(target: dict) -> dict | None:
    if target.get("local"):
        return _collect_metrics_local()

    user = os.environ.get(target["user_env"])
    passwd = os.environ.get(target["pass_env"])
    if not user or not passwd:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target["ip"], username=user, password=passwd,
                       timeout=6, look_for_keys=False, allow_agent=False)
        # Команда сама спит секунду между замерами CPU — таймаут с запасом.
        _, stdout, _ = client.exec_command(_METRICS_CMD, timeout=8 + METRICS_CPU_SAMPLE)
        return _parse_metrics(stdout.read().decode(errors="replace").splitlines())
    except Exception:
        return None
    finally:
        client.close()


def _metrics_loop():
    while True:
        for target in METRICS_TARGETS:
            data = _collect_metrics_for(target)
            with metrics_lock:
                metrics_data[target["ip"]] = data
        time.sleep(METRICS_INTERVAL)


threading.Thread(target=_metrics_loop, daemon=True).start()

# ---- Личный дроп ------------------------------------------------------------
# Содержимое лежит на диске под именами-uuid, настоящие имена только в индексе.
# Пользовательский текст никогда не попадает в путь, поэтому выйти за пределы
# каталога принципиально нечем. Удаления по времени нет — только вручную,
# ограничителем служит квота.
DROP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drop_data")
DROP_TMP_DIR = os.path.join(DROP_DIR, "tmp")
DROP_INDEX_PATH = os.path.join(DROP_DIR, "index.json")
DROP_QUOTA = 30 * 1024 * 1024 * 1024      # 30 ГБ на весь дроп
DROP_MAX_SIZE = 2 * 1024 * 1024 * 1024    # 2 ГБ на один файл
DROP_CHUNK_TTL = 6 * 3600                 # брошенные недокачки убираем через 6 ч
DROP_TEXT_PREVIEW = 400

drop_items: dict = {}
drop_uploads: dict = {}
drop_lock = threading.Lock()
os.makedirs(DROP_TMP_DIR, exist_ok=True)


def _drop_path(item_id):
    return os.path.join(DROP_DIR, f"{item_id}.bin")


def _drop_tmp_path(upload_id):
    return os.path.join(DROP_TMP_DIR, f"{upload_id}.part")


def _drop_write_index():
    """Вызывать под drop_lock."""
    tmp = DROP_INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(drop_items, fh, ensure_ascii=False)
    os.replace(tmp, DROP_INDEX_PATH)


def _drop_used():
    """Занято байт. Вызывать под drop_lock."""
    return sum(item.get("size", 0) for item in drop_items.values())


def _drop_children(parent):
    """Прямые потомки папки. Вызывать под drop_lock."""
    return [k for k, v in drop_items.items() if v.get("parent") == parent]


# Значки папок. Имя из этого списка сохраняется в индексе, а рисует его
# уже страница — так на сервере не лежит ни байта разметки.
DROP_FOLDER_ICONS = (
    "folder", "warn", "clock", "tree", "monitor", "phone",
    "claude", "vitaz", "star", "lock", "music", "photo",
)


def _drop_folder_stats(item_id, memo=None):
    """Сколько папка весит, сколько в ней всего и когда её трогали в последний
    раз — считая по всему содержимому вглубь. Вызывать под drop_lock.

    Свежесть папки берём по самому свежему файлу внутри: на Windows папка
    считается изменённой, когда правишь её содержимое, и сортировка «сначала
    новые» без этого выглядит враньём."""
    memo = {} if memo is None else memo
    if item_id in memo:
        return memo[item_id]
    memo[item_id] = (0, 0.0, 0)                       # заглушка от петли в индексе
    size = 0
    touched = drop_items.get(item_id, {}).get("created", 0.0)
    count = 0
    for child in _drop_children(item_id):
        node = drop_items[child]
        count += 1
        if node["kind"] == "folder":
            sub_size, sub_touched, sub_count = _drop_folder_stats(child, memo)
            size += sub_size
            count += sub_count
            touched = max(touched, sub_touched)
        else:
            size += node.get("size", 0)
            touched = max(touched, node.get("created", 0.0))
    memo[item_id] = (size, touched, count)
    return memo[item_id]


def _drop_discard(item_id):
    """Удаляет элемент, для папки — вместе со всем содержимым. Под drop_lock."""
    item = drop_items.get(item_id)
    if not item:
        return
    if item["kind"] == "folder":
        for child in _drop_children(item_id):
            _drop_discard(child)
    drop_items.pop(item_id, None)
    for path in (_drop_path(item_id), os.path.join(DROP_DIR, f"{item_id}.thumb")):
        try:
            os.remove(path)
        except OSError:
            pass


def _drop_path_to_root(item_id):
    """Цепочка папок от корня до item_id включительно. Под drop_lock."""
    chain, seen = [], set()
    while item_id and item_id in drop_items and item_id not in seen:
        seen.add(item_id)
        chain.append({"id": item_id, "name": drop_items[item_id]["name"]})
        item_id = drop_items[item_id].get("parent")
    return list(reversed(chain))


def _drop_is_descendant(item_id, maybe_parent):
    """Не пытаются ли переместить папку внутрь самой себя. Под drop_lock."""
    seen = set()
    while maybe_parent and maybe_parent not in seen:
        if maybe_parent == item_id:
            return True
        seen.add(maybe_parent)
        maybe_parent = drop_items.get(maybe_parent, {}).get("parent")
    return False


def _drop_share_lookup(token):
    """Ищет элемент по токену ссылки. Под drop_lock."""
    now = time.time()
    for item_id, item in drop_items.items():
        share = item.get("share")
        # Сравниваем байты: compare_digest падает на строках с не-ASCII,
        # а токен приходит из адресной строки и может быть каким угодно.
        if share and hmac.compare_digest(share["token"].encode(), token.encode()):
            if share["expires"] and share["expires"] < now:
                return None
            return item_id
    return None


def _drop_sweep_uploads():
    """Подчищает брошенные недокачки. Под drop_lock."""
    now = time.time()
    for upload_id in [k for k, v in drop_uploads.items() if now - v["started"] > DROP_CHUNK_TTL]:
        drop_uploads.pop(upload_id, None)
        try:
            os.remove(_drop_tmp_path(upload_id))
        except OSError:
            pass


def _drop_load_index():
    try:
        with open(DROP_INDEX_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        saved = {}

    for item_id, meta in saved.items():
        # Записи старого формата: плоский список файлов без папок и ссылок.
        meta.setdefault("kind", "text" if meta.pop("is_text", False) else "file")
        meta.setdefault("parent", None)
        meta.setdefault("share", None)
        meta.setdefault("size", 0)
        if meta["kind"] == "folder" or os.path.exists(_drop_path(item_id)):
            drop_items[item_id] = meta

    known = set(drop_items)
    for fname in os.listdir(DROP_DIR):
        for suffix in (".bin", ".thumb"):
            if fname.endswith(suffix) and fname[: -len(suffix)] not in known:
                try:
                    os.remove(os.path.join(DROP_DIR, fname))
                except OSError:
                    pass
    for fname in os.listdir(DROP_TMP_DIR):
        try:
            os.remove(os.path.join(DROP_TMP_DIR, fname))
        except OSError:
            pass

    # Потерянные родители: папку могли удалить в обход рекурсии.
    for item in drop_items.values():
        if item["parent"] and item["parent"] not in drop_items:
            item["parent"] = None
    _drop_write_index()


_drop_load_index()

# ---- Доверенные устройства («запомнить это устройство») ---------------------
# Кука содержит "селектор.валидатор". На сервере лежит только SHA-256 валидатора,
# поэтому утечка файла войти не позволяет. При каждом входе валидатор
# перевыпускается: если украденной кукой воспользуются, у настоящего устройства
# токен перестанет подходить — по этому признаку запись сносится целиком.
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DEVICES_PATH = os.path.join(DATA_DIR, "devices.json")
DEVICE_COOKIE = "vitazgio_device"
DEVICE_TTL_DAYS = 90

trusted_devices: dict = {}
devices_lock = threading.Lock()
os.makedirs(DATA_DIR, exist_ok=True)

# ---- Музыка для плеера в кабинете ------------------------------------------
# Файлы лежат под своими именами в data/music — так их можно просто закинуть
# в папку по SSH, и плеер подхватит сам, разобрав «Исполнитель - Название».
MUSIC_DIR = os.path.join(DATA_DIR, "music")
MUSIC_INDEX_PATH = os.path.join(DATA_DIR, "music.json")
MUSIC_MAX_SIZE = 40 * 1024 * 1024
MUSIC_QUOTA = 2 * 1024 * 1024 * 1024
MUSIC_EXTS = {".mp3", ".m4a", ".aac", ".ogg", ".opus", ".flac", ".wav", ".webm"}
MUSIC_MIMES = {
    ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac",
    ".ogg": "audio/ogg", ".opus": "audio/ogg", ".flac": "audio/flac",
    ".wav": "audio/wav", ".webm": "audio/webm",
}

music_items: dict = {}
music_lock = threading.Lock()
os.makedirs(MUSIC_DIR, exist_ok=True)


def _music_safe_name(name):
    """Имя файла без путей и запрещённых символов. secure_filename не годится —
    он выбрасывает кириллицу, а треки как раз названы по-русски."""
    name = os.path.basename(name or "")
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name).strip(" .")
    return name[:120] or "track"


def _music_split(stem):
    """«Исполнитель - Название» → пара. Разделителем может быть дефис или тире."""
    for sep in (" — ", " – ", " - ", " -", "- "):
        if sep in stem:
            left, _, right = stem.partition(sep)
            if left.strip() and right.strip():
                return left.strip()[:80], right.strip()[:120]
    return "", stem.strip()[:120]


def _music_write_index():
    """Вызывать под music_lock."""
    try:
        tmp = MUSIC_INDEX_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(music_items, fh, ensure_ascii=False)
        os.replace(tmp, MUSIC_INDEX_PATH)
    except OSError:
        pass


def _music_scan():
    """Синхронизирует индекс с папкой: подхватывает закинутое руками,
    выбрасывает записи об исчезнувших файлах. Вызывать под music_lock."""
    try:
        on_disk = {f for f in os.listdir(MUSIC_DIR)
                   if os.path.splitext(f)[1].lower() in MUSIC_EXTS}
    except OSError:
        return

    for track_id in [k for k, v in music_items.items() if v["file"] not in on_disk]:
        music_items.pop(track_id, None)

    known = {v["file"] for v in music_items.values()}
    for fname in sorted(on_disk - known):
        artist, title = _music_split(os.path.splitext(fname)[0])
        try:
            size = os.path.getsize(os.path.join(MUSIC_DIR, fname))
        except OSError:
            continue
        music_items[str(uuid.uuid4())] = {
            "file": fname, "artist": artist, "title": title,
            "size": size, "added": time.time(),
        }


def _music_load():
    try:
        with open(MUSIC_INDEX_PATH, encoding="utf-8") as fh:
            music_items.update(json.load(fh))
    except (OSError, ValueError):
        pass
    _music_scan()
    _music_write_index()


_music_load()


def _client_ip():
    """Реальный адрес клиента.

    Разбором X-Forwarded-For занимается ProxyFix выше, и это принципиально:
    раньше здесь бралась левая запись заголовка, а её клиент присылает сам —
    NPM свою дописывает следом, не затирая чужую. Так в журнал входов можно
    было записать любой выдуманный адрес.
    """
    return request.remote_addr or "unknown"


def _rate_blocked(store, lock, key, window, limit):
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


def _rate_hit(store, lock, key):
    with lock:
        store[key].append(time.monotonic())


def _rate_clear(store, lock, key):
    with lock:
        store.pop(key, None)


def _devices_write():
    """Вызывать под devices_lock."""
    tmp = DEVICES_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(trusted_devices, fh, ensure_ascii=False)
    os.replace(tmp, DEVICES_PATH)


def _devices_prune_expired():
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
    _devices_prune_expired()


def _device_label(ua):
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


def _unique_label(base):
    """Вызывать под devices_lock."""
    taken = {d["label"] for d in trusted_devices.values()}
    if base not in taken:
        return base
    number = 2
    while f"{base} {number}" in taken:
        number += 1
    return f"{base} {number}"


def _device_issue(label, ua, ip, selector=None):
    """Выдаёт или продлевает токен. Вызывать под devices_lock."""
    selector = selector or secrets.token_urlsafe(12)
    validator = secrets.token_urlsafe(32)
    now = time.time()
    previous = trusted_devices.get(selector, {})
    trusted_devices[selector] = {
        "hash": hashlib.sha256(validator.encode()).hexdigest(),
        "label": previous.get("label") or label,
        "ua": (ua or "")[:160],
        "created": previous.get("created", now),
        "last_used": now,
        "last_ip": ip,
        "expires": now + DEVICE_TTL_DAYS * 86400,
    }
    _devices_write()
    return f"{selector}.{validator}"


def _device_check(raw):
    """Проверяет куку. При успехе возвращает свежую куку, иначе None."""
    if not raw or "." not in raw:
        return None
    selector, validator = raw.split(".", 1)
    with devices_lock:
        record = trusted_devices.get(selector)
        if not record or record.get("expires", 0) < time.time():
            return None
        expected = hashlib.sha256(validator.encode()).hexdigest()
        if not hmac.compare_digest(record["hash"], expected):
            # Селектор есть, а валидатор чужой — похоже на кражу токена.
            # Сносим запись: оба устройства пойдут вводить пароль заново.
            trusted_devices.pop(selector, None)
            _devices_write()
            return None
        return _device_issue(record["label"], record.get("ua", ""), _client_ip(), selector)


def _device_forget(selector):
    with devices_lock:
        dropped = trusted_devices.pop(selector, None)
        if dropped:
            _devices_write()
    return dropped is not None


_devices_load()



def console_password_today():
    now = datetime.now(ZoneInfo("Europe/Moscow"))
    return f"{SSH_GATE_PASSWORD_PREFIX}{now:%d%m}"


def ping_once(ip):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_SECONDS * 1000), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=PING_TIMEOUT_SECONDS + 1
        )
    except (subprocess.TimeoutExpired, OSError):
        return False, None
    if result.returncode != 0:
        return False, None
    match = PING_LATENCY_RE.search(result.stdout)
    return True, float(match.group(1)) if match else None


def netbird_ping_loop():
    while True:
        for device in NETBIRD_DEVICES:
            online, latency_ms = ping_once(device["ip"])
            with netbird_status_lock:
                netbird_status[device["ip"]] = {"online": online, "latency_ms": latency_ms}
        time.sleep(PING_INTERVAL_SECONDS)


threading.Thread(target=netbird_ping_loop, daemon=True).start()


# ---- Рекорды аркады --------------------------------------------------------
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
ARCADE_NAME_BAD = re.compile("[\x00-\x1f\x7f\u200b-\u200f\u2028-\u202e\u2066-\u2069]")


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
        tmp = ARCADE_SCORES_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(arcade_scores, fh, ensure_ascii=False)
        os.replace(tmp, ARCADE_SCORES_PATH)
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


LOGIN_LOG_PATH = os.path.join(DATA_DIR, "login_log.json")


def _login_log_trim():
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
        tmp = LOGIN_LOG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(login_log, fh, ensure_ascii=False)
        os.replace(tmp, LOGIN_LOG_PATH)
    except OSError:
        pass


def _login_log_load():
    try:
        with open(LOGIN_LOG_PATH, encoding="utf-8") as fh:
            login_log.extend(json.load(fh))
    except (OSError, ValueError):
        return
    _login_log_trim()


def _log_login(note="", kind="ok"):
    """kind: ok — вошли, fail — пароль не подошёл, block — упёрлись в лимит."""
    with login_log_lock:
        ua = request.headers.get("User-Agent", "")[:100]
        login_log.append({
            "at": time.time(),
            "ip": _client_ip(),
            "ts": datetime.now(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M:%S"),
            "ua": f"{ua} · {note}" if note else ua,
            "kind": kind,
        })
        _login_log_trim()
        _login_log_save()


_login_log_load()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            # Пароль не вводили — но устройство могло быть помечено доверенным.
            fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return redirect(url_for("home"))
            session["authenticated"] = True
            g.new_device_cookie = fresh
            _log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


def password_matches(password):
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), PASSWORD_SALT, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(candidate, PASSWORD_HASH)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    token = getattr(g, "new_device_cookie", None)
    if token:
        response.set_cookie(
            DEVICE_COOKIE, token,
            max_age=DEVICE_TTL_DAYS * 86400,
            httponly=True,
            samesite="Lax",  # Strict не отправился бы при переходе по ссылке извне
            secure=app.config["SESSION_COOKIE_SECURE"],
        )
    if getattr(g, "clear_device_cookie", False):
        response.delete_cookie(DEVICE_COOKIE, samesite="Lax")
    return response


@app.post("/api/login")
def login():
    client = _client_ip()

    if _rate_blocked(login_attempts, login_attempts_lock, client,
                     LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
        _log_login("лимит попыток", kind="block")
        return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not password_matches(password):
        _rate_hit(login_attempts, login_attempts_lock, client)
        _log_login("неверный пароль", kind="fail")
        return jsonify(error="Неверный пароль."), 401

    _rate_clear(login_attempts, login_attempts_lock, client)
    session.clear()
    session["authenticated"] = True
    session.permanent = False
    _log_login()
    return jsonify(redirect=url_for("cabinet"))


@app.post("/logout")
def logout():
    # Доверие устройству намеренно переживает выход: «Выйти» закрывает кабинет,
    # а не отзывает устройство. Отзыв — снять галку или нажать корзину в списке.
    session.clear()
    return redirect(url_for("home"))


@app.get("/api/session/probe")
def session_probe():
    """Помнит ли сервер это устройство. Токен не расходуется и не ротируется.
    Несовпадение валидатора здесь намеренно НЕ удаляет запись: эндпоинт открыт
    без авторизации, иначе его можно было бы использовать для сноса токенов."""
    if session.get("authenticated"):
        return jsonify(trusted=True)
    raw = request.cookies.get(DEVICE_COOKIE) or ""
    if "." not in raw:
        return jsonify(trusted=False)
    selector, validator = raw.split(".", 1)
    with devices_lock:
        record = trusted_devices.get(selector)
        trusted = bool(
            record
            and record.get("expires", 0) > time.time()
            and hmac.compare_digest(record["hash"], hashlib.sha256(validator.encode()).hexdigest())
        )
    return jsonify(trusted=trusted)


@app.get("/api/netbird/status")
@login_required
def netbird_status_api():
    with netbird_status_lock:
        return jsonify(netbird_status)


@app.post("/api/console/login")
@login_required
def console_login():
    if not SSH_GATE_PASSWORD_PREFIX:
        return jsonify(error="Консоль не настроена."), 503

    client = _client_ip()
    if _rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                     CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
        return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not hmac.compare_digest(
        password.encode(), console_password_today().encode()
    ):
        _rate_hit(console_login_attempts, console_login_attempts_lock, client)
        _log_login("неверный суточный пароль (консоль)", kind="fail")
        return jsonify(error="Неверный пароль."), 401

    _rate_clear(console_login_attempts, console_login_attempts_lock, client)
    session["console_authenticated"] = True
    return jsonify(ok=True)


@sock.route("/ws/console/<ip>")
def console_ws(ws, ip):
    if not session.get("authenticated") or not session.get("console_authenticated"):
        ws.close()
        return
    if ip not in ssh_enabled_ips:
        ws.close()
        return

    message = ws.receive(timeout=15)
    try:
        auth = json.loads(message) if message else {}
    except ValueError:
        auth = {}
    username = auth.get("username") if auth.get("type") == "auth" else None
    password = auth.get("password") if auth.get("type") == "auth" else None
    if not username or not password:
        ws.close()
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False
        )
    except (paramiko.SSHException, OSError):
        ws.send(json.dumps({"type": "data", "data": "\r\nНе удалось подключиться (проверь логин/пароль).\r\n"}))
        ws.close()
        return

    client.get_transport().set_keepalive(20)
    channel = client.invoke_shell(term="xterm")
    channel.settimeout(0.0)

    stop_event = threading.Event()

    def pump_channel_to_ws():
        try:
            while not stop_event.is_set():
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    ws.send(json.dumps({"type": "data", "data": chunk.decode(errors="replace")}))
                else:
                    time.sleep(0.03)
                if channel.closed:
                    break
        except Exception:
            pass
        finally:
            stop_event.set()

    reader = threading.Thread(target=pump_channel_to_ws, daemon=True)
    reader.start()

    def ssh_keepalive():
        while not stop_event.is_set():
            time.sleep(10)
            if stop_event.is_set():
                break
            try:
                ws.send(json.dumps({"type": "ping"}))
            except Exception:
                stop_event.set()

    threading.Thread(target=ssh_keepalive, daemon=True).start()

    try:
        while not stop_event.is_set():
            message = ws.receive(timeout=120)
            if message is None:
                continue
            try:
                payload = json.loads(message)
            except ValueError:
                continue
            ptype = payload.get("type")
            if ptype == "data":
                channel.send(payload.get("data", ""))
            elif ptype == "resize":
                cols = int(payload.get("cols", 80))
                rows = int(payload.get("rows", 24))
                channel.resize_pty(width=cols, height=rows)
            elif ptype == "ping":
                ws.send(json.dumps({"type": "pong"}))
    except Exception:
        pass
    finally:
        stop_event.set()
        channel.close()
        client.close()


rdp_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("rdp_enabled")}
vnc_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("vnc_enabled")}


def _guac_encode(*args):
    parts = [f"{len(str(a))}.{a}" for a in args]
    return (",".join(parts) + ";").encode()


def _guac_recv_instr(sock_file):
    parts = []
    buf = ""
    while True:
        while "." not in buf:
            ch = sock_file.read(1)
            if not ch:
                raise ConnectionError("guacd closed")
            buf += ch.decode()
        dot = buf.index(".")
        length = int(buf[:dot])
        buf = buf[dot + 1:]
        while len(buf) < length:
            ch = sock_file.read(1)
            if not ch:
                raise ConnectionError("guacd closed")
            buf += ch.decode()
        parts.append(buf[:length])
        buf = buf[length:]
        while not buf:
            ch = sock_file.read(1)
            if not ch:
                raise ConnectionError("guacd closed")
            buf += ch.decode()
        sep, buf = buf[0], buf[1:]
        if sep == ";":
            return parts


# Пресеты качества RDP. Чем ниже качество, тем меньше данных по каналу:
# срезаем глубину цвета и отключаем украшения рабочего стола.
RDP_QUALITY = {
    "high": {"color-depth": "32", "enable-wallpaper": "true", "enable-theming": "true",
             "enable-font-smoothing": "true", "enable-full-window-drag": "true",
             "enable-desktop-composition": "true", "enable-menu-animations": "true"},
    "medium": {"color-depth": "16", "enable-wallpaper": "false", "enable-theming": "true",
               "enable-font-smoothing": "true", "enable-full-window-drag": "false",
               "enable-desktop-composition": "false", "enable-menu-animations": "false"},
    "low": {"color-depth": "8", "enable-wallpaper": "false", "enable-theming": "false",
            "enable-font-smoothing": "false", "enable-full-window-drag": "false",
            "enable-desktop-composition": "false", "enable-menu-animations": "false"},
}


def _guac_handshake(guac_sock, hostname, username, password, width, height, quality="medium"):
    f = guac_sock.makefile("rb", buffering=0)
    guac_sock.sendall(_guac_encode("select", "rdp"))
    instr = _guac_recv_instr(f)
    if not instr or instr[0] != "args":
        raise ValueError(f"expected args, got {instr}")
    arg_names = instr[1:]
    guac_sock.sendall(_guac_encode("size", str(width), str(height), "96"))
    guac_sock.sendall(_guac_encode("audio"))
    guac_sock.sendall(_guac_encode("video"))
    guac_sock.sendall(_guac_encode("image", "image/png", "image/jpeg"))
    rdp_params = {
        "hostname": hostname,
        "port": "3389",
        "username": username,
        "password": password,
        "ignore-cert": "true",
        "security": "any",
        "width": str(width),
        "height": str(height),
        "dpi": "96",
    }
    rdp_params.update(RDP_QUALITY.get(quality, RDP_QUALITY["medium"]))
    connect_values = [rdp_params.get(name, "") for name in arg_names]
    guac_sock.sendall(_guac_encode("connect", *connect_values))


@sock.route("/ws/rdp/<ip>")
def rdp_ws(ws, ip):
    if not session.get("authenticated") or not session.get("console_authenticated"):
        ws.close()
        return
    if ip not in rdp_enabled_ips:
        ws.close()
        return

    message = ws.receive(timeout=15)
    try:
        auth = json.loads(message) if message else {}
    except ValueError:
        auth = {}
    if auth.get("type") != "auth":
        ws.close()
        return
    username = auth.get("username")
    password = auth.get("password")
    width = int(auth.get("width", 1280))
    height = int(auth.get("height", 720))
    quality = auth.get("quality") if auth.get("quality") in RDP_QUALITY else "medium"
    if not username or not password:
        ws.close()
        return

    try:
        guac_sock = socket.create_connection((GUACD_HOST, GUACD_PORT), timeout=5)
    except OSError as e:
        print(f"[rdp] guacd connect error ({ip}): {e}", flush=True)
        ws.close()
        return

    try:
        _guac_handshake(guac_sock, ip, username, password, width, height, quality)
    except Exception as e:
        print(f"[rdp] handshake error ({ip}): {e}", flush=True)
        guac_sock.close()
        ws.close()
        return

    # After handshake, switch to short recv timeout so the pump thread
    # can periodically check stop_event when the screen is static.
    # Without this, create_connection's timeout=5 causes recv() to raise
    # socket.timeout after 5 s of idle screen, silently killing the session.
    guac_sock.settimeout(2.0)

    stop_event = threading.Event()

    def pump_guac_to_ws():
        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            while not stop_event.is_set():
                try:
                    data = guac_sock.recv(8192)
                except socket.timeout:
                    continue  # screen idle — no data from guacd, keep waiting
                if not data:
                    print(f"[rdp] guacd closed connection ({ip})", flush=True)
                    break
                text = decoder.decode(data)
                if text:
                    ws.send(text)
        except Exception as e:
            print(f"[rdp] pump error ({ip}): {e}", flush=True)
        finally:
            stop_event.set()

    threading.Thread(target=pump_guac_to_ws, daemon=True).start()

    def rdp_keepalive():
        while not stop_event.is_set():
            time.sleep(10)
            if stop_event.is_set():
                break
            try:
                ws.send("3.nop;")
            except Exception:
                stop_event.set()

    threading.Thread(target=rdp_keepalive, daemon=True).start()

    try:
        while not stop_event.is_set():
            message = ws.receive(timeout=120)
            if message is None:
                continue
            guac_sock.sendall(message.encode() if isinstance(message, str) else message)
    except Exception as e:
        print(f"[rdp] ws error ({ip}): {e}", flush=True)
    finally:
        stop_event.set()
        guac_sock.close()


def _guac_handshake_vnc(guac_sock, hostname, password, width, height):
    f = guac_sock.makefile("rb", buffering=0)
    guac_sock.sendall(_guac_encode("select", "vnc"))
    instr = _guac_recv_instr(f)
    if not instr or instr[0] != "args":
        raise ValueError(f"expected args, got {instr}")
    arg_names = instr[1:]
    guac_sock.sendall(_guac_encode("size", str(width), str(height), "96"))
    guac_sock.sendall(_guac_encode("audio"))
    guac_sock.sendall(_guac_encode("video"))
    guac_sock.sendall(_guac_encode("image", "image/png", "image/jpeg"))
    vnc_params = {
        "hostname": hostname,
        "port": "5900",
        "password": password,
        "color-depth": "24",
        "encodings": "zrle ultra copyrect hextile zlib corre rre raw",
    }
    connect_values = [vnc_params.get(name, "") for name in arg_names]
    guac_sock.sendall(_guac_encode("connect", *connect_values))


@sock.route("/ws/vnc/<ip>")
def vnc_ws(ws, ip):
    if not session.get("authenticated") or not session.get("console_authenticated"):
        ws.close()
        return
    if ip not in vnc_enabled_ips:
        ws.close()
        return

    message = ws.receive(timeout=15)
    try:
        auth = json.loads(message) if message else {}
    except ValueError:
        auth = {}
    if auth.get("type") != "auth":
        ws.close()
        return
    password = auth.get("password", "")
    width = int(auth.get("width", 1280))
    height = int(auth.get("height", 720))

    try:
        guac_sock = socket.create_connection((GUACD_HOST, GUACD_PORT), timeout=5)
    except OSError as e:
        print(f"[vnc] guacd connect error ({ip}): {e}", flush=True)
        ws.close()
        return

    try:
        _guac_handshake_vnc(guac_sock, ip, password, width, height)
    except Exception as e:
        print(f"[vnc] handshake error ({ip}): {e}", flush=True)
        guac_sock.close()
        ws.close()
        return

    guac_sock.settimeout(2.0)
    stop_event = threading.Event()

    def pump_guac_to_ws():
        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            while not stop_event.is_set():
                try:
                    data = guac_sock.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    break
                text = decoder.decode(data)
                if text:
                    ws.send(text)
        except Exception as e:
            print(f"[vnc] pump error ({ip}): {e}", flush=True)
        finally:
            stop_event.set()

    threading.Thread(target=pump_guac_to_ws, daemon=True).start()

    def vnc_keepalive():
        while not stop_event.is_set():
            time.sleep(10)
            if stop_event.is_set():
                break
            try:
                ws.send("3.nop;")
            except Exception:
                stop_event.set()

    threading.Thread(target=vnc_keepalive, daemon=True).start()

    try:
        while not stop_event.is_set():
            message = ws.receive(timeout=120)
            if message is None:
                continue
            guac_sock.sendall(message.encode() if isinstance(message, str) else message)
    except Exception as e:
        print(f"[vnc] ws error ({ip}): {e}", flush=True)
    finally:
        stop_event.set()
        guac_sock.close()


@app.get("/api/metrics")
@login_required
def metrics_api():
    with metrics_lock:
        result = []
        for t in METRICS_TARGETS:
            d = metrics_data.get(t["ip"])
            result.append({"ip": t["ip"], "name": t["name"], "data": d})
    return jsonify(result)


@app.post("/api/pc/shutdown")
@login_required
def pc_shutdown():
    host = os.environ.get("PC_SHUTDOWN_HOST")
    user = os.environ.get("PC_SHUTDOWN_USER")
    key_path = os.environ.get("PC_SHUTDOWN_KEY")
    if not host or not user or not key_path:
        return jsonify(error="PC_SHUTDOWN_* не настроены в .env"), 503
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, key_filename=key_path,
                       timeout=6, look_for_keys=False, allow_agent=False)
        client.exec_command("shutdown /s /t 0")
        client.close()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e)), 500


WOL_RELAY_HOST = os.environ.get("WOL_RELAY_HOST", "100.104.221.91")   # домашний сервер
WOL_RELAY_USER = os.environ.get("WOL_RELAY_USER") or os.environ.get("METRICS_UBUNTUSERVER_USER")
WOL_RELAY_PASS = os.environ.get("WOL_RELAY_PASS") or os.environ.get("METRICS_UBUNTUSERVER_PASS")
WOL_BROADCASTS = ("255.255.255.255", "192.168.1.255")


def _wol_relay(hex_packet):
    """Шлёт пакет с машины, стоящей в домашней сети.

    Само приложение живёт в Амстердаме, а «магический пакет» — широковещательный:
    он расходится только по той подсети, откуда отправлен, и до домашнего ПК
    не долетает. Поэтому отправку выполняет постоянно включённый хост дома.
    """
    if not (WOL_RELAY_USER and WOL_RELAY_PASS):
        return "Ретранслятор не настроен: нет WOL_RELAY_USER/PASS."
    targets = ";".join(f"s.sendto(p,('{addr}',9))" for addr in WOL_BROADCASTS)
    command = (
        "python3 -c \"import socket;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);"
        f"p=bytes.fromhex('{hex_packet}');{targets}\""
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(WOL_RELAY_HOST, username=WOL_RELAY_USER, password=WOL_RELAY_PASS,
                       timeout=8, look_for_keys=False, allow_agent=False)
        _, _, stderr = client.exec_command(command, timeout=8)
        problem = stderr.read().decode("utf-8", "replace").strip()
        return problem or None
    except Exception as e:
        return f"{WOL_RELAY_HOST}: {e}"
    finally:
        client.close()


@app.post("/api/wol")
@login_required
def wol():
    payload = request.get_json(silent=True) or {}
    mac = payload.get("mac", "")
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        return jsonify(error="Неверный MAC-адрес."), 400

    packet_hex = "ff" * 6 + (mac_clean.lower() * 16)
    problem = _wol_relay(packet_hex)
    if problem:
        return jsonify(error=f"Не удалось разбудить: {problem}"), 502

    # Заодно шлём из своей подсети — на случай, если приложение всё-таки
    # окажется в одной сети с машиной.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for addr in WOL_BROADCASTS:
                s.sendto(bytes.fromhex(packet_hex), (addr, 9))
    except OSError:
        pass
    return jsonify(ok=True)


@app.get("/api/uptime")
@login_required
def uptime_api():
    try:
        with open("/proc/uptime") as f:
            seconds = int(float(f.read().split()[0]))
        return jsonify(seconds=seconds)
    except Exception:
        return jsonify(seconds=None)


@app.get("/api/login-log")
@login_required
def login_log_api():
    with login_log_lock:
        _login_log_trim()
        return jsonify(list(reversed(login_log)))


# ---- Рекорды аркады: без пароля, аркада ведь тоже открыта -------------------
@app.get("/api/arcade/scores")
def arcade_scores_api():
    with arcade_lock:
        return jsonify(
            scores=_arcade_public(),
            games={g: {"title": m["title"], "order": m["order"], "unit": m["unit"]}
                   for g, m in ARCADE_GAMES.items()},
        )


@app.post("/api/arcade/scores")
def arcade_score_add():
    client = _client_ip()
    if _rate_blocked(arcade_submit_attempts, arcade_submit_lock, client,
                     ARCADE_SUBMIT_WINDOW, ARCADE_SUBMIT_MAX):
        return jsonify(error="Слишком часто. Попробуйте позже."), 429
    _rate_hit(arcade_submit_attempts, arcade_submit_lock, client)

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


@app.post("/api/arcade/scores/delete")
def arcade_score_delete():
    """Чистка таблицы от неприличных ников. Пускаем по тому же суточному
    паролю, что и в консоль, — заводить ради этого отдельный секрет незачем."""
    client = _client_ip()
    if _rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                     CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
        _log_login("лимит попыток (рекорды)", kind="block")
        return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not SSH_GATE_PASSWORD_PREFIX or not isinstance(password, str) or \
            not hmac.compare_digest(password.encode(), console_password_today().encode()):
        _rate_hit(console_login_attempts, console_login_attempts_lock, client)
        _log_login("неверный суточный пароль (рекорды)", kind="fail")
        return jsonify(error="Неверный суточный пароль."), 401
    _rate_clear(console_login_attempts, console_login_attempts_lock, client)

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


@app.get("/api/music")
@login_required
def music_list_api():
    with music_lock:
        _music_scan()
        _music_write_index()
        used = sum(t["size"] for t in music_items.values())
        tracks = [
            {"id": k, "artist": v["artist"], "title": v["title"],
             "size": v["size"], "added": v["added"]}
            for k, v in sorted(music_items.items(),
                               key=lambda x: (x[1]["artist"].lower(), x[1]["title"].lower()))
        ]
    return jsonify(tracks=tracks, used=used, quota=MUSIC_QUOTA)


@app.post("/api/music")
@login_required
def music_upload_api():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Файл не выбран."), 400
    name = _music_safe_name(f.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in MUSIC_EXTS:
        return jsonify(error="Это не музыка."), 415
    if request.content_length and request.content_length > MUSIC_MAX_SIZE + 8192:
        return jsonify(error="Трек больше 40 МБ."), 413

    with music_lock:
        _music_scan()
        if sum(t["size"] for t in music_items.values()) > MUSIC_QUOTA:
            return jsonify(error="Места под музыку больше нет."), 507
        taken = {t["file"] for t in music_items.values()}

    stem, suffix = os.path.splitext(name)
    candidate, counter = name, 2
    while candidate in taken or os.path.exists(os.path.join(MUSIC_DIR, candidate)):
        candidate = f"{stem} ({counter}){suffix}"
        counter += 1

    path = os.path.join(MUSIC_DIR, candidate)
    try:
        f.save(path)
        size = os.path.getsize(path)
    except OSError as e:
        return jsonify(error=f"Не удалось сохранить: {e}"), 500
    if size > MUSIC_MAX_SIZE:
        try:
            os.remove(path)
        except OSError:
            pass
        return jsonify(error="Трек больше 40 МБ."), 413

    artist, title = _music_split(os.path.splitext(candidate)[0])
    track_id = str(uuid.uuid4())
    with music_lock:
        music_items[track_id] = {"file": candidate, "artist": artist, "title": title,
                                 "size": size, "added": time.time()}
        _music_write_index()
    return jsonify(id=track_id, artist=artist, title=title)


@app.patch("/api/music/<track_id>")
@login_required
def music_rename_api(track_id):
    payload = request.get_json(silent=True) or {}
    with music_lock:
        track = music_items.get(track_id)
        if not track:
            return jsonify(error="Трек не найден."), 404
        if "artist" in payload:
            track["artist"] = (payload.get("artist") or "").strip()[:80]
        if "title" in payload:
            title = (payload.get("title") or "").strip()[:120]
            if not title:
                return jsonify(error="Название пустое."), 400
            track["title"] = title
        _music_write_index()
        return jsonify(ok=True, artist=track["artist"], title=track["title"])


@app.delete("/api/music/<track_id>")
@login_required
def music_delete_api(track_id):
    with music_lock:
        track = music_items.pop(track_id, None)
        if track:
            try:
                os.remove(os.path.join(MUSIC_DIR, track["file"]))
            except OSError:
                pass
            _music_write_index()
    return jsonify(ok=True)


@app.get("/api/music/file/<track_id>")
@login_required
def music_file_api(track_id):
    with music_lock:
        track = music_items.get(track_id)
    if not track:
        return "", 404
    # Имя берём только из индекса — из адреса в путь не попадает ничего.
    path = os.path.join(MUSIC_DIR, track["file"])
    if not os.path.exists(path):
        return "", 404
    ext = os.path.splitext(track["file"])[1].lower()
    return send_file(path, mimetype=MUSIC_MIMES.get(ext, "audio/mpeg"), conditional=True)


@app.post("/api/devices/trust")
@login_required
def device_trust():
    if not SSH_GATE_PASSWORD_PREFIX:
        return jsonify(error="Суточный пароль не настроен на сервере."), 503

    client = _client_ip()
    if _rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                     CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
        return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    password = (request.get_json(silent=True) or {}).get("password", "")
    if not isinstance(password, str) or not hmac.compare_digest(
        password.encode(), console_password_today().encode()
    ):
        _rate_hit(console_login_attempts, console_login_attempts_lock, client)
        _log_login("неверный суточный пароль (доверие устройству)", kind="fail")
        return jsonify(error="Неверный суточный пароль."), 401

    _rate_clear(console_login_attempts, console_login_attempts_lock, client)

    ua = request.headers.get("User-Agent", "")
    raw = request.cookies.get(DEVICE_COOKIE) or ""
    selector = raw.split(".", 1)[0] if "." in raw else None
    with devices_lock:
        _devices_prune_expired()
        if selector not in trusted_devices:
            selector = None
        label = trusted_devices[selector]["label"] if selector else _unique_label(_device_label(ua))
        g.new_device_cookie = _device_issue(label, ua, _client_ip(), selector)
    return jsonify(ok=True, label=label)


@app.get("/api/devices")
@login_required
def devices_list_api():
    current = (request.cookies.get(DEVICE_COOKIE) or "").split(".", 1)[0]
    with devices_lock:
        if _devices_prune_expired():
            _devices_write()
        items = [
            {"id": selector, "label": d["label"], "last_used": d["last_used"],
             "last_ip": d.get("last_ip", ""), "created": d["created"],
             "current": selector == current}
            for selector, d in sorted(trusted_devices.items(), key=lambda x: -x[1]["last_used"])
        ]
    return jsonify(items)


@app.patch("/api/devices/<selector>")
@login_required
def device_rename_api(selector):
    label = ((request.get_json(silent=True) or {}).get("label") or "").strip()[:40]
    if not label:
        return jsonify(error="Пустое имя."), 400
    with devices_lock:
        if selector not in trusted_devices:
            return jsonify(error="Устройство не найдено."), 404
        trusted_devices[selector]["label"] = label
        _devices_write()
    return jsonify(ok=True, label=label)


@app.delete("/api/devices/<selector>")
@login_required
def device_forget_api(selector):
    removed = _device_forget(selector)
    if removed and (request.cookies.get(DEVICE_COOKIE) or "").split(".", 1)[0] == selector:
        g.clear_device_cookie = True
    return jsonify(ok=True)


def _drop_thumb_path(item_id):
    return os.path.join(DROP_DIR, f"{item_id}.thumb")


def _drop_can_thumb(item):
    """Миниатюры делаем только для растровых картинок. SVG сюда не пускаем:
    это документ со скриптами, а не картинка."""
    if item.get("kind") != "file":
        return False
    name = item.get("name", "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in {"jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff"}


def _drop_make_thumb(item_id):
    """Рисует миниатюру рядом с файлом. Возвращает путь или None."""
    thumb_path = _drop_thumb_path(item_id)
    if os.path.exists(thumb_path):
        return thumb_path
    try:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = 80_000_000  # защита от «бомб» с гигантским разрешением
        with Image.open(_drop_path(item_id)) as image:
            image.draft("RGB", (256, 256))  # для JPEG декодируем сразу уменьшенным
            image = image.convert("RGB")
            image.thumbnail((200, 200))
            image.save(thumb_path, "JPEG", quality=62, optimize=True)
        return thumb_path
    except Exception:
        return None


@app.get("/api/drop/thumb/<item_id>")
@login_required
def drop_thumb(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
    if not item or not _drop_can_thumb(item):
        return "", 404
    thumb_path = _drop_make_thumb(item_id)
    if not thumb_path:
        return "", 404
    response = send_file(thumb_path, mimetype="image/jpeg", conditional=True)
    response.headers["Cache-Control"] = "private, max-age=86400"
    return response


# Растровые картинки, которые можно безопасно отдать в строку: они не умеют
# выполнять скрипты. SVG сюда не входит намеренно — внутри него живёт
# полноценный JS, и на домене сайта он дотянулся бы до сессии.
# Что можно безопасно показать прямо в браузере. Ни один из этих типов не
# умеет выполнять скрипты. SVG и HTML сюда не входят намеренно: внутри них
# живёт полноценный JS, и на домене сайта он дотянулся бы до сессии.
DROP_INLINE_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".ico": "image/x-icon", ".avif": "image/avif",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8", ".csv": "text/plain; charset=utf-8",
    ".mp4": "video/mp4", ".webm": "video/webm",
    ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav",
}


def _drop_send(item_id, item, inline=False):
    """По умолчанию отдаём вложением: иначе загруженный .html или .svg со
    скриптом выполнился бы на домене сайта и добрался до сессии и токена
    устройства. Открываем в браузере только по бессрочной ссылке и только
    те типы, которые заведомо ничего не выполняют."""
    ext = os.path.splitext(item["name"])[1].lower()
    mime = DROP_INLINE_TYPES.get(ext) if inline else None
    response = send_file(
        _drop_path(item_id),
        mimetype=mime or "application/octet-stream",
        as_attachment=not mime,
        download_name=item["name"],
        conditional=True,
    )
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    # Без этого браузер может «донюхать» тип сам и решить, что перед ним HTML
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _drop_text_name(first_line):
    """Имя текстовой заметки: первая строка плюс .txt, если его ещё нет."""
    name = (first_line or "").strip()[:60] or "Текст"
    return name if name.lower().endswith(".txt") else name + ".txt"


@app.post("/api/drop/text")
@login_required
def drop_upload_text():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    parent = payload.get("parent") or None
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Текст пустой."), 400
    data = text.encode("utf-8")
    item_id = str(uuid.uuid4())
    with drop_lock:
        if parent and drop_items.get(parent, {}).get("kind") != "folder":
            parent = None
        if _drop_used() + len(data) > DROP_QUOTA:
            return jsonify(error="Нет места: квота исчерпана."), 507
        try:
            with open(_drop_path(item_id), "wb") as fh:
                fh.write(data)
        except OSError as e:
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        # Имя лепим из первой строки, но обязательно с .txt на конце. Без
        # него любая точка в тексте («1. Убрать датчики») выглядела как
        # расширение, и переименование правило текст до этой точки.
        first = text.strip().splitlines()[0][:60] if text.strip() else "Текст"
        drop_items[item_id] = {
            "kind": "text", "name": _drop_text_name(first), "parent": parent,
            "content_type": "text/plain; charset=utf-8", "size": len(data),
            "created": time.time(), "preview": text[:DROP_TEXT_PREVIEW],
            "truncated": len(text) > DROP_TEXT_PREVIEW, "share": None,
        }
        _drop_write_index()
    return jsonify(id=item_id)


@app.get("/api/drop/text/<item_id>")
@login_required
def drop_text_full(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
    if not item or item["kind"] != "text":
        return jsonify(error="Не найдено."), 404
    try:
        with open(_drop_path(item_id), encoding="utf-8") as fh:
            return jsonify(text=fh.read())
    except OSError:
        return jsonify(error="Файл потерян."), 404


@app.put("/api/drop/text/<item_id>")
@login_required
def drop_text_update(item_id):
    """Переписать содержимое заметки. Имя не трогаем: его пользователь мог
    уже поправить руками, и подменять его под новый первый абзац — грубо."""
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Текст пустой."), 400
    data = text.encode("utf-8")
    with drop_lock:
        item = drop_items.get(item_id)
        if not item or item["kind"] != "text":
            return jsonify(error="Не найдено."), 404
        if _drop_used() - item["size"] + len(data) > DROP_QUOTA:
            return jsonify(error="Нет места: квота исчерпана."), 507
        try:
            with open(_drop_path(item_id), "wb") as fh:
                fh.write(data)
        except OSError as e:
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        item["size"] = len(data)
        item["preview"] = text[:DROP_TEXT_PREVIEW]
        item["truncated"] = len(text) > DROP_TEXT_PREVIEW
        item["edited"] = time.time()
        _drop_write_index()
    return jsonify(ok=True, size=len(data))


@app.post("/api/drop/folder")
@login_required
def drop_folder_create():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:60]
    parent = payload.get("parent") or None
    if not name:
        return jsonify(error="Имя пустое."), 400
    item_id = str(uuid.uuid4())
    with drop_lock:
        if parent and drop_items.get(parent, {}).get("kind") != "folder":
            parent = None
        drop_items[item_id] = {
            "kind": "folder", "name": name, "parent": parent,
            "size": 0, "created": time.time(), "share": None,
        }
        _drop_write_index()
    return jsonify(id=item_id, name=name)


@app.post("/api/drop/upload/init")
@login_required
def drop_upload_init():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "файл")[:120]
    parent = payload.get("parent") or None
    try:
        size = int(payload.get("size", 0))
    except (TypeError, ValueError):
        return jsonify(error="Некорректный размер."), 400
    if size <= 0:
        return jsonify(error="Пустой файл."), 400
    if size > DROP_MAX_SIZE:
        return jsonify(error="Файл больше 2 ГБ."), 413

    upload_id = str(uuid.uuid4())
    with drop_lock:
        _drop_sweep_uploads()
        if parent and drop_items.get(parent, {}).get("kind") != "folder":
            parent = None
        reserved = sum(u["size"] for u in drop_uploads.values())
        if _drop_used() + reserved + size > DROP_QUOTA:
            return jsonify(error="Нет места: квота исчерпана."), 507
        drop_uploads[upload_id] = {
            "name": name, "size": size, "parent": parent,
            "received": 0, "started": time.time(),
            "content_type": payload.get("content_type") or "application/octet-stream",
        }
    try:
        open(_drop_tmp_path(upload_id), "wb").close()
    except OSError as e:
        return jsonify(error=f"Не удалось начать загрузку: {e}"), 500
    return jsonify(upload_id=upload_id)


@app.post("/api/drop/upload/chunk/<upload_id>")
@login_required
def drop_upload_chunk(upload_id):
    with drop_lock:
        upload = drop_uploads.get(upload_id)
    if not upload:
        return jsonify(error="Загрузка не найдена."), 404

    try:
        offset = int(request.args.get("offset", "-1"))
    except ValueError:
        offset = -1
    if offset != upload["received"]:
        # Кусок пришёл не тот, что ждали (повтор после обрыва) — говорим,
        # с какого места продолжать, вместо того чтобы портить файл.
        return jsonify(error="Рассинхронизация.", expected=upload["received"]), 409

    data = request.get_data(cache=False)
    if not data:
        return jsonify(error="Пустой кусок."), 400
    if upload["received"] + len(data) > upload["size"]:
        return jsonify(error="Больше заявленного размера."), 413

    try:
        with open(_drop_tmp_path(upload_id), "ab") as fh:
            fh.write(data)
    except OSError as e:
        return jsonify(error=f"Ошибка записи: {e}"), 500

    with drop_lock:
        if upload_id in drop_uploads:
            drop_uploads[upload_id]["received"] += len(data)
            received = drop_uploads[upload_id]["received"]
        else:
            return jsonify(error="Загрузка не найдена."), 404
    return jsonify(received=received)


@app.post("/api/drop/upload/finish/<upload_id>")
@login_required
def drop_upload_finish(upload_id):
    with drop_lock:
        upload = drop_uploads.pop(upload_id, None)
    if not upload:
        return jsonify(error="Загрузка не найдена."), 404

    tmp_path = _drop_tmp_path(upload_id)
    try:
        actual = os.path.getsize(tmp_path)
    except OSError:
        return jsonify(error="Временный файл потерян."), 500
    if actual != upload["size"]:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return jsonify(error="Размер не сошёлся, загрузка прервана."), 400

    item_id = str(uuid.uuid4())
    with drop_lock:
        if _drop_used() + actual > DROP_QUOTA:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return jsonify(error="Нет места: квота исчерпана."), 507
        try:
            os.replace(tmp_path, _drop_path(item_id))
        except OSError as e:
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        parent = upload["parent"]
        if parent and parent not in drop_items:
            parent = None
        drop_items[item_id] = {
            "kind": "file", "name": upload["name"], "parent": parent,
            "content_type": upload["content_type"], "size": actual,
            "created": time.time(), "share": None,
        }
        _drop_write_index()
    return jsonify(id=item_id)


@app.get("/api/drop/list")
@login_required
def drop_list_api():
    parent = request.args.get("parent") or None
    with drop_lock:
        if parent and parent not in drop_items:
            parent = None
        memo = {}
        items = []
        for k, v in drop_items.items():
            if v.get("parent") != parent:
                continue
            row = {
                "id": k, "kind": v["kind"], "name": v["name"], "size": v.get("size", 0),
                "created": v["created"], "preview": v.get("preview"),
                "truncated": v.get("truncated", False),
                "thumb": _drop_can_thumb(v),
                "share": bool(v.get("share")),
                "share_expires": (v.get("share") or {}).get("expires"),
                # Ссылку отдаём готовой: страница должна уметь показать её
                # ещё раз, а не только выдать один раз при создании.
                "share_url": (url_for("drop_public", token=v["share"]["token"], _external=True)
                              if v.get("share") else None),
                # По этой отметке страница сортирует. У файла это его время,
                # у папки — время самого свежего файла внутри.
                "touched": v["created"],
            }
            if v["kind"] == "folder":
                size, touched, count = _drop_folder_stats(k, memo)
                row["size"] = size
                row["count"] = count
                row["touched"] = touched
                row["icon"] = v.get("icon") or "folder"
            items.append(row)
        items.sort(key=lambda x: -x["touched"])
        return jsonify(
            items=items,
            breadcrumbs=_drop_path_to_root(parent),
            used=_drop_used(),
            quota=DROP_QUOTA,
        )


@app.get("/api/drop/download/<item_id>")
@login_required
def drop_download(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
    if not item or item["kind"] == "folder":
        return "Не найдено", 404
    return _drop_send(item_id, item)


@app.patch("/api/drop/<item_id>")
@login_required
def drop_update(item_id):
    payload = request.get_json(silent=True) or {}
    with drop_lock:
        item = drop_items.get(item_id)
        if not item:
            return jsonify(error="Не найдено."), 404
        if "name" in payload:
            name = (payload.get("name") or "").strip()[:120]
            if not name:
                return jsonify(error="Имя пустое."), 400
            # Расширение переименованием не трогаем: иначе картинка перестаёт
            # быть картинкой, а архив — архивом.
            if item["kind"] != "folder":
                old_ext = os.path.splitext(item["name"])[1]
                if old_ext:
                    name = os.path.splitext(name)[0] + old_ext
            item["name"] = name
        if "icon" in payload:
            if item["kind"] != "folder":
                return jsonify(error="Значок меняется только у папок."), 400
            icon = payload.get("icon") or "folder"
            if icon not in DROP_FOLDER_ICONS:
                return jsonify(error="Нет такого значка."), 400
            item["icon"] = icon
        if "parent" in payload:
            target = payload.get("parent") or None
            if target and drop_items.get(target, {}).get("kind") != "folder":
                return jsonify(error="Такой папки нет."), 400
            if target and _drop_is_descendant(item_id, target):
                return jsonify(error="Нельзя переместить папку внутрь себя."), 400
            item["parent"] = target
        _drop_write_index()
    return jsonify(ok=True)


# ---- Пакетные действия: копирование, перенос, удаление -----------------------
# Копирование гигабайтной папки занимает секунды, а то и минуты, поэтому работа
# уходит в отдельный поток, а страница спрашивает о ходе дела по номеру задачи.
# Диск трогаем вне drop_lock: под ним весь дроп встал бы на всё время копии.
drop_jobs: dict = {}
drop_jobs_lock = threading.Lock()
DROP_JOB_TTL = 900              # доделанную задачу держим ещё четверть часа
DROP_COPY_CHUNK = 4 * 1024 * 1024


def _drop_job_set(job_id, **fields):
    with drop_jobs_lock:
        job = drop_jobs.get(job_id)
        if job:
            job.update(fields)


def _drop_jobs_sweep():
    """Выкидываем задачи, о которых уже не спросят. Под drop_jobs_lock."""
    edge = time.time() - DROP_JOB_TTL
    for key in [k for k, v in drop_jobs.items()
                if v["state"] != "run" and v["ended"] < edge]:
        drop_jobs.pop(key, None)


def _drop_unique_name(name, parent, extra=()):
    """«файл.txt» рядом с таким же становится «файл (2).txt». Под drop_lock.

    extra — имена, которых в папке ещё нет, но они там вот-вот появятся:
    при копировании план строится целиком заранее, и без этого списка две
    одинаковые копии в одной пачке получили бы одно и то же имя."""
    taken = {drop_items[k]["name"] for k in _drop_children(parent)} | set(extra)
    if name not in taken:
        return name
    stem, ext = os.path.splitext(name)
    for n in range(2, 1000):
        candidate = f"{stem} ({n}){ext}"
        if candidate not in taken:
            return candidate
    return f"{stem} ({uuid.uuid4().hex[:6]}){ext}"


def _drop_copy_plan(ids, target):
    """Разворачивает выделенное в плоский список работ. Под drop_lock.

    Порядок обхода такой, что папка всегда идёт раньше своего содержимого —
    значит к моменту создания ребёнка его новый родитель уже существует."""
    plan, total, claimed = [], 0, set()

    def walk(item_id, parent, rename):
        nonlocal total
        item = drop_items.get(item_id)
        if not item:
            return
        new_id = str(uuid.uuid4())
        if rename:
            name = _drop_unique_name(item["name"], parent, claimed)
            claimed.add(name)
        else:
            name = item["name"]
        plan.append({"src": item_id, "new": new_id, "parent": parent,
                     "name": name, "kind": item["kind"],
                     "size": item.get("size", 0)})
        total += item.get("size", 0)
        if item["kind"] == "folder":
            for child in _drop_children(item_id):
                walk(child, new_id, False)

    for item_id in ids:
        walk(item_id, target, True)
    return plan, total


def _drop_copy_file(src_id, new_id, job_id):
    """Копирует тело файла кусками, отмечая пройденные байты."""
    src, dst = _drop_path(src_id), _drop_path(new_id)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(DROP_COPY_CHUNK)
            if not chunk:
                break
            fout.write(chunk)
            with drop_jobs_lock:
                job = drop_jobs.get(job_id)
                if not job:
                    raise RuntimeError("задача отменена")
                job["bytes"] += len(chunk)
    thumb = _drop_thumb_path(src_id)
    if os.path.exists(thumb):
        try:
            shutil.copyfile(thumb, _drop_thumb_path(new_id))
        except OSError:
            pass


def _drop_run_copy(job_id, ids, target):
    with drop_lock:
        plan, total_bytes = _drop_copy_plan(ids, target)
        free = DROP_QUOTA - _drop_used()
    if total_bytes > free:
        raise RuntimeError("Не хватает места: нужно "
                           f"{total_bytes // 1048576} МБ, свободно {max(free, 0) // 1048576} МБ.")
    _drop_job_set(job_id, total=len(plan), bytes_total=total_bytes)
    for step in plan:
        if step["kind"] != "folder":
            _drop_copy_file(step["src"], step["new"], job_id)
        with drop_lock:
            src = drop_items.get(step["src"])
            if not src:                       # исчез, пока копировали
                continue
            copy = dict(src)
            copy.update({"name": step["name"], "parent": step["parent"],
                         "created": time.time(), "share": None})
            drop_items[step["new"]] = copy
            _drop_write_index()
        with drop_jobs_lock:
            job = drop_jobs.get(job_id)
            if job:
                job["done"] += 1


def _drop_run_move(job_id, ids, target):
    with drop_lock:
        if target and drop_items.get(target, {}).get("kind") != "folder":
            raise RuntimeError("Такой папки нет.")
        for item_id in ids:
            if target and _drop_is_descendant(item_id, target):
                raise RuntimeError("Нельзя переложить папку внутрь себя.")
        _drop_job_set(job_id, total=len(ids))
        for item_id in ids:
            item = drop_items.get(item_id)
            if not item or item.get("parent") == target:
                with drop_jobs_lock:
                    drop_jobs[job_id]["done"] += 1
                continue
            # Имя подбираем до перекладывания: после него элемент уже лежит
            # в приёмнике и считает тёзкой сам себя — папка «Склад» так
            # переезжала и становилась «Склад (2)».
            item["name"] = _drop_unique_name(item["name"], target)
            item["parent"] = target
            with drop_jobs_lock:
                drop_jobs[job_id]["done"] += 1
        _drop_write_index()


def _drop_run_delete(job_id, ids, _target):
    with drop_lock:
        _drop_job_set(job_id, total=len(ids))
        for item_id in ids:
            _drop_discard(item_id)
            with drop_jobs_lock:
                drop_jobs[job_id]["done"] += 1
        _drop_write_index()


DROP_OPS = {"copy": _drop_run_copy, "move": _drop_run_move, "delete": _drop_run_delete}


@app.post("/api/drop/op")
@login_required
def drop_op_start():
    payload = request.get_json(silent=True) or {}
    op = payload.get("op")
    ids = [str(i) for i in (payload.get("ids") or [])][:2000]
    target = payload.get("parent") or None
    if op not in DROP_OPS:
        return jsonify(error="Неизвестное действие."), 400
    if not ids:
        return jsonify(error="Ничего не выбрано."), 400

    job_id = str(uuid.uuid4())
    with drop_jobs_lock:
        _drop_jobs_sweep()
        drop_jobs[job_id] = {"state": "run", "op": op, "done": 0, "total": len(ids),
                             "bytes": 0, "bytes_total": 0, "error": "", "ended": 0.0}

    def work():
        try:
            DROP_OPS[op](job_id, ids, target)
            _drop_job_set(job_id, state="done", ended=time.time())
        except Exception as e:                      # noqa: BLE001 — причину показываем как есть
            _drop_job_set(job_id, state="fail", error=str(e), ended=time.time())

    threading.Thread(target=work, daemon=True).start()
    return jsonify(job=job_id)


@app.get("/api/drop/op/<job_id>")
@login_required
def drop_op_status(job_id):
    with drop_jobs_lock:
        job = drop_jobs.get(job_id)
        if not job:
            return jsonify(error="Задача не найдена."), 404
        return jsonify(**{k: v for k, v in job.items() if k != "ended"})


@app.post("/api/drop/share/<item_id>")
@login_required
def drop_share_create(item_id):
    payload = request.get_json(silent=True) or {}
    forever = bool(payload.get("forever"))
    try:
        hours = int(payload.get("hours", 24))
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(hours, 24 * 30))
    with drop_lock:
        item = drop_items.get(item_id)
        if not item or item["kind"] == "folder":
            return jsonify(error="Папки ссылкой не отдаются."), 400
        # expires = None означает «без срока»: проверка на истечение такую
        # ссылку пропускает, потому что сравнивает только заданное время.
        item["share"] = {
            "token": secrets.token_urlsafe(24),
            "expires": None if forever else time.time() + hours * 3600,
        }
        token = item["share"]["token"]
        _drop_write_index()
    return jsonify(url=url_for("drop_public", token=token, _external=True),
                   hours=0 if forever else hours, forever=forever)


@app.delete("/api/drop/share/<item_id>")
@login_required
def drop_share_revoke(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
        if item:
            item["share"] = None
            _drop_write_index()
    return jsonify(ok=True)


@app.get("/d/<token>")
def drop_public(token):
    """Публичная ссылка. Единственный эндпоинт дропа без авторизации —
    поэтому отдаёт строго один файл по неугадываемому токену и только вложением."""
    with drop_lock:
        item_id = _drop_share_lookup(token)
        item = drop_items.get(item_id) if item_id else None
    if not item:
        return "Ссылка недействительна или истекла", 404
    # Ссылка со сроком ведёт себя как раньше — файл скачивается. Бессрочная
    # открывается прямо в браузере: её и делают, чтобы вставить адресом
    # картинки в настройки другого сайта, а не чтобы качать по одному файлу.
    forever = not (item.get("share") or {}).get("expires")
    return _drop_send(item_id, item, inline=forever)


@app.delete("/api/drop/<item_id>")
@login_required
def drop_delete(item_id):
    with drop_lock:
        if item_id in drop_items:
            _drop_discard(item_id)
            _drop_write_index()
    return jsonify(ok=True)


@app.get("/cabinet")
@login_required
def cabinet():
    device_items = "".join(
        f'<li class="device" data-ip="{device["ip"]}">'
        f'<button class="copy-ip" type="button" data-ip="{device["ip"]}">{device["ip"]}</button>'
        f'<span class="device-name">{device["name"]}</span>'
        f'<span class="device-status" data-status>проверка…</span>'
        + (
            f'<button class="wol-btn" type="button" data-mac="{device["wol_mac"]}" title="Wake-on-LAN">⚡</button>'
            if device.get("wol_mac") else '<span class="wol-empty"></span>'
        )
        + (
            f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="ssh">SSH</button>'
            if device.get("ssh_enabled")
            else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="rdp">RDP</button>'
            if device.get("rdp_enabled")
            else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="vnc">VNC</button>'
            if device.get("vnc_enabled")
            else '<span class="connect-btn-empty"></span>'
        )
        + '<span class="copy-status">Скопировано</span>'
        + "</li>"
        for device in NETBIRD_DEVICES
    )
    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="robots" content="noindex, nofollow">
      <title>Личный кабинет · vitazgio.ru</title>
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <meta name="theme-color" content="#0d1321">
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100svh; color: #e9fbff; font-family: "Cascadia Code", Consolas, monospace; background: radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .cabinet { min-height: 100svh; padding: clamp(24px, 4vw, 54px); background: linear-gradient(135deg, rgba(10,18,32,.25), transparent 60%); }
        .cabinet-header { display: flex; align-items: center; gap: 20px; }
        h1 { margin: 0; font-size: clamp(1.7rem, 3.6vw, 2.6rem); font-weight: 700; letter-spacing: -.02em;
             color: #eaf6ff; text-shadow: 0 0 22px rgba(45,226,255,.35); }
        h1 span { color: #2de2ff; text-shadow: 0 0 22px rgba(45,226,255,.5); }
        .logout-form { margin: 0; }
        .logout-button { padding: 10px 16px; color: #dffaff; font: 700 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.07); cursor: pointer; }
        .logout-button:hover { border-color: #2de2ff; background: rgba(45,226,255,.14); }
        .install-button { margin-left: auto; color: #1a0d04; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); }
        .install-button:hover { border: 0; background: linear-gradient(90deg, #ff8f4f, #ffc379); }
        [hidden] { display: none !important; }
        .workspace { flex: 1 1 auto; min-width: 0; margin-top: clamp(22px, 3.5vw, 40px); }
        .device-list { container-type: inline-size; margin: 0; padding: 8px 18px 18px; list-style: none; border-top: 1px solid rgba(255,255,255,.07); }
        .device { min-height: 48px; display: grid; grid-template-columns: 150px 1fr 70px 36px 116px 82px; align-items: center; gap: 12px; border-bottom: 1px solid rgba(255,255,255,.06); }
        .device:last-child { border-bottom: 0; }
        .copy-ip { padding: 7px 8px; color: #69e8ff; text-align: left; border: 0; background: transparent; }
        .copy-ip:hover, .copy-ip:focus-visible { color: #fff; border: 0; outline: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.08); }
        .device-name { min-width: 0; color: #c4cad5; font-size: .84rem; overflow-wrap: break-word; }
        .device-status { color: #6b7385; font-size: .76rem; text-align: right; white-space: nowrap; }
        .device-status::before { content: "● "; }
        .device-status.online { color: #63f5ad; }
        .device-status.offline { color: #ff6b81; }
        .connect-btn { padding: 6px 10px; color: #ff782f; font: 700 .7rem "Cascadia Code", Consolas, monospace; letter-spacing: .04em; text-transform: uppercase; border: 1px solid rgba(255,120,47,.35); background: rgba(255,120,47,.07); cursor: pointer; }
        .connect-btn:hover, .connect-btn:focus-visible { color: #fff; background: rgba(255,120,47,.22); outline: none; }
        .connect-btn.btn-offline { color: #4a5060; border-color: rgba(100,100,110,.2); background: rgba(60,65,75,.06); cursor: not-allowed; pointer-events: none; }
        .connect-btn-empty { display: block; }
        .wol-btn { padding: 5px 7px; color: #fbbf24; font-size: .9rem; border: 1px solid rgba(251,191,36,.3); background: rgba(251,191,36,.07); cursor: pointer; transition: all .2s; }
        .wol-btn:hover { background: rgba(251,191,36,.18); border-color: #fbbf24; }
        .wol-btn.wol-online { color: #ff6b81; border-color: rgba(255,107,129,.3); background: rgba(255,107,129,.07); }
        .wol-btn.wol-online:hover { background: rgba(255,107,129,.18); border-color: #ff6b81; }
        .wol-btn.wol-sent { color: #63f5ad; border-color: rgba(99,245,173,.4); background: rgba(99,245,173,.1); }
        .wol-empty { display: block; }
        .copy-status { color: #63f5ad; font-size: .7rem; opacity: 0; transition: opacity .18s ease; }
        .copy-status.visible { opacity: 1; }
        @media (max-width: 900px) {
          .workspace { width: 100%; min-width: 0; }
        }
        @media (max-width: 560px) {
          .cabinet { padding-inline: 20px; }
          .cabinet-header { align-items: flex-start; justify-content: space-between; gap: 12px; }
        }
        /* Считаем ширину самого списка, а не окна: в две колонки кабинет
           бывает узким и при широком экране — тогда имя устройства сжималось
           в ноль и рассыпалось по одной букве в строку. */
        @container (max-width: 640px) {
          .device { grid-template-columns: 1fr auto; gap: 4px 10px; padding: 8px 0; }
          .device-name { grid-column: 1; grid-row: 2; padding-left: 8px; }
          .device-status { grid-column: 2; grid-row: 1; }
          .connect-btn, .connect-btn-empty { grid-column: 1; grid-row: 3; justify-self: start; margin-left: 8px; }
          .wol-btn, .wol-empty { grid-column: 2; grid-row: 3; justify-self: end; }
          .copy-status { grid-column: 2; grid-row: 2; text-align: right; }
        }

        .gate-modal { position: fixed; z-index: 100; inset: 0; display: grid; place-items: center; padding: 20px; }
        .gate-backdrop { position: absolute; inset: 0; background: rgba(3, 6, 13, .82); backdrop-filter: blur(12px); }
        .gate-panel { position: relative; width: min(380px, 100%); padding: 30px; color: #e8fbff; border: 1px solid rgba(255,120,47,.3); background: linear-gradient(145deg, rgba(16, 30, 47, .98), rgba(20, 16, 37, .98)); box-shadow: 0 32px 100px rgba(0,0,0,.65); }
        .gate-panel h2 { margin: 0 0 18px; font-size: 1.3rem; }
        .gate-panel input { width: 100%; height: 46px; padding: 0 14px; color: #f4fbff; font: 700 1rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.65); }
        .gate-panel input:focus { border-color: #ff782f; }
        .gate-panel input + input { margin-top: 10px; }
        .gate-select { width: 100%; height: 46px; margin-top: 10px; padding: 0 12px; color: #f4fbff;
                       font: 600 .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12);
                       outline: none; background: rgba(4,10,20,.65); cursor: pointer; }
        .gate-select:focus { border-color: #ff782f; }
        .gate-select option { background: #101a2b; }
        .gate-submit { width: 100%; height: 46px; margin-top: 12px; color: #1a0d04; font: 800 .8rem "Cascadia Code", Consolas, monospace; letter-spacing: .06em; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); cursor: pointer; }
        .gate-error { min-height: 18px; margin: 10px 0 0; color: #ff6ba8; font-size: .78rem; }
        .gate-close { position: absolute; top: 12px; right: 14px; padding: 5px; color: #7d8799; font-size: 1.3rem; border: 0; background: none; cursor: pointer; }

        /* Высота задаётся переменной, а не inset:0. На телефоне экранная
           клавиатура ужимает видимую область, но макетная остаётся прежней —
           и шапка с рядом кнопок уезжала под клавиатуру. Теперь окно живёт
           ровно в видимой части, а сжимается только тело терминала. */
        .term-overlay { position: fixed; z-index: 100; left: 0; right: 0; top: 0;
                        height: var(--term-h, 100%); display: flex; flex-direction: column;
                        background: #05070c; transform: translateY(var(--term-top, 0px)); }
        .term-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; color: #c4cad5; font-size: .82rem; background: rgba(255,255,255,.04); border-bottom: 1px solid rgba(255,255,255,.08); }
        .term-close { padding: 7px 12px; color: #dffaff; font: 700 .76rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.16); background: transparent; cursor: pointer; }
        .term-close:hover { background: rgba(255,255,255,.08); }
        .term-body { flex: 1 1 auto; min-height: 0; padding: 10px; overflow: hidden; }
        .term-header, .term-tools { flex: none; }
        .term-tools { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px 12px; flex: none;
                      background: rgba(255,255,255,.03); border-bottom: 1px solid rgba(255,255,255,.07); }
        .term-key { min-width: 46px; padding: 9px 12px; color: #c4cad5;
                    font: 600 .74rem "Cascadia Code", Consolas, monospace;
                    border: 1px solid rgba(255,255,255,.14); border-radius: 5px;
                    background: linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
                    cursor: pointer; touch-action: manipulation; user-select: none; -webkit-user-select: none; }
        .term-key:active { color: #2de2ff; border-color: rgba(45,226,255,.5); background: rgba(45,226,255,.14); }
        .term-key-wide { min-width: 96px; color: #1a0d04; border: 0;
                         background: linear-gradient(90deg, #ff782f, #ffb35c); font-weight: 800; }
        .term-key-go { color: #04121c; border: 0; background: linear-gradient(90deg, #2de2ff, #7df9ff); font-weight: 800; }
        .term-toast { position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%);
                      z-index: 120; padding: 9px 16px; color: #04121c; font: 700 .74rem "Cascadia Code", Consolas, monospace;
                      background: #2de2ff; }
        .rdp-overlay { position: fixed; z-index: 100; inset: 0; display: flex; flex-direction: column; background: #000; }
        .rdp-content { display: flex; flex: 1; min-height: 0; overflow: hidden; }
        .rdp-display { flex: 1; overflow: hidden; cursor: none; position: relative; min-width: 0; }
        .rdp-display > div { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
        .rdp-header-actions { display: flex; align-items: center; gap: 8px; }
        .rdp-toolbar { display: flex; flex-direction: column; flex-wrap: nowrap; gap: 4px; padding: 6px; background: rgba(16,24,38,.96); border-left: 1px solid rgba(255,255,255,.07); flex-shrink: 0; overflow-y: auto; align-items: stretch; }
        .rdp-lock-hint { position: absolute; inset: 0; display: grid; place-items: center; color: rgba(140,150,168,.6); font: .78rem "Cascadia Code", Consolas, monospace; pointer-events: none; z-index: 1; }
        .rdp-key { padding: 7px 10px; min-width: 38px; color: #c4cad5; font: 600 .72rem "Cascadia Code", Consolas, monospace; text-align: center; border: 1px solid rgba(255,255,255,.13); background: rgba(255,255,255,.05); cursor: pointer; touch-action: manipulation; user-select: none; -webkit-user-select: none; }
        .rdp-key:active, .rdp-key.active { color: #ff782f; border-color: rgba(255,120,47,.55); background: rgba(255,120,47,.13); }
        .rdp-key-combo { padding: 7px 10px; color: #ff6b81; font: 600 .7rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,107,129,.28); background: rgba(255,107,129,.06); cursor: pointer; touch-action: manipulation; user-select: none; -webkit-user-select: none; }
        .rdp-key-combo:active { background: rgba(255,107,129,.2); }
        .rdp-kbd-input { position: fixed; left: -9999px; opacity: 0; width: 1px; height: 1px; pointer-events: none; }
        .conn-quality { display: inline-block; padding: 2px 7px; border-radius: 3px; font: 600 .7rem "Cascadia Code", Consolas, monospace; background: rgba(255,255,255,.07); color: #8f99ab; pointer-events: none; transition: color .3s; vertical-align: middle; margin-left: 8px; }
        .conn-quality:empty { display: none; }
        .conn-quality.good { color: #4ade80; }
        .conn-quality.warn { color: #fbbf24; }
        .conn-quality.bad  { color: #f87171; }
        @media (max-width: 900px) {
          .term-header { padding: 8px 12px; }
          .rdp-display > div { top: 0; left: 0; transform: none; }
        }

        /* ── Панели кабинета ── */
        .widget-empty { color: #4a5060; font-size: .8rem; margin: 0; padding: 4px 0; }

        /* Колонка фиксированного размера: не тянется за левой стороной,
           сколько бы панелей там ни развернули. */
        .cabinet-cols { display: flex; align-items: flex-start; gap: 20px; max-width: 1900px; }
        .rail { width: 268px; flex: none; display: flex; flex-direction: column; gap: 12px;
                margin-top: clamp(22px, 3.5vw, 40px); }
        /* Узкий экран или половина окна — правой колонки просто нет. */
        @media (max-width: 1220px) { .rail { display: none; } }

        .rail-card { position: relative; padding: 13px 15px; border: 1px solid rgba(45,226,255,.18);
                     background: linear-gradient(160deg, rgba(12,20,36,.95), rgba(10,14,26,.95)); overflow: hidden; }
        .rail-corner { position: absolute; width: 12px; height: 12px; pointer-events: none; }
        .rail-corner--tl { top: -1px; left: -1px; border-top: 2px solid #2de2ff; border-left: 2px solid #2de2ff; }
        .rail-corner--tr { top: -1px; right: -1px; border-top: 2px solid #ff3fa4; border-right: 2px solid #ff3fa4; }
        .rail-corner--bl { bottom: -1px; left: -1px; border-bottom: 2px solid #ff3fa4; border-left: 2px solid #ff3fa4; }
        .rail-corner--br { bottom: -1px; right: -1px; border-bottom: 2px solid #2de2ff; border-right: 2px solid #2de2ff; }

        /* Часы */
        .clock { text-align: center; }
        .clock-time { display: flex; align-items: baseline; justify-content: center; gap: 2px;
                      font: 800 2.25rem "Cascadia Code", Consolas, monospace; letter-spacing: -.04em; color: #2de2ff;
                      text-shadow: 0 0 14px rgba(45,226,255,.55), 0 0 42px rgba(45,226,255,.22); }
        .clock-time em { font-style: normal; color: #ff3fa4; text-shadow: 0 0 14px rgba(255,63,164,.6); animation: blink 2s steps(1) infinite; }
        .clock-time small { margin-left: 5px; font-size: .88rem; color: #ff3fa4; text-shadow: 0 0 12px rgba(255,63,164,.5); }
        @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: .25; } }
        .clock-date { margin-top: 5px; color: #6b7385; font-size: .62rem; letter-spacing: .18em; text-transform: uppercase; }
        .clock-scan { position: absolute; inset: 0; pointer-events: none;
                      background: repeating-linear-gradient(180deg, rgba(45,226,255,.05) 0 1px, transparent 1px 4px); }

        /* Плеер */
        .pl-head { display: flex; align-items: center; justify-content: space-between; }
        .pl-label { color: #8f99ab; font-size: .66rem; letter-spacing: .22em; text-transform: uppercase; }
        .pl-actions { display: flex; gap: 6px; }
        .pl-icon { width: 24px; height: 24px; display: grid; place-items: center; color: #2de2ff; font-size: .9rem; line-height: 1;
                   border: 1px solid rgba(45,226,255,.3); background: rgba(45,226,255,.06); cursor: pointer; transition: all .16s; }
        .pl-icon:hover { color: #061018; border-color: #2de2ff; background: #2de2ff; }
        .pl-eq { display: flex; align-items: flex-end; justify-content: center; gap: 2px; height: 26px; margin: 11px 0 8px; }
        .pl-eq span { width: 2px; height: 3px; background: linear-gradient(180deg, #ff3fa4, #2de2ff); opacity: .35; transition: height .12s, opacity .12s; }
        .player.on .pl-eq span { opacity: 1; }
        .pl-now { text-align: center; }
        .pl-title { color: #eaf6ff; font-size: .79rem; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .pl-artist { margin-top: 2px; color: #6b7385; font-size: .66rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .pl-seek { position: relative; height: 3px; margin: 10px 0 4px; background: rgba(255,255,255,.09); }
        .pl-seek-fill { height: 100%; width: 0; background: linear-gradient(90deg, #ff3fa4, #2de2ff); }
        .pl-seek-input { position: absolute; inset: -7px 0; width: 100%; height: 18px; margin: 0; opacity: 0; cursor: pointer; }
        .pl-times { display: flex; justify-content: space-between; color: #55607a; font-size: .64rem; }
        .pl-controls { display: flex; align-items: center; gap: 6px; margin-top: 9px; }
        .pl-btn { padding: 5px 7px; color: #9fb0c6; font: 700 .66rem "Cascadia Code", Consolas, monospace;
                  border: 1px solid rgba(255,255,255,.12); background: transparent; cursor: pointer; transition: all .16s; }
        .pl-btn:hover { color: #fff; border-color: rgba(45,226,255,.5); background: rgba(45,226,255,.1); }
        .pl-play { flex: none; min-width: 36px; color: #061018; border-color: transparent; background: linear-gradient(90deg, #2de2ff, #7fe9ff); }
        .pl-play:hover { color: #061018; background: linear-gradient(90deg, #7fe9ff, #2de2ff); }
        .pl-vol { flex: 1; min-width: 0; height: 3px; accent-color: #ff3fa4; cursor: pointer; }
        .player.over { border-color: #2de2ff; }
        .pl-list { margin-top: 11px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,.08); }
        .pl-list-head { display: flex; justify-content: space-between; color: #55607a; font-size: .64rem; letter-spacing: .1em; text-transform: uppercase; }
        /* Высота списка постоянная — колонка не «дышит» вслед за левой стороной. */
        #pl-tracks { height: 232px; margin-top: 4px; overflow-y: auto; scrollbar-width: thin;
                     scrollbar-color: rgba(45,226,255,.35) transparent; overscroll-behavior: contain; }
        #pl-tracks::-webkit-scrollbar { width: 6px; }
        #pl-tracks::-webkit-scrollbar-thumb { background: rgba(45,226,255,.3); }
        #pl-tracks::-webkit-scrollbar-track { background: transparent; }
        .pl-track { display: grid; grid-template-columns: 1fr auto auto; align-items: center; gap: 2px 6px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.05); }
        .pl-track:last-of-type { border-bottom: 0; }
        .pl-track-name { min-width: 0; color: #c4cad5; font-size: .71rem; cursor: pointer; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .pl-track-name:hover { color: #2de2ff; }
        .pl-track.current .pl-track-name { color: #2de2ff; }
        .pl-track-sub { grid-column: 1 / -1; color: #55607a; font-size: .64rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .pl-mini { padding: 3px 5px; color: #55607a; font-size: .7rem; line-height: 1; border: 1px solid rgba(255,255,255,.1); background: transparent; cursor: pointer; }
        .pl-mini:hover { color: #fff; border-color: rgba(45,226,255,.4); }
        .pl-mini.rm:hover { color: #ff6b81; border-color: rgba(255,107,129,.45); }
        .pl-edit { width: 100%; height: 24px; padding: 0 6px; color: #f4fbff; font: 600 .72rem "Cascadia Code", Consolas, monospace;
                   border: 1px solid rgba(45,226,255,.4); outline: none; background: rgba(4,10,20,.7); }

        /* Верхний блок: метрики во всю ширину */
        .dash { padding: 18px 20px 16px; border: 1px solid rgba(45,226,255,.16); background: rgba(10,17,30,.72); }
        .dash-title { margin-bottom: 14px; color: #8f99ab; font: 700 .76rem "Cascadia Code", Consolas, monospace; letter-spacing: .1em; text-transform: uppercase; }

        /* Панель с логотипом. Модификатор --right зеркалит: логотип справа. */
        .panel { display: block; margin-top: 14px; color: inherit; text-decoration: none;
                 border: 1px solid color-mix(in srgb, var(--accent, #2de2ff) 26%, transparent);
                 background: rgba(10,17,30,.72); transition: border-color .2s, background .2s; }
        .panel:hover { border-color: color-mix(in srgb, var(--accent, #2de2ff) 55%, transparent); }
        .panel-head { width: 100%; display: flex; align-items: center; gap: 16px; padding: 16px 18px;
                      text-align: left; border: 0; background: linear-gradient(100deg,
                        color-mix(in srgb, var(--accent, #2de2ff) 9%, transparent), transparent 65%);
                      cursor: pointer; }
        .panel-head:hover { background: linear-gradient(100deg,
                        color-mix(in srgb, var(--accent, #2de2ff) 17%, transparent), transparent 70%); }
        .panel--right .panel-head { flex-direction: row-reverse; text-align: right;
                      background: linear-gradient(260deg,
                        color-mix(in srgb, var(--accent, #2de2ff) 9%, transparent), transparent 65%); }
        .panel--right .panel-head:hover { background: linear-gradient(260deg,
                        color-mix(in srgb, var(--accent, #2de2ff) 17%, transparent), transparent 70%); }
        .panel-logo { width: 54px; height: 54px; flex: none; display: grid; place-items: center;
                      padding: 7px; border-radius: 14px; background: #050608; }
        .panel-logo img, .panel-logo svg { width: 100%; height: 100%; object-fit: contain; display: block; }
        .panel-text { flex: 1; min-width: 0; }
        .panel-title { display: block; color: #f8fbff; font-size: 1.18rem; font-weight: 800; }
        .panel-sub { display: block; margin-top: 5px; color: #8f99ab; font-size: .72rem; letter-spacing: .06em; text-transform: uppercase; }
        .panel-arrow { flex: none; color: var(--accent, #2de2ff); font-size: 1.3rem; transition: transform .25s; }
        .panel-head[aria-expanded="true"] .panel-arrow { transform: rotate(180deg); }
        .panel:hover .panel-arrow--go { transform: translateX(5px); }
        .panel-body { padding: 0 18px 16px; }

        /* Метрики */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); gap: 12px; }
        .metrics-host { border: 1px solid rgba(255,255,255,.07); padding: 12px 14px; }
        .metrics-host-name { font: 700 .82rem "Cascadia Code", Consolas, monospace; color: #c4cad5; margin-bottom: 10px; }
        .metrics-bars { display: grid; grid-template-columns: 40px 1fr 36px; align-items: center; gap: 5px 8px; font-size: .74rem; }
        .metrics-label { color: #6b7385; }
        .metrics-track { height: 6px; background: rgba(255,255,255,.07); border-radius: 3px; overflow: hidden; }
        .metrics-fill { height: 100%; border-radius: 3px; transition: width .4s ease; }
        .fill-cpu  { background: linear-gradient(90deg,#2de2ff,#69e8ff); }
        .fill-ram  { background: linear-gradient(90deg,#ff782f,#ffb35c); }
        .fill-disk { background: linear-gradient(90deg,#a855f7,#c084fc); }
        .metrics-val { color: #e8fbff; text-align: right; white-space: nowrap; }
        .metrics-extra { display: flex; gap: 14px; margin-top: 8px; font-size: .72rem; color: #6b7385; }
        .metrics-offline { color: #4a5060; font-size: .78rem; font-style: italic; }


        /* Деплой */
        .deploy-item { display: grid; grid-template-columns: 64px 1fr auto; gap: 6px 10px; align-items: baseline; padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,.06); font-size: .78rem; }
        .deploy-item:last-child { border-bottom: 0; }
        .deploy-sha { color: #69e8ff; font-family: Consolas, monospace; white-space: nowrap; }
        .deploy-msg { color: #c4cad5; word-break: break-word; }
        .deploy-meta { color: #6b7385; font-size: .7rem; white-space: nowrap; text-align: right; }
        .ds { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
        .ds-ok { background: #63f5ad; } .ds-fail { background: #ff6b81; } .ds-run { background: #fbbf24; } .ds-none { background: #4a5060; }

        /* Журнал входов */
        .log-row { display: grid; grid-template-columns: 150px 1fr; gap: 4px 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.06); font-size: .76rem; }
        .log-row:last-child { border-bottom: 0; }
        .log-ts { color: #6b7385; white-space: nowrap; }
        .log-ip { color: #69e8ff; }
        .log-ua { color: #4a5060; font-size: .68rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; grid-column: 1 / -1; }
        .log-bad .log-ip { color: #ff6b81; }
        .log-bad .log-ip::before { content: "✕ "; }
        .log-alarm { margin: 0 0 8px; padding: 6px 9px; color: #ffb35c; font-size: .72rem; border-left: 2px solid #ff6b81; background: rgba(255,107,129,.07); }

        /* Запомненные устройства */
        .dev-remember { display: flex; align-items: center; gap: 9px; padding: 4px 0 2px; color: #c4cad5; font-size: .82rem; cursor: pointer; }
        .dev-remember input { width: 15px; height: 15px; accent-color: #ff782f; cursor: pointer; }
        .dev-hint { margin: 0 0 10px; color: #6b7385; font-size: .7rem; }
        .dev-confirm { display: flex; gap: 8px; margin-bottom: 10px; }
        .dev-confirm input { flex: 1; min-width: 0; height: 34px; padding: 0 10px; color: #f4fbff; font: 600 .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,120,47,.35); outline: none; background: rgba(4,10,20,.65); }
        .dev-confirm input:focus { border-color: #ff782f; }
        .dev-confirm-btn { padding: 0 14px; color: #1a0d04; font: 800 .7rem "Cascadia Code", Consolas, monospace; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); cursor: pointer; }
        .dev-error { min-height: 16px; margin: 0 0 8px; color: #ff6ba8; font-size: .72rem; }
        .dev-row { display: grid; grid-template-columns: 1fr auto auto; align-items: center; gap: 4px 8px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,.06); }
        .dev-row:last-child { border-bottom: 0; }
        .dev-name { min-width: 0; color: #c4cad5; font-size: .8rem; overflow-wrap: break-word; }
        .dev-name.is-current::after { content: " · это устройство"; color: #63f5ad; font-size: .68rem; }
        .dev-meta { grid-column: 1 / -1; color: #6b7385; font-size: .68rem; }
        .dev-act { padding: 4px 7px; color: #6b7385; font-size: .85rem; line-height: 1; border: 1px solid rgba(255,255,255,.1); background: transparent; cursor: pointer; transition: all .18s; }
        .dev-act:hover { color: #fff; border-color: rgba(45,226,255,.4); background: rgba(45,226,255,.08); }
        .dev-act.dev-del:hover { color: #ff6b81; border-color: rgba(255,107,129,.45); background: rgba(255,107,129,.1); }
        .dev-rename { min-width: 0; height: 28px; padding: 0 8px; color: #f4fbff; font: 600 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.4); outline: none; background: rgba(4,10,20,.65); }
      </style>
    </head>
    <body>
      <main class="cabinet">
        <header class="cabinet-header">
          <h1>Личный <span>кабинет</span></h1>
          <button class="logout-button install-button" id="install" type="button" hidden>Установить приложение</button>
          <form class="logout-form" action="/logout" method="post"><button class="logout-button" type="submit">Выйти</button></form>
        </header>
        <div class="cabinet-cols">
        <div class="workspace">

          <!-- Метрики: наверху, во всю ширину -->
          <section class="dash">
            <div class="dash-title">Метрики машин</div>
            <div class="metrics-grid" id="metrics-grid"><p class="widget-empty">Загрузка…</p></div>
          </section>

          <!-- NetBird — логотип слева -->
          <section class="panel" style="--accent:#ff7026">
            <button id="netbird-toggle" class="panel-head" type="button" aria-expanded="false" aria-controls="netbird-devices">
              <span class="panel-logo"><img src="/static/netbird-official.png" alt=""></span>
              <span class="panel-text">
                <span class="panel-title">NetBird</span>
                <span class="panel-sub">8 устройств</span>
              </span>
              <span class="panel-arrow" aria-hidden="true">⌄</span>
            </button>
            <div id="netbird-devices" hidden>
              <ul class="device-list">{{DEVICE_ITEMS}}</ul>
            </div>
          </section>

          <!-- Личный дроп — логотип справа -->
          <a class="panel panel--right" href="/drop" style="--accent:#f5c344">
            <span class="panel-head">
              <span class="panel-logo">
                <svg viewBox="0 0 48 40" aria-hidden="true">
                  <defs>
                    <linearGradient id="fold-back" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0" stop-color="#ffd772"/><stop offset="1" stop-color="#e8a521"/>
                    </linearGradient>
                    <linearGradient id="fold-front" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0" stop-color="#ffe9a8"/><stop offset="1" stop-color="#f5bb3c"/>
                    </linearGradient>
                  </defs>
                  <path d="M2 8a4 4 0 0 1 4-4h11.2a3 3 0 0 1 2.3 1.1L23 9h19a4 4 0 0 1 4 4v19a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8Z" fill="url(#fold-back)"/>
                  <path d="M2 15h44v17a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V15Z" fill="url(#fold-front)"/>
                  <path d="M2 15h44" stroke="#fff" stroke-opacity=".45" stroke-width="1.4"/>
                </svg>
              </span>
              <span class="panel-text">
                <span class="panel-title">Личный дроп</span>
                <span class="panel-sub">файлы и текст между устройствами</span>
              </span>
              <span class="panel-arrow panel-arrow--go" aria-hidden="true">⟶</span>
            </span>
          </a>

          <!-- Журнал входов — логотип слева -->
          <section class="panel" style="--accent:#2de2ff">
            <button class="panel-head" id="loginlog-toggle" type="button" aria-expanded="false" aria-controls="loginlog-body">
              <span class="panel-logo">
                <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                  <circle cx="24" cy="24" r="17" stroke="#2de2ff" stroke-width="2.6" stroke-opacity=".55"/>
                  <path d="M24 13v11l7.5 4.5" stroke="#7fe9ff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
                  <path d="M7 24a17 17 0 0 1 5-12" stroke="#2de2ff" stroke-width="2.6" stroke-linecap="round"/>
                  <circle cx="24" cy="24" r="2.6" fill="#7fe9ff"/>
                </svg>
              </span>
              <span class="panel-text">
                <span class="panel-title">Журнал входов</span>
                <span class="panel-sub">история за две недели</span>
              </span>
              <span class="panel-arrow" aria-hidden="true">⌄</span>
            </button>
            <div id="loginlog-body" hidden class="panel-body">
              <div id="loginlog-list"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

          <!-- Запомненные устройства — логотип справа -->
          <section class="panel panel--right" style="--accent:#63f5ad">
            <button class="panel-head" id="devices-toggle" type="button" aria-expanded="false" aria-controls="devices-body">
              <span class="panel-logo">
                <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                  <rect x="4" y="10" width="28" height="19" rx="2.5" stroke="#63f5ad" stroke-width="2.6"/>
                  <path d="M2 33h32" stroke="#63f5ad" stroke-width="2.6" stroke-linecap="round"/>
                  <rect x="30" y="20" width="14" height="22" rx="2.5" fill="#0d1321" stroke="#a8ffd6" stroke-width="2.6"/>
                  <path d="M35 38h4" stroke="#a8ffd6" stroke-width="2.2" stroke-linecap="round"/>
                </svg>
              </span>
              <span class="panel-text">
                <span class="panel-title">Запомнить устройства</span>
                <span class="panel-sub">вход без пароля на своих</span>
              </span>
              <span class="panel-arrow" aria-hidden="true">⌄</span>
            </button>
            <div id="devices-body" hidden class="panel-body">
              <label class="dev-remember">
                <input type="checkbox" id="dev-remember-cb">
                <span>Запомнить это устройство</span>
              </label>
              <p class="dev-hint" id="dev-hint">Вход в кабинет без пароля на 90 дней. Снять галку — устройство забудется.</p>
              <div class="dev-confirm" id="dev-confirm" hidden>
                <input type="password" id="dev-daily" placeholder="Суточный пароль" autocomplete="off">
                <button class="dev-confirm-btn" id="dev-confirm-btn" type="button">Подтвердить</button>
              </div>
              <p class="dev-error" id="dev-error"></p>
              <div id="devices-list"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

          <!-- Тестовые темы: витрина оформления -->
          <a class="panel panel--right" href="/themes" style="--accent:#ff3fa4; margin-bottom:32px">
            <span class="panel-head">
              <span class="panel-logo">
                <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                  <path d="M24 6c8 0 13 5.5 13 13v7c0 3.5-2 5.5-4.5 6.5L31 38H17l-1.5-5.5C13 31.5 11 29.5 11 26v-7C11 11.5 16 6 24 6Z" stroke="#ff3fa4" stroke-width="2.4"/>
                  <path d="M24 14v18M17 20h14M18 27h12" stroke="#2de2ff" stroke-width="1.8" stroke-linecap="round"/>
                  <circle cx="24" cy="14" r="2.6" fill="#2de2ff"/>
                  <path d="M17 41h14" stroke="#ff3fa4" stroke-width="2.4" stroke-linecap="round"/>
                </svg>
              </span>
              <span class="panel-text">
                <span class="panel-title">Тестовые темы</span>
                <span class="panel-sub">разделы как импланты · киберпанк</span>
              </span>
              <span class="panel-arrow panel-arrow--go" aria-hidden="true">⟶</span>
            </span>
          </a>

        </div>

        <!-- Правая колонка: прячется, когда места мало -->
        <aside class="rail">

          <div class="rail-card clock">
            <span class="rail-corner rail-corner--tl"></span><span class="rail-corner rail-corner--tr"></span>
            <span class="rail-corner rail-corner--bl"></span><span class="rail-corner rail-corner--br"></span>
            <div class="clock-time"><span id="clk-h">--</span><em id="clk-sep">:</em><span id="clk-m">--</span><small id="clk-s">--</small></div>
            <div class="clock-date" id="clk-date">—</div>
            <div class="clock-scan"></div>
          </div>

          <div class="rail-card player" id="player">
            <span class="rail-corner rail-corner--tl"></span><span class="rail-corner rail-corner--tr"></span>
            <span class="rail-corner rail-corner--bl"></span><span class="rail-corner rail-corner--br"></span>

            <div class="pl-head">
              <span class="pl-label">Аудио</span>
              <span class="pl-actions">
                <button class="pl-icon" id="pl-add" type="button" title="Добавить треки">+</button>
                <button class="pl-icon" id="pl-toggle-list" type="button" title="Список треков">☰</button>
              </span>
            </div>

            <div class="pl-eq" id="pl-eq" aria-hidden="true"></div>

            <div class="pl-now">
              <div class="pl-title" id="pl-title">ничего не играет</div>
              <div class="pl-artist" id="pl-artist">плеер выключен</div>
            </div>

            <div class="pl-seek"><div class="pl-seek-fill" id="pl-seek-fill"></div>
              <input class="pl-seek-input" id="pl-seek" type="range" min="0" max="1000" value="0" aria-label="Перемотка">
            </div>
            <div class="pl-times"><span id="pl-cur">0:00</span><span id="pl-dur">0:00</span></div>

            <div class="pl-controls">
              <button class="pl-btn" id="pl-prev" type="button" title="Предыдущий">◀◀</button>
              <button class="pl-btn pl-play" id="pl-play" type="button" title="Играть">▶</button>
              <button class="pl-btn" id="pl-next" type="button" title="Следующий">▶▶</button>
              <input class="pl-vol" id="pl-vol" type="range" min="0" max="100" value="70" aria-label="Громкость">
            </div>

            <div class="pl-list" id="pl-list">
              <div class="pl-list-head">
                <span id="pl-count">0 треков</span>
                <span id="pl-used"></span>
              </div>
              <div id="pl-tracks"></div>
              <input type="file" id="pl-file" accept="audio/*,.mp3,.m4a,.flac,.ogg,.opus,.wav,.aac" multiple hidden>
            </div>

            <audio id="pl-audio" preload="none"></audio>
          </div>

        </aside>
        </div>
      </main>

      <div id="gate-modal" class="gate-modal" hidden>
        <div class="gate-backdrop" data-gate-close></div>
        <section class="gate-panel" role="dialog" aria-modal="true" aria-labelledby="gate-title">
          <button class="gate-close" type="button" data-gate-close aria-label="Закрыть">×</button>
          <h2 id="gate-title">Пароль консоли</h2>
          <form id="gate-form">
            <input id="gate-password" name="password" type="password" autocomplete="off" required>
            <button class="gate-submit" type="submit">Войти</button>
            <p id="gate-error" class="gate-error" role="alert"></p>
          </form>
        </section>
      </div>

      <div id="ssh-login-modal" class="gate-modal" hidden>
        <div class="gate-backdrop" data-ssh-login-close></div>
        <section class="gate-panel" role="dialog" aria-modal="true" aria-labelledby="ssh-login-title">
          <button class="gate-close" type="button" data-ssh-login-close aria-label="Закрыть">×</button>
          <h2 id="ssh-login-title">SSH-логин</h2>
          <form id="ssh-login-form">
            <input id="ssh-login-username" name="username" type="text" autocomplete="off" placeholder="Имя пользователя" required>
            <input id="ssh-login-password" name="password" type="password" autocomplete="off" placeholder="Пароль" required>
            <button class="gate-submit" type="submit">Подключиться</button>
            <p id="ssh-login-error" class="gate-error" role="alert"></p>
          </form>
        </section>
      </div>

      <div id="vnc-login-modal" class="gate-modal" hidden>
        <div class="gate-backdrop" data-vnc-login-close></div>
        <section class="gate-panel" role="dialog" aria-modal="true" aria-labelledby="vnc-login-title">
          <button class="gate-close" type="button" data-vnc-login-close aria-label="Закрыть">×</button>
          <h2 id="vnc-login-title">VNC</h2>
          <form id="vnc-login-form">
            <input id="vnc-login-password" name="password" type="password" autocomplete="off" placeholder="Пароль (если задан)" required>
            <button class="gate-submit" type="submit">Подключиться</button>
            <p id="vnc-login-error" class="gate-error" role="alert"></p>
          </form>
        </section>
      </div>

      <div id="rdp-login-modal" class="gate-modal" hidden>
        <div class="gate-backdrop" data-rdp-login-close></div>
        <section class="gate-panel" role="dialog" aria-modal="true" aria-labelledby="rdp-login-title">
          <button class="gate-close" type="button" data-rdp-login-close aria-label="Закрыть">×</button>
          <h2 id="rdp-login-title">Windows RDP</h2>
          <form id="rdp-login-form">
            <input id="rdp-login-username" name="username" type="text" autocomplete="off" placeholder="Имя пользователя" required>
            <input id="rdp-login-password" name="password" type="password" autocomplete="off" placeholder="Пароль" required>
            <select id="rdp-login-quality" class="gate-select">
              <option value="high">Качество: высокое — 32 бита, все эффекты</option>
              <option value="medium" selected>Качество: среднее — 16 бит, без обоев</option>
              <option value="low">Качество: низкое — 8 бит, для слабой связи</option>
            </select>
            <button class="gate-submit" type="submit">Подключиться</button>
            <p id="rdp-login-error" class="gate-error" role="alert"></p>
          </form>
        </section>
      </div>

      <div id="rdp-overlay" class="rdp-overlay" hidden>
        <div class="term-header">
          <span id="rdp-title"></span><span id="rdp-quality" class="conn-quality"></span>
          <div class="rdp-header-actions">
            <button id="rdp-toolbar-toggle" class="term-close" type="button" hidden>☰</button>
            <button id="rdp-touch-toggle" class="term-close" type="button" hidden>Touchpad</button>
            <button id="rdp-close" class="term-close" type="button">Закрыть</button>
          </div>
        </div>
        <div class="rdp-content">
          <div id="rdp-display" class="rdp-display"></div>
          <div id="rdp-toolbar" class="rdp-toolbar" hidden>
            <button class="rdp-key" data-keysym="65307">Esc</button>
            <button class="rdp-key" data-keysym="65289">Tab</button>
            <button class="rdp-key" data-mod="65507">Ctrl</button>
            <button class="rdp-key" data-mod="65513">Alt</button>
            <button class="rdp-key" data-mod="65515">Win</button>
            <button class="rdp-key" data-keysym="65288">⌫</button>
            <button class="rdp-key" data-keysym="65361">◀</button>
            <button class="rdp-key" data-keysym="65362">▲</button>
            <button class="rdp-key" data-keysym="65364">▼</button>
            <button class="rdp-key" data-keysym="65363">▶</button>
            <button class="rdp-key-combo" data-combo="65507,65513,65535">C+A+D</button>
            <button class="rdp-key-combo" data-combo="65507,65505">C+Shift</button>
            <button class="rdp-key-combo" data-combo="65513,65505">A+Shift</button>
            <button class="rdp-key-combo" data-combo="65515,65513">Win+A</button>
            <button id="rdp-kbd-btn" class="rdp-key" type="button" hidden>⌨</button>
          </div>
        </div>
        <input id="rdp-kbd-input" class="rdp-kbd-input" type="text" autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false" inputmode="text">
      </div>

      <div id="term-overlay" class="term-overlay" hidden>
        <div class="term-header">
          <span id="term-title"></span><span id="ssh-quality" class="conn-quality"></span>
          <button id="term-close" class="term-close" type="button">Закрыть</button>
        </div>
        <!-- Ряд кнопок для телефона: с экранной клавиатуры ни стрелок, ни Tab,
             ни Ctrl нет, а вставку буфера браузер сам в терминал не отдаёт. -->
        <div class="term-tools" id="term-tools">
          <button class="term-key term-key-wide" type="button" data-paste>Вставить</button>
          <button class="term-key term-key-go" type="button" data-key="enter">Enter ⏎</button>
          <button class="term-key" type="button" data-key="up">↑</button>
          <button class="term-key" type="button" data-key="down">↓</button>
          <button class="term-key" type="button" data-key="tab">Tab</button>
          <button class="term-key" type="button" data-key="ctrlc">Ctrl+C</button>
          <button class="term-key" type="button" data-key="esc">Esc</button>
        </div>
        <div id="term-body" class="term-body"></div>
      </div>

      <!-- Библиотеки лежат в static/vendor, а не на CDN: когда jsdelivr
           недоступен, консоль и RDP переставали открываться вообще без
           объяснений. Адрес CDN оставлен запасным на случай, если файл
           почему-то не отдался. -->
      <script>
        // Догружает библиотеку с CDN, если своя копия почему-то не отдалась.
        function vendorFallback(el, url) {
          el.onerror = null;
          var script = document.createElement("script");
          script.src = url;
          document.head.appendChild(script);
        }
      </script>
      <link rel="stylesheet" href="/static/vendor/xterm.css">
      <script defer src="/static/vendor/xterm.js"
              onerror="vendorFallback(this, 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js')"></script>
      <script defer src="/static/vendor/xterm-addon-fit.js"
              onerror="vendorFallback(this, 'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js')"></script>
      <script defer src="/static/vendor/guacamole-common.min.js"
              onerror="vendorFallback(this, 'https://cdn.jsdelivr.net/npm/guacamole-common-js@1.5.0/dist/cjs/guacamole-common.min.js')"></script>
      <script>
        (() => {
          // Раскрытием занимается общий обработчик .panel-head[aria-controls]
          // ниже по странице — свой здесь дал бы двойное срабатывание.
          const devices = document.getElementById("netbird-devices");
          const timers = new WeakMap();

          const copyFallback = (text) => {
            const input = document.createElement("textarea");
            input.value = text;
            input.style.position = "fixed";
            input.style.opacity = "0";
            document.body.appendChild(input);
            input.select();
            document.execCommand("copy");
            input.remove();
          };

          document.querySelectorAll(".copy-ip").forEach((button) => {
            button.addEventListener("click", async () => {
              try {
                if (navigator.clipboard && window.isSecureContext) {
                  await navigator.clipboard.writeText(button.dataset.ip);
                } else {
                  copyFallback(button.dataset.ip);
                }
                const message = button.parentElement.querySelector(".copy-status");
                message.classList.add("visible");
                clearTimeout(timers.get(message));
                timers.set(message, setTimeout(() => message.classList.remove("visible"), 1800));
              } catch {
                const message = button.parentElement.querySelector(".copy-status");
                message.textContent = "Ошибка";
                message.classList.add("visible");
                setTimeout(() => { message.classList.remove("visible"); message.textContent = "Скопировано"; }, 1800);
              }
            });
          });
        })();

        (() => {
          const refreshStatus = async () => {
            let data;
            try {
              const response = await fetch("/api/netbird/status", { credentials: "same-origin" });
              if (!response.ok) return;
              data = await response.json();
            } catch {
              return;
            }
            document.querySelectorAll(".device").forEach((item) => {
              const info = data[item.dataset.ip];
              const statusEl = item.querySelector(".device-status");
              if (!info) return;
              const btn = item.querySelector(".connect-btn");
              const wolBtn = item.querySelector(".wol-btn");
              if (info.online) {
                statusEl.textContent = info.latency_ms != null ? `${Math.round(info.latency_ms)} ms` : "онлайн";
                statusEl.className = "device-status online";
                if (btn) btn.classList.remove("btn-offline");
                if (wolBtn) { wolBtn.classList.add("wol-online"); wolBtn.title = "Выключить ПК"; wolBtn.textContent = "⏻"; }
              } else {
                statusEl.textContent = "офлайн";
                statusEl.className = "device-status offline";
                if (btn) btn.classList.add("btn-offline");
                if (wolBtn) { wolBtn.classList.remove("wol-online"); wolBtn.title = "Wake-on-LAN"; wolBtn.textContent = "⚡"; }
              }
            });
          };
          refreshStatus();
          setInterval(refreshStatus, 10000);
        })();

        (() => {
          document.querySelectorAll(".wol-btn").forEach(btn => {
            btn.addEventListener("click", async () => {
              const isOnline = btn.classList.contains("wol-online");
              btn.disabled = true;
              const origText = btn.textContent;
              try {
                if (isOnline) {
                  if (!confirm("Выключить ПК?")) { btn.disabled = false; return; }
                  const r = await fetch("/api/pc/shutdown", { method: "POST", credentials: "same-origin" });
                  if (!r.ok) throw new Error((await r.json()).error);
                } else {
                  const r = await fetch("/api/wol", {
                    method: "POST", credentials: "same-origin",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mac: btn.dataset.mac }),
                  });
                  if (!r.ok) throw new Error((await r.json()).error);
                }
                btn.textContent = "✓";
                btn.classList.add("wol-sent");
                setTimeout(() => { btn.textContent = origText; btn.classList.remove("wol-sent"); btn.disabled = false; }, 4000);
              } catch (e) {
                btn.textContent = "✗";
                setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
              }
            });
          });
        })();

        (() => {
          const gateModal = document.getElementById("gate-modal");
          const gateForm = document.getElementById("gate-form");
          const gatePassword = document.getElementById("gate-password");
          const gateError = document.getElementById("gate-error");
          const sshLoginModal = document.getElementById("ssh-login-modal");
          const sshLoginForm = document.getElementById("ssh-login-form");
          const sshLoginUsername = document.getElementById("ssh-login-username");
          const sshLoginPassword = document.getElementById("ssh-login-password");
          const sshLoginError = document.getElementById("ssh-login-error");
          const termOverlay = document.getElementById("term-overlay");
          const termTitle = document.getElementById("term-title");
          const termBody = document.getElementById("term-body");

          /* Подгоняем окно консоли под видимую часть экрана. На телефоне при
             появлении клавиатуры visualViewport становится ниже, а обычный
             resize при этом может вообще не сработать — поэтому слушаем
             именно его. Пересчёт откладываем на кадр: во время анимации
             выезда клавиатуры размеры меняются десятки раз подряд. */
          let kbdWatching = false;
          const watchKeyboard = (onFit) => {
            const vv = window.visualViewport;
            const apply = () => {
              const root = termOverlay.style;
              if (!vv) { root.removeProperty("--term-h"); root.removeProperty("--term-top"); }
              else {
                root.setProperty("--term-h", vv.height + "px");
                root.setProperty("--term-top", vv.offsetTop + "px");
              }
              if (onFit) onFit();
            };
            apply();
            if (!vv || kbdWatching) return;
            kbdWatching = true;
            let pending = 0;
            const later = () => {
              cancelAnimationFrame(pending);
              pending = requestAnimationFrame(apply);
            };
            vv.addEventListener("resize", later);
            vv.addEventListener("scroll", later);
          };
          const termClose = document.getElementById("term-close");

          let consoleAuthenticated = false;
          let pendingDevice = null;
          let term = null;
          let fitAddon = null;
          let ws = null;

          const rdpLoginModal = document.getElementById("rdp-login-modal");
          const rdpLoginForm = document.getElementById("rdp-login-form");
          const rdpLoginUsername = document.getElementById("rdp-login-username");
          const rdpLoginPassword = document.getElementById("rdp-login-password");
          const rdpLoginError = document.getElementById("rdp-login-error");
          const rdpLoginQuality = document.getElementById("rdp-login-quality");
          const rdpOverlay = document.getElementById("rdp-overlay");
          const rdpTitleEl = document.getElementById("rdp-title");
          const rdpDisplay = document.getElementById("rdp-display");
          const rdpCloseBtn = document.getElementById("rdp-close");
          let rdpClient = null;
          let rdpKeyboard = null;
          let toolbarAbort = null;
          let rdpKeepalive = null;
          let rdpNopSentAt = null;

          const rdpQuality = document.getElementById("rdp-quality");
          const sshQuality = document.getElementById("ssh-quality");
          const updateQuality = (el, rtt) => {
            el.textContent = `● ${rtt} ms`;
            el.className = "conn-quality " + (rtt < 80 ? "good" : rtt < 250 ? "warn" : "bad");
          };

          // ── VNC login modal ───────────────────────────────────────────
          const vncLoginModal    = document.getElementById("vnc-login-modal");
          const vncLoginForm     = document.getElementById("vnc-login-form");
          const vncLoginPassword = document.getElementById("vnc-login-password");
          const vncLoginError    = document.getElementById("vnc-login-error");

          const closeVncLogin = () => {
            vncLoginModal.hidden = true;
            vncLoginForm.reset();
            vncLoginError.textContent = "";
          };
          document.querySelectorAll("[data-vnc-login-close]").forEach(el => el.addEventListener("click", () => {
            closeVncLogin(); pendingDevice = null;
          }));

          const openVncLogin = () => {
            document.getElementById("vnc-login-title").textContent = pendingDevice ? `VNC — ${pendingDevice.name}` : "VNC";
            vncLoginModal.hidden = false;
            requestAnimationFrame(() => vncLoginPassword.focus());
          };

          vncLoginForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const device = pendingDevice;
            const password = vncLoginPassword.value;
            closeVncLogin();
            if (device) openRdp(device.ip, device.name, "", password, "vnc");
          });

          // ── RDP helpers ──────────────────────────────────────────────
          function GuacAuthTunnel(ip, authPayload, protocol) {
            Guacamole.Tunnel.call(this);
            const self = this;
            let ws = null;
            let guacBuf = "";
            this.connect = function() {
              const proto = location.protocol === "https:" ? "wss:" : "ws:";
              ws = new WebSocket(`${proto}//${location.host}/ws/${protocol ?? "rdp"}/${ip}`);
              self.state = Guacamole.Tunnel.State.CONNECTING;
              if (self.onstatechange) self.onstatechange(self.state);
              ws.onopen = () => {
                ws.send(JSON.stringify(authPayload));
                self.state = Guacamole.Tunnel.State.OPEN;
                if (self.onstatechange) self.onstatechange(self.state);
              };
              ws.onmessage = (event) => {
                guacBuf += event.data;
                let pos = 0;
                outer: while (pos < guacBuf.length) {
                  const instrStart = pos;
                  const parts = [];
                  while (true) {
                    let dot = pos;
                    while (dot < guacBuf.length && guacBuf[dot] !== ".") dot++;
                    if (dot >= guacBuf.length) { pos = instrStart; break outer; }
                    const len = parseInt(guacBuf.slice(pos, dot), 10);
                    if (isNaN(len)) { pos = dot + 1; break; }
                    pos = dot + 1;
                    if (pos + len >= guacBuf.length) { pos = instrStart; break outer; }
                    parts.push(guacBuf.slice(pos, pos + len));
                    pos += len;
                    const sep = guacBuf[pos++];
                    if (sep === ";") break;
                  }
                  if (parts.length) {
                    if (parts[0] === "nop") {
                      ws.send("3.nop;");
                      if (rdpNopSentAt !== null) {
                        updateQuality(rdpQuality, Math.round(performance.now() - rdpNopSentAt));
                        rdpNopSentAt = null;
                      }
                    } else if (self.oninstruction) {
                      self.oninstruction(parts[0], parts.slice(1));
                    }
                  }
                }
                guacBuf = guacBuf.slice(pos);
              };
              ws.onclose = () => {
                self.state = Guacamole.Tunnel.State.CLOSED;
                if (self.onstatechange) self.onstatechange(self.state);
              };
              ws.onerror = () => { if (self.onerror) self.onerror({ code: 0, message: "WebSocket error" }); };
            };
            this.sendMessage = function(...args) {
              if (!ws || ws.readyState !== WebSocket.OPEN) return;
              ws.send(args.map(v => { const s = String(v); return `${s.length}.${s}`; }).join(",") + ";");
            };
            this.disconnect = function() { if (ws) { ws.close(); ws = null; } };
          }
          const closeRdpLogin = () => {
            rdpLoginModal.hidden = true;
            rdpLoginForm.reset();
            rdpLoginError.textContent = "";
          };
          document.querySelectorAll("[data-rdp-login-close]").forEach(el => el.addEventListener("click", () => {
            closeRdpLogin();
            pendingDevice = null;
          }));

          const openRdpLogin = () => {
            document.getElementById("rdp-login-title").textContent = pendingDevice ? `RDP — ${pendingDevice.name}` : "Windows RDP";
            if (rdpLoginQuality) rdpLoginQuality.value = localStorage.getItem("rdpQuality") || "medium";
            rdpLoginModal.hidden = false;
            requestAnimationFrame(() => rdpLoginUsername.focus());
          };

          const closeRdp = () => {
            rdpOverlay.hidden = true;
            rdpOverlay.style.height = "";
            rdpOverlay.style.top = "";
            rdpNopSentAt = null;
            rdpQuality.textContent = "";
            rdpQuality.className = "conn-quality";
            if (document.pointerLockElement) document.exitPointerLock();
            if (toolbarAbort) { toolbarAbort.abort(); toolbarAbort = null; }
            if (rdpKeepalive) { clearInterval(rdpKeepalive); rdpKeepalive = null; }
            if (rdpClient) { rdpClient.disconnect(); rdpClient = null; }
            if (rdpKeyboard) { rdpKeyboard.onkeydown = rdpKeyboard.onkeyup = null; rdpKeyboard = null; }
            document.getElementById("rdp-toolbar").querySelectorAll(".rdp-key.active").forEach(el => el.classList.remove("active"));
            rdpDisplay.innerHTML = "";
          };
          rdpCloseBtn.addEventListener("click", closeRdp);

          const openRdp = (ip, name, username, password, protocol = "rdp", quality = "medium") => {
            if (typeof Guacamole === "undefined") {
              alert("Не удалось загрузить guacamole-common-js — проверьте сеть/CDN.");
              return;
            }
            GuacAuthTunnel.prototype = Object.create(Guacamole.Tunnel.prototype);
            GuacAuthTunnel.prototype.constructor = GuacAuthTunnel;
            const isMobile = window.innerWidth <= 900 || navigator.maxTouchPoints > 0 ||
                             /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

            rdpTitleEl.textContent = name + " — " + ip;
            rdpOverlay.hidden = false;

            const toolbar            = document.getElementById("rdp-toolbar");
            const touchToggleBtn     = document.getElementById("rdp-touch-toggle");
            const kbdBtn             = document.getElementById("rdp-kbd-btn");
            const kbdInput           = document.getElementById("rdp-kbd-input");
            const toolbarToggleBtn   = document.getElementById("rdp-toolbar-toggle");
            toolbar.hidden           = isMobile;
            kbdBtn.hidden            = !isMobile;
            touchToggleBtn.hidden    = !isMobile;
            toolbarToggleBtn.hidden  = !isMobile;
            toolbarToggleBtn.onclick = () => { toolbar.hidden = !toolbar.hidden; };

            const displayRect = rdpDisplay.getBoundingClientRect();
            const width  = Math.round(displayRect.width)  || window.innerWidth;
            const height = Math.round(displayRect.height) || (window.innerHeight - 45);

            // ── tunnel + client ─────────────────────────────────────────
            const tunnel = new GuacAuthTunnel(ip, { type: "auth", username, password, width, height, quality }, protocol);
            rdpClient = new Guacamole.Client(tunnel);
            const displayEl = rdpClient.getDisplay().getElement();
            rdpDisplay.innerHTML = "";
            rdpDisplay.appendChild(displayEl);

            // ── mouse / touch ────────────────────────────────────────────
            let touchMode = "touchpad";
            let inputHandler = null;
            const scaleMouseState = (e) => {
              const st = e.state ?? e;
              const sc = rdpClient?.getDisplay()?.getScale() ?? 1;
              return (sc && sc !== 1)
                ? { ...st, x: Math.round(st.x / sc), y: Math.round(st.y / sc) }
                : st;
            };
            const attachInput = () => {
              if (inputHandler) { inputHandler.onmousedown = inputHandler.onmouseup = inputHandler.onmousemove = null; }
              const Ctor = !isMobile              ? Guacamole.Mouse
                         : touchMode === "touchpad" ? Guacamole.Mouse.Touchpad
                         : Guacamole.Mouse.Touchscreen;
              inputHandler = new Ctor(displayEl);
              inputHandler.onmousedown = inputHandler.onmouseup = inputHandler.onmousemove =
                (e) => rdpClient?.sendMouseState(scaleMouseState(e));
            };
            attachInput();

            touchToggleBtn.textContent = "Touchpad";
            touchToggleBtn.onclick = () => {
              touchMode = touchMode === "touchpad" ? "touchscreen" : "touchpad";
              touchToggleBtn.textContent = touchMode === "touchpad" ? "Touchpad" : "Touchscreen";
              attachInput();
            };

            // ── AbortController (shared by pointer lock + toolbar) ───────
            if (toolbarAbort) toolbarAbort.abort();
            toolbarAbort = new AbortController();
            const sig = toolbarAbort.signal;

            // ── pointer lock (desktop only) ──────────────────────────────
            if (!isMobile && rdpDisplay.requestPointerLock) {
              let plLocked = false, plX = width / 2, plY = height / 2;
              const lockHint = document.createElement("div");
              lockHint.className = "rdp-lock-hint";
              lockHint.textContent = "Кликни для захвата мыши · Esc — отпустить";
              rdpDisplay.appendChild(lockHint);
              const plSend = (x, y, btns) => rdpClient?.sendMouseState({
                x, y,
                left:   (btns & 1) !== 0,
                middle: (btns & 4) !== 0,
                right:  (btns & 2) !== 0,
                up: false, down: false
              });
              // До захвата: клик на displayEl запрашивает lock
              displayEl.addEventListener("mousedown", (e) => {
                if (!plLocked) {
                  if (inputHandler) inputHandler.onmousedown = inputHandler.onmouseup = inputHandler.onmousemove = null;
                  rdpDisplay.requestPointerLock();
                  e.stopImmediatePropagation();
                }
              }, { signal: sig, capture: true });
              // После захвата: все события идут на rdpDisplay (locked element)
              rdpDisplay.addEventListener("mousedown", (e) => { if (plLocked) plSend(plX, plY, e.buttons); }, { signal: sig });
              rdpDisplay.addEventListener("mouseup",   (e) => { if (plLocked) plSend(plX, plY, e.buttons); }, { signal: sig });
              rdpDisplay.addEventListener("mousemove", (e) => {
                if (!plLocked) return;
                const d = rdpClient?.getDisplay();
                const nW = d?.getWidth()  || width;
                const nH = d?.getHeight() || height;
                plX = Math.max(0, Math.min(nW - 1, plX + e.movementX));
                plY = Math.max(0, Math.min(nH - 1, plY + e.movementY));
                plSend(plX, plY, e.buttons);
              }, { signal: sig });
              rdpDisplay.addEventListener("wheel", (e) => {
                if (!plLocked) return;
                e.preventDefault();
                const up = e.deltaY < 0;
                rdpClient?.sendMouseState({ x: plX, y: plY, left: false, middle: false, right: false, up, down: !up });
                rdpClient?.sendMouseState({ x: plX, y: plY, left: false, middle: false, right: false, up: false, down: false });
              }, { signal: sig, passive: false });
              document.addEventListener("pointerlockchange", () => {
                plLocked = document.pointerLockElement === rdpDisplay;
                lockHint.hidden = plLocked;
                if (!plLocked) attachInput();
              }, { signal: sig });
            }

            // ── hardware keyboard ────────────────────────────────────────
            rdpKeyboard = new Guacamole.Keyboard(document);
            rdpKeyboard.onkeydown = (k) => { if (!rdpOverlay.hidden && rdpClient) rdpClient.sendKeyEvent(1, k); };
            rdpKeyboard.onkeyup   = (k) => { if (!rdpOverlay.hidden && rdpClient) rdpClient.sendKeyEvent(0, k); };
            // Intercept Win/Meta key — prevents Start menu on host when RDP is open
            document.addEventListener("keydown", (e) => {
              if (!rdpOverlay.hidden && (e.key === "Meta" || e.key === "OS" || e.code === "MetaLeft" || e.code === "MetaRight")) {
                e.preventDefault();
              }
            }, { capture: true, signal: sig });

            // ── toolbar ──────────────────────────────────────────────────
            const activeModifiers = new Set();

            const clearMods = () => {
              activeModifiers.forEach(k => rdpClient?.sendKeyEvent(0, k));
              activeModifiers.clear();
              toolbar.querySelectorAll(".rdp-key.active").forEach(el => el.classList.remove("active"));
            };

            toolbar.addEventListener("pointerdown", (e) => {
              const btn = e.target.closest("[data-keysym],[data-mod],[data-combo]");
              if (!btn) return;
              e.preventDefault();
              if (btn.dataset.keysym) {
                const k = parseInt(btn.dataset.keysym, 10);
                activeModifiers.forEach(m => rdpClient?.sendKeyEvent(1, m));
                rdpClient?.sendKeyEvent(1, k);
                rdpClient?.sendKeyEvent(0, k);
                clearMods();
              } else if (btn.dataset.mod) {
                const k = parseInt(btn.dataset.mod, 10);
                if (activeModifiers.has(k)) { activeModifiers.delete(k); btn.classList.remove("active"); }
                else                         { activeModifiers.add(k);    btn.classList.add("active"); }
              } else if (btn.dataset.combo) {
                clearMods();
                const keys = btn.dataset.combo.split(",").map(Number);
                keys.forEach(k => rdpClient?.sendKeyEvent(1, k));
                [...keys].reverse().forEach(k => rdpClient?.sendKeyEvent(0, k));
              }
            }, { signal: sig });

            // ── virtual (soft) keyboard ──────────────────────────────────
            kbdBtn.onclick = () => { kbdInput.value = ""; kbdInput.focus(); };
            kbdInput.addEventListener("input", (e) => {
              for (const ch of (e.data ?? "")) {
                const k = ch.codePointAt(0);
                rdpClient?.sendKeyEvent(1, k);
                rdpClient?.sendKeyEvent(0, k);
              }
              kbdInput.value = "";
            }, { signal: sig });
            kbdInput.addEventListener("keydown", (e) => {
              const map = { Backspace: 65288, Enter: 65293, Tab: 65289, Escape: 65307 };
              if (e.key in map) { e.preventDefault(); rdpClient?.sendKeyEvent(1, map[e.key]); rdpClient?.sendKeyEvent(0, map[e.key]); }
            }, { signal: sig });

            // ── mobile: 2-finger scroll + keyboard resize ────────────────
            if (isMobile) {
              // Track RDP cursor position from single-touch moves
              let lastRdpX = Math.round(width / 2), lastRdpY = Math.round(height / 2);
              displayEl.addEventListener("touchmove", (e) => {
                if (e.touches.length === 1) {
                  const rect = displayEl.getBoundingClientRect();
                  const sc = rdpClient?.getDisplay()?.getScale() ?? 1;
                  lastRdpX = Math.round((e.touches[0].clientX - rect.left) / sc);
                  lastRdpY = Math.round((e.touches[0].clientY - rect.top)  / sc);
                }
              }, { signal: sig });

              // 2-finger drag = scroll wheel
              let scrollStart = null;
              displayEl.addEventListener("touchstart", (e) => {
                if (e.touches.length === 2) {
                  scrollStart = { y: (e.touches[0].clientY + e.touches[1].clientY) / 2 };
                  e.preventDefault();
                  e.stopImmediatePropagation();
                }
              }, { passive: false, capture: true, signal: sig });

              displayEl.addEventListener("touchmove", (e) => {
                if (e.touches.length !== 2 || !scrollStart || !rdpClient) return;
                const cy = (e.touches[0].clientY + e.touches[1].clientY) / 2;
                const dy = cy - scrollStart.y;
                if (Math.abs(dy) >= 8) {
                  const up = dy > 0;
                  const st = { x: lastRdpX, y: lastRdpY, left: false, middle: false, right: false, up, down: !up };
                  rdpClient.sendMouseState(st);
                  rdpClient.sendMouseState({ ...st, up: false, down: false });
                  scrollStart.y = cy;
                }
                e.preventDefault();
                e.stopImmediatePropagation();
              }, { passive: false, capture: true, signal: sig });

              displayEl.addEventListener("touchend", (e) => {
                if (e.touches.length < 2) scrollStart = null;
              }, { capture: true, signal: sig });

              // Shrink overlay when software keyboard opens
              if (window.visualViewport) {
                const vvHandler = () => {
                  rdpOverlay.style.height = window.visualViewport.height + "px";
                  rdpOverlay.style.top    = window.visualViewport.offsetTop + "px";
                  fitDisplay();
                };
                window.visualViewport.addEventListener("resize", vvHandler, { signal: sig });
              }
            }

            const fitDisplay = () => {
              if (!rdpClient) return;
              const d = rdpClient.getDisplay();
              if (!d.getWidth() || !d.getHeight()) return;
              const s = Math.min(
                rdpDisplay.clientWidth  / d.getWidth(),
                rdpDisplay.clientHeight / d.getHeight()
              );
              d.scale(s);
            };
            rdpClient.getDisplay().onresize = fitDisplay;
            window.addEventListener("resize", fitDisplay, { signal: sig });

            rdpClient.onerror = (err) => {
              rdpDisplay.innerHTML = `<p style="color:#ff6b81;padding:20px;font-family:monospace">Ошибка RDP: ${err?.message ?? JSON.stringify(err)}</p>`;
            };
            tunnel.onstatechange = (state) => {
              if (state === Guacamole.Tunnel.State.CLOSED && !rdpOverlay.hidden)
                rdpDisplay.insertAdjacentHTML("beforeend", '<p style="color:#8f99ab;padding:10px 20px;font-family:monospace;position:absolute;bottom:0">Соединение закрыто.</p>');
            };
            rdpClient.connect();
            rdpQuality.textContent = "● …";
            rdpQuality.className = "conn-quality";
            rdpKeepalive = setInterval(() => {
              if (tunnel.state === Guacamole.Tunnel.State.OPEN) {
                rdpNopSentAt = performance.now();
                tunnel.sendMessage("nop");
              }
            }, 10000);
          };

          rdpLoginForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const device = pendingDevice;
            const username = rdpLoginUsername.value;
            const password = rdpLoginPassword.value;
            const quality = rdpLoginQuality ? rdpLoginQuality.value : "medium";
            if (rdpLoginQuality) localStorage.setItem("rdpQuality", quality);
            closeRdpLogin();
            if (device) openRdp(device.ip, device.name, username, password, "rdp", quality);
          });
          // ─────────────────────────────────────────────────────────────

          const closeGate = () => {
            gateModal.hidden = true;
            gateForm.reset();
            gateError.textContent = "";
          };

          document.querySelectorAll("[data-gate-close]").forEach((el) => el.addEventListener("click", () => {
            closeGate();
            pendingDevice = null;
          }));

          gateForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            gateError.textContent = "";
            try {
              const response = await fetch("/api/console/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: gatePassword.value }),
              });
              if (!response.headers.get("content-type")?.includes("application/json")) {
                gateError.textContent = "Сессия истекла, обновите страницу и войдите заново.";
                return;
              }
              const result = await response.json();
              if (!response.ok) {
                gateError.textContent = result.error || "Не удалось войти.";
                return;
              }
              consoleAuthenticated = true;
              closeGate();
              if (pendingDevice?.type === "rdp") openRdpLogin();
              else if (pendingDevice?.type === "vnc") openVncLogin();
              else openSshLogin();
            } catch {
              gateError.textContent = "Сервер недоступен.";
            }
          });

          const closeSshLogin = () => {
            sshLoginModal.hidden = true;
            sshLoginForm.reset();
            sshLoginError.textContent = "";
            pendingDevice = null;
          };

          document.querySelectorAll("[data-ssh-login-close]").forEach((el) => el.addEventListener("click", closeSshLogin));

          const openSshLogin = () => {
            document.getElementById("ssh-login-title").textContent = pendingDevice ? `SSH — ${pendingDevice.name}` : "SSH-логин";
            sshLoginModal.hidden = false;
            requestAnimationFrame(() => sshLoginUsername.focus());
          };

          sshLoginForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const device = pendingDevice;
            const username = sshLoginUsername.value;
            const password = sshLoginPassword.value;
            sshLoginModal.hidden = true;
            sshLoginForm.reset();
            sshLoginError.textContent = "";
            pendingDevice = null;
            if (device) openTerminal(device.ip, device.name, username, password);
          });

          const closeTerminal = () => {
            termOverlay.hidden = true;
            if (ws) { ws.close(); ws = null; }
            if (term) { term.dispose(); term = null; }
            termBody.innerHTML = "";
          };
          termClose.addEventListener("click", closeTerminal);

          // ── Кнопки консоли ───────────────────────────────────────────
          // Всё уходит в тот же канал, что и набор с клавиатуры, поэтому
          // сервер про эти кнопки ничего не знает и знать не должен.
          const termSend = (data) => {
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: "data", data }));
            }
            if (term) term.focus();
          };

          const termToast = (text) => {
            const el = document.createElement("div");
            el.className = "term-toast";
            el.textContent = text;
            document.body.appendChild(el);
            setTimeout(() => el.remove(), 1800);
          };

          // Коды держим здесь, а не в атрибутах разметки: в атрибуте «\\r» так и
          // остался бы двумя символами, и терминал получал бы текст вместо Enter.
          const TERM_KEYS = {
            enter: "\\r", up: "\\x1b[A", down: "\\x1b[B",
            tab: "\\t", ctrlc: "\\x03", esc: "\\x1b",
          };
          document.querySelectorAll("#term-tools [data-key]").forEach(btn => {
            btn.addEventListener("click", () => termSend(TERM_KEYS[btn.dataset.key] || ""));
          });

          document.querySelector("#term-tools [data-paste]").addEventListener("click", async () => {
            let text = null;
            try {
              // Работает только по HTTPS и только по жесту пользователя —
              // нажатие кнопки как раз им и является.
              text = await navigator.clipboard.readText();
            } catch (e) {
              // Firefox и старые браузеры чтение буфера не дают: спрашиваем руками.
              text = window.prompt("Вставьте команды сюда (браузер не даёт прочитать буфер сам):", "");
            }
            if (!text) { termToast("Буфер пуст"); return; }
            termSend(text);
            const lines = text.split("\\n").filter(l => l.trim()).length;
            termToast(lines > 1 ? `Вставлено строк: ${lines}` : "Вставлено");
          });

          const openTerminal = (ip, name, username, password) => {
            termTitle.textContent = name + " — " + ip;
            termOverlay.hidden = false;
            if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
              termBody.textContent = "Не удалось загрузить библиотеку терминала (xterm.js) — проверьте сеть/CDN.";
              return;
            }
            term = new Terminal({ convertEol: true, fontFamily: "Cascadia Code, Consolas, monospace", fontSize: 14, theme: { background: "#05070c" } });
            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(termBody);
            fitAddon.fit();

            const protocol = location.protocol === "https:" ? "wss:" : "ws:";
            let gotData = false;
            ws = new WebSocket(`${protocol}//${location.host}/ws/console/${ip}`);

            ws.addEventListener("open", () => {
              ws.send(JSON.stringify({ type: "auth", username, password }));
              fitAddon.fit();
              ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
            });

            let sshPingTime = null;
            sshQuality.textContent = "● …";
            sshQuality.className = "conn-quality";
            const pingInterval = setInterval(() => {
              if (ws && ws.readyState === WebSocket.OPEN) {
                sshPingTime = performance.now();
                ws.send(JSON.stringify({ type: "ping" }));
              }
            }, 10000);

            ws.addEventListener("message", (event) => {
              gotData = true;
              try {
                const payload = JSON.parse(event.data);
                if (payload.type === "data") term.write(payload.data);
                else if (payload.type === "pong" && sshPingTime !== null) {
                  updateQuality(sshQuality, Math.round(performance.now() - sshPingTime));
                  sshPingTime = null;
                }
              } catch {}
            });

            ws.addEventListener("close", () => {
              clearInterval(pingInterval);
              sshQuality.textContent = "";
              sshQuality.className = "conn-quality";
              term.write("\\r\\nСоединение закрыто.\\r\\n");
            });

            term.onData((data) => {
              if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "data", data }));
            });

            const sendResize = () => {
              fitAddon.fit();
              if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
              }
            };
            term.onResize(() => sendResize());
            window.addEventListener("resize", () => fitAddon.fit());
            watchKeyboard(sendResize);
          };

          document.querySelectorAll(".connect-btn").forEach((button) => {
            button.addEventListener("click", () => {
              pendingDevice = { ip: button.dataset.ip, name: button.dataset.name, type: button.dataset.type || "ssh" };
              if (consoleAuthenticated) {
                if (pendingDevice.type === "rdp") openRdpLogin();
                else if (pendingDevice.type === "vnc") openVncLogin();
                else openSshLogin();
              } else {
                gateModal.hidden = false;
                requestAnimationFrame(() => gatePassword.focus());
              }
            });
          });
        })();
      </script>
      <script>
      {
        const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

        // ── Установка приложения ──
        // Ставится весь сайт целиком: приложение открывается на главной,
        // оттуда вход в кабинет и дальше в дроп.
        {
          const button = document.getElementById("install");
          let prompt = null;
          if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

          // Уже открыто как приложение — предлагать установку незачем.
          const installed = window.matchMedia("(display-mode: standalone)").matches ||
                            window.navigator.standalone === true;

          // Только на телефоне и планшете. На настольном браузере поставить
          // сайт тоже можно, но смысла в этом нет: то же самое окно и та же
          // вкладка — кнопка там только мозолит глаза.
          const handheld = window.matchMedia("(pointer: coarse)").matches &&
                           "ontouchstart" in window && navigator.maxTouchPoints > 0;

          // Кнопку показываем всегда, кроме этих случаев. Раньше она ждала
          // beforeinstallprompt, а он молчит, если приложение уже поставлено
          // или браузер решил, что показывать рано, — и кнопка исчезала
          // насовсем без единого объяснения.
          if (button && !installed && handheld) button.hidden = false;

          window.addEventListener("beforeinstallprompt", e => {
            e.preventDefault();
            prompt = e;
            if (button && handheld) button.hidden = false;
          });
          window.addEventListener("appinstalled", () => { if (button) button.hidden = true; });

          if (button) button.addEventListener("click", async () => {
            if (prompt) {
              prompt.prompt();
              await prompt.userChoice;
              prompt = null;
              button.hidden = true;
              return;
            }
            // Своего окна установки нет — подсказываем, где оно у браузера.
            const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
            alert(ios
              ? "Поделиться → «На экран Домой»."
              : "Меню браузера (⋮) → «Установить приложение» или «Добавить на главный экран».\\n\\n" +
                "Если пункта нет — приложение уже установлено, проверьте рабочий стол.");
          });
        }

        // ── Часы ──
        {
          const pad = n => String(n).padStart(2, "0");
          const days = ["воскресенье","понедельник","вторник","среда","четверг","пятница","суббота"];
          const months = ["января","февраля","марта","апреля","мая","июня",
                          "июля","августа","сентября","октября","ноября","декабря"];
          const h = document.getElementById("clk-h");
          const tick = () => {
            const now = new Date();
            h.textContent = pad(now.getHours());
            document.getElementById("clk-m").textContent = pad(now.getMinutes());
            document.getElementById("clk-s").textContent = pad(now.getSeconds());
            document.getElementById("clk-date").textContent =
              days[now.getDay()] + ", " + now.getDate() + " " + months[now.getMonth()];
          };
          if (h) { tick(); setInterval(tick, 1000); }
        }

        // ── Плеер ──
        {
          const box = document.getElementById("player");
          const audio = document.getElementById("pl-audio");
          if (box && audio) {
            const el = id => document.getElementById(id);
            const eq = el("pl-eq");
            const bars = [];
            for (let i = 0; i < 20; i++) { const b = document.createElement("span"); eq.appendChild(b); bars.push(b); }

            let tracks = [];      // в порядке воспроизведения (перемешанном)
            let index = -1;
            let analyser = null, freq = null, raf = null;

            const fmt = s => {
              if (!isFinite(s)) return "0:00";
              return Math.floor(s / 60) + ":" + String(Math.floor(s % 60)).padStart(2, "0");
            };
            const shuffle = list => {
              const copy = list.slice();
              for (let i = copy.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [copy[i], copy[j]] = [copy[j], copy[i]];
              }
              return copy;
            };

            const drawBars = () => {
              if (!audio.paused && analyser) {
                analyser.getByteFrequencyData(freq);
                const step = Math.floor(freq.length / bars.length / 2) || 1;
                bars.forEach((b, i) => {
                  const v = freq[i * step] / 255;
                  b.style.height = Math.max(2, v * 26) + "px";
                });
              } else if (!audio.paused) {
                bars.forEach(b => { b.style.height = (3 + Math.random() * 20) + "px"; });
              } else {
                bars.forEach(b => { b.style.height = "3px"; });
              }
              raf = requestAnimationFrame(drawBars);
            };

            const wireAnalyser = () => {
              if (analyser) return;
              try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const src = ctx.createMediaElementSource(audio);
                analyser = ctx.createAnalyser();
                analyser.fftSize = 128;
                freq = new Uint8Array(analyser.frequencyBinCount);
                src.connect(analyser);
                analyser.connect(ctx.destination);
                if (ctx.state === "suspended") ctx.resume();
              } catch { analyser = null; }   // не вышло — рисуем без спектра
            };

            const label = t => (t.artist ? t.artist + " — " : "") + t.title;

            const renderList = () => {
              el("pl-count").textContent = tracks.length + " треков";
              el("pl-tracks").innerHTML = tracks.map((t, i) => `
                <div class="pl-track${i === index ? " current" : ""}" data-id="${esc(t.id)}">
                  <span class="pl-track-name">${esc(t.title)}</span>
                  <button class="pl-mini" data-act="ed" title="Переименовать">✎</button>
                  <button class="pl-mini rm" data-act="rm" title="Удалить">🗑</button>
                  <span class="pl-track-sub">${esc(t.artist || "без исполнителя")}</span>
                </div>`).join("");
            };

            const showNow = () => {
              const t = tracks[index];
              el("pl-title").textContent = t ? t.title : "ничего не играет";
              el("pl-artist").textContent = t ? (t.artist || "без исполнителя") : "плеер выключен";
              renderList();
            };

            const load = async (autoplay) => {
              try {
                const r = await fetch("/api/music", { credentials: "same-origin" });
                const data = await r.json();
                tracks = shuffle(data.tracks);
                const mb = (data.used / 1048576).toFixed(0);
                el("pl-used").textContent = data.tracks.length ? mb + " МБ" : "";
                if (index >= tracks.length) index = -1;
                showNow();
                if (autoplay && tracks.length) play(0);
              } catch {}
            };

            const play = i => {
              if (!tracks.length) return;
              index = (i + tracks.length) % tracks.length;
              audio.src = "/api/music/file/" + encodeURIComponent(tracks[index].id);
              wireAnalyser();
              audio.play().catch(() => {});
              showNow();
            };

            el("pl-play").addEventListener("click", () => {
              if (!tracks.length) { el("pl-list").hidden = false; return; }
              if (audio.paused) { index < 0 ? play(0) : (wireAnalyser(), audio.play().catch(() => {})); }
              else audio.pause();
            });
            el("pl-next").addEventListener("click", () => play(index + 1));
            el("pl-prev").addEventListener("click", () => {
              if (audio.currentTime > 3) { audio.currentTime = 0; return; }
              play(index - 1);
            });
            audio.addEventListener("ended", () => play(index + 1));
            audio.addEventListener("play", () => { box.classList.add("on"); el("pl-play").textContent = "❚❚"; });
            audio.addEventListener("pause", () => { box.classList.remove("on"); el("pl-play").textContent = "▶"; });
            audio.addEventListener("timeupdate", () => {
              const d = audio.duration || 0;
              el("pl-cur").textContent = fmt(audio.currentTime);
              el("pl-dur").textContent = fmt(d);
              const pct = d ? (audio.currentTime / d) * 100 : 0;
              el("pl-seek-fill").style.width = pct + "%";
              el("pl-seek").value = Math.round(pct * 10);
            });
            el("pl-seek").addEventListener("input", e => {
              if (audio.duration) audio.currentTime = (e.target.value / 1000) * audio.duration;
            });

            const savedVol = parseInt(localStorage.getItem("plVol") || "70", 10);
            el("pl-vol").value = savedVol;
            audio.volume = savedVol / 100;
            el("pl-vol").addEventListener("input", e => {
              audio.volume = e.target.value / 100;
              localStorage.setItem("plVol", e.target.value);
            });

            el("pl-toggle-list").addEventListener("click", () => {
              const list = el("pl-list");
              list.hidden = !list.hidden;
              if (!list.hidden) load(false);
            });
            el("pl-add").addEventListener("click", () => { el("pl-list").hidden = false; el("pl-file").click(); });
            el("pl-file").addEventListener("change", e => { upload(e.target.files); e.target.value = ""; });

            // Приёмником служит вся карточка — отдельной надписи больше нет.
            ["dragenter", "dragover"].forEach(ev => box.addEventListener(ev, e => {
              if (!e.dataTransfer.types.includes("Files")) return;
              e.preventDefault(); e.stopPropagation(); box.classList.add("over");
            }));
            ["dragleave", "drop"].forEach(ev => box.addEventListener(ev, e => {
              e.preventDefault(); e.stopPropagation(); box.classList.remove("over");
            }));
            box.addEventListener("drop", e => upload(e.dataTransfer.files));

            const upload = async files => {
              const list = Array.from(files || []);
              if (!list.length) return;
              const status = el("pl-count");
              status.textContent = "загрузка…";
              for (const file of list) {
                const body = new FormData();
                body.append("file", file);
                try {
                  const r = await fetch("/api/music", { method: "POST", credentials: "same-origin", body });
                  if (!r.ok) status.textContent = ((await r.json()).error || "ошибка");
                } catch { status.textContent = "нет сети"; }
              }
              load(false);
            };

            el("pl-tracks").addEventListener("click", async e => {
              const row = e.target.closest(".pl-track");
              if (!row) return;
              const id = row.dataset.id;
              const at = tracks.findIndex(t => t.id === id);
              const act = e.target.dataset.act;

              if (!act) { if (at >= 0) play(at); return; }

              if (act === "rm") {
                if (!confirm("Удалить трек?")) return;
                if (at === index) audio.pause();
                try { await fetch("/api/music/" + encodeURIComponent(id), { method: "DELETE", credentials: "same-origin" }); } catch {}
                load(false);
                return;
              }

              if (act === "ed") {
                const track = tracks[at];
                const nameEl = row.querySelector(".pl-track-name");
                const subEl = row.querySelector(".pl-track-sub");
                const titleInput = document.createElement("input");
                const artistInput = document.createElement("input");
                titleInput.className = artistInput.className = "pl-edit";
                titleInput.value = track.title; artistInput.value = track.artist;
                titleInput.placeholder = "Название"; artistInput.placeholder = "Исполнитель";
                nameEl.replaceWith(titleInput); subEl.replaceWith(artistInput);
                titleInput.focus(); titleInput.select();
                let saved = false;
                const save = async () => {
                  if (saved) return;
                  saved = true;
                  try {
                    await fetch("/api/music/" + encodeURIComponent(id), {
                      method: "PATCH", credentials: "same-origin",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ title: titleInput.value, artist: artistInput.value }),
                    });
                  } catch {}
                  const keep = index >= 0 ? tracks[index].id : null;
                  await load(false);
                  if (keep) index = tracks.findIndex(t => t.id === keep);
                  showNow();
                };
                [titleInput, artistInput].forEach(inp => {
                  inp.addEventListener("keydown", ev => {
                    if (ev.key === "Enter") save();
                    if (ev.key === "Escape") { saved = true; renderList(); }
                  });
                });
                artistInput.addEventListener("blur", save);
              }
            });

            drawBars();
            load(false);   // плеер молчит, пока не нажмут play
          }
        }

        // ── Раскрытие виджетов ──
        document.querySelectorAll(".panel-head[aria-controls]").forEach(btn => {
          const target = document.getElementById(btn.getAttribute("aria-controls"));
          if (!target) return;
          btn.addEventListener("click", () => {
            const opened = btn.getAttribute("aria-expanded") !== "true";
            btn.setAttribute("aria-expanded", String(opened));
            target.hidden = !opened;
            btn.dispatchEvent(new CustomEvent("widget-open", { detail: opened, bubbles: false }));
          });
        });

        // ── Метрики ──
        {
          const toggle = document.getElementById("metrics-toggle");
          const grid = document.getElementById("metrics-grid");
          let timer = null;
          const fmtUp = s => {
            if (!s) return "";
            const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
            return d ? `${d}д ${h}ч` : h ? `${h}ч ${m}м` : `${m}м`;
          };
          const bar = (cls, pct) => {
            const w = Math.min(100, Math.max(0, pct || 0));
            const color = pct > 85 ? "#ef4444" : pct > 60 ? "#fbbf24" : "";
            return `<div class="metrics-track"><div class="metrics-fill ${cls}" style="width:${w}%;${color?"background:"+color:""}"></div></div>`;
          };
          const render = async () => {
            try {
              const r = await fetch("/api/metrics", { credentials: "same-origin" });
              const items = await r.json();
              grid.innerHTML = items.map(({ name, data: d }) => {
                if (!d) return `<div class="metrics-host"><div class="metrics-host-name">${esc(name)}</div><div class="metrics-offline">нет данных / офлайн</div></div>`;
                return `<div class="metrics-host">
                  <div class="metrics-host-name">${esc(name)}</div>
                  <div class="metrics-bars">
                    <span class="metrics-label">CPU</span>${bar("fill-cpu",d.cpu)}<span class="metrics-val">${d.cpu!=null?d.cpu.toFixed(1)+"%" :"—"}</span>
                    <span class="metrics-label">RAM</span>${bar("fill-ram",d.ram)}<span class="metrics-val">${d.ram!=null?d.ram.toFixed(1)+"%":"—"}</span>
                    <span class="metrics-label">Disk</span>${bar("fill-disk",d.disk)}<span class="metrics-val">${d.disk!=null?d.disk+"%":"—"}</span>
                  </div>
                  <div class="metrics-extra">
                    ${d.uptime!=null?`<span>⏱ ${fmtUp(d.uptime)}</span>`:""}
                    ${d.temp!=null?`<span>🌡 ${d.temp.toFixed(1)}°C</span>`:""}
                  </div>
                </div>`;
              }).join("");
            } catch {}
          };
          // Метрики теперь всегда наверху и всегда открыты — грузим сразу.
          if (grid) { render(); timer = setInterval(render, 32000); }
        }

        // Отдельной строки с аптаймом больше нет: у каждой из четырёх машин
        // время работы и так подписано в своей карточке. /api/uptime жив —
        // он ещё пригодится, просто на витрине его никто не показывает.

        // ── Журнал входов ──
        {
          const toggle = document.getElementById("loginlog-toggle");
          const listEl = document.getElementById("loginlog-list");
          let loaded = false;
          const load = async () => {
            try {
              const r = await fetch("/api/login-log", { credentials: "same-origin" });
              const data = await r.json();
              if (!data.length) { listEl.innerHTML = '<p class="widget-empty">Нет записей</p>'; return; }
              const fails = data.filter(e => e.kind && e.kind !== "ok").length;
              const head = fails
                ? `<p class="log-alarm">Неудачных попыток за две недели: ${fails}</p>` : "";
              listEl.innerHTML = head + data.map(e => {
                const bad = e.kind && e.kind !== "ok";
                return `<div class="log-row${bad ? " log-bad" : ""}"><span class="log-ts">${esc(e.ts)}</span><span class="log-ip">${esc(e.ip)}</span><span class="log-ua">${esc(e.ua)}</span></div>`;
              }).join("");
            } catch {}
          };
          if (toggle) toggle.addEventListener("widget-open", e => { if (e.detail && !loaded) { loaded = true; load(); } });
        }

        // ── Запомненные устройства ──
        {
          const toggle = document.getElementById("devices-toggle");
          const listEl = document.getElementById("devices-list");
          const checkbox = document.getElementById("dev-remember-cb");
          const confirmBox = document.getElementById("dev-confirm");
          const dailyInput = document.getElementById("dev-daily");
          const confirmBtn = document.getElementById("dev-confirm-btn");
          const errorEl = document.getElementById("dev-error");
          let devices = [];

          const ago = ts => {
            const mins = Math.floor((Date.now() / 1000 - ts) / 60);
            if (mins < 1) return "только что";
            if (mins < 60) return mins + " мин назад";
            const hours = Math.floor(mins / 60);
            if (hours < 24) return hours + " ч назад";
            const days = Math.floor(hours / 24);
            if (days < 30) return days + " дн назад";
            return new Date(ts * 1000).toLocaleDateString("ru-RU");
          };

          const render = () => {
            const current = devices.find(d => d.current);
            if (checkbox) checkbox.checked = Boolean(current);
            if (!devices.length) {
              listEl.innerHTML = '<p class="widget-empty">Пока ни одного устройства не запомнено</p>';
              return;
            }
            listEl.innerHTML = devices.map(d => `
              <div class="dev-row" data-id="${esc(d.id)}">
                <span class="dev-name${d.current ? " is-current" : ""}">${esc(d.label)}</span>
                <button class="dev-act dev-edit" type="button" title="Переименовать">✎</button>
                <button class="dev-act dev-del" type="button" title="Забыть устройство">🗑</button>
                <span class="dev-meta">Последний вход: ${esc(ago(d.last_used))}${d.last_ip ? " · " + esc(d.last_ip) : ""}</span>
              </div>`).join("");
          };

          const load = async () => {
            try {
              const r = await fetch("/api/devices", { credentials: "same-origin" });
              devices = await r.json();
              render();
            } catch {}
          };

          const showError = text => { if (errorEl) errorEl.textContent = text || ""; };

          const trust = async () => {
            showError("");
            try {
              const r = await fetch("/api/devices/trust", {
                method: "POST", credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: dailyInput.value }),
              });
              const data = await r.json();
              if (!r.ok) { showError(data.error || "Не получилось."); return; }
              dailyInput.value = "";
              confirmBox.hidden = true;
              load();
            } catch { showError("Сеть недоступна."); }
          };

          const forget = async id => {
            try {
              await fetch("/api/devices/" + encodeURIComponent(id), { method: "DELETE", credentials: "same-origin" });
              load();
            } catch {}
          };

          if (checkbox) checkbox.addEventListener("change", () => {
            showError("");
            if (checkbox.checked) {
              confirmBox.hidden = false;
              dailyInput.focus();
            } else {
              confirmBox.hidden = true;
              const current = devices.find(d => d.current);
              if (current) forget(current.id);
            }
          });

          if (confirmBtn) confirmBtn.addEventListener("click", trust);
          if (dailyInput) dailyInput.addEventListener("keydown", e => { if (e.key === "Enter") trust(); });

          if (listEl) listEl.addEventListener("click", async e => {
            const row = e.target.closest(".dev-row");
            if (!row) return;
            const id = row.dataset.id;

            if (e.target.classList.contains("dev-del")) {
              const item = devices.find(d => d.id === id);
              const warn = item && item.current
                ? "Забыть это устройство? Придётся вводить пароль заново."
                : "Забыть устройство «" + (item ? item.label : "") + "»?";
              if (confirm(warn)) forget(id);
              return;
            }

            if (e.target.classList.contains("dev-edit")) {
              const nameEl = row.querySelector(".dev-name");
              const item = devices.find(d => d.id === id);
              const input = document.createElement("input");
              input.className = "dev-rename";
              input.value = item ? item.label : "";
              input.maxLength = 40;
              nameEl.replaceWith(input);
              input.focus();
              input.select();
              const save = async () => {
                const label = input.value.trim();
                if (label) {
                  try {
                    await fetch("/api/devices/" + encodeURIComponent(id), {
                      method: "PATCH", credentials: "same-origin",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ label }),
                    });
                  } catch {}
                }
                load();
              };
              input.addEventListener("blur", save, { once: true });
              input.addEventListener("keydown", ev => {
                if (ev.key === "Enter") input.blur();
                if (ev.key === "Escape") { input.removeEventListener("blur", save); load(); }
              });
            }
          });

          if (toggle) toggle.addEventListener("widget-open", e => { if (e.detail) load(); });
        }
      }
      </script>
    </body>
    </html>
    """
    return html.replace("{{DEVICE_ITEMS}}", device_items) \
               .replace("__ICONLINKS__", ICON_LINKS)


@app.get("/manifest.webmanifest")
def manifest():
    """Делает сайт устанавливаемым и, главное, объявляет приём «Поделиться»:
    после установки дроп появляется в системном меню отправки любого файла."""
    return Response(
        json.dumps({
            # Под ярлыком на телефоне подписывается short_name, и места там
            # мало: длинное имя оболочка обрежет многоточием.
            "name": "Vitaz Gio",
            "short_name": "Vitaz Gio",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#0d1321",
            "theme_color": "#0d1321",
            # Версия в адресе обязательна. Браузер кэширует иконки манифеста по
            # ссылке и на смену самой картинки не смотрит: пока адрес прежний,
            # при установке он рисует старую, даже если сервер отдаёт новую.
            "icons": [
                {"src": f"/icon-192.png?v={ICON_VERSION}", "sizes": "192x192", "type": "image/png"},
                {"src": f"/icon-512.png?v={ICON_VERSION}", "sizes": "512x512", "type": "image/png"},
                # Маскируемый — отдельным рисунком с запасом по краям, а не
                # тем же файлом: круглая обрезка съедала бы углы знака.
                {"src": f"/icon-maskable-512.png?v={ICON_VERSION}", "sizes": "512x512",
                 "type": "image/png", "purpose": "maskable"},
                {"src": f"/icon-maskable-192.png?v={ICON_VERSION}", "sizes": "192x192",
                 "type": "image/png", "purpose": "maskable"},
            ],
            "share_target": {
                "action": "/share-target",
                "method": "POST",
                "enctype": "multipart/form-data",
                "params": {
                    "title": "title",
                    "text": "text",
                    "url": "url",
                    # Только "*/*" мало: на такой шаблон Android часто не
                    # показывает приложение при отправке документов и архивов.
                    "files": [{"name": "files", "accept": [
                        "*/*", "image/*", "video/*", "audio/*", "text/*",
                        "application/pdf", "application/zip", "application/octet-stream",
                        "application/msword", "application/vnd.ms-excel",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        "application/x-7z-compressed", "application/x-rar-compressed",
                        "application/gzip", "application/x-tar", "application/json",
                    ]}],
                },
            },
        }, ensure_ascii=False),
        mimetype="application/manifest+json",
    )


@app.get("/sw.js")
def service_worker():
    """Делает три вещи: принимает «Поделиться», держит офлайн-страницу с игрой
    и следит, чтобы установленное приложение показывало свежий сайт.

    Стратегия намеренно «сначала сеть»: страницы никогда не берутся из кэша,
    пока сеть жива, поэтому любая правка на сервере видна в приложении сразу,
    без переустановки. Из кэша достаётся только запасная страница — и только
    когда сети нет вовсе."""
    return Response(
        """
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
                .filter(Boolean).join("\\n").trim();
              if (text) {
                await cache.put(new Request("/__shared-text?t=" + Date.now()),
                                new Response(text));
              }
            } catch (e) {}
            return Response.redirect("/drop?shared=1", 303);
          })());
        });
        """,
        mimetype="application/javascript",
    )


# ---- Пиксельные значки для кнопок игр ---------------------------------------
# Спрайт описан строками: символ — цвет из палитры, точка — прозрачно.
# Собираем из них SVG с прямоугольниками 1x1: масштабируется без размытия,
# весит копейки и не требует ни одной картинки.

def _pixel_svg(rows, palette):
    width = max(len(row) for row in rows)
    parts = []
    for y, row in enumerate(rows):
        x = 0
        while x < len(row):
            char = row[x]
            if char == ".":
                x += 1
                continue
            # Соседние клетки одного цвета склеиваем в один прямоугольник —
            # иначе на спрайт уходит под сотню тегов.
            run = 1
            while x + run < len(row) and row[x + run] == char:
                run += 1
            color, cls = palette[char]
            klass = f' class="{cls}"' if cls else ""
            parts.append(f'<rect x="{x}" y="{y}" width="{run}" height="1" fill="{color}"{klass}/>')
            x += run
    return (f'<svg viewBox="0 0 {width} {len(rows)}" shape-rendering="crispEdges" '
            f'aria-hidden="true">{"".join(parts)}</svg>')


_GAME_ICONS = {
    # 1. Аркадный автомат: экран мигает, на нём бегут пиксели
    "cabinet": _pixel_svg([
        "..hhhhhhhh..",
        ".hSSSSSSSSh.",
        ".hSggggggSh.",
        ".hSg.pp.gSh.",
        ".hSgpppppgSh",
        ".hSg.pp.gSh.",
        ".hSSSSSSSSh.",
        ".hhhhhhhhhh.",
        ".hbbbbbbbbh.",
        ".hbRbb..Ybh.",
        ".hbbbbbbbbh.",
        ".hhhhhhhhhh.",
        "..h......h..",
        ".hhh....hhh.",
    ], {
        "h": ("#48566b", None), "S": ("#151a22", None), "g": ("#0b2231", "px-screen"),
        "p": ("#2de2ff", "px-screen"), "b": ("#232a35", None),
        "R": ("#ff3b53", "px-blink"), "Y": ("#ffd84a", None),
    }),
    # 2. Пиксельный герой с мечом
    "hero": _pixel_svg([
        "...hhhh...",
        "..hffffh..",
        "..fFffFf..",
        "..ffffff..",
        ".sbbBBbb..",
        ".sbBBBBb..",
        ".s.bbbb...",
        "...bb.bb..",
        "...dd.dd..",
        "...dd.dd..",
        "..ddd.ddd.",
        "..........",
    ], {
        "h": ("#8a5a2b", None), "f": ("#e3ac7d", None), "F": ("#231610", "px-blink"),
        "b": ("#2f6ee0", None), "B": ("#5f9bff", None),
        "s": ("#cbd6e4", "px-sword"), "d": ("#3a4658", None),
    }),
    # Серверная стойка — значок личного кабинета: там как раз про сервера,
    # а мигающие лампы делают кнопку живой без единой буквы.
    "rack": _pixel_svg([
        "..hhhhhhhhhh..",
        ".hccccccccccg.",
        ".hcSSSSSSSSch.",
        ".hcS1y32d1Scg.",
        ".hcSSSSSSSSch.",
        ".hcSSSSSSSSch.",
        ".hcS31r23yScg.",
        ".hcSSSSSSSSch.",
        ".hcSSSSSSSSch.",
        ".hcS2d31y2Scg.",
        ".hcSSSSSSSSch.",
        ".hccccccccccg.",
        "..hhhhhhhhhh..",
        "..h........h..",
    ], {
        "h": ("#48566b", None), "c": ("#232a35", None), "g": ("#161c25", None),
        "S": ("#2f3846", None),
        # Лампы идут во всю ширину полки. Зелёных две трети и мигают они
        # вразнобой: одинаковый такт превращает стойку в новогоднюю гирлянду.
        "1": ("#63f5ad", "px-blink"),
        "2": ("#63f5ad", "px-blink2"),
        "3": ("#63f5ad", None),
        "y": ("#ffd84a", "px-blink3"),
        "r": ("#ff3b53", "px-blink2"),
        "d": ("#1b2530", None),
    }),
    # 3. Геймпад с моргающим индикатором.
    # Полоска светодиода стоит на столбцах 5–8: центр значка — 6.5, и раньше
    # она была сдвинута влево, из-за чего налезала на крестовину.
    "pad": _pixel_svg([
        "..BBBBBBBBBB..",
        ".BBBBBBBBBBBB.",
        "BB.w.BBBB.r.BB",
        "B.www.BB.rrrBB",
        "BB.w.BBBB.r.BB",
        "BBBBBLLLLBBBBB",
        ".BBBBBBBBBBBB.",
        "..BBB....BBB..",
    ], {
        "B": ("#3d4757", None), "w": ("#cdd8e6", None), "r": ("#ff5a6e", None),
        "L": ("#63f5ad", "px-blink"),
    }),
    # 4. Космический захватчик
    "invader": _pixel_svg([
        "..g.....g..",
        "...g...g...",
        "..ggggggg..",
        ".gg.ggg.gg.",
        "ggggggggggg",
        "g.ggggggg.g",
        "g.g.....g.g",
        "...gg.gg...",
    ], {"g": ("#63f5ad", "px-invader")}),
    # 5. Монета «брось жетон»
    "coin": _pixel_svg([
        "...cccc...",
        ".ccyyyycc.",
        ".cyy..yyc.",
        "cyy.yy.yyc",
        "cy.yyyy.yc",
        "cy.yyyy.yc",
        "cyy.yy.yyc",
        ".cyy..yyc.",
        ".ccyyyycc.",
        "...cccc...",
    ], {"c": ("#b8860b", None), "y": ("#ffd84a", "px-shine")}),
    # 6. Картридж
    "cart": _pixel_svg([
        "pppppppppppp",
        "p.llllllll.p",
        "p.l......l.p",
        "p.l.LLLL.l.p",
        "p.l.L..L.l.p",
        "p.l.LLLL.l.p",
        "p.l......l.p",
        "p.llllllll.p",
        "pppppppppppp",
        ".pppppppppp.",
        ".gggggggggg.",
        "..g.g.g.g...",
    ], {
        "p": ("#6b3fa0", None), "l": ("#432769", None),
        "L": ("#ff3fa4", "px-blink"), "g": ("#d8b23a", None),
    }),
}


# ---- Иконка приложения ------------------------------------------------------
# Знак VG вычерчен хозяином в КОМПАСе и залит мелким процедурным зерном.
# Исходник лежит в static/icons/vg.svg, рядом с ним готовые png на все
# ходовые размеры: рисовать монограмму кодом больше не нужно.
#
# Маскируемый вариант отдельным файлом: Android режет значок в круг, и знак
# в нём ужат до 62% поля, иначе углы обкусывает.
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "icons")
ICON_SIZES = (16, 32, 48, 64, 96, 128, 152, 180, 192, 256, 384, 512)
ICON_MASKABLE_SIZES = (192, 512)

# Поднимать при смене рисунка: версия попадает в адреса в манифесте и в
# разметке, иначе браузер продолжит показывать иконку из кэша.
ICON_VERSION = "vg7"

# Одни и те же ссылки в head всех страниц. Версия в адресе обязательна:
# браузер держит иконку в кэше и на смену картинки не смотрит.
ICON_LINKS = (
    f'<link rel="icon" href="/icon-32.png?v={ICON_VERSION}" sizes="32x32" type="image/png">'
    f'<link rel="icon" href="/icon-192.png?v={ICON_VERSION}" sizes="192x192" type="image/png">'
    f'<link rel="apple-touch-icon" href="/icon-180.png?v={ICON_VERSION}">'
    # Айфон манифест не читает и подписывает ярлык по этой метке, а без неё
    # берёт <title> страницы — вышло бы «Личный кабинет · vitazgio.ru».
    '<meta name="apple-mobile-web-app-title" content="Vitaz Gio">'
)


def _icon_response(name):
    path = os.path.join(ICON_DIR, name)
    if not os.path.exists(path):
        return "", 404
    response = send_file(path, conditional=True)
    # Сутки — достаточно, чтобы не дёргать сервер, и мало, чтобы не залипло
    # навсегда, если версию поднять забудут.
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@app.get("/favicon.ico")
def favicon():
    """Браузеры просят его сами, без всяких ссылок в разметке. Внутри три
    размера — 16, 32 и 48, — иначе на разных экранах видно лесенку."""
    return _icon_response("favicon.ico")


@app.get("/icon-<int:size>.png")
def app_icon(size):
    if size not in ICON_SIZES:
        return "", 404
    return _icon_response(f"icon-{size}.png")


@app.get("/icon-maskable-<int:size>.png")
def app_icon_maskable(size):
    if size not in ICON_MASKABLE_SIZES:
        return "", 404
    return _icon_response(f"maskable-{size}.png")


@app.post("/share-target")
@login_required
def share_target_fallback():
    """Сюда попадаем, только если обработчик в браузере ещё не встал."""
    saved = 0
    for storage in request.files.getlist("files"):
        if not storage or not storage.filename:
            continue
        item_id = str(uuid.uuid4())
        path = _drop_path(item_id)
        try:
            storage.save(path)
            size = os.path.getsize(path)
        except OSError:
            continue
        with drop_lock:
            if size > DROP_MAX_SIZE or _drop_used() + size > DROP_QUOTA:
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            drop_items[item_id] = {
                "kind": "file", "name": storage.filename[:120], "parent": None,
                "content_type": storage.content_type or "application/octet-stream",
                "size": size, "created": time.time(), "share": None,
            }
            _drop_write_index()
        saved += 1
    return redirect(url_for("drop_page") + ("?saved=%d" % saved if saved else ""))


@app.get("/themes")
@login_required
def themes_page():
    """Витрина оформления: разделы кабинета как органы и импланты киборга.
    Своего бэкенда нет — данные берутся из уже существующих эндпоинтов."""
    organs = ["ЛОБНАЯ ДОЛЯ", "ТЕМЕННАЯ ДОЛЯ", "ЗАТЫЛОЧНАЯ ДОЛЯ", "ВИСОЧНАЯ ДОЛЯ",
              "МОЗЖЕЧОК", "СТВОЛ МОЗГА", "ТАЛАМУС", "ГИПОФИЗ"]
    cols, rows = [60, 330, 600, 870], [250, 420]
    cards = []
    for i, device in enumerate(NETBIRD_DEVICES[:8]):
        left, top = cols[i % 4], rows[i // 4]
        kind = ("SSH" if device.get("ssh_enabled") else
                "RDP" if device.get("rdp_enabled") else
                "VNC" if device.get("vnc_enabled") else "\u2014")
        cards.append(
            f'<g class="ncard" style="--i:{i}">'
            f'<path class="ncard-plate" d="M{left} {top + 12} L{left + 12} {top} L{left + 246} {top} '
            f'L{left + 246} {top + 68} L{left + 234} {top + 80} L{left} {top + 80} Z"/>'
            f'<text class="ncard-organ" x="{left + 84}" y="{top + 20}">{organs[i]}</text>'
            f'<text class="ncard-name" x="{left + 84}" y="{top + 38}">{device["name"]}</text>'
            f'<text class="ncard-ip" x="{left + 84}" y="{top + 54}">{device["ip"]}</text>'
            f'<text class="ncard-ping" x="{left + 236}" y="{top + 22}" text-anchor="end" '
            f'data-ping="{device["ip"]}">\u2014 \u2014 \u2014</text>'
            f'<g class="ncard-btn"><rect x="{left + 84}" y="{top + 60}" width="100" height="16" rx="1"/>'
            f'<text x="{left + 134}" y="{top + 72}" text-anchor="middle">ПОДКЛЮЧИТЬСЯ</text></g>'
            f'<text class="ncard-ip" x="{left + 236}" y="{top + 72}" text-anchor="end">{kind}</text>'
            f'</g>'
        )

    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="robots" content="noindex, nofollow">
      <title>Тестовые темы · vitazgio.ru</title>
      <style>
        * { box-sizing:border-box; }
        body { margin:0; min-height:100svh; color:#cfe9f5; font-family:"Cascadia Code",Consolas,monospace;
               background:#05070d; overflow-x:hidden; }
        .stage { position:relative; min-height:100svh; padding:14px clamp(12px,2vw,28px) 30px;
                 background:radial-gradient(ellipse 65% 50% at 42% 40%, rgba(45,226,255,.07), transparent 70%),
                            radial-gradient(ellipse 40% 35% at 80% 30%, rgba(255,63,164,.05), transparent 70%), #05070d; }
        .stage::after { content:""; position:fixed; inset:0; pointer-events:none; opacity:.5;
              background:repeating-linear-gradient(180deg, rgba(0,0,0,.3) 0 1px, transparent 1px 3px); }
        .bar { position:relative; z-index:3; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
        .back { width:38px; height:38px; flex:none; display:grid; place-items:center; color:#2de2ff;
                text-decoration:none; border:1px solid rgba(45,226,255,.32); border-radius:50%; background:rgba(45,226,255,.07); }
        .back svg { width:17px; height:17px; display:block; }
        .back:hover { color:#fff; border-color:#2de2ff; background:rgba(45,226,255,.18); }
        .bar h1 { margin:0; font-size:clamp(1rem,2.2vw,1.5rem); font-weight:700; color:#eaf6ff; letter-spacing:.02em; }
        .bar h1 b { color:#ff3fa4; }
        .bar .hint { margin-left:auto; color:#46617a; font-size:.66rem; letter-spacing:.16em; text-transform:uppercase; }
        .frame { position:relative; z-index:2; max-width:1400px; margin:6px auto 0; }
        .toast { position:fixed; left:50%; bottom:22px; transform:translateX(-50%); z-index:9;
                 padding:9px 16px; color:#04121c; font-size:.72rem; background:#2de2ff; }

  body { margin:0; background:#05070d; }
  svg { width:100%; height:auto; display:block; }

  .plate     { fill:url(#gPlate);   stroke:#12161c; stroke-width:2; stroke-linejoin:round; }
  .plate-in  { fill:url(#gPlateIn); stroke:#12161c; stroke-width:1.7; stroke-linejoin:round; }
  .seam      { fill:none; stroke:#2b323b; stroke-width:1.2; }
  .seam-thin { fill:none; stroke:#414b58; stroke-width:.8; }
  .ghost     { fill:none; stroke:#2de2ff; stroke-width:1; opacity:.22; stroke-dasharray:5 6; }
  .cavity    { fill:#080b11; stroke:#12161c; stroke-width:2; }
  .rib       { fill:none; stroke:#2a343f; stroke-width:3.4; stroke-linecap:round; }
  .trace     { fill:none; stroke:#2de2ff; stroke-width:.8; opacity:.45; }
  .muscle    { fill:url(#gMus); stroke:#4a121c; stroke-width:1.2; }
  .fiber     { fill:none; stroke:#c2515c; stroke-width:.7; opacity:.5; }
  .bone      { fill:#e2dcd0; stroke:#12161c; stroke-width:1.5; }
  .cable     { fill:none; stroke:#0f1319; stroke-width:5.5; stroke-linecap:round; }
  .cable-hi  { fill:none; stroke:#333e4b; stroke-width:1.5; stroke-linecap:round; }
  .lens      { fill:url(#gLens); stroke:#0e1218; stroke-width:1.4; }
  .hot       { fill:none; stroke:#ff3fa4; stroke-width:1.3; opacity:.9; }

  .lobe   { stroke:#5d1b28; stroke-width:1.3; }
  .lobe-f { fill:#c8737f; } .lobe-p { fill:#b96878; }
  .lobe-o { fill:#a85a6a; } .lobe-t { fill:#d2848d; }
  .cereb  { fill:#8e4757; stroke:#4d1620; stroke-width:1.3; }
  .stem   { fill:#dda691; stroke:#5d1b28; stroke-width:1.3; }
  .deep   { fill:#e6bcaa; stroke:#5d1b28; stroke-width:1.1; }
  .gyrus  { fill:none; stroke:#7d2c3b; stroke-width:1.1; opacity:.8; stroke-linecap:round; }
  .cerebline { fill:none; stroke:#5d2130; stroke-width:.7; opacity:.85; }

  .lbl  { fill:#4d6379; font:9px "Cascadia Code",Consolas,monospace; letter-spacing:.22em; }
  .lead { fill:none; stroke:#28394a; stroke-width:1; }
  .hud  { fill:rgba(6,14,22,.85); stroke:#2de2ff; stroke-width:1.2; }
  /* ── взаимодействие ── */
  .zone { cursor:pointer; }
  .zone:hover .lobe, .zone:hover .cereb, .zone:hover .stem, .zone:hover .deep { filter:brightness(1.2); }
  .shard { transition:transform .8s cubic-bezier(.2,.9,.25,1); transition-delay:calc(var(--i) * 50ms); }
  .open .shard { transform:translate(var(--dx), var(--dy)); filter:drop-shadow(0 0 8px rgba(255,63,164,.45)); }
  #figure, #arm, #projection, #clock, #labels { transition:opacity .55s, filter .55s; }
  .open #figure, .open #arm, .open #projection, .open #clock, .open #labels { opacity:.13; filter:blur(1.6px); }
  .open #brainzone { opacity:1 !important; filter:none !important; }

  .ncard { opacity:0; pointer-events:none; transform:translateY(16px);
           transition:opacity .45s, transform .45s; transition-delay:calc(var(--i) * 50ms + .3s); }
  .open .ncard { opacity:1; pointer-events:auto; transform:none; }
  .ncard-plate { fill:rgba(8,16,26,.95); stroke:rgba(45,226,255,.42); stroke-width:1.2; }
  .ncard:hover .ncard-plate { stroke:#2de2ff; fill:rgba(14,28,46,.98); }
  .ncard-organ { fill:#ff7f9c; font:8px "Cascadia Code",monospace; letter-spacing:.14em; }
  .ncard-name  { fill:#eaf6ff; font:700 13px "Cascadia Code",monospace; }
  .ncard-ip    { fill:#4d6a86; font:10px "Cascadia Code",monospace; }
  .ncard-ping  { fill:#63f5ad; font:700 12px "Cascadia Code",monospace; }
  .ncard-ping.off { fill:#ff5f7a; }
  .ncard-btn rect { fill:rgba(45,226,255,.1); stroke:rgba(45,226,255,.45); stroke-width:1; cursor:pointer; }
  .ncard-btn text { fill:#2de2ff; font:8.5px "Cascadia Code",monospace; letter-spacing:.1em; pointer-events:none; }
  .ncard-btn:hover rect { fill:#2de2ff; }
  .ncard-btn:hover text { fill:#04121c; }

  #jaw { transition:transform .5s cubic-bezier(.3,.8,.3,1); transform-origin:-30px 58px; }
  .mouth #jaw { transform:rotate(11deg); }

      </style>
    </head>
    <body>
      <div class="stage">
        <div class="bar">
          <a class="back" href="/cabinet" aria-label="Назад в кабинет">
            <svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <h1>КИБОРГ · <b>ПОЛУРАЗБОР</b></h1>
          <span class="hint" id="hint">мозг — узлы сети · рот — плеер</span>
        </div>
        <div class="frame">
<svg id="scheme" viewBox="0 0 1200 900" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="gPlate" x1="0" y1="0" x2=".35" y2="1">
      <stop offset="0" stop-color="#f4f0e8"/><stop offset=".5" stop-color="#dbd5c9"/><stop offset="1" stop-color="#a29a8c"/>
    </linearGradient>
    <linearGradient id="gPlateIn" x1="0" y1="0" x2=".3" y2="1">
      <stop offset="0" stop-color="#c3bcae"/><stop offset="1" stop-color="#8a8377"/>
    </linearGradient>
    <linearGradient id="gMus" x1="0" y1="0" x2=".2" y2="1">
      <stop offset="0" stop-color="#a83c48"/><stop offset="1" stop-color="#5f1a24"/>
    </linearGradient>
    <radialGradient id="gLens" cx=".35" cy=".3" r=".8">
      <stop offset="0" stop-color="#b7f7ff"/><stop offset=".45" stop-color="#2de2ff"/><stop offset="1" stop-color="#07303d"/>
    </radialGradient>
    <linearGradient id="gBeam" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#2de2ff" stop-opacity=".30"/>
      <stop offset="1" stop-color="#2de2ff" stop-opacity="0"/>
    </linearGradient>
  </defs>

  <!-- ═══ ФИГУРА: голова, шея и торс в одной системе координат ═══ -->
  <g id="figure" transform="translate(388,322)">

    <!-- ── ТОРС ── -->
      <path class="muscle" d="M-96 96 C-60 118 -8 130 44 126 L64 168 C6 178 -60 164 -110 136 Z"/>
      <path class="fiber" d="M-88 108 C-52 128 -6 138 44 136 M-92 120 C-56 140 -8 150 46 148"/>
    <g id="torso">
      <path class="ghost" d="M-24 132 C40 126 104 146 134 186 C156 216 162 254 164 292
        L168 396 C172 438 148 466 110 474 L-94 474 C-134 466 -156 438 -152 396
        L-144 292 C-144 250 -132 210 -108 182 C-84 152 -60 136 -24 132 Z"/>
      <path class="cavity" d="M-22 138 C38 132 98 152 128 190 C148 218 155 254 157 292
        L161 394 C165 432 144 458 108 466 L-92 466 C-128 458 -149 432 -145 394
        L-137 292 C-137 252 -126 214 -104 188 C-82 158 -56 142 -22 138 Z"/>

      <!-- мышцы плечевого пояса -->
      <path class="muscle" d="M-108 186 C-70 158 -18 148 32 156 C74 162 108 182 126 210
        L134 268 C104 236 60 218 12 214 C-40 210 -84 226 -114 254 Z"/>
      <path class="fiber" d="M-92 200 C-46 176 8 172 56 182 M-98 224 C-50 200 8 196 62 206
        M-104 248 C-56 224 6 220 66 230"/>

      <path class="muscle" d="M-118 282 C-60 262 6 260 56 276 L60 440 C6 424 -62 426 -122 446 Z" opacity=".45"/>
      <!-- рёбра: слева броня снята -->
      <path class="rib" d="M-118 288 C-66 268 -4 266 46 280"/>
      <path class="rib" d="M-122 326 C-68 306 -4 304 50 318"/>
      <path class="rib" d="M-126 364 C-70 344 -4 342 54 356"/>
      <path class="rib" d="M-128 402 C-72 382 -4 380 56 394"/>
      <path class="rib" d="M-130 440 C-72 420 -4 418 58 432"/>
      <path class="trace" d="M-112 296 C-64 280 -6 278 40 288"/>
      <path class="trace" d="M-120 372 C-66 356 -6 354 46 364"/>

      <!-- позвоночник -->
      <g>
        <path class="bone" d="M-140 260 L-114 254 L-111 288 L-137 294 Z"/>
        <path class="bone" d="M-142 302 L-116 296 L-113 330 L-139 336 Z"/>
        <path class="bone" d="M-144 344 L-118 338 L-115 372 L-141 378 Z"/>
        <path class="bone" d="M-146 386 L-120 380 L-117 414 L-143 420 Z"/>
        <path class="bone" d="M-148 428 L-122 422 L-119 456 L-145 462 Z"/>
      </g>

      <!-- грудная броня справа -->
      <path class="plate" d="M60 168 C102 178 130 202 142 236 L152 300 L159 394
        C163 430 144 454 110 462 L48 462 L56 388 C64 316 68 240 60 168 Z"/>
      <path class="seam" d="M74 240 C106 252 128 272 140 300"/>
      <path class="seam-thin" d="M60 336 L156 348 M56 412 L160 424"/>
      <circle cx="132" cy="212" r="4" fill="#2b323b"/>

      <!-- порт данных в груди -->
      <a href="/drop"><g id="chestport" class="zone">
        <rect x="76" y="326" width="60" height="44" rx="3" fill="#0f1319" stroke="#39424e" stroke-width="2"/>
        <path class="trace" d="M85 340 L127 340 M85 350 L127 350 M85 360 L115 360"/>
        <circle cx="127" cy="360" r="3.6" fill="#2de2ff"/>
      </g></a>

      <!-- наплечник -->
      <path class="plate" d="M76 148 C112 154 140 172 154 198 C164 218 164 240 156 256
        L126 236 C122 212 104 190 80 178 Z"/>
      <path class="seam-thin" d="M88 170 C114 180 132 196 142 218"/>

      <!-- плечевой разъём: рука снята -->
      <g id="socket">
        <ellipse cx="-116" cy="200" rx="32" ry="37" transform="rotate(-20 -116 200)"
                 fill="#0f1319" stroke="#39424e" stroke-width="2.4"/>
        <ellipse cx="-116" cy="200" rx="18" ry="21" transform="rotate(-20 -116 200)"
                 fill="none" stroke="#2de2ff" stroke-width="1.6" opacity=".8"/>
        <circle cx="-116" cy="200" r="5" fill="#2de2ff" opacity=".9"/>
        <path class="hot" d="M-146 176 C-152 196 -150 216 -140 234" stroke-dasharray="5 5"/>
      </g>
    </g>

    <!-- ── ШЕЯ: соединяет голову с торсом ── -->
    <g id="neck" transform="translate(-4,-34)">
      <path class="muscle" d="M-48 44 C-32 66 -8 82 16 88 L20 140 C-14 134 -48 116 -70 88 Z"/>
      <path class="fiber" d="M-44 54 C-28 74 -6 88 18 94 M-50 68 C-34 88 -12 102 16 108"/>
      <path class="muscle" d="M-84 34 C-94 58 -94 92 -82 118 L-62 108 C-72 86 -72 62 -64 42 Z"/>
      <path class="fiber" d="M-82 48 C-90 70 -90 92 -80 112"/>
      <path class="bone" d="M-70 30 L-40 24 L-36 40 L-66 46 Z"/>
      <path class="bone" d="M-74 52 L-44 46 L-40 62 L-70 68 Z"/>
      <path class="bone" d="M-78 74 L-48 68 L-44 84 L-74 90 Z"/>
      <path class="bone" d="M-82 96 L-52 90 L-48 106 L-78 112 Z"/>
      <path class="bone" d="M-86 118 L-56 112 L-52 128 L-82 134 Z"/>
      <path class="cable" d="M-100 26 C-118 60 -118 104 -100 140"/>
      <path class="cable-hi" d="M-100 26 C-118 60 -118 104 -100 140"/>
      <path class="cable" d="M-90 20 C-110 58 -110 108 -90 146"/>

      <!-- шейный разъём: журнал входов -->
      <g id="neckport">
        <rect x="-30" y="92" width="42" height="30" rx="3" fill="#0f1319" stroke="#39424e" stroke-width="2"/>
        <path class="hot" d="M-22 102 L2 102 M-22 110 L-4 110"/>
        <circle cx="6" cy="112" r="3" fill="#ff3fa4"/>
      </g>
    </g>

    <!-- ── ГОЛОВА ── -->
    <g id="head" transform="translate(10,-128) scale(1.22)">
      <path class="ghost" d="M0 -138 C30 -138 48 -126 58 -110 C72 -88 80 -74 86 -62
        C90 -54 90 -50 92 -46 C98 -38 108 -30 112 -22 C115 -16 110 -8 96 -6
        C100 -2 102 0 100 4 C104 8 102 12 98 16 C100 20 100 24 96 26
        C96 34 94 40 92 44 C88 54 82 60 72 62 C52 70 30 74 10 74
        C-6 72 -20 66 -30 56 C-52 48 -72 38 -88 22 C-104 4 -112 -14 -112 -34
        C-112 -62 -102 -84 -86 -100 C-66 -122 -34 -138 0 -138 Z"/>

      <path class="cavity" d="M-108 -36 C-108 -62 -98 -84 -82 -99 C-62 -119 -32 -132 2 -132
        C30 -132 48 -120 58 -104 C70 -84 78 -66 82 -54 C60 -14 6 2 -34 -4
        C-70 -10 -100 -16 -108 -36 Z"/>

      <path class="rib" d="M-96 -44 C-92 -70 -78 -92 -58 -106"/>
      <path class="trace" d="M-88 -46 C-84 -68 -72 -86 -56 -98"/>

      <g id="brainzone" class="zone"><g id="brain">
        <g class="shard" style="--dx:-411px; --dy:194px; --i:0"><path class="lobe lobe-f" d="M14 -116 C44 -120 68 -102 71 -74 C73 -58 67 -46 55 -38
                                     C43 -44 27 -52 15 -62 C7 -78 9 -98 14 -116 Z"/>
        <path class="gyrus" d="M26 -108 C40 -104 52 -94 58 -83"/>
        <path class="gyrus" d="M20 -93 C34 -89 48 -79 55 -68"/>
        <path class="gyrus" d="M20 -76 C32 -70 44 -61 50 -52"/></g>
        <g class="shard" style="--dx:-75px; --dy:206px; --i:1"><path class="lobe lobe-p" d="M-40 -114 C-18 -124 -2 -122 14 -116 C9 -98 7 -78 15 -62
                                     C1 -58 -21 -56 -38 -60 C-45 -80 -45 -99 -40 -114 Z"/>
        <path class="gyrus" d="M-32 -106 C-21 -96 -15 -81 -15 -65"/>
        <path class="gyrus" d="M-16 -113 C-5 -101 0 -86 0 -66"/></g>
        <g class="shard" style="--dx:253px; --dy:200px; --i:2"><path class="lobe lobe-o" d="M-84 -56 C-82 -84 -66 -104 -40 -114 C-45 -99 -45 -80 -38 -60
                                     C-54 -54 -72 -50 -84 -56 Z"/>
        <path class="gyrus" d="M-73 -60 C-67 -76 -60 -92 -50 -103"/>
        <path class="gyrus" d="M-79 -50 C-73 -66 -66 -82 -56 -95"/></g>
        <g class="shard" style="--dx:440px; --dy:142px; --i:3"><path class="lobe lobe-t" d="M-38 -60 C-21 -56 1 -58 15 -62 C27 -52 43 -44 55 -38
                                     C45 -20 19 -12 -7 -14 C-25 -16 -35 -30 -38 -46 Z"/>
        <path class="gyrus" d="M-26 -42 C-8 -32 18 -28 42 -32"/>
        <path class="gyrus" d="M-24 -28 C-6 -20 16 -18 36 -22"/></g>
        <g class="shard" style="--dx:-279px; --dy:295px; --i:4"><path class="cereb" d="M-82 -46 C-98 -34 -98 -10 -80 -2 C-62 6 -44 2 -36 -10 C-30 -20 -38 -38 -54 -46 Z"/>
        <path class="cerebline" d="M-90 -34 L-42 -38 M-93 -26 L-39 -28 M-92 -18 L-40 -18 M-88 -10 L-46 -8"/></g>
        <g class="shard" style="--dx:-53px; --dy:254px; --i:5"><path class="stem" d="M-46 -16 C-42 4 -40 22 -38 38 L-14 38 C-16 20 -20 0 -24 -16 Z"/>
        <path class="cerebline" d="M-40 2 L-20 2 M-39 14 L-19 14 M-38 26 L-18 26"/></g>
        <g class="shard" style="--dx:200px; --dy:320px; --i:6"><ellipse class="deep" cx="-16" cy="-44" rx="15" ry="10"/></g>
        <g class="shard" style="--dx:452px; --dy:281px; --i:7"><ellipse class="deep" cx="-2" cy="-12" rx="8" ry="6"/></g>
      </g></g>

      <path class="plate" d="M-112 -34 C-112 -62 -102 -84 -86 -100 L-74 -88
        C-88 -73 -97 -55 -97 -35 C-97 -12 -87 8 -70 23 C-56 35 -44 46 -30 56
        C-52 48 -72 38 -88 22 C-104 4 -112 -14 -112 -34 Z"/>
      <path class="seam" d="M-104 -44 C-102 -20 -93 2 -78 18"/>

      <g id="lid" transform="translate(-14,-26) rotate(-12)">
        <path class="plate" d="M-86 -100 C-66 -122 -34 -138 0 -138 C30 -138 48 -126 58 -110
                               L45 -97 C35 -111 18 -121 -2 -121 C-31 -121 -57 -108 -73 -88 Z"/>
        <path class="seam-thin" d="M-70 -96 C-52 -112 -26 -122 0 -122"/>
        <circle cx="-80" cy="-95" r="4" fill="#2b323b"/>
      </g>
      <circle cx="-92" cy="-116" r="5.5" fill="#151a21" stroke="#39424e" stroke-width="1.6"/>
      <path class="cable" d="M-86 -104 C-94 -118 -98 -128 -102 -138"/>
      <path class="cable-hi" d="M-86 -104 C-94 -118 -98 -128 -102 -138"/>

      <g transform="translate(7,1)">
        <path class="plate" d="M58 -110 C72 -88 80 -70 86 -58 C90 -50 90 -46 92 -42
          C98 -34 108 -28 112 -20 C115 -14 110 -6 96 -4 C100 0 102 2 100 6
          C104 10 102 14 98 18 L70 18 C58 6 50 -12 46 -34 C42 -60 44 -88 45 -97 Z"/>
        <path class="seam" d="M62 -96 C70 -74 74 -52 74 -34"/>
        <path class="seam-thin" d="M88 -44 C96 -38 104 -30 108 -22"/>
        <path class="cavity" d="M50 -76 C63 -81 79 -76 86 -65 C79 -54 63 -50 52 -55 Z"/>
        <ellipse class="lens" cx="68" cy="-65" rx="10" ry="7.6"/>
        <circle cx="70.5" cy="-67.5" r="2.8" fill="#eafcff"/>
      </g>

      <g id="jawzone" class="zone"><g id="jaw" transform="translate(5,5)">
        <path class="plate-in" d="M98 18 C100 22 100 26 96 28 C96 36 94 42 92 46
          C88 56 82 62 72 64 C52 72 30 76 10 76 C-6 74 -20 68 -30 58 L-14 42
          C2 52 24 54 46 50 C64 46 78 36 86 22 Z"/>
        <path class="seam-thin" d="M-4 58 C18 60 42 56 62 46"/>
        <path class="cavity" d="M60 27 C74 23 87 21 93 23 C91 31 83 39 69 43 C59 45 55 39 57 33 Z"/>
        <path class="hot" d="M63 31 L89 27 M63 36 L85 32"/>
      </g></g>

      <g transform="translate(-34,-14)">
        <path class="plate-in" d="M-16 -18 C-2 -24 12 -18 14 -4 C16 10 6 22 -8 22 C-20 22 -28 12 -26 -2 Z"/>
        <circle r="11" fill="#0f1319" stroke="#39424e" stroke-width="2"/>
        <circle r="6" fill="none" stroke="#2de2ff" stroke-width="1.4" opacity=".85"/>
        <circle r="2.4" fill="#2de2ff"/>
      </g>
    </g>
  </g>

  <!-- ═══ ОТОРВАННАЯ РУКА ═══ -->
  <g id="arm" transform="translate(144,536) rotate(9)">
    <path class="ghost" d="M-4 -40 C22 -30 46 -22 66 -20 L54 60 C48 130 40 200 30 264
      C26 292 6 308 -18 304 C-42 300 -58 280 -54 254 L-30 90 C-24 40 -16 -6 -4 -40 Z"/>
    <path class="hot" d="M-10 -46 C14 -34 40 -26 64 -24" stroke-dasharray="5 5"/>
    <path class="muscle" d="M-6 -34 C18 -22 44 -14 66 -12 C60 18 50 46 38 72
      C18 60 0 44 -12 24 C-10 -2 -8 -20 -6 -34 Z"/>
    <path class="fiber" d="M4 -22 C24 -10 46 -4 64 -2 M-2 0 C16 14 38 22 54 24"/>
    <path class="bone" d="M14 -8 C30 2 46 6 60 6 L44 92 C26 84 12 72 4 56 Z"/>
    <path class="plate" d="M28 66 C50 70 64 86 62 108 L38 246 C34 270 14 286 -8 282
      C-32 278 -46 258 -42 234 L-16 96 C-12 74 8 62 28 66 Z"/>
    <path class="seam" d="M4 116 L54 124 M-4 168 L46 176 M-12 220 L38 228"/>
    <path class="seam-thin" d="M18 82 C38 86 50 96 54 110"/>
    <path class="plate-in" d="M-8 286 C10 288 22 300 20 316 L14 348 C12 364 -2 374 -18 372
      C-34 370 -44 356 -42 340 L-36 308 C-34 292 -22 284 -8 286 Z"/>
    <path class="seam-thin" d="M-30 314 L12 320 M-32 334 L10 340"/>
    <path class="plate-in" d="M-20 374 C-8 376 0 386 -2 398 L-8 424 C-10 436 -22 442 -34 440
      C-46 438 -52 428 -50 416 L-44 390 C-42 378 -32 372 -20 374 Z"/>

    <!-- часы на предплечье -->
    <g id="watch">
      <rect x="-30" y="150" width="94" height="52" rx="5" transform="rotate(-6 17 176)"
            fill="#060e16" stroke="#2de2ff" stroke-width="2"/>
      <g transform="rotate(-6 17 176)">
        <text id="w-time" x="-20" y="184" fill="#2de2ff" style="font:800 24px 'Cascadia Code',Consolas,monospace">--:--</text>
        <text id="w-date" x="-20" y="197" fill="#4d6379" style="font:8px 'Cascadia Code',Consolas,monospace">—</text>
        <circle cx="56" cy="160" r="3.5" fill="#ff3fa4"/>
      </g>
    </g>
  </g>

  <!-- ═══ ПРОЕКЦИЯ ИЗ ГЛАЗА ═══ -->
  <g id="projection">
    <path d="M536 250 L742 200 L742 470 L536 302 Z" fill="url(#gBeam)"/>
    <rect x="742" y="150" width="404" height="322" rx="2" class="hud"/>
    <path d="M742 150 L1146 150 L1146 178 L742 178 Z" fill="rgba(45,226,255,.1)"/>
    <text x="758" y="169" class="lbl" fill="#7fd8ff">П Р О Е К Ц И Я · Д А Т Ч И К И</text>
    <g id="vitals" transform="translate(758,214)"></g>
  </g>

  <!-- ═══ ХРОНОМЕТР ═══ -->
  <g id="clock">
    <path class="hud" d="M40 96 L316 96 L316 216 L96 216 L74 238 L74 216 L40 216 Z"/>
    <text x="58" y="120" class="lbl" fill="#7fd8ff">Х Р О Н О М Е Т Р</text>
    <text id="c-time" x="58" y="176" fill="#2de2ff" style="font:800 46px 'Cascadia Code',Consolas,monospace">--:--</text>
    <text id="c-sec" x="228" y="176" fill="#ff3fa4" style="font:800 20px 'Cascadia Code',Consolas,monospace">--</text>
    <text id="c-date" x="58" y="200" class="lbl">—</text>
  </g>

  <!-- ═══ ПОДПИСИ ═══ -->
  <g id="labels" transform="translate(-64,0)">
    <path class="lead" d="M452 118 L452 86 L560 86"/>
    <text x="568" y="90" class="lbl">М О З Г  ·  N E T B I R D</text>
    <path class="lead" d="M556 214 L610 202"/>
    <text x="616" y="206" class="lbl">Г Л А З · М Е Т Р И К И</text>
    <path class="lead" d="M584 318 L640 330"/>
    <text x="646" y="334" class="lbl">Р О Т · П Л Е Е Р</text>
    <path class="lead" d="M470 372 L556 388"/>
    <text x="562" y="392" class="lbl">Ш Е Я · Ж У Р Н А Л</text>
    <path class="lead" d="M588 650 L654 638"/>
    <text x="660" y="642" class="lbl">Г Р У Д Ь · Д Р О П</text>
    <path class="lead" d="M614 438 L672 428"/>
    <text x="678" y="432" class="lbl">У С Т Р О Й С Т В А</text>
    <path class="lead" d="M244 726 L156 742"/>
    <text x="96" y="746" class="lbl">Ч А С Ы</text>
    <path class="lead" d="M312 528 L344 518"/>
    <text x="110" y="492" class="lbl">Р А З Ъ Ё М  П Л Е Ч А</text>
  </g>
  <g id="nodes">__NODES__</g>
</svg>
        </div>
      </div>
      <audio id="audio" preload="none"></audio>
      <script>
      (() => {
        const $ = id => document.getElementById(id);
        const scheme = $("scheme");
        let toastTimer = null;
        const toast = t => {
          document.querySelectorAll(".toast").forEach(x => x.remove());
          const el = document.createElement("div"); el.className = "toast"; el.textContent = t;
          document.body.appendChild(el); clearTimeout(toastTimer);
          toastTimer = setTimeout(() => el.remove(), 2600);
        };

        let open = false;
        const setOpen = v => {
          open = v; scheme.classList.toggle("open", v);
          $("hint").textContent = v ? "нажми ещё раз или Escape \u2014 собрать череп" : "мозг \u2014 узлы сети · рот \u2014 плеер";
        };
        $("brainzone").addEventListener("click", e => { e.preventDefault(); setOpen(!open); });
        document.addEventListener("keydown", e => { if (e.key === "Escape" && open) setOpen(false); });
        document.querySelectorAll(".ncard-btn").forEach(b => b.addEventListener("click", e => {
          e.stopPropagation(); toast("Это витрина оформления \u2014 подключение живёт в кабинете");
        }));

        const ping = async () => {
          try {
            const r = await fetch("/api/netbird/status", { credentials:"same-origin" });
            const d = await r.json();
            document.querySelectorAll("[data-ping]").forEach(el => {
              const s = d[el.dataset.ping];
              if (s && s.online) { el.textContent = s.latency_ms != null ? s.latency_ms + " ms" : "в сети"; el.classList.remove("off"); }
              else { el.textContent = "офлайн"; el.classList.add("off"); }
            });
          } catch {}
        };
        ping(); setInterval(ping, 10000);

        const pad = n => String(n).padStart(2, "0");
        const MON = ["ЯНВ","ФЕВ","МАР","АПР","МАЯ","ИЮН","ИЮЛ","АВГ","СЕН","ОКТ","НОЯ","ДЕК"];
        const DAY = ["ВОСКРЕСЕНЬЕ","ПОНЕДЕЛЬНИК","ВТОРНИК","СРЕДА","ЧЕТВЕРГ","ПЯТНИЦА","СУББОТА"];
        const MONL = ["ЯНВАРЯ","ФЕВРАЛЯ","МАРТА","АПРЕЛЯ","МАЯ","ИЮНЯ","ИЮЛЯ","АВГУСТА","СЕНТЯБРЯ","ОКТЯБРЯ","НОЯБРЯ","ДЕКАБРЯ"];
        const tick = () => {
          const d = new Date(), hm = pad(d.getHours()) + ":" + pad(d.getMinutes());
          $("c-time").textContent = hm; $("c-sec").textContent = pad(d.getSeconds());
          $("c-date").textContent = DAY[d.getDay()] + ", " + d.getDate() + " " + MONL[d.getMonth()];
          $("w-time").textContent = hm; $("w-date").textContent = pad(d.getDate()) + " " + MON[d.getMonth()];
        };
        tick(); setInterval(tick, 1000);

        const vit = $("vitals");
        const drawVitals = async () => {
          try {
            const list = (await (await fetch("/api/metrics", { credentials:"same-origin" })).json()).slice(0, 3);
            let y = 0, out = "";
            list.forEach(({ name, data }) => {
              out += `<text class="lbl" fill="#9ad9f0" y="${y}" style="letter-spacing:.08em">${name}</text>`;
              [["CPU", data && data.cpu], ["RAM", data && data.ram], ["DSK", data && data.disk]].forEach(([k, v], j) => {
                const yy = y + 20 + j * 16, p = Math.max(0, Math.min(100, v || 0));
                const col = p > 85 ? "#ff5f7a" : p > 60 ? "#ffb35c" : "#2de2ff";
                out += `<text class="lbl" y="${yy}">${k}</text>`
                     + `<rect x="46" y="${yy - 8}" width="230" height="6" fill="rgba(255,255,255,.08)"/>`
                     + `<rect x="46" y="${yy - 8}" width="${p * 2.3}" height="6" fill="${col}"/>`
                     + `<text class="lbl" x="300" y="${yy}" fill="#cfe9f5" text-anchor="end">${v != null ? Math.round(v) + "%" : "\u2014"}</text>`;
              });
              y += 88;
            });
            vit.innerHTML = out;
          } catch {}
        };
        drawVitals(); setInterval(drawVitals, 30000);

        const audio = $("audio");
        let tracks = [], idx = -1;
        fetch("/api/music", { credentials:"same-origin" }).then(r => r.json())
          .then(d => { tracks = d.tracks.sort(() => Math.random() - .5); }).catch(() => {});
        const playAt = i => {
          if (!tracks.length) { toast("Треков нет \u2014 добавь их в кабинете"); return; }
          idx = (i + tracks.length) % tracks.length;
          audio.src = "/api/music/file/" + encodeURIComponent(tracks[idx].id);
          audio.play().catch(() => {});
          toast(((tracks[idx].artist ? tracks[idx].artist + " \u2014 " : "") + tracks[idx].title).slice(0, 46));
        };
        const jaw = $("jawzone");
        if (jaw) jaw.addEventListener("click", e => {
          e.preventDefault(); e.stopPropagation();
          if (audio.paused) { idx < 0 ? playAt(0) : audio.play().catch(() => {}); }
          else audio.pause();
        });
        audio.addEventListener("ended", () => playAt(idx + 1));
        audio.addEventListener("play",  () => scheme.classList.add("mouth"));
        audio.addEventListener("pause", () => scheme.classList.remove("mouth"));
      })();
      </script>
    </body>
    </html>
    """
    return html.replace("__NODES__", "".join(cards)) \
               .replace("__ICONLINKS__", ICON_LINKS)


@app.get("/drop")
@login_required
def drop_page():
    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="robots" content="noindex, nofollow">
      <meta name="theme-color" content="#0d1321">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Личный дроп · vitazgio.ru</title>
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100svh; color: #e9fbff; font-family: "Cascadia Code", Consolas, monospace; background: radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        [hidden] { display: none !important; }
        .wrap { max-width: 1100px; margin: 0 auto; padding: clamp(18px, 3vw, 40px); }

        .top { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        .back { width: 44px; height: 44px; flex: none; display: grid; place-items: center; color: #2de2ff; text-decoration: none; border: 1px solid rgba(45,226,255,.3); border-radius: 50%; background: rgba(45,226,255,.07); transition: all .18s; }
        .back svg { width: 20px; height: 20px; display: block; }
        .back:hover { color: #fff; border-color: #2de2ff; background: rgba(45,226,255,.18); }
        h1 { margin: 0; font-size: clamp(1.5rem, 3.5vw, 2.3rem); font-weight: 700; letter-spacing: -.02em;
             color: #eaf6ff; text-shadow: 0 0 22px rgba(45,226,255,.35); }
        h1 span { color: #2de2ff; text-shadow: 0 0 22px rgba(45,226,255,.5); }
        .quota { margin-left: auto; min-width: 190px; }
        .quota-text { color: #8f99ab; font-size: .7rem; }
        .quota-bar { height: 5px; margin-top: 5px; background: rgba(255,255,255,.08); }
        .quota-fill { height: 100%; width: 0; background: linear-gradient(90deg, #2de2ff, #63f5ad); transition: width .4s; }
        .quota-fill.hot { background: linear-gradient(90deg, #ffb35c, #ff6b81); }

        .bar { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 22px; }
        .btn { padding: 9px 14px; color: #dffaff; font: 700 .74rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.07); cursor: pointer; transition: all .18s; }
        .btn:hover { border-color: #2de2ff; background: rgba(45,226,255,.16); }
        .btn.primary { color: #1a0d04; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); }
        .search { flex: 1; min-width: 140px; height: 36px; padding: 0 12px; color: #e9fbff; font: 400 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.6); }
        .search:focus { border-color: #2de2ff; }

        .crumbs { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 18px; color: #6b7385; font-size: .76rem; }
        .crumb { color: #69e8ff; background: none; border: 0; padding: 2px 4px; font: inherit; cursor: pointer; }
        .crumb:hover { color: #fff; text-decoration: underline; }
        .crumb.here { color: #8f99ab; cursor: default; text-decoration: none; }

        .composer { margin-top: 16px; }
        .composer textarea { width: 100%; min-height: 76px; padding: 11px 13px; color: #e9fbff; font: 400 .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.6); resize: vertical; }
        .composer textarea:focus { border-color: #ff782f; }

        .uploads { margin-top: 14px; }
        .up { padding: 9px 12px; margin-bottom: 6px; border: 1px solid rgba(45,226,255,.16); background: rgba(10,17,30,.8); }
        .up-head { display: flex; justify-content: space-between; gap: 10px; font-size: .74rem; }
        .up-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .up-pct { color: #63f5ad; flex: none; }
        .up-bar { height: 4px; margin-top: 6px; background: rgba(255,255,255,.08); }
        .up-fill { height: 100%; width: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); transition: width .2s; }
        .up.failed { border-color: rgba(255,107,129,.45); }
        .up.failed .up-pct { color: #ff6b81; }

        .items { margin-top: 18px; display: grid; gap: 8px; }
        /* Именованные области: без них браузер раскладывал элементы как попало. */
        .item { display: grid; grid-template-columns: 46px minmax(0, 1fr) auto;
                grid-template-areas: "ico name acts" "ico meta acts" "body body body";
                align-items: center; gap: 2px 13px; padding: 11px 13px;
                border: 1px solid rgba(255,255,255,.08); background: rgba(10,17,30,.7);
                transition: border-color .18s, background .18s; }
        .item:hover { border-color: rgba(45,226,255,.3); background: rgba(14,24,42,.85); }
        .item.folder { cursor: pointer; }
        .item.drag-over { border-color: #63f5ad; background: rgba(99,245,173,.1); }
        .item.dragging { opacity: .4; }

        /* ── Режим выделения ─────────────────────────────────────────── */
        /* В нём тык по строке не открывает папку, а ставит и снимает галку.
           Чтобы это было видно сразу, строки в этом режиме подсвечены рамкой,
           а выделенные — ещё и заливкой с галочкой слева. */
        body.picking .item { cursor: pointer; border-color: rgba(45,226,255,.16);
                position: relative; }
        /* Кнопки строки в этом режиме убираем совсем, а не приглушаем: на
           телефоне они занимают отдельную строку, и список раздувался вдвое
           ровно там, где нужно видеть побольше файлов сразу. */
        body.picking .item .acts { display: none; }
        .item.picked { border-color: #2de2ff; background: rgba(45,226,255,.12);
                box-shadow: inset 0 0 0 1px rgba(45,226,255,.25); }
        /* Галка уголком у самого края рамки, а не поверх значка файла */
        .item.picked::after { content: "✓"; position: absolute; left: -1px; top: -1px;
                width: 22px; height: 20px; display: grid; place-items: center;
                color: #04121c; font-size: .74rem; font-weight: 800; line-height: 1;
                background: #2de2ff; border-radius: 0 0 7px 0; }
        /* Место под панель действий, иначе она накрывает последнюю строку */
        body.picking .wrap, body.has-clip .wrap { padding-bottom: 132px; }

        .selbar { position: fixed; left: 0; right: 0; bottom: 0; z-index: 120;
                  display: flex; align-items: center; gap: 12px;
                  padding: 10px 52px 10px 14px;
                  padding-bottom: calc(10px + env(safe-area-inset-bottom));
                  border-top: 1px solid rgba(45,226,255,.35);
                  background: linear-gradient(180deg, rgba(12,20,33,.99), rgba(7,12,20,.99));
                  box-shadow: 0 -14px 40px rgba(0,0,0,.6); }
        .selbar .count { flex: none; color: #2de2ff;
                  font: 700 .76rem "Cascadia Code", Consolas, monospace; letter-spacing: .04em; }
        .selbar .count b { color: #eafcff; }
        .selbar .count i { display: block; margin-top: 3px; color: #6b7c8f;
                  font-style: normal; font-size: .66rem; letter-spacing: .02em; }
        .selbar .row { flex: 1; display: flex; justify-content: flex-end; gap: 8px; }

        /* Кнопки: значок плюс подпись, подпись никогда не вылезает наружу —
           её режет overflow, а не удача с длиной слова. */
        .selbar button { display: inline-flex; align-items: center; justify-content: center;
                  gap: 7px; height: 40px; padding: 0 14px; cursor: pointer; color: #cfe2ee;
                  font: 700 .70rem "Cascadia Code", Consolas, monospace; letter-spacing: .04em;
                  white-space: nowrap; overflow: hidden; border-radius: 9px;
                  border: 1px solid rgba(255,255,255,.14);
                  background: linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03));
                  transition: border-color .16s, background .16s, transform .1s; }
        .selbar button svg { width: 15px; height: 15px; flex: none; }
        .selbar button span { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
        .selbar button:hover:not([disabled]) { border-color: rgba(45,226,255,.55);
                  background: linear-gradient(180deg, rgba(45,226,255,.2), rgba(45,226,255,.07)); }
        .selbar button:active:not([disabled]) { transform: translateY(1px); }
        .selbar button.go { color: #04121c; border-color: #2de2ff;
                  background: linear-gradient(180deg, #6df0ff, #21c8e6); }
        .selbar button.go:hover:not([disabled]) { background: linear-gradient(180deg, #8af5ff, #2de2ff); }
        .selbar button.bad { color: #ffb3b3; border-color: rgba(255,90,90,.38);
                  background: linear-gradient(180deg, rgba(255,90,90,.16), rgba(255,90,90,.05)); }
        .selbar button.bad:hover:not([disabled]) { border-color: rgba(255,90,90,.7);
                  background: linear-gradient(180deg, rgba(255,90,90,.28), rgba(255,90,90,.1)); }
        .selbar button[disabled] { opacity: .28; cursor: default; }

        /* Крестик закрытия — в углу самой панели, как у окошек в браузере.
           Отдельной кнопкой в ряду он съедал место у четырёх нужных. */
        .selbar .shut { position: absolute; right: 10px; top: 8px; width: 30px; height: 30px;
                  padding: 0; gap: 0; border-radius: 8px; color: #7f93a8;
                  border-color: transparent; background: transparent; }
        .selbar .shut svg { width: 15px; height: 15px; }
        .selbar .shut:hover:not([disabled]) { color: #eafcff;
                  border-color: rgba(255,255,255,.18);
                  background: rgba(255,255,255,.07); }

        /* Полоса хода дела — показываем только когда работа затянулась */
        .oplane { position: fixed; left: 0; right: 0; bottom: 0; z-index: 130;
                  padding: 14px 16px calc(14px + env(safe-area-inset-bottom));
                  border-top: 1px solid rgba(45,226,255,.35); background: rgba(6,11,20,.99); }
        .oplane .txt { display: flex; justify-content: space-between; margin-bottom: 8px;
                  color: #9fd7e8; font: 700 .72rem "Cascadia Code", Consolas, monospace; }
        .oplane .bar { height: 6px; background: rgba(255,255,255,.08); }
        .oplane .fill { height: 100%; width: 0; background: linear-gradient(90deg,#2de2ff,#63f5ad);
                  transition: width .2s ease; }

        /* На телефоне панель в два ряда: сверху счётчик, снизу кнопки сеткой
           по три. В одну строку пять кнопок с подписями не влезают — слова
           вроде «ПЕРЕМЕСТИТЬ» вылезали за рамку. */
        @media (max-width: 620px) {
          .selbar { flex-direction: column; align-items: stretch; gap: 9px;
                    padding-right: 14px; }
          .selbar .count { width: 100%; padding-right: 38px; }
          .selbar .row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; }
          .selbar button { padding: 0 5px; font-size: .60rem; gap: 5px; letter-spacing: 0; }
          .selbar button svg { width: 14px; height: 14px; }
          .selbar .shut { padding: 0; }
        }
        @media (max-width: 380px) {
          .selbar .row { gap: 6px; }
          .selbar button { font-size: .55rem; gap: 3px; padding: 0 3px; }
          .selbar button svg { width: 12px; height: 12px; }
        }

        .ico { grid-area: ico; justify-self: center; width: 34px; height: 42px; display: grid; place-items: center;
               color: var(--tint, #7d8798); font-size: .5rem; font-weight: 800; letter-spacing: .02em;
               border: 2px solid var(--tint, #7d8798); border-radius: 5px;
               background: color-mix(in srgb, var(--tint, #7d8798) 12%, transparent); }
        .ico.img { border-style: solid; background-size: cover; background-position: center; font-size: 0; }
        /* Та же ширина, что у бейджей, иначе значок папки съезжает на пару пикселей. */
        .ico.dir { width: 34px; height: 34px; border: 0; border-radius: 0; background: none;
                   cursor: pointer; transition: transform .16s; }
        .ico.dir svg { width: 32px; height: 32px; }
        .ico.dir:hover { transform: scale(1.12); }

        .nm { grid-area: name; min-width: 0; color: #dfe7f3; font-size: .84rem; overflow-wrap: anywhere; }
        .meta { grid-area: meta; color: #6b7385; font-size: .68rem; }
        .acts { grid-area: acts; display: flex; gap: 5px; align-self: center; }
        .act { padding: 5px 7px; color: #6b7385; font-size: .82rem; line-height: 1; border: 1px solid rgba(255,255,255,.1); background: transparent; cursor: pointer; transition: all .16s; }
        .act:hover { color: #fff; border-color: rgba(45,226,255,.4); background: rgba(45,226,255,.1); }
        .act.del:hover { color: #ff6b81; border-color: rgba(255,107,129,.45); background: rgba(255,107,129,.1); }
        .act.on { color: #63f5ad; border-color: rgba(99,245,173,.4); }

        .txt { position: relative; grid-area: body; margin-top: 8px; padding: 10px 34px 10px 12px; color: #b8c2d4; font-size: .76rem; white-space: pre-wrap; overflow-wrap: anywhere; border-left: 2px solid rgba(255,120,47,.5); background: rgba(4,10,20,.5); }
        /* Карандаш висит в правом верхнем углу самого текста, а не в общем
           ряду кнопок: там уже живёт переименование, и два карандаша рядом
           путали бы — этот правит содержимое, тот название. */
        .txt-edit { position: absolute; top: 6px; right: 6px; width: 24px; height: 24px; display: grid; place-items: center;
                    color: #ff9f45; font-size: .9rem; line-height: 1; cursor: pointer; border: 1px solid rgba(255,159,69,.35);
                    border-radius: 4px; background: rgba(255,159,69,.08); }
        .txt-edit:hover { color: #04060b; background: #ff9f45; border-color: #ff9f45; }
        .txt-area { width: 100%; min-height: 160px; margin: 0; padding: 10px 12px; color: #eaf6ff; font: 400 .78rem "Cascadia Code", Consolas, monospace;
                    line-height: 1.6; resize: vertical; border: 1px solid rgba(255,159,69,.5); outline: none; background: rgba(4,10,20,.8); }
        .txt-bar { display: flex; gap: 8px; margin-top: 8px; }
        .txt-bar button { height: 30px; padding: 0 14px; font: 700 .72rem "Cascadia Code", Consolas, monospace; letter-spacing: .06em;
                          cursor: pointer; border: 1px solid rgba(255,255,255,.16); background: rgba(255,255,255,.05); color: #cfe2ee; }
        .txt-bar button.go { color: #04060b; border-color: #ff9f45; background: #ff9f45; }

        body.modal-open { overflow: hidden; }

        .share-panel { width: min(380px, 100%); padding: 24px; color: #e8fbff;
                       border: 1px solid rgba(45,226,255,.35);
                       background: linear-gradient(145deg, rgba(16,30,47,.99), rgba(20,16,37,.99));
                       box-shadow: 0 32px 100px rgba(0,0,0,.7); }
        .share-panel h3 { margin: 0 0 16px; font-size: 1.05rem; letter-spacing: .04em; }
        .share-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px;
                     font-size: .82rem; color: #b8c8d8; }
        .share-row input[type=number] { width: 90px; height: 34px; padding: 0 10px; color: #f4fbff;
                     font: 600 .85rem "Cascadia Code", Consolas, monospace;
                     border: 1px solid rgba(255,255,255,.14); outline: none; background: rgba(4,10,20,.65); }
        .share-row input[type=number]:disabled { opacity: .4; }
        .share-row.check { cursor: pointer; }
        .share-row input[type=checkbox] { width: 17px; height: 17px; margin: 0; accent-color: #2de2ff; }
        .share-note { margin: 0 0 16px; color: #5d6d80; font-size: .72rem; line-height: 1.5; }
        .share-btns { display: flex; gap: 10px; }
        .share-btns button { flex: 1; height: 36px; font: 700 .74rem "Cascadia Code", Consolas, monospace;
                     letter-spacing: .06em; cursor: pointer; color: #cfe2ee;
                     border: 1px solid rgba(255,255,255,.16); background: rgba(255,255,255,.05); }
        .share-btns button.go { color: #04121c; border-color: #2de2ff; background: #2de2ff; }
        .share-btns button.bad { color: #ff8f8f; border-color: rgba(255,90,90,.4); }

        /* Карточка папки: сколько весит и каким значком её пометить */
        .fi-stat { margin: 0 0 16px; color: #7f93a8; font-size: .76rem; line-height: 1.7; }
        .fi-stat b { color: #cfe2ee; font-weight: 700; }
        .fi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 16px; }
        .fi-cell { display: grid; place-items: center; height: 56px; cursor: pointer;
                   border: 1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.03); }
        .fi-cell svg { width: 27px; height: 27px; }
        .fi-cell:hover { border-color: rgba(45,226,255,.5); background: rgba(45,226,255,.09); }
        .fi-cell.on { border-color: #2de2ff; background: rgba(45,226,255,.16); }

        /* Выданная раньше ссылка — её надо уметь показать и скопировать снова */
        .lk-url { margin: 0 0 14px; padding: 11px; color: #9fd7e8; font-size: .72rem;
                  word-break: break-all; line-height: 1.55;
                  border: 1px solid rgba(255,255,255,.1); background: rgba(4,10,20,.6); }

        /* Меню сортировки */
        .sort-wrap { position: relative; }
        .sort-menu { position: absolute; right: 0; top: calc(100% + 6px); z-index: 40; min-width: 200px;
                     padding: 5px; border: 1px solid rgba(45,226,255,.3);
                     background: rgba(10,16,26,.99); box-shadow: 0 18px 50px rgba(0,0,0,.6); }
        .sort-menu button { display: block; width: 100%; padding: 10px 12px; text-align: left; cursor: pointer;
                     color: #cfe2ee; font: 600 .76rem "Cascadia Code", Consolas, monospace;
                     border: 0; background: transparent; }
        .sort-menu button:hover { background: rgba(45,226,255,.12); }
        .sort-menu button.on { color: #2de2ff; }

        /* Просмотр картинки во весь экран */
        .lightbox { position: fixed; inset: 0; z-index: 300; display: grid; place-items: center; padding: 24px;
                    background: rgba(2,5,10,.94); backdrop-filter: blur(4px); }
        .lightbox img { max-width: 100%; max-height: 100%; object-fit: contain; border: 1px solid rgba(45,226,255,.25);
                        box-shadow: 0 24px 70px rgba(0,0,0,.7); }
        .lightbox .lb-close { position: absolute; top: 16px; right: 16px; width: 44px; height: 44px; display: grid; place-items: center;
                              color: #eaf6ff; font-size: 1.5rem; line-height: 1; cursor: pointer; border: 1px solid rgba(255,255,255,.22);
                              border-radius: 6px; background: rgba(10,16,26,.85); }
        .lightbox .lb-close:hover { color: #04060b; background: #2de2ff; border-color: #2de2ff; }
        .lightbox .lb-name { position: absolute; left: 16px; top: 24px; max-width: calc(100% - 90px); color: #7f93a8;
                             font-size: .74rem; letter-spacing: .04em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .txt-more { margin-top: 6px; color: #69e8ff; font-size: .72rem; background: none; border: 0; padding: 0; cursor: pointer; }

        .empty { padding: 40px 0; color: #4a5060; font-size: .82rem; text-align: center; }
        .rename { min-width: 0; width: 100%; height: 28px; padding: 0 8px; color: #f4fbff; font: 600 .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.4); outline: none; background: rgba(4,10,20,.65); }

        .veil { position: fixed; inset: 0; z-index: 50; display: grid; place-items: center; background: rgba(3,6,13,.85); backdrop-filter: blur(6px); color: #2de2ff; font-size: 1.3rem; letter-spacing: .04em; border: 3px dashed rgba(45,226,255,.5); }
        .toast { position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%); z-index: 60; max-width: 90vw; padding: 11px 18px; color: #06131c; font-size: .78rem; background: #63f5ad; box-shadow: 0 10px 40px rgba(0,0,0,.5); }
        .toast.bad { background: #ff6b81; color: #fff; }

        @media (max-width: 560px) {
          .quota { margin-left: 0; width: 100%; }
          .item { grid-template-areas: "ico name name" "ico meta meta" "acts acts acts" "body body body"; }
          .acts { justify-content: flex-end; margin-top: 8px; }
        }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="top">
          <a class="back" href="/cabinet" title="Назад в кабинет" aria-label="Назад в кабинет">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </a>
          <h1>Личный <span>дроп</span></h1>
          <div class="quota">
            <div class="quota-text" id="quota-text">—</div>
            <div class="quota-bar"><div class="quota-fill" id="quota-fill"></div></div>
          </div>
        </div>

        <div class="bar">
          <button class="btn primary" id="pick" type="button">Выбрать файлы</button>
          <button class="btn" id="from-clip" type="button">Из буфера</button>
          <button class="btn" id="mkdir" type="button">Новая папка</button>
          <input class="search" id="search" type="search" placeholder="Поиск в этой папке…">
          <div class="sort-wrap"><button class="btn" id="sort" type="button">Сначала новые</button></div>
          <!-- accept обязателен: без него Android показывает только камеру и галерею -->
          <input type="file" id="file-input" accept="*/*" multiple hidden>
        </div>

        <div class="crumbs" id="crumbs"></div>

        <div class="composer">
          <textarea id="text-area" placeholder="Текст — отправится отдельной панелью. Ctrl+Enter"></textarea>
          <button class="btn" id="send-text" type="button" style="margin-top:8px">Отправить текст</button>
        </div>

        <div class="uploads" id="uploads"></div>
        <div class="items" id="items"><p class="empty">Загрузка…</p></div>
      </div>

      <div class="veil" id="veil" hidden>Отпусти — загрузим</div>

      <script>
      (() => {
        const CHUNK = 4 * 1024 * 1024;
        const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
        const $ = id => document.getElementById(id);

        let parent = null;
        let items = [];
        const expanded = new Set();

        /* Выделение нескольких штук сразу. picking — в режиме мы или нет,
           picked — что отмечено, clip — что лежит в буфере после «копировать»
           или «переместить». Буфер переживает переход в другую папку: в этом
           и весь смысл — набрал здесь, вставил там. */
        let picking = false;
        const picked = new Set();
        let clip = null;             // { mode: "copy" | "move", ids: [...] }

        /* Сортировка одна на папки и файлы вперемешку — как в проводнике,
           когда столбец «Изменён» уже нажат. Свежесть папки сервер считает
           по самому свежему файлу внутри: правишь содержимое — папка
           поднимается наверх. */
        const SORTS = {
          new: ["Сначала новые", (a, b) => b.touched - a.touched],
          old: ["Сначала старые", (a, b) => a.touched - b.touched],
          az:  ["По алфавиту А→Я", (a, b) => a.name.localeCompare(b.name, "ru")],
          za:  ["По алфавиту Я→А", (a, b) => b.name.localeCompare(a.name, "ru")],
        };
        let sortKey = localStorage.getItem("vitaz-drop-sort") || "new";
        if (!SORTS[sortKey]) sortKey = "new";

        const fmtSize = b => {
          if (b < 1024) return b + " Б";
          if (b < 1048576) return (b / 1024).toFixed(1) + " КБ";
          if (b < 1073741824) return (b / 1048576).toFixed(1) + " МБ";
          return (b / 1073741824).toFixed(2) + " ГБ";
        };
        const fmtDate = ts => new Date(ts * 1000).toLocaleString("ru-RU",
          { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" });

        // Эмодзи выглядят по-разному на каждой платформе, поэтому рисуем
        // одинаковые значки сами: рамка нужного цвета плюс подпись типа.
        const TINTS = [
          [["pdf"], "#ff5a5a"],
          [["doc","docx","odt","rtf"], "#4a90e2"],
          [["xls","xlsx","ods","csv"], "#3ec97a"],
          [["ppt","pptx","odp"], "#ff9f45"],
          [["zip","7z","rar","tar","gz","xz"], "#f5c344"],
          [["mp4","mkv","avi","mov","webm","m4v"], "#c77dff"],
          [["mp3","wav","flac","ogg","m4a","opus"], "#56d4dd"],
          [["exe","msi","apk","deb","appimage"], "#8b95a5"],
          [["jpg","jpeg","png","gif","webp","bmp","svg","heic","tif","tiff"], "#63f5ad"],
          [["txt","md","log","json","xml","yml","yaml","ini","conf"], "#9aa6b8"],
        ];
        const extOf = name => (name.includes(".") ? name.split(".").pop() : "").toLowerCase();
        const tintOf = ext => (TINTS.find(([list]) => list.includes(ext)) || [null, "#7d8798"])[1];

        /* Значки папок. Рисуем сами, а не эмодзи: те на каждой системе
           выглядят по-своему, а тут всё должно быть в одном стиле. Имя
           значка хранится в индексе, вся отрисовка — здесь. */
        const FOLDER_ICONS = {
          folder:  ["Папка", "#f5c344",
            '<path d="M3 7a2 2 0 0 1 2-2h6l3 3h13a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" fill="currentColor" fill-opacity=".2"/>' +
            '<path d="M3 7a2 2 0 0 1 2-2h6l3 3h13a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>'],
          warn:    ["Внимание", "#ff8f4a",
            '<path d="M16 4.5 29.5 27.5H2.5L16 4.5Z" fill="currentColor" fill-opacity=".2"/>' +
            '<path d="M16 4.5 29.5 27.5H2.5L16 4.5Z"/><path d="M16 13v6"/><path d="M16 23.2h.01"/>'],
          clock:   ["Часы", "#4ec8ff",
            '<circle cx="16" cy="16" r="12.5" fill="currentColor" fill-opacity=".18"/>' +
            '<circle cx="16" cy="16" r="12.5"/><path d="M16 8.5V16l5.5 3.2"/>'],
          tree:    ["Дерево", "#56d97f",
            '<path d="M16 3.5 25 15.5h-4.5l6 8H5.5l6-8H7l9-12Z" fill="currentColor" fill-opacity=".2"/>' +
            '<path d="M16 3.5 25 15.5h-4.5l6 8H5.5l6-8H7l9-12Z"/><path d="M16 23.5v5.5"/>'],
          monitor: ["Компьютер", "#9aa6b8",
            '<rect x="2.5" y="5" width="27" height="17.5" rx="2" fill="currentColor" fill-opacity=".18"/>' +
            '<rect x="2.5" y="5" width="27" height="17.5" rx="2"/><path d="M16 22.5v5M11 27.5h10"/>'],
          phone:   ["Телефон", "#b57cff",
            '<rect x="9" y="2.5" width="14" height="27" rx="3" fill="currentColor" fill-opacity=".18"/>' +
            '<rect x="9" y="2.5" width="14" height="27" rx="3"/><path d="M14.2 6h3.6"/><path d="M16 25.6h.01"/>'],
          // Одиннадцать лучей — это один луч и десять его поворотов вокруг
          // середины: так они одинаковы по построению. Основание заходит за
          // центр, иначе в середине оставалась бы дырка.
          claude:  ["Клод", "#d97757",
            '<g fill="currentColor" stroke="none">' +
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(function (i) {
              return '<path d="M15.45 17L14.6 3.9A1.4 1.4 0 0 1 17.4 3.9L16.55 17Z"' +
                     ' transform="rotate(' + (i * 360 / 11).toFixed(3) + ' 16 16)"/>';
            }).join("") + '</g>'],
          // Тот же знак, что стоит иконкой сайта: пять фигур, вычерченных
          // хозяином. Цвет бирюзовый, как у настоящего логотипа; зерно на
          // значке в двадцать семь пикселей всё равно не разглядеть.
          vitaz:   ["Vitaz Gio", "#2de2ff",
            '<path fill="currentColor" stroke="none" d="' +
            'M1.60 4.04 7.90 24.70 9.88 18.21 5.56 4.04Z' +
            'M8.92 27.96 11.77 27.96 12.92 24.14 17.89 7.86 19.04 4.04 15.08 4.04 10.34 19.59 8.32 26.08Z' +
            'M23.13 27.96 25.71 19.54 21.70 19.54 20.28 24.14 13.75 24.14 12.60 27.96Z' +
            'M27.09 14.90 19.73 14.90 18.53 18.71 21.93 18.71 25.94 18.71Z' +
            'M18.76 7.86 29.25 7.86 30.40 4.04 19.91 4.04Z' +
            '"/>'],
          star:    ["Звезда", "#ffd84a",
            '<path d="m16 3.5 3.9 8.4 9.2 1.1-6.8 6.3 1.8 9.1-8.1-4.5-8.1 4.5 1.8-9.1-6.8-6.3 9.2-1.1L16 3.5Z" fill="currentColor" fill-opacity=".2"/>' +
            '<path d="m16 3.5 3.9 8.4 9.2 1.1-6.8 6.3 1.8 9.1-8.1-4.5-8.1 4.5 1.8-9.1-6.8-6.3 9.2-1.1L16 3.5Z"/>'],
          lock:    ["Замок", "#ff5a5a",
            '<rect x="6" y="14" width="20" height="15" rx="3" fill="currentColor" fill-opacity=".18"/>' +
            '<rect x="6" y="14" width="20" height="15" rx="3"/><path d="M11 14V9.6a5 5 0 0 1 10 0V14"/>'],
          music:   ["Музыка", "#35e0f0",
            '<path d="M12.5 23.5V7l14-3v16.5"/>' +
            '<circle cx="8.5" cy="24" r="4.2" fill="currentColor" fill-opacity=".22"/><circle cx="8.5" cy="24" r="4.2"/>' +
            '<circle cx="22.5" cy="20.5" r="4.2" fill="currentColor" fill-opacity=".22"/><circle cx="22.5" cy="20.5" r="4.2"/>'],
          photo:   ["Фото", "#63f5ad",
            '<rect x="3" y="6" width="26" height="20" rx="2" fill="currentColor" fill-opacity=".18"/>' +
            '<rect x="3" y="6" width="26" height="20" rx="2"/><circle cx="10.5" cy="13" r="2.6"/>' +
            '<path d="m4.5 23.5 7.5-7.5 5 5 4-3.2 6 6.2"/>'],
        };

        const folderSvg = name => {
          const [, tint, body] = FOLDER_ICONS[name] || FOLDER_ICONS.folder;
          return `<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round" style="color:${tint}"
            aria-hidden="true">${body}</svg>`;
        };

        const iconHtml = it => {
          if (it.kind === "folder") {
            return `<span class="ico dir" data-act="icon" title="Значок и размер папки">${
              folderSvg(it.icon || "folder")}</span>`;
          }
          if (it.kind === "text") return `<span class="ico" style="--tint:#ff9f45">ТЕКСТ</span>`;
          const ext = extOf(it.name);
          if (it.thumb) {
            // Картинку можно открыть во весь экран — по самой миниатюре
            return `<span class="ico img" data-act="view" title="Открыть картинку"
              style="--tint:${tintOf(ext)};background-image:url(/api/drop/thumb/${encodeURIComponent(it.id)})"></span>`;
          }
          const label = ext ? ext.slice(0, 4).toUpperCase() : "ФАЙЛ";
          return `<span class="ico" style="--tint:${tintOf(ext)}">${esc(label)}</span>`;
        };

        /* Окно выдачи ссылки: часы и галка «без срока». Бессрочная нужна,
           чтобы картинку можно было вставить адресом в настройки другого
           сайта — там ссылка с истечением через сутки бесполезна. */
        const askShare = () => new Promise(resolve => {
          const box = document.createElement("div");
          box.className = "lightbox share-ask";
          box.innerHTML =
            '<div class="share-panel">' +
              '<h3>Ссылка на файл</h3>' +
              '<label class="share-row"><span>Часов</span>' +
                '<input type="number" min="1" max="720" value="24" id="sh-h"></label>' +
              '<label class="share-row check"><input type="checkbox" id="sh-f">' +
                '<span>Без срока — не истекает никогда</span></label>' +
              '<p class="share-note">Ссылка со сроком скачивает файл. ' +
                'Бессрочная открывает его прямо в браузере — такой адрес ' +
                'можно вставить как картинку в настройки другого сайта.</p>' +
              '<div class="share-btns">' +
                '<button type="button" class="go" id="sh-ok">СОЗДАТЬ</button>' +
                '<button type="button" id="sh-no">ОТМЕНА</button>' +
              '</div>' +
            '</div>';
          document.body.appendChild(box);
          document.body.classList.add("modal-open");
          const hours = box.querySelector("#sh-h");
          const forever = box.querySelector("#sh-f");
          hours.focus();
          const shut = value => {
            box.remove();
            document.body.classList.remove("modal-open");
            document.removeEventListener("keydown", onKey);
            resolve(value);
          };
          const onKey = ev => {
            if (ev.key === "Escape") shut(null);
            if (ev.key === "Enter") box.querySelector("#sh-ok").click();
          };
          // Галка и поле часов взаимно исключают друг друга — так понятнее,
          // чем оставлять серое неактивное число рядом с «без срока».
          forever.addEventListener("change", () => { hours.disabled = forever.checked; });
          box.querySelector("#sh-ok").addEventListener("click", () => {
            shut(forever.checked
              ? { forever: true }
              : { hours: parseInt(hours.value, 10) || 24 });
          });
          box.querySelector("#sh-no").addEventListener("click", () => shut(null));
          box.addEventListener("click", ev => { if (ev.target === box) shut(null); });
          document.addEventListener("keydown", onKey);
        });

        /* Общая обёртка для окошек: тёмный фон, панель, Escape и щелчок мимо
           закрывают. Раньше это дублировалось в каждом окне отдельно. */
        const modal = html => {
          const box = document.createElement("div");
          box.className = "lightbox share-ask";
          box.innerHTML = '<div class="share-panel">' + html + "</div>";
          document.body.appendChild(box);
          document.body.classList.add("modal-open");
          const shut = () => {
            box.remove();
            document.body.classList.remove("modal-open");
            document.removeEventListener("keydown", onKey);
          };
          const onKey = ev => { if (ev.key === "Escape") shut(); };
          box.addEventListener("click", ev => { if (ev.target === box) shut(); });
          document.addEventListener("keydown", onKey);
          return { box: box, shut: shut };
        };

        /* Карточка папки: сколько она занимает на диске, сколько внутри всего
           и каким значком её пометить. Открывается тычком по самому значку —
           тычок по имени по-прежнему заходит внутрь. */
        const folderCard = item => {
          const cells = Object.keys(FOLDER_ICONS).map(key => {
            const [label] = FOLDER_ICONS[key];
            const on = (item.icon || "folder") === key ? " on" : "";
            return `<button type="button" class="fi-cell${on}" data-icon="${key}"
              title="${esc(label)}" aria-label="${esc(label)}">${folderSvg(key)}</button>`;
          }).join("");
          const m = modal(
            "<h3>" + esc(item.name) + "</h3>" +
            '<p class="fi-stat">На диске: <b>' + fmtSize(item.size || 0) + "</b><br>" +
            "Внутри: <b>" + (item.count || 0) + "</b> " + plural(item.count || 0,
              ["объект", "объекта", "объектов"]) + "<br>" +
            "Последняя правка: <b>" + fmtDate(item.touched || item.created) + "</b></p>" +
            '<p class="share-note">Значок папки</p>' +
            '<div class="fi-grid">' + cells + "</div>" +
            '<div class="share-btns"><button type="button" id="fi-no">ЗАКРЫТЬ</button></div>');
          m.box.querySelector("#fi-no").addEventListener("click", m.shut);
          m.box.querySelectorAll(".fi-cell").forEach(cell => {
            cell.addEventListener("click", async () => {
              const icon = cell.dataset.icon;
              try {
                await api("/api/drop/" + item.id, { method: "PATCH",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ icon }) });
              } catch (err) { toast(err.message, true); return; }
              m.shut();
              load();
            });
          });
        };

        // «объект / объекта / объектов» — без этого счётчик читается коряво
        const plural = (n, forms) => {
          const a = Math.abs(n) % 100, b = a % 10;
          if (a > 10 && a < 20) return forms[2];
          if (b > 1 && b < 5) return forms[1];
          return b === 1 ? forms[0] : forms[2];
        };

        /* Ссылка уже выдана: показываем её саму, даём скопировать ещё раз и
           отозвать. Раньше повторный тык по цепочке умел только отзывать, и
           узнать адрес заново было неоткуда. */
        const linkMenu = item => {
          const url = item.share_url || "";
          const life = item.share_expires
            ? "истекает " + fmtDate(item.share_expires)
            : "без срока — открывается прямо в браузере";
          const m = modal(
            "<h3>Ссылка активна</h3>" +
            '<div class="lk-url">' + esc(url) + "</div>" +
            '<p class="share-note">' + esc(life) + "</p>" +
            '<div class="share-btns">' +
              '<button type="button" class="go" id="lk-copy">⧉ КОПИРОВАТЬ</button>' +
              '<button type="button" class="bad" id="lk-del">УДАЛИТЬ ССЫЛКУ</button>' +
            "</div>");
          m.box.querySelector("#lk-copy").addEventListener("click", async () => {
            try { await navigator.clipboard.writeText(url); toast("Ссылка скопирована"); }
            catch { prompt("Ссылка:", url); }
            m.shut();
          });
          m.box.querySelector("#lk-del").addEventListener("click", async () => {
            try { await api("/api/drop/share/" + item.id, { method: "DELETE" }); toast("Ссылка отозвана"); }
            catch (err) { toast(err.message, true); return; }
            m.shut();
            load();
          });
        };

        /* Картинка во весь экран. Закрыть можно крестиком, щелчком по фону,
           Escape или кнопкой «назад» — последнее важно на телефоне, где
           крестик легко не заметить и по привычке смахнуть назад. */
        const openImage = item => {
          const box = document.createElement("div");
          box.className = "lightbox";
          const img = document.createElement("img");
          img.src = "/api/drop/download/" + encodeURIComponent(item.id);
          img.alt = item.name;
          const name = document.createElement("div");
          name.className = "lb-name";
          name.textContent = item.name;
          const close = document.createElement("button");
          close.className = "lb-close";
          close.type = "button";
          close.setAttribute("aria-label", "Закрыть картинку");
          close.textContent = "×";
          box.append(img, name, close);
          document.body.appendChild(box);
          document.body.classList.add("modal-open");

          let closed = false;
          const shut = fromBack => {
            if (closed) return;
            closed = true;
            box.remove();
            document.body.classList.remove("modal-open");
            document.removeEventListener("keydown", onEsc);
            window.removeEventListener("popstate", onBack);
            if (!fromBack && history.state && history.state.lightbox) history.back();
          };
          const onEsc = ev => { if (ev.key === "Escape") shut(false); };
          const onBack = () => shut(true);
          close.addEventListener("click", () => shut(false));
          box.addEventListener("click", ev => { if (ev.target === box) shut(false); });
          document.addEventListener("keydown", onEsc);
          history.pushState({ lightbox: true }, "");
          window.addEventListener("popstate", onBack);
        };

        let toastTimer = null;
        const toast = (text, bad) => {
          document.querySelectorAll(".toast").forEach(t => t.remove());
          const el = document.createElement("div");
          el.className = "toast" + (bad ? " bad" : "");
          el.textContent = text;
          document.body.appendChild(el);
          clearTimeout(toastTimer);
          toastTimer = setTimeout(() => el.remove(), 3600);
        };

        const api = async (url, options) => {
          const response = await fetch(url, Object.assign({ credentials: "same-origin" }, options || {}));
          let data = {};
          try { data = await response.json(); } catch {}
          if (!response.ok) throw new Error(data.error || "Ошибка " + response.status);
          return data;
        };

        // ── Отрисовка ──
        const renderCrumbs = crumbs => {
          const parts = ['<button class="crumb" data-go="">Дроп</button>'];
          crumbs.forEach((c, i) => {
            parts.push("<span>/</span>");
            const last = i === crumbs.length - 1;
            parts.push(`<button class="crumb${last ? " here" : ""}" data-go="${esc(c.id)}">${esc(c.name)}</button>`);
          });
          $("crumbs").innerHTML = parts.join("");
        };

        const render = () => {
          const needle = $("search").value.trim().toLowerCase();
          let list = items.filter(it => !needle || it.name.toLowerCase().includes(needle));
          list.sort(SORTS[sortKey][1]);
          $("sort").textContent = SORTS[sortKey][0];

          if (!list.length) {
            $("items").innerHTML = '<p class="empty">' + (needle ? "Ничего не нашлось" : "Пусто. Перетащи файлы сюда или вставь через Ctrl+V") + "</p>";
            paintPicks();          // панель нужна и в пустой папке: сюда вставляют
            return;
          }
          $("items").innerHTML = list.map(it => {
            const isText = it.kind === "text";
            const isFolder = it.kind === "folder";
            const open = expanded.has(it.id);
            const body = isText && it.preview != null
              ? `<div class="txt"><button class="txt-edit" data-act="edit" title="Изменить текст">✎</button>${
                   esc(open && it.full ? it.full : it.preview)}${
                   it.truncated && !open ? "…" : ""}${
                   it.truncated ? `<br><button class="txt-more" data-act="more">${open ? "свернуть" : "показать целиком"}</button>` : ""}</div>`
              : "";
            const meta = isFolder
              ? "папка · " + fmtSize(it.size || 0) + " · " + fmtDate(it.touched || it.created)
              : fmtSize(it.size) + " · " + fmtDate(it.created);
            return `<div class="item ${it.kind}" data-id="${esc(it.id)}" draggable="true">
              ${iconHtml(it)}
              <span class="nm">${esc(it.name)}</span>
              <span class="acts">
                ${isFolder ? "" : `<button class="act" data-act="dl" title="Скачать">⤓</button>`}
                ${isText ? `<button class="act" data-act="copy" title="Копировать">⧉</button>` : ""}
                ${isFolder ? "" : `<button class="act${it.share ? " on" : ""}" data-act="share" title="Ссылка для скачивания">🔗</button>`}
                <button class="act" data-act="ren" title="Переименовать">✎</button>
                <button class="act del" data-act="del" title="Удалить">🗑</button>
              </span>
              <span class="meta">${esc(meta)}${it.share ? " · ссылка активна" : ""}</span>
              ${body}
            </div>`;
          }).join("");
          // Разметку строк перерисовали заново — вернуть галки на место
          paintPicks();
        };

        const load = async () => {
          try {
            const data = await api("/api/drop/list?parent=" + encodeURIComponent(parent || ""));
            items = data.items;
            renderCrumbs(data.breadcrumbs);
            const pct = data.quota ? (data.used / data.quota) * 100 : 0;
            $("quota-text").textContent = fmtSize(data.used) + " из " + fmtSize(data.quota);
            $("quota-fill").style.width = Math.min(pct, 100) + "%";
            $("quota-fill").classList.toggle("hot", pct > 80);
            render();
          } catch (e) { toast(e.message, true); }
        };

        /* ── Выделение, буфер и пакетные действия ─────────────────────────
           Как в проводнике: долгий тык включает режим, дальше обычные тычки
           ставят и снимают галки. Сняли всё — режим выключился сам, и папки
           снова открываются одним касанием. */

        const paintPicks = () => {
          document.body.classList.toggle("picking", picking);
          document.body.classList.toggle("has-clip", !!clip);
          document.querySelectorAll(".item").forEach(row => {
            row.classList.toggle("picked", picked.has(row.dataset.id));
            // Заодно снимаем следы перетаскивания. На телефоне событие его
            // окончания не приходит вовсе, и строка оставалась бледной.
            row.classList.remove("dragging", "drag-over");
          });
          drawSelbar();
        };

        const stopPicking = () => {
          picking = false;
          picked.clear();
          paintPicks();
        };

        const togglePick = id => {
          if (picked.has(id)) picked.delete(id); else picked.add(id);
          // Сняли последнюю галку — выходим из режима, чтобы не гадать,
          // откроется папка от тычка или нет.
          if (!picked.size) picking = false;
          paintPicks();
        };

        const startPicking = id => {
          picking = true;
          picked.add(id);
          if (navigator.vibrate) navigator.vibrate(12);
          paintPicks();
        };

        /* Значки на кнопках панели. Рисуем сами по той же причине, что и
           значки папок: эмодзи на каждой системе выглядят по-своему. */
        const OP_ICONS = {
          copy: '<rect x="6.5" y="6.5" width="11" height="13" rx="2"/>' +
                '<path d="M13.5 6.5V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h1.5"/>',
          cut:  '<path d="M3 6h6l2 2h9a1 1 0 0 1 1 1v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V7"/>' +
                '<path d="M9 13.5h6"/><path d="M12.5 11l2.5 2.5-2.5 2.5"/>',
          paste:'<rect x="4.5" y="4" width="15" height="17" rx="2"/>' +
                '<path d="M9 4V2.8A1.3 1.3 0 0 1 10.3 1.5h3.4A1.3 1.3 0 0 1 15 2.8V4"/>' +
                '<path d="M8.5 12h7M8.5 16h4.5"/>',
          del:  '<path d="M4 6.5h16"/><path d="M9 6.5V4.2A1.2 1.2 0 0 1 10.2 3h3.6A1.2 1.2 0 0 1 15 4.2v2.3"/>' +
                '<path d="M6 6.5 7 20a1.5 1.5 0 0 0 1.5 1.4h7A1.5 1.5 0 0 0 17 20l1-13.5"/>' +
                '<path d="M10 10.5v7M14 10.5v7"/>',
          off:  '<path d="M6 6l12 12M18 6 6 18"/>',
        };
        const opIcon = name =>
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
          'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
          OP_ICONS[name] + "</svg>";

        function drawSelbar() {
          let bar = document.querySelector(".selbar");
          if (!picking && !clip) { if (bar) bar.remove(); return; }
          if (!bar) {
            bar = document.createElement("div");
            bar.className = "selbar";
            document.body.appendChild(bar);
            bar.addEventListener("click", onSelbarClick);
          }
          const n = picked.size;
          const clipNote = clip
            ? '<i>в буфере ' + clip.ids.length + " " +
              plural(clip.ids.length, ["штука", "штуки", "штук"]) +
              (clip.mode === "move" ? " на перенос" : " на копию") + "</i>"
            : "";
          const btn = (op, label, cls, off) =>
            '<button type="button" data-op="' + op + '"' +
            (cls ? ' class="' + cls + '"' : "") + (off ? " disabled" : "") +
            ' aria-label="' + label + '">' + opIcon(op) +
            "<span>" + label + "</span></button>";
          bar.innerHTML =
            '<span class="count">Выделено <b>' + n + "</b>" + clipNote + "</span>" +
            '<span class="row">' +
              btn("copy", "КОПИЯ", "", !n) +
              btn("cut", "ПЕРЕНОС", "", !n) +
              btn("paste", "ВСТАВИТЬ", "go", !clip) +
              btn("del", "УДАЛИТЬ", "bad", !n) +
            "</span>" +
            '<button type="button" class="shut" data-op="off" title="Выйти из режима" ' +
            'aria-label="Выйти из режима выделения">' + opIcon("off") + "</button>";
        }

        /* Полоса хода дела. Появляется только если работа затянулась дольше
           секунды: на мелочи она мигала бы и раздражала. */
        const runOp = async (op, ids, target, title) => {
          let data;
          try {
            data = await api("/api/drop/op", { method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ op, ids, parent: target }) });
          } catch (err) { toast(err.message, true); return false; }

          const started = Date.now();
          let lane = null;
          const showLane = st => {
            if (!lane) {
              lane = document.createElement("div");
              lane.className = "oplane";
              lane.innerHTML = '<div class="txt"><span>' + esc(title) +
                '</span><span data-pct>0%</span></div>' +
                '<div class="bar"><div class="fill"></div></div>';
              document.body.appendChild(lane);
            }
            // Если известен объём в байтах, считаем по нему: одна большая
            // папка иначе висела бы на нуле до самого конца.
            const pct = st.bytes_total
              ? st.bytes / st.bytes_total * 100
              : (st.total ? st.done / st.total * 100 : 0);
            lane.querySelector(".fill").style.width = Math.min(pct, 100).toFixed(1) + "%";
            lane.querySelector("[data-pct]").textContent = Math.round(pct) + "%";
          };

          for (;;) {
            await new Promise(r => setTimeout(r, 250));
            let st;
            try { st = await api("/api/drop/op/" + data.job); }
            catch (err) { toast(err.message, true); break; }
            if (Date.now() - started > 1000 && st.state === "run") showLane(st);
            if (st.state !== "run") {
              if (lane) { showLane(st); await new Promise(r => setTimeout(r, 180)); }
              if (st.state === "fail") toast(st.error || "Не получилось", true);
              break;
            }
          }
          if (lane) lane.remove();
          return true;
        };

        async function onSelbarClick(e) {
          const btn = e.target.closest("button");
          if (!btn || btn.disabled) return;
          const op = btn.dataset.op;

          if (op === "off") { clip = null; stopPicking(); return; }

          if (op === "copy" || op === "cut") {
            clip = { mode: op === "copy" ? "copy" : "move", ids: [...picked] };
            picking = false;
            picked.clear();
            paintPicks();
            toast(clip.mode === "copy" ? "Скопировано в буфер — открой папку и вставь"
                                       : "Взято на перенос — открой папку и вставь");
            return;
          }

          if (op === "paste") {
            const job = clip;
            if (!job) return;
            await runOp(job.mode, job.ids, parent,
                        job.mode === "copy" ? "Копирую" : "Переношу");
            // Перенос буфер опустошает: то же самое второй раз уже не вставить.
            if (job.mode === "move") clip = null;
            paintPicks();
            load();
            return;
          }

          if (op === "del") {
            const n = picked.size;
            if (!confirm("Удалить " + n + " " + plural(n, ["штуку", "штуки", "штук"]) +
                         "? Папки удалятся со всем содержимым.")) return;
            const ids = [...picked];
            stopPicking();
            await runOp("delete", ids, null, "Удаляю");
            load();
          }
        }

        // Долгий тык по строке — вход в режим. На мышке та же роль у правой
        // кнопки: держать её секунду никто не станет.
        let holdTimer = null, holdFrom = null, touching = false;
        const holdStart = (id, x, y) => {
          clearTimeout(holdTimer);
          holdFrom = { x, y };
          holdTimer = setTimeout(() => { holdTimer = null; if (!picking) startPicking(id); }, 420);
        };
        const holdStop = () => {
          clearTimeout(holdTimer);
          holdTimer = null;
          holdFrom = null;
          touching = false;
          document.querySelectorAll(".item.dragging, .item.drag-over")
            .forEach(r => r.classList.remove("dragging", "drag-over"));
        };

        $("items").addEventListener("touchstart", e => {
          touching = true;
          const row = e.target.closest(".item");
          if (!row || picking) return;
          if (e.target.closest("[data-act]")) return;     // кнопки строки не трогаем
          holdStart(row.dataset.id, e.touches[0].clientX, e.touches[0].clientY);
        }, { passive: true });
        $("items").addEventListener("touchmove", e => {
          if (!holdFrom) return;
          const t = e.touches[0];
          // Уехал пальцем — значит листает, а не держит
          if (Math.abs(t.clientX - holdFrom.x) > 12 || Math.abs(t.clientY - holdFrom.y) > 12) holdStop();
        }, { passive: true });
        $("items").addEventListener("touchend", holdStop);
        $("items").addEventListener("touchcancel", holdStop);

        $("items").addEventListener("contextmenu", e => {
          const row = e.target.closest(".item");
          if (!row) return;
          e.preventDefault();
          if (picking) togglePick(row.dataset.id); else startPicking(row.dataset.id);
        });

        // Escape выходит из режима — привычка из проводника
        document.addEventListener("keydown", e => {
          if (e.key === "Escape" && (picking || clip)) { clip = null; stopPicking(); }
        });

        // ── Загрузка кусками ──
        const queue = [];
        let busy = false;

        const upRow = file => {
          const row = document.createElement("div");
          row.className = "up";
          row.innerHTML = `<div class="up-head"><span class="up-name">${esc(file.name)}</span><span class="up-pct">0%</span></div>
                           <div class="up-bar"><div class="up-fill"></div></div>`;
          $("uploads").appendChild(row);
          return row;
        };

        const sendOne = async (file, row) => {
          const pctEl = row.querySelector(".up-pct");
          const fillEl = row.querySelector(".up-fill");
          const init = await api("/api/drop/upload/init", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: file.name, size: file.size, parent,
                                   content_type: file.type || "application/octet-stream" }),
          });
          let offset = 0;
          while (offset < file.size) {
            const piece = file.slice(offset, offset + CHUNK);
            let done = false;
            for (let attempt = 0; attempt < 4 && !done; attempt++) {
              try {
                const response = await fetch(
                  "/api/drop/upload/chunk/" + init.upload_id + "?offset=" + offset,
                  { method: "POST", credentials: "same-origin", body: piece });
                const data = await response.json();
                if (response.status === 409) { offset = data.expected; done = true; break; }
                if (!response.ok) throw new Error(data.error || "сбой куска");
                offset = data.received;
                done = true;
              } catch (err) {
                if (attempt === 3) throw err;
                await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
              }
            }
            const pct = Math.round((offset / file.size) * 100);
            pctEl.textContent = pct + "%";
            fillEl.style.width = pct + "%";
          }
          await api("/api/drop/upload/finish/" + init.upload_id, { method: "POST" });
        };

        const pump = async () => {
          if (busy) return;
          busy = true;
          while (queue.length) {
            const file = queue.shift();
            const row = upRow(file);
            try {
              await sendOne(file, row);
              row.remove();
            } catch (e) {
              row.classList.add("failed");
              row.querySelector(".up-pct").textContent = e.message;
              setTimeout(() => row.remove(), 6000);
            }
          }
          busy = false;
          load();
        };

        const enqueue = files => {
          const list = Array.from(files || []).filter(f => f.size > 0);
          if (!list.length) return;
          list.forEach(f => queue.push(f));
          pump();
        };

        // ── Ввод ──
        $("pick").addEventListener("click", () => $("file-input").click());
        $("file-input").addEventListener("change", e => { enqueue(e.target.files); e.target.value = ""; });

        let dragDepth = 0;
        document.addEventListener("dragenter", e => {
          if (!e.dataTransfer.types.includes("Files")) return;
          dragDepth++; $("veil").hidden = false;
        });
        document.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("veil").hidden = true; } });
        document.addEventListener("dragover", e => { if (e.dataTransfer.types.includes("Files")) e.preventDefault(); });
        document.addEventListener("drop", e => {
          if (!e.dataTransfer.files.length) return;
          e.preventDefault(); dragDepth = 0; $("veil").hidden = true;
          enqueue(e.dataTransfer.files);
        });

        // Снимок экрана (Win+Shift+S) кладётся в буфер картинкой, но в
        // clipboardData.files её может не оказаться — Chrome отдаёт её только
        // через items[].getAsFile(). Из-за этого Ctrl+V молчал на картинке,
        // хотя текст вставлялся. Смотрим оба места.
        const clipFiles = data => {
          const out = [];
          const seen = new Set();
          Array.from(data.files || []).forEach(f => { out.push(f); seen.add(f.name + f.size); });
          Array.from(data.items || []).forEach(it => {
            if (it.kind !== "file" || !it.type.startsWith("image/")) return;
            const f = it.getAsFile();
            if (f && !seen.has(f.name + f.size)) out.push(f);
          });
          // Имя у снимка пустое или generic — даём своё, по времени
          return out.map(f => {
            if (f.name && f.name !== "image.png") return f;
            const ext = (f.type.split("/")[1] || "png").split("+")[0];
            const t = new Date();
            const pad = n => String(n).padStart(2, "0");
            const stamp = t.getFullYear() + "-" + pad(t.getMonth() + 1) + "-" + pad(t.getDate()) +
                          "-" + pad(t.getHours()) + pad(t.getMinutes()) + pad(t.getSeconds());
            return new File([f], "снимок-" + stamp + "." + ext, { type: f.type });
          });
        };

        document.addEventListener("paste", e => {
          const files = clipFiles(e.clipboardData);
          if (files.length) {
            // Картинка идёт файлом всегда, даже если курсор стоит в поле
            // текста: в текстовое поле её всё равно не вставить.
            e.preventDefault();
            enqueue(files);
            toast(files.length > 1 ? "Вставлено " + files.length + " файла" : "Картинка из буфера");
            return;
          }
          if (document.activeElement === $("text-area")) return;
          const text = (e.clipboardData.getData("text/plain") || "").trim();
          if (text) {
            // Текст кладём в поле заметки — оттуда его отправляют как .txt
            e.preventDefault();
            $("text-area").value = text;
            $("text-area").focus();
            toast("Текст вставлен — проверь и отправь");
          }
        });

        // Кнопка «Из буфера»: на телефоне это обход кривого выбора файлов —
        // скопировал картинку в любом приложении и нажал сюда.
        $("from-clip").addEventListener("click", async () => {
          if (!navigator.clipboard || !navigator.clipboard.read) {
            toast("Браузер не отдаёт буфер. Нажми Ctrl+V прямо на странице", true);
            return;
          }
          try {
            const entries = await navigator.clipboard.read();
            const files = [];
            let plain = "";
            for (const entry of entries) {
              const imageType = entry.types.find(t => t.startsWith("image/"));
              if (imageType) {
                const blob = await entry.getType(imageType);
                const ext = imageType.split("/")[1].split("+")[0];
                const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
                files.push(new File([blob], `буфер-${stamp}.${ext}`, { type: imageType }));
              } else if (entry.types.includes("text/plain")) {
                plain = await (await entry.getType("text/plain")).text();
              }
            }
            if (files.length) { enqueue(files); toast("Загружаю из буфера"); return; }
            if (plain.trim()) { $("text-area").value = plain; toast("Текст вставлен — проверь и отправь"); return; }
            toast("В буфере ничего подходящего", true);
          } catch (err) {
            // Чтение буфера кнопкой браузер разрешает не всегда. Ctrl+V
            // работает без всяких разрешений — на него и отправляем.
            toast("Браузер не дал прочитать буфер. Нажми Ctrl+V прямо на странице", true);
          }
        });

        // Приём «Поделиться»: обработчик в браузере складывает файлы в кэш,
        // забираем их отсюда и грузим обычным путём — с прогрессом и куками.
        const collectShared = async () => {
          if (!("caches" in window) || !location.search.includes("shared=1")) return;
          try {
            const cache = await caches.open("share-inbox");
            const keys = await cache.keys();
            const files = [];
            for (const key of keys) {
              const response = await cache.match(key);
              await cache.delete(key);
              if (!response) continue;
              if (new URL(key.url).pathname === "/__shared-text") {
                const text = await response.text();
                if (text.trim()) $("text-area").value = text;
                continue;
              }
              const name = decodeURIComponent(response.headers.get("X-Name") || "файл");
              const type = response.headers.get("X-Type") || "application/octet-stream";
              files.push(new File([await response.blob()], name, { type }));
            }
            history.replaceState({}, "", "/drop");
            if (files.length) { enqueue(files); toast("Принято из «Поделиться»"); }
          } catch (e) {}
        };

        if ("serviceWorker" in navigator) {
          navigator.serviceWorker.register("/sw.js").catch(() => {});
        }

        $("mkdir").addEventListener("click", async () => {
          const name = prompt("Название папки");
          if (!name || !name.trim()) return;
          try { await api("/api/drop/folder", { method: "POST", headers: { "Content-Type": "application/json" },
                                                body: JSON.stringify({ name, parent }) }); load(); }
          catch (e) { toast(e.message, true); }
        });

        const sendText = async () => {
          const text = $("text-area").value;
          if (!text.trim()) return;
          try {
            await api("/api/drop/text", { method: "POST", headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({ text, parent }) });
            $("text-area").value = "";
            load();
          } catch (e) { toast(e.message, true); }
        };
        $("send-text").addEventListener("click", sendText);
        $("text-area").addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) sendText(); });

        $("search").addEventListener("input", render);
        // Раньше кнопка просто переключала «новые ⇄ старые». Теперь она
        // роняет меню со всеми порядками, а выбор запоминается.
        $("sort").addEventListener("click", e => {
          e.stopPropagation();
          const old = document.querySelector(".sort-menu");
          if (old) { old.remove(); return; }
          const menu = document.createElement("div");
          menu.className = "sort-menu";
          menu.innerHTML = Object.keys(SORTS).map(k =>
            `<button type="button" data-sort="${k}"${k === sortKey ? ' class="on"' : ""}>${
              SORTS[k][0]}</button>`).join("");
          $("sort").parentNode.appendChild(menu);
          menu.addEventListener("click", ev => {
            const btn = ev.target.closest("button");
            if (!btn) return;
            sortKey = btn.dataset.sort;
            localStorage.setItem("vitaz-drop-sort", sortKey);
            menu.remove();
            render();
          });
        });
        document.addEventListener("click", () => {
          const menu = document.querySelector(".sort-menu");
          if (menu) menu.remove();
        });

        $("crumbs").addEventListener("click", e => {
          const btn = e.target.closest(".crumb");
          if (!btn || btn.classList.contains("here")) return;
          parent = btn.dataset.go || null;
          expanded.clear();
          load();
        });

        // ── Перетаскивание элементов в папки ──
        let dragId = null;
        $("items").addEventListener("dragstart", e => {
          const row = e.target.closest(".item");
          if (!row) return;
          // На касаниях встроенное перетаскивание браузера только мешает:
          // работать оно всё равно не работает, а строку глушит до 40%
          // прозрачности и обратно не возвращает — события конца нет.
          if (touching) { e.preventDefault(); return; }
          dragId = row.dataset.id;
          row.classList.add("dragging");
          e.dataTransfer.effectAllowed = "move";
          e.dataTransfer.setData("text/plain", dragId);
        });
        $("items").addEventListener("dragend", e => {
          dragId = null;
          document.querySelectorAll(".item").forEach(r => r.classList.remove("dragging", "drag-over"));
        });
        $("items").addEventListener("dragover", e => {
          const row = e.target.closest(".item.folder");
          if (!row || !dragId || row.dataset.id === dragId) return;
          e.preventDefault();
          row.classList.add("drag-over");
        });
        $("items").addEventListener("dragleave", e => {
          const row = e.target.closest(".item");
          if (row) row.classList.remove("drag-over");
        });
        $("items").addEventListener("drop", async e => {
          const row = e.target.closest(".item.folder");
          if (!row || !dragId || row.dataset.id === dragId) return;
          e.preventDefault();
          e.stopPropagation();
          const target = row.dataset.id;
          // Тащат отмеченную строку — переносим всю пачку разом, как в
          // проводнике. Тащат постороннюю — только её одну.
          const bunch = picked.has(dragId) ? [...picked] : [dragId];
          dragId = null;
          if (bunch.includes(target)) { toast("Папка не может лежать в себе самой", true); return; }
          stopPicking();
          await runOp("move", bunch, target, "Переношу");
          load();
        });

        // ── Действия над элементами ──
        $("items").addEventListener("click", async e => {
          const row = e.target.closest(".item");
          if (!row) return;
          const id = row.dataset.id;
          const item = items.find(i => i.id === id);
          // closest, а не сам e.target: у значка папки внутри лежит svg,
          // и щелчок прилетает из его path — без подъёма вверх действие
          // терялось и вместо окна открывалась сама папка.
          const hit = e.target.closest("[data-act]");
          const act = hit && row.contains(hit) ? hit.dataset.act : null;

          // В режиме выделения строка целиком работает галкой: ни папки не
          // открываются, ни кнопки строки не срабатывают.
          if (picking) { togglePick(id); return; }

          if (!act) {
            if (item && item.kind === "folder") { parent = id; expanded.clear(); load(); }
            return;
          }

          if (act === "dl") { window.location.assign("/api/drop/download/" + id); return; }

          if (act === "icon") { folderCard(item); return; }

          if (act === "view") {
            openImage(item);
            return;
          }

          if (act === "edit") {
            const box = row.querySelector(".txt");
            if (!box || box.dataset.editing) return;
            box.dataset.editing = "1";
            let full = "";
            try {
              // Показываем всегда полный текст, а не обрезанный предпросмотр:
              // сохранить кусок вместо целого было бы потерей данных.
              const data = await api("/api/drop/text/" + id);
              full = data.text;
            } catch (err) { toast(err.message, true); delete box.dataset.editing; return; }
            box.innerHTML = "";
            const area = document.createElement("textarea");
            area.className = "txt-area";
            area.value = full;
            const bar = document.createElement("div");
            bar.className = "txt-bar";
            const ok = document.createElement("button");
            ok.className = "go"; ok.textContent = "СОХРАНИТЬ";
            const no = document.createElement("button");
            no.textContent = "ОТМЕНА";
            bar.append(ok, no);
            box.append(area, bar);
            area.focus();
            const stop = ev => ev.stopPropagation();
            box.addEventListener("click", stop);
            no.addEventListener("click", () => { delete box.dataset.editing; load(); });
            ok.addEventListener("click", async () => {
              const text = area.value;
              if (!text.trim()) { toast("Текст пустой", true); return; }
              ok.disabled = true;
              try {
                await api("/api/drop/text/" + id, { method: "PUT",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ text }) });
                toast("Сохранено");
              } catch (err) { toast(err.message, true); ok.disabled = false; return; }
              delete box.dataset.editing;
              expanded.delete(id);
              load();
            });
            // Ctrl+Enter — сохранить, Escape — отменить: руки со сборки текста
            // убирать не хочется.
            area.addEventListener("keydown", ev => {
              if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); ok.click(); }
              if (ev.key === "Escape") { ev.preventDefault(); no.click(); }
            });
            return;
          }

          if (act === "more") {
            if (expanded.has(id)) { expanded.delete(id); render(); return; }
            try {
              const data = await api("/api/drop/text/" + id);
              item.full = data.text;
              expanded.add(id);
              render();
            } catch (err) { toast(err.message, true); }
            return;
          }

          if (act === "copy") {
            try {
              const data = await api("/api/drop/text/" + id);
              await navigator.clipboard.writeText(data.text);
              toast("Текст скопирован");
            } catch { toast("Не удалось скопировать", true); }
            return;
          }

          if (act === "share") {
            // Ссылка уже есть — показываем её и даём выбор: скопировать
            // ещё раз или отозвать.
            if (item.share) { linkMenu(item); return; }
            const choice = await askShare();
            if (!choice) return;
            try {
              const data = await api("/api/drop/share/" + id, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify(choice) });
              const life = data.forever ? "без срока" : "живёт " + data.hours + " ч";
              try { await navigator.clipboard.writeText(data.url); toast("Ссылка скопирована, " + life); }
              catch { prompt("Ссылка (" + life + "):", data.url); }
              load();
            } catch (err) { toast(err.message, true); }
            return;
          }

          if (act === "del") {
            const what = item.kind === "folder"
              ? "Удалить папку «" + item.name + "» со всем содержимым?"
              : "Удалить «" + item.name + "»?";
            if (!confirm(what)) return;
            try { await api("/api/drop/" + id, { method: "DELETE" }); load(); }
            catch (err) { toast(err.message, true); }
            return;
          }

          if (act === "ren") {
            const nameEl = row.querySelector(".nm");
            // Правим только имя без расширения — менять его нельзя,
            // иначе файл перестаёт открываться. Но расширением считаем
            // лишь то, что на него похоже: точка, а за ней до восьми букв
            // или цифр без пробелов. Иначе имя вроде «1. Убрать датчики»
            // резалось по первой же точке, и правилась одна цифра.
            const m = item.kind === "folder" ? null : /^(.*)(\.[A-Za-z0-9]{1,8})$/.exec(item.name);
            const stem = m ? m[1] : item.name;
            const ext = m ? m[2] : "";
            const input = document.createElement("input");
            input.className = "rename";
            input.value = stem;
            input.maxLength = 120;
            if (ext) input.title = "Расширение " + ext + " останется прежним";
            nameEl.replaceWith(input);
            input.focus();
            input.select();
            let saving = false;
            const save = async () => {
              if (saving) return;
              saving = true;
              const name = input.value.trim() ? input.value.trim() + ext : "";
              if (name && name !== item.name) {
                try { await api("/api/drop/" + id, { method: "PATCH", headers: { "Content-Type": "application/json" },
                                                     body: JSON.stringify({ name }) }); }
                catch (err) { toast(err.message, true); }
              }
              load();
            };
            input.addEventListener("blur", save);
            input.addEventListener("keydown", ev => {
              if (ev.key === "Enter") input.blur();
              if (ev.key === "Escape") { saving = true; render(); }
            });
            input.addEventListener("click", ev => ev.stopPropagation());
          }
        });

        load();
        collectShared();
      })();
      </script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


@app.route("/")
def home():
    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Витрина сервисов vitazgio.ru">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
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
          padding: clamp(32px, 6vw, 76px) 0 12px;
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

        /* Не сетка, а лента: карточки одной ширины идут в строку и
           прокручиваются по кругу, как барабан. Ужимать их под число
           сервисов больше не нужно — добавится восьмой, просто станет
           на один оборот длиннее. Сама закольцовка живёт в скрипте. */
        .services {
          display: flex;
          gap: 14px;
          width: max-content;
          margin: 0 auto;
        }
        .service { flex: none; width: 264px; }

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
        .service--qb { --accent: #4fa8e8; --glow: rgba(79,168,232,.22); }
        /* Знак GitHub официально чёрно-белый; на тёмной подложке
           используется белый, поэтому и оттенок карточки светлый. */
        .service--github { --accent: #dfe6ee; --glow: rgba(223,230,238,.16); }
        .service--gitea { --accent: #609926; --glow: rgba(96,153,38,.24); }

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
        /* Адрес в одну строку: рвать его посреди слова нельзя, читается
           как ошибка. Если вдруг не влезет — обрежется многоточием. */
        .domain { display: block; color: var(--accent); font-size: .74rem; font-weight: 750;
                 letter-spacing: .08em; text-transform: uppercase;
                 white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Подпись прижата к самому левому нижнему углу окна. Раньше она
           жила в общей колонке шириной 1380px и на широком мониторе
           повисала в воздухе далеко от края — колонка-то по центру. */
        footer {
          width: 100%;
          display: flex;
          justify-content: flex-start;
          gap: 20px;
          margin: auto 0 0;
          padding: 28px 12px 0 clamp(12px, 1.4vw, 20px);
          color: #686f80;
          font-size: .82rem;
        }

        [hidden] { display: none !important; }

        /* ── Полка с кнопками аркады ────────────────────────────────────── */
        .arcade-bar {
          width: min(1380px, calc(100% - 40px));
          margin: clamp(26px, 4vw, 44px) auto 0;
        }
        .arcade-bar-line {
          display: flex; align-items: center; gap: 14px;
          color: #6b7590; font: 700 .68rem "Cascadia Code", Consolas, monospace;
          letter-spacing: .32em;
        }
        .arcade-bar-line::before, .arcade-bar-line::after {
          content: ""; flex: 1; height: 1px;
          background: linear-gradient(90deg, transparent, rgba(255,255,255,.14), transparent);
        }
        .arcade-picks {
          display: flex; justify-content: center; gap: 14px; margin-top: 16px;
        }
        .arcade-picks .pick { width: clamp(104px, 16vw, 132px); }
        .pick {
          --pc: #2de2ff;
          position: relative; display: grid; place-items: center;
          aspect-ratio: 1 / 1; padding: 14px; cursor: pointer; overflow: hidden;
          border: 1px solid rgba(255,255,255,.1); border-radius: 14px;
          background:
            repeating-linear-gradient(45deg, rgba(255,255,255,.015) 0 8px, transparent 8px 16px),
            linear-gradient(165deg, rgba(26,34,50,.95), rgba(9,13,20,.96));
          transition: transform .2s cubic-bezier(.2,.9,.3,1.3), border-color .2s, box-shadow .2s;
        }
        .pick-art { position: relative; z-index: 2; width: 68%; display: block; }
        .pick-art svg { width: 100%; height: auto; display: block;
                        filter: drop-shadow(0 3px 6px rgba(0,0,0,.6)); }
        /* мягкое пятно света под персонажем, разгорается при наведении */
        .pick-glow {
          position: absolute; z-index: 1; inset: auto 0 -40% 0; height: 80%;
          background: radial-gradient(ellipse at 50% 100%, var(--pc), transparent 68%);
          opacity: .1; transition: opacity .25s;
        }
        .pick::after {
          content: ""; position: absolute; inset: 0; z-index: 3; pointer-events: none;
          background: repeating-linear-gradient(180deg, rgba(0,0,0,.16) 0 2px, transparent 2px 4px);
          opacity: .35;
        }
        .pick:hover, .pick:focus-visible {
          transform: translateY(-5px);
          border-color: var(--pc); outline: none;
          box-shadow: 0 0 0 1px var(--pc), 0 16px 34px rgba(0,0,0,.5);
        }
        .pick:hover .pick-glow, .pick:focus-visible .pick-glow { opacity: .4; }
        .pick:active { transform: translateY(-1px) scale(.97); }

        .pick--cabinet { --pc: #2de2ff; }
        .pick--rack    { --pc: #2de2ff; }
        .pick--hero    { --pc: #5f9bff; }
        .pick--pad     { --pc: #63f5ad; }
        .pick--invader { --pc: #63f5ad; }
        .pick--coin    { --pc: #ffd84a; }
        .pick--cart    { --pc: #ff3fa4; }

        /* Каждый персонаж живёт по-своему: у автомата мерцает экран, у героя
           блестит меч, захватчик приплясывает, монета крутится. */
        .pick-art .px-blink { animation: pxBlink 2.2s steps(1) infinite; }
        @keyframes pxBlink { 0%, 82% { opacity: 1; } 86%, 100% { opacity: .25; } }
        .pick--cabinet .px-screen { animation: pxFlicker 3.4s ease-in-out infinite; }
        @keyframes pxFlicker { 0%, 100% { opacity: 1; } 47% { opacity: .72; } 51% { opacity: 1; } }
        .pick--hero .pick-art svg { animation: pxHop 1.9s ease-in-out infinite; }
        @keyframes pxHop { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-6%); } }
        .pick--hero .px-sword { animation: pxShine 2.6s ease-in-out infinite; }
        @keyframes pxShine { 0%, 70%, 100% { fill: #cbd6e4; } 80% { fill: #ffffff; } }
        .pick--invader .pick-art svg { animation: pxMarch 1.1s steps(2) infinite; }
        @keyframes pxMarch { 0% { transform: translateX(-6%); } 50% { transform: translateX(6%); } }
        .pick--coin .pick-art svg { animation: pxSpin 2.8s ease-in-out infinite; }
        @keyframes pxSpin { 0%, 100% { transform: scaleX(1); } 50% { transform: scaleX(.18); } }
        .pick--cart .pick-art svg { animation: pxSlot 3.2s ease-in-out infinite; }
        @keyframes pxSlot { 0%, 62%, 100% { transform: translateY(0); } 74% { transform: translateY(10%); } }
        .pick--pad .pick-art svg { animation: pxTilt 3s ease-in-out infinite; }
        @keyframes pxTilt { 0%, 100% { transform: rotate(-4deg); } 50% { transform: rotate(4deg); } }
        /* У стойки лампы моргают вразнобой: одинаковый такт выглядит мёртво. */
        .pick-art .px-blink2 { animation: pxBlink2 2.9s steps(1) infinite; }
        @keyframes pxBlink2 { 0%, 58% { opacity: 1; } 64%, 100% { opacity: .18; } }
        .pick-art .px-blink3 { animation: pxBlink3 1.3s steps(1) infinite; }
        @keyframes pxBlink3 { 0%, 44% { opacity: 1; } 51%, 100% { opacity: .28; } }

        @media (prefers-reduced-motion: reduce) {
          .pick-art svg, .pick-art .px-blink, .pick-art .px-blink2,
          .pick-art .px-blink3, .pick--cabinet .px-screen { animation: none; }
        }

        .auth-modal {
          position: fixed;
          z-index: 100;
          inset: 0;
          display: grid;
          place-items: center;
          padding: 20px;
        }

        .auth-backdrop {
          position: absolute;
          inset: 0;
          background: rgba(3, 6, 13, .82);
          backdrop-filter: blur(12px);
        }

        .auth-panel {
          position: relative;
          width: min(430px, 100%);
          padding: 38px;
          color: #e8fbff;
          border: 1px solid rgba(45, 226, 255, .3);
          background: linear-gradient(145deg, rgba(16, 30, 47, .98), rgba(20, 16, 37, .98));
          clip-path: polygon(0 0, calc(100% - 22px) 0, 100% 22px, 100% 100%, 22px 100%, 0 calc(100% - 22px));
          box-shadow: 0 32px 100px rgba(0,0,0,.65), inset 0 0 40px rgba(45,226,255,.05);
        }

        .auth-kicker { color: #2de2ff; font: 700 .7rem/1 "Cascadia Code", Consolas, monospace; letter-spacing: .16em; text-transform: uppercase; }
        .auth-panel h2 { margin: 16px 0 8px; font: 800 clamp(2rem, 8vw, 3rem)/1 "Cascadia Code", Consolas, monospace; letter-spacing: -.07em; text-shadow: 2px 0 #ff3fa4, -2px 0 #2de2ff; }
        .auth-hint { margin: 0 0 26px; color: #8792a6; line-height: 1.55; }
        .auth-close { position: absolute; top: 15px; right: 17px; padding: 5px; color: #7d8799; font-size: 1.35rem; border: 0; background: none; cursor: pointer; }
        .auth-close:hover { color: #fff; }
        .auth-form label { display: block; margin-bottom: 9px; color: #b8c1d2; font-size: .78rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
        .auth-form input { width: 100%; height: 50px; padding: 0 15px; color: #f4fbff; font: 700 1rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.65); }
        .auth-form input:focus { border-color: #2de2ff; box-shadow: 0 0 0 3px rgba(45,226,255,.09); }
        .auth-submit { width: 100%; height: 50px; margin-top: 14px; color: #071018; font: 800 .82rem "Cascadia Code", Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #2de2ff, #65f2bd); cursor: pointer; }
        .auth-submit:hover { filter: brightness(1.08); }
        .auth-submit:disabled { opacity: .55; cursor: wait; }
        .auth-error { min-height: 20px; margin: 12px 0 0; color: #ff6ba8; font-size: .8rem; }
        body.modal-open { overflow: hidden; }

        @media (max-width: 700px) {
          .page { justify-content: flex-start; }
          .hero { margin-bottom: 22px; }
          /* На узком экране размер, привязанный к ширине окна, схлопывался
             до упора: «DOMAIN CONTROL» становился мельче подписи под ним,
             хотя места в рамке оставалось на две таких строки. Здесь у
             надписей свои, более щедрые размеры; на широком экране всё
             остаётся как было. Потолок подобран по самой длинной из трёх
             строк — «VITAZGIO NETWORK», шестнадцать знаков. */
          .cyber-terminal { min-height: 112px; padding-inline: 12px; }
          .terminal-prompt { margin-right: .18em; font-size: clamp(1.6rem, 7.9vw, 2.7rem); }
          .cyber-text { letter-spacing: -.08em; font-size: clamp(1.6rem, 8.8vw, 2.9rem); }
          .eyebrow { margin-bottom: 18px; font-size: .95rem; letter-spacing: .12em; }
          .eyebrow::before { width: 9px; height: 9px; }
          .arcade-bar-line { font-size: .86rem; letter-spacing: .26em; }
          footer { font-size: .95rem; }
          .service { width: 78vw; min-height: 280px; scroll-snap-align: center; }
          .services-wrap { scroll-snap-type: x mandatory; }
          footer { flex-direction: column; }
          .auth-panel { padding: 34px 25px 28px; }
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
              <div class="service-copy"><h2>Jellyfin</h2><p>Фильмы и сериалы</p><span class="domain">jel.vitazgio.ru</span></div>
            </a>

            <a class="service service--npm" href="https://npm.vitazgio.ru" aria-label="Открыть Nginx Proxy Manager">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/nginx-proxy-manager.svg" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Nginx Proxy</h2><p>Управление доменами и прокси</p><span class="domain">npm.vitazgio.ru</span></div>
            </a>

            <a class="service service--qb" href="https://qb.vitazgio.ru" aria-label="Открыть qBittorrent">
              <div class="service-top">
                <span class="logo" aria-hidden="true">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
                    <defs><linearGradient x1="34.012%" y1="0%" x2="76.373%" y2="76.805%" id="qb-grad"><stop stop-color="#72B4F5" offset="0%"/><stop stop-color="#356EBF" offset="100%"/></linearGradient></defs>
                    <g fill="none" fill-rule="evenodd">
                      <circle stroke="#DAEFFF" stroke-width="32" fill="url(#qb-grad)" cx="512" cy="512" r="496"/>
                      <path d="M712.898 332.399q66.657 0 103.38 45.671 37.03 45.364 37.03 128.684t-37.34 129.61q-37.03 45.98-103.07 45.98-33.02 0-60.484-12.035-27.156-12.344-45.672-37.649h-3.703l-10.8 43.512h-36.724V196h51.227v116.65q0 39.191-2.469 70.359h2.47q35.796-50.61 106.155-50.61zm-7.406 42.894q-52.46 0-75.605 30.242-23.145 29.934-23.145 101.219t23.762 102.145q23.761 30.55 76.222 30.55 47.215 0 70.36-34.254 23.144-34.562 23.144-99.058 0-66.04-23.144-98.442-23.145-32.402-71.594-32.402z" fill="#fff"/>
                      <path d="M317.273 639.45q51.227 0 74.68-27.466 23.453-27.464 24.996-92.578v-11.418q0-70.976-24.07-102.144-24.07-31.168-76.223-31.168-45.055 0-69.125 35.18-23.762 34.87-23.762 98.75 0 63.879 23.454 97.515 23.761 33.328 70.05 33.328zm-7.715 42.894q-65.421 0-102.144-45.98-36.723-45.981-36.723-128.376 0-83.011 37.032-129.609 37.03-46.598 103.07-46.598 69.433 0 106.773 52.461h2.778l7.406-46.289h40.426V828h-51.227V683.27q0-30.86 3.395-52.461h-4.012q-35.488 51.535-106.774 51.535z" fill="#c8e8ff"/>
                    </g>
                  </svg>
                </span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>qBittorrent</h2><p>Веб-интерфейс торрент-клиента</p><span class="domain">qb.vitazgio.ru</span></div>
            </a>

            <a class="service service--github" href="https://github.com/VITAZGIO"
               target="_blank" rel="noopener" aria-label="Открыть GitHub">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>GitHub</h2><p>Исходники проектов и история правок</p><span class="domain">github.com</span></div>
            </a>

            <a class="service service--gitea" href="https://git.vitazgio.ru"
               target="_blank" rel="noopener" aria-label="Открыть Gitea">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4.209 4.603c-.247 0-.525.02-.84.088-.333.07-1.28.283-2.054 1.027C-.403 7.25.035 9.685.089 10.052c.065.446.263 1.687 1.21 2.768 1.749 2.141 5.513 2.092 5.513 2.092s.462 1.103 1.168 2.119c.955 1.263 1.936 2.248 2.89 2.367 2.406 0 7.212-.004 7.212-.004s.458.004 1.08-.394c.535-.324 1.013-.893 1.013-.893s.492-.527 1.18-1.73c.21-.37.385-.729.538-1.068 0 0 2.107-4.471 2.107-8.823-.042-1.318-.367-1.55-.443-1.627-.156-.156-.366-.153-.366-.153s-4.475.252-6.792.306c-.508.011-1.012.023-1.512.027v4.474l-.634-.301c0-1.39-.004-4.17-.004-4.17-1.107.016-3.405-.084-3.405-.084s-5.399-.27-5.987-.324c-.187-.011-.401-.032-.648-.032zm.354 1.832h.111s.271 2.269.6 3.597C5.549 11.147 6.22 13 6.22 13s-.996-.119-1.641-.348c-.99-.324-1.409-.714-1.409-.714s-.73-.511-1.096-1.52C1.444 8.73 2.021 7.7 2.021 7.7s.32-.859 1.47-1.145c.395-.106.863-.12 1.072-.12zm8.33 2.554c.26.003.509.127.509.127l.868.422-.529 1.075a.686.686 0 0 0-.614.359.685.685 0 0 0 .072.756l-.939 1.924a.69.69 0 0 0-.66.527.687.687 0 0 0 .347.763.686.686 0 0 0 .867-.206.688.688 0 0 0-.069-.882l.916-1.874a.667.667 0 0 0 .237-.02.657.657 0 0 0 .271-.137 8.826 8.826 0 0 1 1.016.512.761.761 0 0 1 .286.282c.073.21-.073.569-.073.569-.087.29-.702 1.55-.702 1.55a.692.692 0 0 0-.676.477.681.681 0 1 0 1.157-.252c.073-.141.141-.282.214-.431.19-.397.515-1.16.515-1.16.035-.066.218-.394.103-.814-.095-.435-.48-.638-.48-.638-.467-.301-1.116-.58-1.116-.58s0-.156-.042-.27a.688.688 0 0 0-.148-.241l.516-1.062 2.89 1.401s.48.218.583.619c.073.282-.019.534-.069.657-.24.587-2.1 4.317-2.1 4.317s-.232.554-.748.588a1.065 1.065 0 0 1-.393-.045l-.202-.08-4.31-2.1s-.417-.218-.49-.596c-.083-.31.104-.691.104-.691l2.073-4.272s.183-.37.466-.497a.855.855 0 0 1 .35-.077z"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Gitea</h2><p>Свой git на домашнем сервере</p><span class="domain">git.vitazgio.ru</span></div>
            </a>
          </div>
        </nav>

        <!-- Полка с двумя кнопками: стойка ведёт в кабинет, геймпад — в игры.
             Обе без единой буквы: подпись даёт aria-label и всплывающая
             подсказка, а глазу хватает пиксельного значка. -->
        <section class="arcade-bar" aria-label="Рубка">
          <div class="arcade-bar-line"><span>РУБКА</span></div>
          <div class="arcade-picks">
            <button class="pick pick--pad" type="button" data-games
                    title="Игры" aria-label="Открыть игры">
              <span class="pick-art">__ICON_PAD__</span>
              <span class="pick-glow"></span>
            </button>
            <button class="pick pick--rack" type="button" id="cabinet-pick"
                    title="Личный кабинет" aria-label="Открыть личный кабинет">
              <span class="pick-art">__ICON_RACK__</span>
              <span class="pick-glow"></span>
            </button>
          </div>
        </section>

        <footer><span>@Vitaz Gio · Основан 2:12 04.05.2026</span></footer>
      </main>
      <div id="auth-modal" class="auth-modal" hidden>
        <div class="auth-backdrop" data-auth-close></div>
        <section class="auth-panel" role="dialog" aria-modal="true" aria-labelledby="auth-title">
          <button class="auth-close" type="button" data-auth-close aria-label="Закрыть">×</button>
          <div class="auth-kicker">Restricted area // 01</div>
          <h2 id="auth-title">Авторизация</h2>
          <p class="auth-hint">Введите пароль для доступа к личному кабинету.</p>
          <form id="auth-form" class="auth-form">
            <label for="auth-password">Пароль</label>
            <input id="auth-password" name="password" type="password" autocomplete="current-password" required>
            <button class="auth-submit" type="submit">Получить доступ</button>
            <p id="auth-error" class="auth-error" role="alert"></p>
          </form>
        </section>
      </div>
      <script>
        /* Лента сервисов крутится по кругу, как барабан: докрутил до конца —
           и снова пошли первые карточки, без упора в край.

           Делается это подменой: рядом с настоящим набором лежат две его
           копии, слева и справа. Пока смотришь на середину — всё честно.
           Как только уехал на копию, прокрутка перескакивает на ровно одну
           длину набора назад или вперёд. Картинка при этом не меняется —
           карточки-то те же, — поэтому глазу перескок не виден.

           Копии закрыты от чтения с экрана и от перехода табом: ссылки в
           них те же самые, и без этого каждая читалась бы трижды. */
        (() => {
          const wrap = document.querySelector(".services-wrap");
          const row = document.querySelector(".services");
          if (!wrap || !row) return;

          const GAP = 14;
          const originals = Array.prototype.slice.call(row.children);
          let clones = [];
          let setWidth = 0;
          let looping = false;

          const measure = () => originals.reduce(
            (sum, card) => sum + card.getBoundingClientRect().width + GAP, 0);

          const makeCopy = () => {
            const copy = document.createDocumentFragment();
            originals.forEach((card) => {
              const twin = card.cloneNode(true);
              twin.setAttribute("aria-hidden", "true");
              twin.setAttribute("tabindex", "-1");
              twin.dataset.twin = "1";
              copy.appendChild(twin);
              clones.push(twin);
            });
            return copy;
          };

          const dropCopies = () => {
            clones.forEach((twin) => twin.remove());
            clones = [];
          };

          const wrapAround = () => {
            if (!looping) return;
            const x = wrap.scrollLeft;
            // Порог в половину набора: перескакиваем задолго до края, иначе
            // на резком рывке палец успевает доехать до самого конца ленты.
            if (x < setWidth * 0.5) wrap.scrollLeft = x + setWidth;
            else if (x > setWidth * 1.5) wrap.scrollLeft = x - setWidth;
          };

          const build = () => {
            dropCopies();
            looping = false;
            setWidth = measure();
            // Влезло ли — спрашиваем у самой прокрутки. Считать по ширине
            // блока нельзя: по бокам у него широкие поля, и лента в 1736
            // пикселей на мониторе 1920 выглядела бы помещающейся, хотя
            // видно от неё только 1380.
            if (wrap.scrollWidth <= wrap.clientWidth + 1) { wrap.scrollLeft = 0; return; }
            row.insertBefore(makeCopy(), row.firstChild);
            row.appendChild(makeCopy());
            looping = true;
            wrap.scrollLeft = setWidth;          // встаём на настоящий набор
          };

          build();
          wrap.addEventListener("scroll", wrapAround, { passive: true });

          // Ширина карточек на телефоне задана в долях экрана, так что при
          // повороте набор меняет длину — пересобираем.
          let resizeTimer = 0;
          window.addEventListener("resize", () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(build, 180);
          });
        })();

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

        (() => {
          const trigger = document.getElementById("cabinet-pick");
          const modal = document.getElementById("auth-modal");
          const form = document.getElementById("auth-form");
          const password = document.getElementById("auth-password");
          const error = document.getElementById("auth-error");
          const submit = form.querySelector("button[type='submit']");

          const openModal = () => {
            modal.hidden = false;
            document.body.classList.add("modal-open");
            error.textContent = "";
            requestAnimationFrame(() => password.focus());
          };

          const closeModal = () => {
            modal.hidden = true;
            document.body.classList.remove("modal-open");
            form.reset();
            error.textContent = "";
            trigger.focus();
          };

          // Помнит — сразу в кабинет, не помнит — просим пароль.
          trigger.addEventListener("click", async () => {
            try {
              const response = await fetch("/api/session/probe", { credentials: "same-origin" });
              const result = await response.json();
              if (result.trusted) {
                window.location.assign("/cabinet");
                return;
              }
            } catch {}
            openModal();
          });
          modal.querySelectorAll("[data-auth-close]").forEach((element) => element.addEventListener("click", closeModal));
          document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && !modal.hidden) closeModal();
          });

          form.addEventListener("submit", async (event) => {
            event.preventDefault();
            error.textContent = "";
            submit.disabled = true;
            try {
              const response = await fetch("/api/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: password.value }),
              });
              const result = await response.json();
              if (!response.ok) {
                error.textContent = result.error || "Не удалось выполнить вход.";
                password.select();
                return;
              }
              window.location.assign(result.redirect);
            } catch {
              error.textContent = "Сервер недоступен. Повторите попытку.";
            } finally {
              submit.disabled = false;
            }
          });
        })();

        // Service worker регистрируем и здесь: приложение стартует с главной,
        // и без него запасная страница с лисой в офлайне просто не покажется.
        if ("serviceWorker" in navigator) {
          navigator.serviceWorker.register("/sw.js").catch(() => {});
        }

        // ── Игры: кнопки на полке ARCADE и код Konami ──
        // Сама аркада живёт в /static/games/ и подгружается только по требованию:
        // на обычном заходе на витрину эти килобайты никто не качает.
        (() => {
          let pending = null;
          const openArcade = (game) => {
            if (window.VitazArcade) { window.VitazArcade.open(game); return; }
            if (pending) return;
            pending = document.createElement("script");
            pending.src = "/static/games/arcade.js";
            pending.onload = () => { pending = null; window.VitazArcade.open(game); };
            pending.onerror = () => { pending = null; };
            document.head.appendChild(pending);
          };

          document.querySelectorAll("[data-games]").forEach(btn => {
            btn.addEventListener("click", () => openArcade());
          });

          // Пасхалка осталась прежней, только теперь ведёт сразу в змейку.
          const SEQ = ["ArrowUp","ArrowUp","ArrowDown","ArrowDown","ArrowLeft","ArrowRight","ArrowLeft","ArrowRight","b","a"];
          let pos = 0;
          document.addEventListener("keydown", e => {
            if (e.key === SEQ[pos]) { pos++; if (pos === SEQ.length) { pos = 0; openArcade("snake"); } }
            else { pos = e.key === SEQ[0] ? 1 : 0; }
          });
        })();
      </script>
    </body>
    </html>
    """
    for name, svg in _GAME_ICONS.items():
        html = html.replace("__ICON_%s__" % name.upper(), svg)
    html = html.replace("__ICONLINKS__", ICON_LINKS)
    return html


if __name__ == "__main__":
    # На домашнем сервере (за NAT) слушаем все интерфейсы. На VPS с публичным
    # адресом ставим BIND_HOST=127.0.0.1, чтобы снаружи можно было попасть
    # только через реверс-прокси, а не напрямую по IP без TLS.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=5000, threaded=True)
