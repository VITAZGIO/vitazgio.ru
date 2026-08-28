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
import shlex
import shutil
import tempfile
import socket
import subprocess
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

import paramiko
from flask import Flask, Response, g, jsonify, redirect, request, send_file, session, url_for
from markupsafe import escape
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
# Особая папка «MUSIK»: всегда внизу списка, удалить нельзя. Что кинешь в
# неё (треки или папки с треками) — попадает в плеер. Живёт под своим
# постоянным id, чтобы переживать перезапуски.
DROP_MUSIK_ID = "musik"
DROP_AUDIO_EXTS = {".mp3", ".ogg", ".wav", ".m4a", ".opus", ".flac", ".aac"}

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
    "video", "work", "trash", "game",
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
        # Удалённое (в корзине) в счёт живой папки не идёт — оно считается
        # отдельно, как содержимое корзины.
        if node.get("deleted"):
            continue
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


# ---- Корзина -------------------------------------------------------------
# Удалённое не стирается сразу, а уезжает в корзину: метка `deleted` со
# временем. Место оно продолжает занимать (входит в «Занято»), само чистится
# через месяц, а до того его можно вернуть или снести вручную по паролю.
DROP_TRASH_TTL = 30 * 24 * 3600
# Пароль корзины хранится хешем — plaintext в исходник не кладём.
# sha256("1224"); пароль простой, это защёлка «как в Windows», не броня.
DROP_TRASH_PASS_HASH = "0d866ba9f9fd0f2cbb2134daf52356d2021a3686352d5c19d967305bf9e4bbdc"


def _drop_trash(item_id, when=None):
    """Отправляет элемент в корзину. Для папки метку ставим только на неё —
    содержимое уезжает вместе, но своих меток не получает. Особую папку MUSIK
    не трогаем. Под drop_lock."""
    if item_id == DROP_MUSIK_ID:
        return
    item = drop_items.get(item_id)
    if item and item.get("special"):
        return
    if item and not item.get("deleted"):
        item["deleted"] = when or time.time()


def _drop_has_deleted_ancestor(item_id):
    """Лежит ли элемент внутри уже удалённой папки. Под drop_lock."""
    seen = set()
    parent = drop_items.get(item_id, {}).get("parent")
    while parent and parent in drop_items and parent not in seen:
        seen.add(parent)
        if drop_items[parent].get("deleted"):
            return True
        parent = drop_items[parent].get("parent")
    return False


def _drop_trash_roots():
    """Корни удалённых поддеревьев — то, что показываем в корзине списком.
    Вложенное в удалённую папку отдельной строкой не выводим. Под drop_lock."""
    return [k for k, v in drop_items.items()
            if v.get("deleted") and not _drop_has_deleted_ancestor(k)]


def _drop_trash_bytes(memo=None):
    """Сколько всего занимает корзина. Под drop_lock."""
    memo = {} if memo is None else memo
    total = 0
    for root in _drop_trash_roots():
        item = drop_items[root]
        if item["kind"] == "folder":
            total += _drop_trash_subtree_bytes(root)
        else:
            total += item.get("size", 0)
    return total


def _drop_trash_subtree_bytes(item_id):
    """Вес удалённой папки со всем, что внутри (живое обычным подсчётом уже
    пропускает удалённое, поэтому считаем отдельно). Под drop_lock."""
    total = 0
    for child in _drop_children(item_id):
        node = drop_items[child]
        if node["kind"] == "folder":
            total += _drop_trash_subtree_bytes(child)
        else:
            total += node.get("size", 0)
    return total


def _drop_sweep_trash():
    """Выносит из корзины то, что пролежало дольше месяца. Под drop_lock."""
    now = time.time()
    for root in _drop_trash_roots():
        if now - (drop_items[root].get("deleted") or 0) > DROP_TRASH_TTL:
            _drop_discard(root)


def _drop_trash_ok(password):
    got = hashlib.sha256((password or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(got, DROP_TRASH_PASS_HASH)


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
        meta.setdefault("deleted", None)
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
    _drop_ensure_musik()         # особая папка MUSIK всегда на месте
    _drop_sweep_trash()          # что пролежало в корзине дольше месяца — вон
    _drop_write_index()


def _drop_ensure_musik():
    """Заводит (или чинит) особую папку MUSIK в корне. Под drop_lock либо на
    старте до потоков."""
    m = drop_items.get(DROP_MUSIK_ID)
    if not m or m.get("kind") != "folder":
        drop_items[DROP_MUSIK_ID] = {
            "kind": "folder", "name": "MUSIK", "parent": None, "share": None,
            "size": 0, "deleted": None, "icon": "music", "special": True,
            "created": time.time(),
        }
    else:
        m["parent"] = None            # всегда в корне
        m["deleted"] = None           # в корзину не уходит
        m["special"] = True
        m.setdefault("icon", "music")


def _drop_musik_tracks():
    """Аудиофайлы внутри папки MUSIK (вглубь по подпапкам) — для плеера.
    Каждый со своим адресом потока. Под drop_lock."""
    out = []

    def walk(parent, label):
        kids = [(k, v) for k, v in drop_items.items()
                if v.get("parent") == parent and not v.get("deleted")]
        kids.sort(key=lambda kv: kv[1]["name"].lower())
        for k, v in kids:
            if v["kind"] == "folder":
                walk(k, (label + " / " if label else "") + v["name"])
            elif v["kind"] == "file":
                if os.path.splitext(v["name"])[1].lower() in DROP_AUDIO_EXTS:
                    out.append({
                        "id": "d_" + k,
                        "title": os.path.splitext(v["name"])[0],
                        "artist": "", "folder": label,
                        "url": "/api/drop/view/" + k,
                    })

    walk(DROP_MUSIK_ID, "")
    return out


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

# ---- Музыка ----------------------------------------------------------------
# Файлы лежат под своими именами в data/music — так их можно просто закинуть
# в папку по SSH, и плеер подхватит сам, разобрав «Исполнитель - Название».
#
# Записей может быть больше, чем файлов: один и тот же трек нередко нужен в
# нескольких папках — в «Роке» и в «Любимом». Хранить его дважды глупо,
# поэтому запись — это ссылка на файл, а файл удаляется, когда на него не
# осталось ни одной ссылки. Одинаковость определяем по содержимому, а не по
# имени: два файла с разными названиями, но одинаковыми байтами — один трек.
MUSIC_DIR = os.path.join(DATA_DIR, "music")
MUSIC_INDEX_PATH = os.path.join(DATA_DIR, "music.json")
MUSIC_MAX_SIZE = 40 * 1024 * 1024
MUSIC_QUOTA = 2 * 1024 * 1024 * 1024
MUSIC_CHUNK = 1024 * 1024
MUSIC_MAX_DEPTH = 6
MUSIC_EXTS = {".mp3", ".m4a", ".aac", ".ogg", ".opus", ".flac", ".wav", ".webm"}
MUSIC_MIMES = {
    ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac",
    ".ogg": "audio/ogg", ".opus": "audio/ogg", ".flac": "audio/flac",
    ".wav": "audio/wav", ".webm": "audio/webm",
}

music_items: dict = {}
music_folders: dict = {}
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
            json.dump({"items": music_items, "folders": music_folders},
                      fh, ensure_ascii=False)
        os.replace(tmp, MUSIC_INDEX_PATH)
    except OSError:
        pass


def _music_digest(fname):
    """Отпечаток содержимого файла. Читаем кусками: трек может быть на
    десятки мегабайт, а держать его целиком в памяти незачем."""
    digest = hashlib.sha256()
    try:
        with open(os.path.join(MUSIC_DIR, fname), "rb") as fh:
            while True:
                chunk = fh.read(MUSIC_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _music_twin(size, digest):
    """Имя уже лежащего файла с тем же содержимым, иначе пусто.

    Считать отпечатки всей фонотеки при каждой загрузке было бы расточительно,
    поэтому сначала отсеиваем по размеру: совпал размер — только тогда читаем
    байты, и посчитанное запоминаем в записи. Вызывать под music_lock."""
    for track in music_items.values():
        if track.get("size") != size:
            continue
        if not track.get("hash"):
            track["hash"] = _music_digest(track["file"])
        if track["hash"] and track["hash"] == digest:
            return track["file"]
    return ""


def _music_used():
    """Занято на диске. Копии в других папках ничего не стоят, поэтому
    считаем по разным файлам, а не по записям. Вызывать под music_lock.

    К кривым записям относимся спокойно: одна порченая строчка в индексе не
    должна ронять ни фонотеку, ни дроп, который показывает её же."""
    seen = {}
    for track in music_items.values():
        if not isinstance(track, dict) or not track.get("file"):
            continue
        size = track.get("size")
        seen[track["file"]] = size if isinstance(size, (int, float)) else 0
    return sum(seen.values())


def _music_drop_file(fname):
    """Убрать файл с диска, если на него больше никто не ссылается.
    Вызывать под music_lock."""
    if any(t["file"] == fname for t in music_items.values()):
        return
    try:
        os.remove(os.path.join(MUSIC_DIR, fname))
    except OSError:
        pass


def _music_folder_depth(folder_id):
    """Сколько папок над этой. Заодно страхует от закольцованного дерева:
    длиннее MUSIC_MAX_DEPTH подниматься не станем. Вызывать под music_lock."""
    depth, seen = 0, set()
    while folder_id and folder_id in music_folders and folder_id not in seen:
        seen.add(folder_id)
        folder_id = music_folders[folder_id].get("parent", "")
        depth += 1
    return depth


def _music_subtree(folder_id):
    """Папка и всё, что под ней. Вызывать под music_lock."""
    found = {folder_id}
    while True:
        grown = {k for k, v in music_folders.items() if v.get("parent") in found}
        if grown <= found:
            return found
        found |= grown


def _music_scan():
    """Синхронизирует индекс с папкой: подхватывает закинутое руками,
    выбрасывает записи об исчезнувших файлах. Вызывать под music_lock."""
    try:
        on_disk = {f for f in os.listdir(MUSIC_DIR)
                   if os.path.splitext(f)[1].lower() in MUSIC_EXTS}
    except OSError:
        return

    # Сначала — прочь всё, что не похоже на запись о треке: без этого одна
    # порченая строчка в индексе валила и фонотеку, и список дропа.
    for track_id in [k for k, v in music_items.items()
                     if not isinstance(v, dict) or not v.get("file")]:
        music_items.pop(track_id, None)
    for folder_id in [k for k, v in music_folders.items()
                      if not isinstance(v, dict) or not v.get("name")]:
        music_folders.pop(folder_id, None)

    for track_id in [k for k, v in music_items.items() if v["file"] not in on_disk]:
        music_items.pop(track_id, None)

    # Папка исчезла — её содержимое всплывает наверх, а не пропадает из виду.
    for track in music_items.values():
        if track.get("folder") and track["folder"] not in music_folders:
            track["folder"] = ""
    for folder in music_folders.values():
        if folder.get("parent") and folder["parent"] not in music_folders:
            folder["parent"] = ""

    known = {v["file"] for v in music_items.values()}
    for fname in sorted(on_disk - known):
        artist, title = _music_split(os.path.splitext(fname)[0])
        try:
            size = os.path.getsize(os.path.join(MUSIC_DIR, fname))
        except OSError:
            continue
        music_items[str(uuid.uuid4())] = {
            "file": fname, "artist": artist, "title": title,
            "size": size, "added": time.time(), "folder": "", "hash": "",
        }


def _music_load():
    try:
        with open(MUSIC_INDEX_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        saved = {}
    # До появления папок индекс был просто «запись → трек». Такой файл узнаём
    # по значениям: у трека есть «file», у нового раздела — нет.
    if isinstance(saved, dict) and "items" not in saved:
        saved = {"items": saved, "folders": {}}
    music_items.update(saved.get("items") or {})
    music_folders.update(saved.get("folders") or {})
    for track in list(music_items.values()):
        if not isinstance(track, dict):
            continue
        track.setdefault("folder", "")
        track.setdefault("hash", "")
        if not isinstance(track.get("size"), (int, float)):
            track["size"] = 0
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


@app.errorhandler(Exception)
def any_error(err):
    """Любая непойманная ошибка. Страницам отдаём как было, а запросам к API —
    внятный JSON: иначе интерфейс просто висит на «Загрузка…», и понять, что
    случилось, нельзя ни хозяину, ни тому, кто чинит."""
    from werkzeug.exceptions import HTTPException

    if isinstance(err, HTTPException):
        return err
    app.logger.exception("Необработанная ошибка: %s", request.path)
    if request.path.startswith("/api/"):
        return jsonify(error="Сервер споткнулся: %s" % err.__class__.__name__,
                       where=request.path), 500
    raise err


@app.get("/api/diag")
@login_required
def diag_api():
    """Короткая самопроверка: что читается, а что нет. Нужна, когда снаружи
    видно только «не работает»."""
    out = {}

    def probe(name, fn):
        try:
            out[name] = fn()
        except Exception as e:                        # noqa: BLE001
            out[name] = "ОШИБКА: %s: %s" % (e.__class__.__name__, e)

    probe("дроп: элементов", lambda: len(drop_items))
    probe("дроп: занято", lambda: _drop_used())
    probe("дроп: корзина", lambda: _drop_trash_bytes())
    probe("папка MUSIK", lambda: bool(drop_items.get(DROP_MUSIK_ID)))
    probe("фонотека: треков", lambda: len(music_items))
    probe("фонотека: папок", lambda: len(music_folders))
    probe("фонотека: занято", lambda: _music_used())
    probe("страна DIY: записей", lambda: len(diy_items))
    probe("блокнот: страниц", lambda: len(notebook_data.get("pages", [])))
    probe("код для ссылок", lambda: bool(__import__("segno")))
    probe("дворецкий", lambda: bool(SEBASTIAN_HOST))
    return jsonify(out)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    # По умолчанию встраивание в рамку запрещено. Исключение — свой же
    # просмотр PDF внутри дропа: там нужен собственный iframe того же домена.
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if getattr(g, "frameable", False) else "DENY"
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




# ---- Вкладка Claude: разговор с Claude Code через сайт ----------------------
# Claude Code — программа для командной строки, и живёт она на домашней машине.
# Городить ради неё отдельный сервис не нужно: у кабинета уже есть готовый
# канал «браузер → WebSocket → SSH → терминал», тот самый, что открывает
# консоль. Здесь тот же канал, только вместо обычной оболочки запускается
# claude, и запускается он внутри tmux.
#
# Зачем tmux: разговор не должен обрываться, когда закрыл вкладку браузера или
# телефон заснул. Сессия tmux живёт на домашней машине сама по себе, а сайт к
# ней просто прицепляется. Отсюда же берутся вкладки — как в чатах кода: одна
# вкладка = одна сессия tmux, закрыл вкладку — разговор продолжает висеть,
# вернулся — увидел его целиком.
#
# Ключей и токенов Claude сайт не хранит и не видит: вход в саму программу
# делается один раз на домашней машине (claude login), а сайт только показывает
# её экран. Пароль SSH живёт в одном соединении и на диск не попадает.
CLAUDE_HOST = os.environ.get("CLAUDE_HOST", "").strip()
CLAUDE_DIR = os.environ.get("CLAUDE_DIR", "").strip()
# Команда, которую вкладка запускает внутри tmux. По умолчанию claude, но
# ничего специфичного для него тут нет: поставь сюда другую — вкладка будет
# разговаривать с ней. Так же встанет любой другой консольный помощник.
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude").strip() or "claude"
CLAUDE_TABS_MAX = 8                     # больше и не нужно, и память не резиновая
CLAUDE_PREFIX = "vg-"                   # чтобы не путать со своими сессиями tmux
CLAUDE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$")


def _claude_ready():
    """Настроена ли вкладка. Хост должен быть из списка своих машин."""
    return bool(CLAUDE_HOST) and CLAUDE_HOST in ssh_enabled_ips


def _claude_host_name():
    for device in NETBIRD_DEVICES:
        if device["ip"] == CLAUDE_HOST:
            return device["name"]
    return CLAUDE_HOST


def _claude_run(client, command, timeout=10):
    """Разовая команда по SSH. Возвращает (код, вывод)."""
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return stdout.channel.recv_exit_status(), (out + err).strip()
    except (paramiko.SSHException, OSError, EOFError) as e:
        return 1, str(e)


def _claude_tabs(client):
    """Список вкладок — это список сессий tmux с нашим префиксом."""
    code, out = _claude_run(
        client,
        "tmux list-sessions -F '#{session_name}\t#{session_created}\t#{session_attached}' 2>/dev/null || true",
    )
    tabs = []
    if code != 0:
        return tabs
    for line in out.splitlines():
        parts = line.split("\t")
        name = parts[0] if parts else ""
        if not name.startswith(CLAUDE_PREFIX):
            continue
        try:
            made = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            made = 0
        tabs.append({
            "id": name[len(CLAUDE_PREFIX):],
            "made": made,
            "live": (len(parts) > 2 and parts[2] not in ("", "0")),
        })
    tabs.sort(key=lambda t: t["made"])
    return tabs


def _claude_free_name(tabs):
    """Первое свободное имя вида «1», «2», …"""
    taken = {t["id"] for t in tabs}
    for n in range(1, CLAUDE_TABS_MAX + 1):
        if str(n) not in taken:
            return str(n)
    return None


@app.get("/api/claude/state")
@login_required
def claude_state_api():
    """Что показывать до подключения: настроена ли вкладка и на какой машине."""
    return jsonify(ready=_claude_ready(),
                   host=_claude_host_name() if _claude_ready() else "",
                   gate=bool(SSH_GATE_PASSWORD_PREFIX),
                   dir=CLAUDE_DIR)


@sock.route("/ws/claude")
def claude_ws(ws):
    """Один канал на весь разговор: и список вкладок, и сам терминал.

    Пароль SSH приходит ровно один раз, в первом сообщении, и дальше живёт
    только в этом соединении — на диск и в журналы он не попадает."""
    if not session.get("authenticated") or not session.get("console_authenticated"):
        ws.close()
        return
    if not _claude_ready():
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
    if not username or not password:
        ws.close()
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(CLAUDE_HOST, username=username, password=password,
                       timeout=6, look_for_keys=False, allow_agent=False)
    except (paramiko.SSHException, OSError):
        try:
            ws.send(json.dumps({"type": "fail",
                                "text": "Не удалось зайти на машину — проверь логин и пароль."}))
        except Exception:
            pass
        ws.close()
        return

    client.get_transport().set_keepalive(20)

    # Проверяем, что на машине вообще есть чем работать. Молча падать в пустой
    # чёрный экран — худший из возможных ответов.
    code, _out = _claude_run(client, "command -v tmux >/dev/null 2>&1")
    if code != 0:
        ws.send(json.dumps({"type": "fail",
                            "text": "На машине нет tmux. Поставь: sudo apt install tmux"}))
        client.close()
        ws.close()
        return
    code, _out = _claude_run(client, f"command -v {shlex.quote(CLAUDE_BIN)} >/dev/null 2>&1")
    if code != 0:
        ws.send(json.dumps({"type": "fail",
                            "text": f"На машине нет команды «{CLAUDE_BIN}». "
                                    "Поставь Claude Code и зайди в него один раз: claude"}))
        client.close()
        ws.close()
        return

    state = {"channel": None, "tab": None, "cols": 100, "rows": 30}
    stop_event = threading.Event()
    send_lock = threading.Lock()

    def say(payload):
        with send_lock:
            ws.send(json.dumps(payload))

    def tabs_out():
        say({"type": "tabs", "tabs": _claude_tabs(client), "open": state["tab"]})

    def tabs_out_when(name):
        """То же, но дождавшись, пока tmux заведёт сессию.

        Команда уходит в оболочку и выполняется не мгновенно: если спросить
        список сразу, только что созданной вкладки в нём ещё нет. Ждём в
        сторонке, чтобы не задерживать разговор."""
        def wait():
            for _ in range(16):
                if stop_event.is_set():
                    return
                tabs = _claude_tabs(client)
                if name in {t["id"] for t in tabs}:
                    say({"type": "tabs", "tabs": tabs, "open": state["tab"]})
                    return
                time.sleep(0.25)
            tabs_out()

        threading.Thread(target=wait, daemon=True).start()

    def open_tab(name):
        """Прицепиться к вкладке, а если её нет — завести."""
        if not CLAUDE_NAME_RE.match(name or ""):
            say({"type": "fail", "text": "Странное имя вкладки."})
            return
        tabs = _claude_tabs(client)
        if name not in {t["id"] for t in tabs} and len(tabs) >= CLAUDE_TABS_MAX:
            say({"type": "fail", "text": f"Больше {CLAUDE_TABS_MAX} вкладок сразу не держим."})
            return

        close_tab_channel()
        session_name = shlex.quote(CLAUDE_PREFIX + name)
        # -A: есть такая сессия — прицепиться, нет — создать с нашей командой.
        # -D: отцепить того, кто смотрел её раньше, иначе размер экрана прыгает.
        start = f"tmux new-session -A -D -s {session_name}"
        if CLAUDE_DIR:
            start += f" -c {shlex.quote(CLAUDE_DIR)}"
        start += f" {shlex.quote(CLAUDE_BIN)}"

        channel = client.invoke_shell(term="xterm-256color",
                                      width=state["cols"], height=state["rows"])
        channel.settimeout(0.0)
        channel.send(start + "\n")
        state["channel"] = channel
        state["tab"] = name

        def pump():
            try:
                while not stop_event.is_set() and state["channel"] is channel:
                    if channel.recv_ready():
                        chunk = channel.recv(8192)
                        if not chunk:
                            break
                        say({"type": "data", "data": chunk.decode(errors="replace")})
                    else:
                        time.sleep(0.03)
                    if channel.closed:
                        break
            except Exception:
                pass
            finally:
                if state["channel"] is channel:
                    state["channel"] = None
                    state["tab"] = None

        threading.Thread(target=pump, daemon=True).start()
        say({"type": "open", "tab": name})
        tabs_out_when(name)

    def close_tab_channel():
        """Отцепиться от вкладки, не трогая саму сессию — она живёт дальше."""
        channel = state["channel"]
        state["channel"] = None
        state["tab"] = None
        if channel:
            try:
                channel.close()
            except Exception:
                pass

    def kill_tab(name):
        if not CLAUDE_NAME_RE.match(name or ""):
            return
        if state["tab"] == name:
            close_tab_channel()
        _claude_run(client, f"tmux kill-session -t {shlex.quote(CLAUDE_PREFIX + name)} 2>/dev/null || true")
        tabs_out()

    def keepalive():
        while not stop_event.is_set():
            time.sleep(10)
            if stop_event.is_set():
                break
            try:
                say({"type": "ping"})
            except Exception:
                stop_event.set()

    threading.Thread(target=keepalive, daemon=True).start()

    try:
        say({"type": "ready", "host": _claude_host_name(), "dir": CLAUDE_DIR})
        tabs_out()
        while not stop_event.is_set():
            message = ws.receive(timeout=120)
            if message is None:
                continue
            try:
                payload = json.loads(message)
            except ValueError:
                continue
            kind = payload.get("type")
            if kind == "data":
                channel = state["channel"]
                if channel:
                    channel.send(payload.get("data", ""))
            elif kind == "resize":
                try:
                    state["cols"] = max(20, min(500, int(payload.get("cols", 100))))
                    state["rows"] = max(5, min(200, int(payload.get("rows", 30))))
                except (TypeError, ValueError):
                    continue
                channel = state["channel"]
                if channel:
                    channel.resize_pty(width=state["cols"], height=state["rows"])
            elif kind == "open":
                open_tab(str(payload.get("tab", "")))
            elif kind == "new":
                tabs = _claude_tabs(client)
                name = _claude_free_name(tabs)
                if not name:
                    say({"type": "fail", "text": f"Больше {CLAUDE_TABS_MAX} вкладок сразу не держим."})
                else:
                    open_tab(name)
            elif kind == "kill":
                kill_tab(str(payload.get("tab", "")))
            elif kind == "list":
                tabs_out()
            elif kind == "ping":
                say({"type": "pong"})
    except Exception:
        pass
    finally:
        stop_event.set()
        close_tab_channel()
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


def music_editor_required(view):
    """Фонотека целиком под паролем кабинета — и слушать, и менять.

    Изначально слушать мог кто угодно, но выкладывать в открытый доступ
    скачанную музыку — это раздача чужого, и претензии тут прилетают
    именно за раздачу, а не за личную копию. Поэтому закрыто всё.

    Отвечаем кодом, а не переадресацией: это разбирает скрипт страницы."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен расширенный режим."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            _log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


@app.get("/api/music")
@music_editor_required
def music_list_api():
    with music_lock:
        _music_scan()
        _music_write_index()
        used = _music_used()
        tracks = [
            {"id": k, "artist": v["artist"], "title": v["title"],
             "size": v["size"], "added": v["added"], "folder": v.get("folder", "")}
            for k, v in sorted(music_items.items(),
                               key=lambda x: (x[1]["artist"].lower(), x[1]["title"].lower()))
        ]
        folders = [
            {"id": k, "name": v["name"], "parent": v.get("parent", "")}
            for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower())
        ]
    return jsonify(tracks=tracks, folders=folders, used=used, quota=MUSIC_QUOTA,
                   limit=MUSIC_MAX_SIZE, can_edit=bool(session.get("authenticated")))


@app.post("/api/music")
@music_editor_required
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

    folder = (request.form.get("folder") or "").strip()
    with music_lock:
        _music_scan()
        if _music_used() > MUSIC_QUOTA:
            return jsonify(error="Места под музыку больше нет."), 507
        if folder and folder not in music_folders:
            folder = ""
        taken = {t["file"] for t in music_items.values()}

    stem, suffix = os.path.splitext(name)
    candidate, counter = name, 2
    while candidate in taken or os.path.exists(os.path.join(MUSIC_DIR, candidate)):
        candidate = f"{stem} ({counter}){suffix}"
        counter += 1

    # Пишем во временный файл и считаем отпечаток на лету: если такой трек уже
    # лежит, лишние байты на диск не попадут вовсе.
    temp = os.path.join(MUSIC_DIR, f".upload-{uuid.uuid4().hex}")
    digest = hashlib.sha256()
    size = 0
    try:
        with open(temp, "wb") as out:
            while True:
                chunk = f.stream.read(MUSIC_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MUSIC_MAX_SIZE:
                    raise ValueError("big")
                digest.update(chunk)
                out.write(chunk)
    except ValueError:
        _music_unlink(temp)
        return jsonify(error="Трек больше 40 МБ."), 413
    except OSError as e:
        _music_unlink(temp)
        return jsonify(error=f"Не удалось сохранить: {e}"), 500

    artist, title = _music_split(os.path.splitext(candidate)[0])
    track_id = str(uuid.uuid4())
    with music_lock:
        twin = _music_twin(size, digest.hexdigest())
        if twin:
            _music_unlink(temp)
            candidate = twin
        else:
            try:
                os.replace(temp, os.path.join(MUSIC_DIR, candidate))
            except OSError as e:
                _music_unlink(temp)
                return jsonify(error=f"Не удалось сохранить: {e}"), 500
        music_items[track_id] = {"file": candidate, "artist": artist, "title": title,
                                 "size": size, "added": time.time(),
                                 "folder": folder, "hash": digest.hexdigest()}
        _music_write_index()
    return jsonify(id=track_id, artist=artist, title=title, folder=folder, twin=bool(twin))


def _music_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass


@app.patch("/api/music/<track_id>")
@music_editor_required
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
        if "folder" in payload:
            folder = (payload.get("folder") or "").strip()
            track["folder"] = folder if folder in music_folders else ""
        _music_write_index()
        return jsonify(ok=True, artist=track["artist"], title=track["title"],
                       folder=track.get("folder", ""))


@app.delete("/api/music/<track_id>")
@music_editor_required
def music_delete_api(track_id):
    with music_lock:
        track = music_items.pop(track_id, None)
        if track:
            _music_drop_file(track["file"])
            _music_write_index()
    return jsonify(ok=True)


@app.post("/api/music/folder")
@music_editor_required
def music_folder_create_api():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:60] or "Новая папка"
    parent = (payload.get("parent") or "").strip()
    with music_lock:
        if parent and parent not in music_folders:
            parent = ""
        if _music_folder_depth(parent) >= MUSIC_MAX_DEPTH:
            return jsonify(error="Глубже вкладывать некуда."), 400
        folder_id = str(uuid.uuid4())
        music_folders[folder_id] = {"name": name, "parent": parent, "added": time.time()}
        _music_write_index()
    return jsonify(id=folder_id, name=name, parent=parent)


@app.patch("/api/music/folder/<folder_id>")
@music_editor_required
def music_folder_patch_api(folder_id):
    payload = request.get_json(silent=True) or {}
    with music_lock:
        folder = music_folders.get(folder_id)
        if not folder:
            return jsonify(error="Папка не найдена."), 404
        if "name" in payload:
            name = (payload.get("name") or "").strip()[:60]
            if not name:
                return jsonify(error="Имя пустое."), 400
            folder["name"] = name
        if "parent" in payload:
            parent = (payload.get("parent") or "").strip()
            if parent and parent not in music_folders:
                parent = ""
            # Папку нельзя убрать внутрь самой себя — дерево бы замкнулось.
            if parent in _music_subtree(folder_id):
                return jsonify(error="Папку нельзя вложить в саму себя."), 400
            folder["parent"] = parent
        _music_write_index()
        return jsonify(ok=True, name=folder["name"], parent=folder.get("parent", ""))


@app.delete("/api/music/folder/<folder_id>")
@music_editor_required
def music_folder_delete_api(folder_id):
    with music_lock:
        if folder_id not in music_folders:
            return jsonify(error="Папка не найдена."), 404
        doomed = _music_subtree(folder_id)
        gone = [k for k, v in music_items.items() if v.get("folder") in doomed]
        files = {music_items[k]["file"] for k in gone}
        for k in gone:
            music_items.pop(k, None)
        for k in doomed:
            music_folders.pop(k, None)
        for fname in files:
            _music_drop_file(fname)
        _music_write_index()
    return jsonify(ok=True, tracks=len(gone), folders=len(doomed))


@app.post("/api/music/op")
@music_editor_required
def music_op_api():
    """Пачкой: скопировать, перенести или удалить треки.

    Копия — это новая запись на тот же файл, поэтому она мгновенная и места
    не занимает. Никакой очереди с полосой тут не нужно."""
    payload = request.get_json(silent=True) or {}
    op = payload.get("op")
    ids = [str(i) for i in (payload.get("ids") or [])][:2000]
    target = (payload.get("target") or "").strip()
    if op not in {"copy", "move", "delete"}:
        return jsonify(error="Неизвестное действие."), 400

    done = 0
    with music_lock:
        if op != "delete" and target and target not in music_folders:
            return jsonify(error="Папка не найдена."), 404
        for track_id in ids:
            track = music_items.get(track_id)
            if not track:
                continue
            if op == "copy":
                twin = dict(track)
                twin["folder"] = target
                twin["added"] = time.time()
                music_items[str(uuid.uuid4())] = twin
            elif op == "move":
                track["folder"] = target
            else:
                music_items.pop(track_id, None)
                _music_drop_file(track["file"])
            done += 1
        _music_write_index()
    return jsonify(ok=True, done=done)


@app.get("/api/music/file/<track_id>")
@music_editor_required
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
    ".mp4": "video/mp4", ".webm": "video/webm", ".m4v": "video/mp4",
    ".mov": "video/quicktime", ".ogv": "video/ogg",
    ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav",
    ".m4a": "audio/mp4", ".opus": "audio/ogg", ".flac": "audio/flac",
    ".aac": "audio/aac",
}

# Чем показывать файл на странице ссылки. Всё, чего тут нет, ссылка просто
# отдаёт файлом — выдумывать просмотр для архива или экзешника незачем.
DROP_VIEW_KINDS = (
    ("image", {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".avif", ".ico"}),
    ("video", {".mp4", ".webm", ".m4v", ".mov", ".ogv"}),
    ("audio", {".mp3", ".ogg", ".wav", ".m4a", ".opus", ".flac", ".aac"}),
    ("page", {".pdf", ".txt", ".log", ".md", ".csv"}),
)


def _drop_human_size(bytes_count):
    """Вес файла по-человечески — для шапки страницы просмотра."""
    if bytes_count >= 1073741824:
        return f"{bytes_count / 1073741824:.2f} ГБ"
    if bytes_count >= 1048576:
        return f"{bytes_count / 1048576:.1f} МБ"
    if bytes_count >= 1024:
        return f"{round(bytes_count / 1024)} КБ"
    return f"{bytes_count} Б"


def _drop_view_kind(name):
    """Каким тегом показывать файл, либо пусто — если показывать нечем."""
    ext = os.path.splitext(name or "")[1].lower()
    for kind, exts in DROP_VIEW_KINDS:
        if ext in exts:
            return kind
    return ""


def _drop_share_mode(share):
    """Что делает ссылка: «view» — открывает страницу, «dl» — отдаёт файл.

    У ссылок, выданных до появления тумблера, поля нет. Раньше правило было
    негласным: бессрочная открывалась в браузере, а срочная скачивалась —
    его и повторяем, чтобы старые ссылки вели себя как вели."""
    mode = (share or {}).get("mode")
    if mode in ("view", "dl"):
        return mode
    return "dl" if (share or {}).get("expires") else "view"


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
    icon = payload.get("icon") if payload.get("icon") in DROP_FOLDER_ICONS else "folder"
    if not name:
        return jsonify(error="Имя пустое."), 400
    item_id = str(uuid.uuid4())
    with drop_lock:
        if parent and drop_items.get(parent, {}).get("kind") != "folder":
            parent = None
        drop_items[item_id] = {
            "kind": "folder", "name": name, "parent": parent, "icon": icon,
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
    music_target = parent == DROP_MUSIK_ID or (parent or "").startswith("mf_")
    with drop_lock:
        _drop_sweep_uploads()
        # MUSIK и папки внутри неё — приёмник фонотеки, а не склад дропа
        if not music_target and parent and drop_items.get(parent, {}).get("kind") != "folder":
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

    parent_in = upload.get("parent") or ""
    if parent_in == DROP_MUSIK_ID or parent_in.startswith("mf_"):
        return _drop_music_take(tmp_path, upload["name"], actual,
                                "" if parent_in == DROP_MUSIK_ID else parent_in[3:])

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


def _drop_music_take(tmp_path, name, size, folder):
    """Принимает файл, брошенный в папку MUSIK, прямо в фонотеку — тогда он
    сразу оказывается и в плеере, и на странице музыки."""
    ext = os.path.splitext(name)[1].lower()
    if ext not in MUSIC_EXTS:
        _music_unlink(tmp_path)
        return jsonify(error="В MUSIK кладём только музыку."), 415
    with music_lock:
        if _music_used() + size > MUSIC_QUOTA:
            _music_unlink(tmp_path)
            return jsonify(error="В фонотеке кончилось место."), 507
        if folder and folder not in music_folders:
            folder = ""
        # подбираем свободное имя, как это делает загрузка на странице музыки
        safe = _music_safe_name(name)
        taken = {t["file"] for t in music_items.values()}
        stem, suffix = os.path.splitext(safe)
        candidate, counter = safe, 2
        while candidate in taken or os.path.exists(os.path.join(MUSIC_DIR, candidate)):
            candidate = f"{stem} ({counter}){suffix}"
            counter += 1
        try:
            os.replace(tmp_path, os.path.join(MUSIC_DIR, candidate))
        except OSError as e:
            _music_unlink(tmp_path)
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        artist, title = _music_split(os.path.splitext(candidate)[0])
        track_id = str(uuid.uuid4())
        music_items[track_id] = {"file": candidate, "artist": artist, "title": title,
                                 "size": size, "added": time.time(), "folder": folder}
        _music_write_index()
    return jsonify(id="mt_" + track_id, music=True)


def _drop_music_view(parent):
    """Содержимое папки MUSIK — это сама фонотека, показанная глазами дропа.

    Раньше дроп и фонотека были двумя разными складами: трек, загруженный на
    странице музыки, в дропе не появлялся, и наоборот. Теперь MUSIK не хранит
    ничего своего, а показывает папки и треки фонотеки — то же самое, что
    играет плеер. Значки виртуальные: id папки начинается с «mf_», трека — с
    «mt_», по ним и разбираем запросы дальше."""
    inside = "" if parent == DROP_MUSIK_ID else parent[3:]
    items, chain = [], []
    with music_lock:
        _music_scan()
        for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower()):
            if v.get("parent", "") != inside:
                continue
            kids = sum(1 for t in music_items.values() if t.get("folder", "") == k)
            size = sum(t.get("size", 0) for t in music_items.values()
                       if t.get("folder", "") == k)
            items.append({"id": "mf_" + k, "kind": "folder", "name": v["name"],
                          "size": size, "count": kids, "icon": "music",
                          "created": v.get("added", 0), "touched": v.get("added", 0),
                          "share": False, "share_expires": None, "share_mode": None,
                          "share_url": None, "thumb": False, "preview": None,
                          "truncated": False, "music": True})
        for k, v in sorted(music_items.items(),
                           key=lambda x: (str(x[1].get("artist", "")).lower(),
                                          str(x[1].get("title", "")).lower())):
            if v.get("folder", "") != inside:
                continue
            name = " — ".join([p for p in (v.get("artist"), v.get("title")) if p]) or v["file"]
            items.append({"id": "mt_" + k, "kind": "file", "name": name,
                          "size": v.get("size", 0), "created": v.get("added", 0),
                          "touched": v.get("added", 0), "preview": None, "truncated": False,
                          "thumb": False, "share": False, "share_expires": None,
                          "share_mode": None, "share_url": None, "music": True})
        # путь наверх: MUSIK, а дальше вложенные папки фонотеки
        node = inside
        seen = set()
        while node and node in music_folders and node not in seen:
            seen.add(node)
            chain.append({"id": "mf_" + node, "name": music_folders[node]["name"]})
            node = music_folders[node].get("parent", "")
        chain.reverse()
    with drop_lock:
        used, quota, trash = _drop_used(), DROP_QUOTA, _drop_trash_bytes()
    return jsonify(items=items,
                   breadcrumbs=[{"id": DROP_MUSIK_ID, "name": "MUSIK"}] + chain,
                   used=used, quota=quota, trash=trash, music_view=True)


@app.get("/api/drop/list")
@login_required
def drop_list_api():
    parent = request.args.get("parent") or None
    # Папка MUSIK и всё внутри неё — это фонотека, а не склад дропа
    if parent == DROP_MUSIK_ID or (parent or "").startswith("mf_"):
        try:
            return _drop_music_view(parent)
        except Exception:                                   # noqa: BLE001
            app.logger.exception("MUSIK: не собрал список фонотеки")
            return jsonify(items=[], breadcrumbs=[{"id": DROP_MUSIK_ID, "name": "MUSIK"}],
                           used=0, quota=DROP_QUOTA, trash=0, music_view=True,
                           warn="Фонотека сейчас не читается.")
    with drop_lock:
        _drop_sweep_trash()
        if parent and parent not in drop_items:
            parent = None
        memo = {}
        items = []
        for k, v in drop_items.items():
            if v.get("parent") != parent or v.get("deleted"):
                continue
            row = {
                "id": k, "kind": v["kind"], "name": v["name"], "size": v.get("size", 0),
                "created": v["created"], "preview": v.get("preview"),
                "truncated": v.get("truncated", False),
                "thumb": _drop_can_thumb(v),
                "share": bool(v.get("share")),
                "share_expires": (v.get("share") or {}).get("expires"),
                "share_mode": _drop_share_mode(v["share"]) if v.get("share") else None,
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
                if v.get("special"):
                    row["special"] = True
                    # MUSIK показывает фонотеку, значит и веса берём её. Если
                    # фонотека почему-то не читается — это не повод ронять
                    # весь список файлов: просто оставим прежние цифры.
                    try:
                        with music_lock:
                            row["size"] = _music_used()
                            row["count"] = len(music_items)
                    except Exception:                       # noqa: BLE001
                        app.logger.exception("MUSIK: не посчитал фонотеку")
            items.append(row)
        # Сначала новые, но особая папка (MUSIK) всегда падает в самый низ.
        # Сортировка устойчивая: сперва по свежести, затем особые — вниз.
        items.sort(key=lambda x: -x["touched"])
        items.sort(key=lambda x: bool(x.get("special")))
        return jsonify(
            items=items,
            breadcrumbs=_drop_path_to_root(parent),
            used=_drop_used(),
            quota=DROP_QUOTA,
            trash=_drop_trash_bytes(memo),
        )


def _drop_music_send(item_id, inline=False):
    """Трек фонотеки, отданный через дроп: id вида «mt_<id>». Возвращает
    ответ или None, если это обычный элемент дропа."""
    if not item_id.startswith("mt_"):
        return None
    with music_lock:
        track = music_items.get(item_id[3:])
    if not track:
        return "Не найдено", 404
    path = os.path.join(MUSIC_DIR, track["file"])
    if not os.path.exists(path):
        return "Не найдено", 404
    ext = os.path.splitext(track["file"])[1].lower()
    name = " — ".join([p for p in (track.get("artist"), track.get("title")) if p]) or track["file"]
    return send_file(path, mimetype=MUSIC_MIMES.get(ext, "audio/mpeg"),
                     as_attachment=not inline, download_name=name + ext, conditional=True)


@app.get("/api/drop/download/<item_id>")
@login_required
def drop_download(item_id):
    tune = _drop_music_send(item_id)
    if tune is not None:
        return tune
    with drop_lock:
        item = drop_items.get(item_id)
    if not item or item["kind"] == "folder":
        return "Не найдено", 404
    return _drop_send(item_id, item)


# Архив папки собираем на лету и сразу отдаём: складывать его в памяти
# нельзя — папка с фотографиями легко весит больше, чем есть оперативки.
DROP_ZIP_CHUNK = 1024 * 1024


class _ZipSink:
    """Приёмник для zipfile: копит записанное и отдаёт порциями наружу.

    zipfile умеет писать в непрокручиваемый поток — тогда размеры файлов он
    дописывает после данных отдельной меткой. Нам это и нужно: считать файл
    заранее, только чтобы узнать его длину, значит прочитать всю папку дважды."""

    def __init__(self):
        self._parts = []
        self._pos = 0
        self._held = 0

    def write(self, data):
        data = bytes(data)
        self._parts.append(data)
        self._pos += len(data)
        self._held += len(data)
        return len(data)

    def tell(self):
        return self._pos

    def flush(self):
        pass

    @property
    def held(self):
        return self._held

    def drain(self):
        out = b"".join(self._parts)
        self._parts.clear()
        self._held = 0
        return out


def _drop_zip_name(name, taken):
    """Имя внутри архива: без разделителей пути и без повторов в одной папке.

    Разделители убираем не для красоты — имя вида «../ключи» распаковалось бы
    мимо выбранной папки."""
    clean = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name or "").strip(" .") or "файл"
    stem, dot, ext = clean.rpartition(".")
    if not dot:
        stem, ext = clean, ""
    candidate, counter = clean, 2
    while candidate.lower() in taken:
        candidate = f"{stem} ({counter})" + (f".{ext}" if dot else "")
        counter += 1
    taken.add(candidate.lower())
    return candidate


def _drop_zip_plan(folder_id):
    """Что кладём в архив: путь внутри архива, файл на диске, размер, время.
    Пустые папки тоже попадают — иначе они пропадут при распаковке.
    Вызывать под drop_lock."""
    plan = []

    def walk(node_id, prefix, seen):
        if node_id in seen:
            return
        seen = seen | {node_id}
        taken = set()
        for child in sorted(_drop_children(node_id),
                            key=lambda k: drop_items[k]["name"].lower()):
            item = drop_items[child]
            name = _drop_zip_name(item["name"], taken)
            if item["kind"] == "folder":
                plan.append((prefix + name + "/", None, 0, item.get("created", 0)))
                walk(child, prefix + name + "/", seen)
            else:
                plan.append((prefix + name, child, item.get("size", 0),
                             item.get("created", 0)))

    walk(folder_id, "", set())
    return plan


def _drop_zip_length(plan):
    """Точный размер будущего архива, чтобы браузер показал полосу загрузки.

    Считается только для несжатого архива без ZIP64: заголовок файла 30 байт
    плюс имя, затем данные, затем метка на 16 байт; в конце по 46 байт плюс
    имя на каждую запись и 22 байта хвоста. Если выходит за четыре гигабайта,
    формат переключится на ZIP64 и эта арифметика перестанет быть верной —
    тогда длину не обещаем вовсе."""
    total = 22
    for arcname, file_id, size, _ in plan:
        name_len = len(arcname.encode("utf-8"))
        # 30 — заголовок файла, 16 — метка с размерами после данных,
        # 46 — запись в оглавлении. Метка пишется и для папок: zipfile
        # ставит её всем записям, раз поток непрокручиваемый.
        total += 30 + name_len + 16 + 46 + name_len
        if file_id:
            total += size
    limit = 0xFFFFFFFF
    if total > limit or any(size > limit for _, _, size, _ in plan):
        return None
    return total


def _drop_zip_time(stamp):
    """Время файла для архива. До 1980 года формат не умеет, ниже не опускаем."""
    try:
        # Время в архиве пишется без пояса — берём местное, как и делают
        # все архиваторы.
        moment = datetime.fromtimestamp(stamp or 0)
    except (OSError, OverflowError, ValueError):
        moment = datetime.now()
    if moment.year < 1980:
        return (1980, 1, 1, 0, 0, 0)
    return (moment.year, moment.month, moment.day,
            moment.hour, moment.minute, moment.second - moment.second % 2)


@app.get("/api/drop/zip/<item_id>")
@login_required
def drop_zip(item_id):
    """Папка целиком одним архивом.

    Ничего не сжимаем: фотографии, видео и музыка уже сжаты, и второй проход
    только сожрал бы процессор ради процента-двух. Зато без сжатия архив
    собирается ровно со скоростью диска."""
    with drop_lock:
        item = drop_items.get(item_id)
        if not item or item["kind"] != "folder":
            return "Не найдено", 404
        plan = _drop_zip_plan(item_id)
        folder = item["name"]

    def pour():
        sink = _ZipSink()
        with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
            for arcname, file_id, _, made in plan:
                info = zipfile.ZipInfo(arcname, _drop_zip_time(made))
                info.compress_type = zipfile.ZIP_STORED
                if file_id is None:
                    zf.writestr(info, b"")          # пустая папка
                    yield sink.drain()
                    continue
                path = _drop_path(file_id)
                if not os.path.exists(path):
                    continue
                with zf.open(info, "w") as dst, open(path, "rb") as src:
                    while True:
                        chunk = src.read(DROP_ZIP_CHUNK)
                        if not chunk:
                            break
                        dst.write(chunk)
                        if sink.held >= DROP_ZIP_CHUNK:
                            yield sink.drain()
                if sink.held:
                    yield sink.drain()
        yield sink.drain()

    safe = (_drop_zip_name(folder, set()) or "папка") + ".zip"
    quoted = urllib.parse.quote(safe)
    response = Response(pour(), mimetype="application/zip")
    # Имя даём дважды. Русское — только в filename* и только процентами:
    # заголовки уходят в latin-1, и сырая кириллица роняет отдачу на месте.
    # Простое filename оставляем латинским, для совсем старых клиентов.
    response.headers["Content-Disposition"] = (
        "attachment; filename=\"archive.zip\"; filename*=UTF-8''" + quoted)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    length = _drop_zip_length(plan)
    if length is not None:
        response.headers["Content-Length"] = str(length)
    return response


@app.get("/api/drop/view/<item_id>")
@login_required
def drop_view(item_id):
    """То же содержимое, но с настоящим типом — для просмотра внутри дропа.

    Скачивание отдаёт всё как поток байтов, и видео от такого не играет:
    тегу нужен разобранный тип, а угадывать его браузеру мы запретили
    заголовком nosniff. Здесь тип берётся из того же белого списка, что и у
    публичной ссылки, так что ничего исполняемого сюда не попадёт."""
    tune = _drop_music_send(item_id, inline=True)
    if tune is not None:
        return tune
    with drop_lock:
        item = drop_items.get(item_id)
    if not item or item["kind"] == "folder":
        return "Не найдено", 404
    response = _drop_send(item_id, item, inline=True)
    if os.path.splitext(item["name"])[1].lower() == ".pdf":
        # Родному просмотрщику PDF жёсткий sandbox мешает работать, а рамку
        # того же домена мы разрешаем — чтобы показать файл прямо в дропе.
        # PDF скриптов страницы не исполняет, nosniff остаётся.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; object-src 'self'; img-src 'self' blob:; "
            "style-src 'unsafe-inline'; frame-ancestors 'self'")
        g.frameable = True
    return response


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
            _drop_trash(item_id)             # пакетное удаление — тоже в корзину
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
    # Срок и режим независимы: бывает нужна и вечная ссылка на скачивание,
    # и суточная на просмотр.
    mode = "view" if payload.get("mode") == "view" else "dl"
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
            "mode": mode,
        }
        token = item["share"]["token"]
        _drop_write_index()
    return jsonify(url=url_for("drop_public", token=token, _external=True),
                   hours=0 if forever else hours, forever=forever, mode=mode)


@app.delete("/api/drop/share/<item_id>")
@login_required
def drop_share_revoke(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
        if item:
            item["share"] = None
            _drop_write_index()
    return jsonify(ok=True)


def _drop_public_item(token):
    """Файл по токену ссылки, либо пусто. Из-под замка выходим сразу:
    держать его на время отдачи файла незачем."""
    with drop_lock:
        item_id = _drop_share_lookup(token)
        item = drop_items.get(item_id) if item_id else None
    return (item_id, item) if item else (None, None)


@app.get("/d/<token>")
def drop_public(token):
    """Публичная ссылка — единственный вход в дроп без авторизации.

    Ссылка бывает двух видов, и вид выбирается отдельно от срока. «Скачать»
    отдаёт файл вложением, как и раньше. «Просмотр» открывает страницу с
    картинкой, видео или проигрывателем — и кнопкой скачивания рядом, чтобы
    просмотровая ссылка не была урезанной.

    Если показывать нечем — архив, установщик, что угодно ещё, — просмотр
    вырождается в обычную отдачу файла."""
    item_id, item = _drop_public_item(token)
    if not item:
        return "Ссылка недействительна или истекла", 404
    if _drop_share_mode(item.get("share")) != "view":
        return _drop_send(item_id, item)
    kind = _drop_view_kind(item["name"])
    if not kind:
        return _drop_send(item_id, item)
    return _drop_view_page(token, item, kind)


@app.get("/d/<token>/raw")
def drop_public_raw(token):
    """Байты для тега на странице просмотра.

    Отдаём потоком с поддержкой запросов по кускам: без неё браузер тянул бы
    весь фильм целиком, прежде чем показать первый кадр, и перемотка не
    работала бы вовсе. Памяти это не стоит ничего — файл читается с диска
    порциями, а не загружается в неё."""
    item_id, item = _drop_public_item(token)
    if not item or _drop_share_mode(item.get("share")) != "view":
        return "", 404
    return _drop_send(item_id, item, inline=True)


@app.get("/d/<token>/save")
def drop_public_save(token):
    """Кнопка «скачать» со страницы просмотра."""
    item_id, item = _drop_public_item(token)
    if not item:
        return "", 404
    return _drop_send(item_id, item)


def _drop_view_page(token, item, kind):
    """Страница просмотра: сам файл, его имя, вес и кнопка скачивания.

    Ничего не читаем в память — теги ссылаются на /raw, а его отдаёт
    send_file прямо с диска."""
    raw = url_for("drop_public_raw", token=token)
    save = url_for("drop_public_save", token=token)
    name = escape(item["name"])
    size = _drop_human_size(item.get("size") or 0)
    if kind == "image":
        body = f'<img src="{raw}" alt="{name}">'
    elif kind == "video":
        body = f'<video src="{raw}" controls playsinline preload="metadata"></video>'
    elif kind == "audio":
        body = f'<audio src="{raw}" controls preload="metadata"></audio>'
    else:
        body = f'<iframe src="{raw}" title="{name}"></iframe>'
    html = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#080b12">
__ICONLINKS__
<title>__NAME__ · vitazgio.ru</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100svh; display: flex; flex-direction: column;
         font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
         background:
           radial-gradient(circle at 12% 8%, rgba(57,126,255,.2), transparent 32rem),
           radial-gradient(circle at 88% 82%, rgba(149,65,255,.16), transparent 34rem),
           #0d1321;
         color: #f7f8fc; }
  header { display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
           padding: 16px max(16px, 4vw); border-bottom: 1px solid rgba(255,255,255,.1); }
  .who { display: inline-flex; align-items: center; gap: 9px; color: #cdd2df;
         font-size: .72rem; font-weight: 700; letter-spacing: .16em;
         text-transform: uppercase; text-decoration: none; }
  .who::before { content: ""; width: 7px; height: 7px; border-radius: 50%;
                 background: #64e6a5; box-shadow: 0 0 16px #64e6a5; }
  .name { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis;
          white-space: nowrap; font-weight: 700; }
  .size { color: #6f7a92; font-size: .8rem; white-space: nowrap; }
  .get { display: inline-flex; align-items: center; gap: 8px; height: 38px;
         padding: 0 16px; color: #04121a; font: 700 .8rem inherit; text-decoration: none;
         background: #2de2ff; border-radius: 10px; white-space: nowrap; }
  .get:hover { filter: brightness(1.12); }
  main { flex: 1; display: grid; place-items: center; padding: max(16px, 3vw);
         min-height: 0; }
  img, video { max-width: 100%; max-height: calc(100svh - 140px);
               border-radius: 12px; background: #05080f; }
  audio { width: min(560px, 100%); }
  iframe { width: min(1000px, 100%); height: calc(100svh - 140px);
           border: 1px solid rgba(255,255,255,.1); border-radius: 12px;
           background: #05080f; }
  @media (max-width: 560px) { .size { display: none; } }
</style>
</head>
<body>
  <header>
    <a class="who" href="/">vitazgio.ru</a>
    <span class="name">__NAME__</span>
    <span class="size">__SIZE__</span>
    <a class="get" href="__SAVE__" download>Скачать</a>
  </header>
  <main>__BODY__</main>
</body>
</html>
"""
    return (html.replace("__ICONLINKS__", ICON_LINKS)
                .replace("__NAME__", name)
                .replace("__SIZE__", size)
                .replace("__SAVE__", save)
                .replace("__BODY__", body))


@app.get("/api/drop/qr")
@login_required
def drop_qr():
    """Ссылка картинкой: показать телефону, а не диктовать вслух.

    Рисуем прямо на сервере в SVG — он чёткий на любом экране и весит
    считанные килобайты. Кодируем только свои же ссылки на этот сайт."""
    url = (request.args.get("url") or "").strip()[:900]
    if not url.startswith(request.host_url.rstrip("/")):
        return "Чужая ссылка", 400
    try:
        import segno
    except ImportError:
        return "Нечем нарисовать", 501
    buf = io.BytesIO()
    segno.make(url, error="m").save(buf, kind="svg", scale=1, border=2,
                                    dark="#04121c", light="#ffffff", xmldecl=False)
    response = Response(buf.getvalue(), mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "private, max-age=600"
    return response


@app.delete("/api/drop/<item_id>")
@login_required
def drop_delete(item_id):
    # Трек или папку фонотеки удаляем прямо в ней: в дропе они только видны.
    if item_id.startswith("mt_") or item_id.startswith("mf_"):
        return _drop_music_delete(item_id)
    with drop_lock:
        if item_id in drop_items:
            _drop_trash(item_id)             # в корзину, не насовсем
            _drop_write_index()
    return jsonify(ok=True)


def _drop_music_delete(item_id):
    """Удаление из фонотеки по запросу из дропа. Корзины у фонотеки нет —
    предупреждение об этом висит на самой кнопке."""
    with music_lock:
        if item_id.startswith("mt_"):
            track = music_items.pop(item_id[3:], None)
            if track:
                still = any(t["file"] == track["file"] for t in music_items.values())
                if not still:
                    _music_unlink(os.path.join(MUSIC_DIR, track["file"]))
                _music_write_index()
            return jsonify(ok=True)
        fid = item_id[3:]
        if fid not in music_folders:
            return jsonify(error="Папка не найдена."), 404
        # вместе с папкой уносим её подпапки и треки
        doomed, queue = {fid}, [fid]
        while queue:
            cur = queue.pop()
            for k, v in music_folders.items():
                if v.get("parent", "") == cur and k not in doomed:
                    doomed.add(k)
                    queue.append(k)
        for k in [k for k, v in music_items.items() if v.get("folder", "") in doomed]:
            track = music_items.pop(k)
            still = any(t["file"] == track["file"] for t in music_items.values())
            if not still:
                _music_unlink(os.path.join(MUSIC_DIR, track["file"]))
        for k in doomed:
            music_folders.pop(k, None)
        _music_write_index()
    return jsonify(ok=True)


@app.post("/api/drop/trash/unlock")
@login_required
def drop_trash_unlock():
    """Открывает корзину по паролю. Дальше действия с ней разрешены до конца
    сессии — как в проводнике, где второй раз пароль не спрашивают."""
    payload = request.get_json(silent=True) or {}
    if not _drop_trash_ok(payload.get("password")):
        return jsonify(error="Неверный пароль."), 403
    session["drop_trash"] = True
    return jsonify(ok=True)


@app.get("/api/drop/trash")
@login_required
def drop_trash_list():
    if not session.get("drop_trash"):
        return jsonify(error="Корзина закрыта."), 403
    with drop_lock:
        _drop_sweep_trash()
        rows = []
        for root in _drop_trash_roots():
            v = drop_items[root]
            row = {"id": root, "kind": v["kind"], "name": v["name"],
                   "deleted": v.get("deleted"), "size": v.get("size", 0)}
            if v["kind"] == "folder":
                row["size"] = _drop_trash_subtree_bytes(root)
            rows.append(row)
        rows.sort(key=lambda x: -(x["deleted"] or 0))
        return jsonify(items=rows, trash=_drop_trash_bytes(),
                       used=_drop_used(), quota=DROP_QUOTA, ttl_days=30)


@app.post("/api/drop/<item_id>/restore")
@login_required
def drop_restore(item_id):
    if not session.get("drop_trash"):
        return jsonify(error="Корзина закрыта."), 403
    with drop_lock:
        item = drop_items.get(item_id)
        if not item or not item.get("deleted"):
            return jsonify(error="Не найдено в корзине."), 404
        # Папки-родителя могло уже не быть или она сама в корзине — тогда
        # возвращаем в корень, чтобы не потерялось.
        parent = item.get("parent")
        if parent and (parent not in drop_items or drop_items[parent].get("deleted")):
            parent = None
            item["parent"] = None
        item["name"] = _drop_unique_name(item["name"], parent)
        item["deleted"] = None
        _drop_write_index()
    return jsonify(ok=True)


@app.delete("/api/drop/trash/<item_id>")
@login_required
def drop_trash_purge(item_id):
    if not session.get("drop_trash"):
        return jsonify(error="Корзина закрыта."), 403
    with drop_lock:
        item = drop_items.get(item_id)
        if not item or not item.get("deleted"):
            return jsonify(error="Не найдено в корзине."), 404
        _drop_discard(item_id)               # теперь насовсем
        _drop_write_index()
    return jsonify(ok=True)


@app.delete("/api/drop/trash")
@login_required
def drop_trash_empty():
    """Выкинуть всю корзину разом.

    Удалять по одному, когда там сотня файлов, — занятие на полчаса. Сносим
    только то, что лежит в корзине верхним уровнем: вложенное уедет вместе с
    папкой, за это отвечает _drop_discard."""
    if not session.get("drop_trash"):
        return jsonify(error="Корзина закрыта."), 403
    with drop_lock:
        _drop_sweep_trash()
        roots = list(_drop_trash_roots())
        for item_id in roots:
            _drop_discard(item_id)
        if roots:
            _drop_write_index()
        return jsonify(ok=True, gone=len(roots), trash=_drop_trash_bytes(),
                       used=_drop_used(), quota=DROP_QUOTA)


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
        .cabinet { min-height: 100svh; padding: clamp(24px, 4vw, 54px); background: linear-gradient(135deg, rgba(10,18,32,.25), transparent 60%); display: flex; flex-direction: column; }
        .cabinet-header { display: flex; align-items: center; gap: 20px; }
        .cabinet-header .back { width: 44px; height: 44px; flex: none; display: grid; place-items: center;
          color: #2de2ff; text-decoration: none; border: 1px solid rgba(45,226,255,.3); border-radius: 50%;
          background: rgba(45,226,255,.07); transition: all .18s; }
        .cabinet-header .back:hover { color: #fff; border-color: #2de2ff; background: rgba(45,226,255,.18); }
        .cabinet-header .back svg { width: 20px; height: 20px; display: block; }
        h1 { margin: 0; font-size: clamp(1.7rem, 3.6vw, 2.6rem); font-weight: 700; letter-spacing: -.02em;
             color: #eaf6ff; text-shadow: 0 0 22px rgba(45,226,255,.35); }
        h1 span { color: #2de2ff; text-shadow: 0 0 22px rgba(45,226,255,.5); }
        .logout-form { margin: 0; }
        .logout-button { padding: 10px 16px; color: #dffaff; font: 700 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.07); cursor: pointer; }
        .logout-button:hover { border-color: #2de2ff; background: rgba(45,226,255,.14); }
        .install-button { margin-left: auto; color: #1a0d04; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); }
        .install-button:hover { border: 0; background: linear-gradient(90deg, #ff8f4f, #ffc379); }
        [hidden] { display: none !important; }
        .workspace { flex: 1 1 auto; min-width: 0; margin-top: clamp(22px, 3.5vw, 40px);
                     display: flex; flex-direction: column; min-height: 0; }
        .workspace > .dash { flex: 1 1 auto; }
        .workspace > .cab { flex: none; }
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
        .cabinet-cols { display: flex; align-items: stretch; gap: 20px; max-width: 1900px; flex: 1 1 auto; min-height: 0; }
        .rail { width: 268px; flex: none; display: flex; flex-direction: column; gap: 12px;
                margin-top: clamp(22px, 3.5vw, 40px); }
        /* плеер добирает высоту до низа левой колонки */
        .rail .player { flex: 1 1 auto; min-height: 320px; display: flex;
                        flex-direction: column; }
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
        .pl-list { margin-top: 11px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,.08);
                    flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; }
        .pl-list-head { display: flex; justify-content: space-between; color: #55607a; font-size: .64rem; letter-spacing: .1em; text-transform: uppercase; }
        /* Высота списка постоянная — колонка не «дышит» вслед за левой стороной. */
        #pl-tracks { flex: 1 1 auto; min-height: 0; margin-top: 4px; overflow-y: auto; scrollbar-width: thin;
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
        .dash { padding: 20px 22px 22px; border: 1px solid rgba(45,226,255,.16); background: rgba(10,17,30,.72); display: flex; flex-direction: column; }
        .dash-title { margin: 0 0 16px; color: #8f99ab; font: 700 .82rem "Cascadia Code", Consolas, monospace; letter-spacing: .12em; text-transform: uppercase; flex: none; }

        /* Панель с логотипом. Модификатор --right зеркалит: логотип справа. */
        /* ── Сервисы кабинета ──────────────────────────────────────────
           Форма говорит о поведении: что разворачивается прямо здесь —
           обычный прямоугольник со стрелкой вниз; что открывается своей
           страницей — плитка-замок, сцепленная с соседями ступенькой.
           Раскладка: NetBird строкой, ниже четыре плитки, потом две
           разворачивающиеся, внизу темы и копия. */
        .cab { display: grid; gap: 20px; grid-template-columns: repeat(4, 1fr); margin-top: 14px; }
        .c4 { grid-column: span 4; } .c2 { grid-column: span 2; }

        /* разворачивающиеся */
        .cabp { --a: #2de2ff; position: relative; border: 1px solid rgba(255,255,255,.1);
                border-radius: 11px; overflow: hidden; transform-origin: center;
                background: linear-gradient(100deg, color-mix(in srgb, var(--a) 9%, transparent),
                            rgba(255,255,255,.022) 55%);
                transition: border-color .17s, transform .17s ease; }
        .cabp:hover { border-color: color-mix(in srgb, var(--a) 50%, transparent);
                      transform: scale(1.012); z-index: 3; }
        .ex-head { position: relative; width: 100%; display: flex; align-items: center; gap: 13px;
                   padding: 19px 72px 19px 36px; cursor: pointer; color: inherit; text-align: left;
                   border: 0; background: none; font: inherit; }
        .ex-head::before { content: ""; position: absolute; left: 0; top: 11px; bottom: 11px; width: 2px;
                           border-radius: 2px; background: var(--a); box-shadow: 0 0 12px var(--a); }
        .ex-ic { width: 56px; height: 56px; flex: none; display: grid; place-items: center; }
        .ex-ic svg, .ex-ic img { width: 100%; height: 100%; object-fit: contain; display: block; }
        .ex-tx { flex: 1; min-width: 0; }
        .ex-tx b { display: block; color: #f8fbff; font-size: 1.34rem; font-weight: 800; }
        .ex-tx i { display: block; margin-top: 5px; font-style: normal; color: #9fadc2; font-size: .92rem; }
        .ex-ar { flex: none; color: var(--a); font-size: 1rem; opacity: .75; transition: transform .25s; }
        .ex-head[aria-expanded="true"] .ex-ar { transform: rotate(180deg); }

        /* плитки-замок: сцепляются ступенькой, как детали в пазу */
        .zrow { display: flex; }
        .z { --a: #2de2ff; --s: 56px; --g: 11px; position: relative; flex: 1 1 0; min-width: 0; min-height: 172px;
             display: flex; flex-direction: column; color: inherit; text-decoration: none;
             margin-left: calc(var(--s) * -1); cursor: pointer; border: 0; font: inherit;
             padding: 0; text-align: left; transform-origin: center;
             transition: filter .18s, transform .18s ease;
             background: linear-gradient(150deg, color-mix(in srgb, var(--a) 30%, #0b1020),
                         color-mix(in srgb, var(--a) 7%, #0b1020));
             clip-path: polygon(calc(var(--s) + var(--g) / 2) 0, calc(100% - var(--g) / 2) 0,
                        calc(100% - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) 100%, calc(var(--g) / 2) 100%,
                        calc(var(--g) / 2) calc(50% + var(--g) / 2),
                        calc(var(--s) + var(--g) / 2) calc(50% + var(--g) / 2)); }
        .z:first-child { margin-left: 0;
             clip-path: polygon(0 0, calc(100% - var(--g) / 2) 0,
                        calc(100% - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) 100%, 0 100%); }
        .z:last-child {
             clip-path: polygon(calc(var(--s) + var(--g) / 2) 0, 100% 0, 100% 100%,
                        calc(var(--g) / 2) 100%, calc(var(--g) / 2) calc(50% + var(--g) / 2),
                        calc(var(--s) + var(--g) / 2) calc(50% + var(--g) / 2)); }
        .z:hover { filter: brightness(1.35) saturate(1.1); transform: scale(1.02); z-index: 3; }
        .z .ztop { flex: 0 0 50%; display: flex; align-items: center; gap: 13px;
                   padding: 0 72px 0 calc(var(--s) + 36px); }
        .z:first-child .ztop { padding-left: 36px; }
        .z-ic { width: 50px; height: 50px; flex: none; display: grid; place-items: center; }
        .z-ic svg, .z-ic img { width: 100%; height: 100%; object-fit: contain; display: block; }
        .z .ztop b { color: #f8fbff; font-size: 1.3rem; font-weight: 800; line-height: 1.2; }
        .z .zbot { flex: 1; display: flex; align-items: center; justify-content: space-between; gap: 10px;
                   padding: 0 calc(var(--s) + 30px) 0 36px; }
        .z:last-child .zbot { padding-right: 30px; }
        .z .zbot i { font-style: normal; color: #b3c0d4; font-size: .92rem; line-height: 1.4;
                     display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
                     overflow: hidden; line-height: 1.25; }
        .z .zbot em { font-style: normal; flex: none; color: var(--a); font-size: 1.1rem; opacity: .85;
                      transition: transform .25s; }
        .z[aria-expanded="true"] .zbot em { transform: rotate(180deg); }

        /* тело панели, которая живёт в ряду плиток */
        .zbody { border: 1px solid rgba(255,255,255,.1); border-radius: 11px;
                 background: rgba(255,255,255,.025); }
        .zbody > .panel-body { padding: 14px 16px; }

        /* На широком мониторе не оставляем пустое поле справа: колонки
           раздаются, правая полоса и плитки становятся крупнее. */
        @media (min-width: 2200px) {
          .cabinet-cols { max-width: none; gap: 30px; }
          .rail { width: 340px; }
          .cab { gap: 24px; }
          .z { --s: 68px; --g: 13px; min-height: 200px; }
          .z-ic { width: 58px; height: 58px; }
          .z .ztop b { font-size: 1.48rem; }
          .z .zbot i { font-size: 1rem; }
          .z .ztop { padding: 0 88px 0 calc(var(--s) + 44px); gap: 17px; }
          .z:first-child .ztop { padding-left: 44px; }
          .z .zbot { padding: 0 calc(var(--s) + 40px) 0 44px; }
          .z:last-child .zbot { padding-right: 40px; }
          .ex-head { padding: 24px 88px 24px 44px; gap: 17px; }
          .ex-ic { width: 56px; height: 56px; }
          .ex-tx b { font-size: 1.36rem; } .ex-tx i { font-size: 1rem; }
        }


        /* Раскрытая карточка «горит», как свеча: чуть увеличена, ярче
           заливка и цветной ореол по контуру, дышит вдох-выдох. */
        .z[aria-expanded="true"] { transform: scale(1.02); z-index: 3;
                                   animation: cab-glow 3.4s ease-in-out infinite; }
        .cabp:has(.ex-head[aria-expanded="true"]) {
                                   transform: scale(1.012); z-index: 3;
                                   border-color: color-mix(in srgb, var(--a) 70%, transparent);
                                   animation: cab-glow-box 3.4s ease-in-out infinite; }
        @keyframes cab-glow {
          0%, 100% { filter: brightness(1.32) saturate(1.15)
                      drop-shadow(0 0 12px color-mix(in srgb, var(--a) 70%, transparent)); }
          50%      { filter: brightness(1.44) saturate(1.22)
                      drop-shadow(0 0 22px color-mix(in srgb, var(--a) 85%, transparent))
                      drop-shadow(0 0 34px color-mix(in srgb, var(--a) 45%, transparent)); }
        }
        @keyframes cab-glow-box {
          0%, 100% { box-shadow: 0 0 16px color-mix(in srgb, var(--a) 22%, transparent),
                      inset 0 0 22px color-mix(in srgb, var(--a) 12%, transparent); }
          50%      { box-shadow: 0 0 28px color-mix(in srgb, var(--a) 40%, transparent),
                      0 0 52px color-mix(in srgb, var(--a) 20%, transparent),
                      inset 0 0 28px color-mix(in srgb, var(--a) 18%, transparent); }
        }
        @media (prefers-reduced-motion: reduce) {
          .z[aria-expanded="true"],
          .cabp:has(.ex-head[aria-expanded="true"]) { animation: none; }
        }

        @media (max-width: 620px) {
          .cab { grid-template-columns: repeat(2, 1fr); gap: 9px; }
          .c4, .c2 { grid-column: span 2; }
          .zrow { flex-wrap: wrap; gap: 9px 0; }
          .z { --s: 34px; --g: 9px; flex: 1 1 calc(50%); min-height: 148px; }
          .z:nth-child(3) { margin-left: 0;
             clip-path: polygon(0 0, calc(100% - var(--g) / 2) 0,
                        calc(100% - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) calc(50% - var(--g) / 2),
                        calc(100% - var(--s) - var(--g) / 2) 100%, 0 100%); }
          .z:nth-child(3) .ztop { padding-left: 9px; }
          .z:nth-child(2) {
             clip-path: polygon(calc(var(--s) + var(--g) / 2) 0, 100% 0, 100% 100%,
                        calc(var(--g) / 2) 100%, calc(var(--g) / 2) calc(50% + var(--g) / 2),
                        calc(var(--s) + var(--g) / 2) calc(50% + var(--g) / 2)); }
          .z:nth-child(2) .zbot { padding-right: 9px; }
          .z .ztop { padding: 0 32px 0 calc(var(--s) + 16px); gap: 9px; }
          .z:first-child .ztop, .z:nth-child(3) .ztop { padding-left: 16px; }
          .z .zbot { padding: 0 calc(var(--s) + 14px) 0 16px; }
          .z-ic { width: 30px; height: 30px; }
          .z .ztop b { font-size: .86rem; }
          .z .zbot i { font-size: .68rem; -webkit-line-clamp: 3; line-height: 1.32; }
          .ex-head { padding: 13px 30px 13px 16px; gap: 11px; }
          .ex-ic { width: 36px; height: 36px; }
          .ex-tx b { font-size: .92rem; } .ex-tx i { font-size: .68rem; }
        }
        .log-more { width: 100%; margin-top: 8px; padding: 9px 12px; cursor: pointer;
                    color: #9fd8ff; font: 700 .76rem "Cascadia Code", Consolas, monospace;
                    border: 1px solid rgba(45,226,255,.28); border-radius: 9px;
                    background: rgba(45,226,255,.07); transition: .16s; }
        .log-more:hover { color: #fff; border-color: rgba(45,226,255,.6); background: rgba(45,226,255,.16); }
        .panel-body { padding: 0 18px 16px; }
        /* Резервная копия */
        .bk-note { margin: 0 0 12px; color: #8f99ab; font-size: .78rem; line-height: 1.6; }
        .bk-note.dim { color: #5d6a7d; font-size: .72rem; }
        .bk-note b { color: #cfe2ee; }
        .bk-keys { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
        .btn-line { display: inline-flex; align-items: center; justify-content: center;
                    height: 38px; padding: 0 16px; cursor: pointer; text-decoration: none;
                    color: #dffaff; font: 700 .76rem "Cascadia Code", Consolas, monospace;
                    border: 1px solid rgba(45,226,255,.28); border-radius: 10px;
                    background: rgba(45,226,255,.07); transition: .16s; }
        .btn-line:hover { color: #fff; border-color: #2de2ff; background: rgba(45,226,255,.16); }
        .btn-line.warn { color: #ffd0a0; border-color: rgba(255,140,60,.35);
                         background: rgba(255,140,60,.08); }
        .btn-line.warn:hover { color: #fff; border-color: #ff8c3c; background: rgba(255,140,60,.18); }

        /* Метрики */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); gap: 14px; flex: 1 1 auto; }
        .metrics-host { border: 1px solid rgba(255,255,255,.07); padding: 22px 24px; display: flex; flex-direction: column; gap: 18px; justify-content: center; }
        .metrics-host-name { font: 700 1.06rem "Cascadia Code", Consolas, monospace; color: #dfe6f2; margin: 0; }
        .metrics-bars { display: grid; grid-template-columns: 48px 1fr 52px; align-items: center; gap: 14px 12px; font-size: .92rem; }
        .metrics-label { color: #6b7385; }
        .metrics-track { height: 12px; background: rgba(255,255,255,.07); border-radius: 6px; overflow: hidden; }
        .metrics-fill { height: 100%; border-radius: 3px; transition: width .4s ease; }
        .fill-cpu  { background: linear-gradient(90deg,#2de2ff,#69e8ff); }
        .fill-ram  { background: linear-gradient(90deg,#ff782f,#ffb35c); }
        .fill-disk { background: linear-gradient(90deg,#a855f7,#c084fc); }
        .metrics-val { color: #e8fbff; text-align: right; white-space: nowrap; }
        .metrics-extra { display: flex; gap: 20px; margin: 0; font-size: .88rem; color: #8592a7; }
        .metrics-offline { color: #4a5060; font-size: 1rem; font-style: italic; text-align: center; }


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
          <a class="back" href="/" title="На главную" aria-label="На главную">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </a>
          <h1>Личный <span>кабинет</span></h1>
          <button class="logout-button install-button" id="install" type="button" hidden>Установить приложение</button>
        </header>
        <div class="cabinet-cols">
        <div class="workspace">

          <!-- Метрики: наверху, во всю ширину -->
          <section class="dash">
            <div class="dash-title">Метрики машин</div>
            <div class="metrics-grid" id="metrics-grid"><p class="widget-empty">Загрузка…</p></div>
          </section>

          <!-- Сервисы. Разворачивающиеся — прямоугольником, открывающиеся
               страницей — плитками-замком, сцепленными ступенькой. -->
          <div class="cab">

            <!-- NetBird: разворачивается прямо здесь -->
            <section class="cabp c4" style="--a:#ff7026">
              <button id="netbird-toggle" class="ex-head panel-head" type="button"
                      aria-expanded="false" aria-controls="netbird-devices">
                <span class="ex-ic"><img src="/static/netbird-official.png" alt=""></span>
                <span class="ex-tx"><b>NetBird</b><i>домашняя сеть · 8 устройств</i></span>
                <span class="ex-ar" aria-hidden="true">⌄</span>
              </button>
              <div id="netbird-devices" hidden>
                <ul class="device-list">{{DEVICE_ITEMS}}</ul>
              </div>
            </section>

            <!-- Четыре двери наружу: сцеплены замком -->
            <div class="zrow c4">
              <a class="z" href="/drop" style="--a:#f5c344">
                <span class="ztop">
                  <span class="z-ic">
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
                  <b>Личный дроп</b>
                </span>
                <span class="zbot"><i>перебросить файлы и текст между машинами</i><em aria-hidden="true">⟶</em></span>
              </a>

              <a class="z" href="/neuro" style="--a:#7b6bff">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 40" aria-hidden="true">
                      <path d="M22 7c-6 0-9 3.4-9 7.6 0 1.4.4 2.6 1.1 3.7-1.9 1-3.1 2.8-3.1 5 0 3.5 3 6.2 7 6.2"
                            fill="none" stroke="#4d6bfe" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M26 7c6 0 9 3.4 9 7.6 0 1.4-.4 2.6-1.1 3.7 1.9 1 3.1 2.8 3.1 5 0 3.5-3 6.2-7 6.2"
                            fill="none" stroke="#d97757" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M24 8v24" stroke="#8b7bff" stroke-width="2" stroke-opacity=".5"/>
                      <circle cx="15" cy="14" r="1.8" fill="#8b7bff"/>
                      <circle cx="33" cy="14" r="1.8" fill="#f0a184"/>
                      <circle cx="15" cy="26" r="1.8" fill="#4d6bfe"/>
                      <circle cx="33" cy="26" r="1.8" fill="#d97757"/>
                    </svg>
                  </span>
                  <b>Нейронки</b>
                </span>
                <span class="zbot"><i>два чата: DeepSeek в облаке, Claude дома</i><em aria-hidden="true">⟶</em></span>
              </a>

              <a class="z" href="/notebook" style="--a:#0a7ce0">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 40 48" aria-hidden="true">
                      <defs>
                        <linearGradient id="nb-cover" x1="0" y1="0" x2="1" y2="1">
                          <stop offset="0" stop-color="#3aa0f5"/><stop offset="1" stop-color="#0a63c4"/>
                        </linearGradient>
                        <linearGradient id="nb-page" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#dce9f9"/>
                        </linearGradient>
                      </defs>
                      <rect x="3" y="2" width="34" height="44" rx="5" fill="url(#nb-cover)"/>
                      <path d="M9 7h16l7 7v25a2.5 2.5 0 0 1-2.5 2.5h-20A2.5 2.5 0 0 1 7 39V9.5A2.5 2.5 0 0 1 9.5 7Z"
                            fill="url(#nb-page)"/>
                      <path d="M25 7v5a2 2 0 0 0 2 2h5Z" fill="#9dc7ef"/>
                      <path d="M12 21h16M12 27h16M12 33h10" stroke="#1668c4" stroke-width="2.2"
                            stroke-linecap="round"/>
                    </svg>
                  </span>
                  <b>Блокнот</b>
                </span>
                <span class="zbot"><i>заметки, ссылки и файлы по вкладкам</i><em aria-hidden="true">⟶</em></span>
              </a>

              <a class="z" href="/music" style="--a:#35e0f0">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 40" aria-hidden="true">
                      <path d="M18 30V8l20-4v22" fill="none" stroke="#35e0f0" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                      <circle cx="13" cy="30" r="6" fill="#35e0f0" fill-opacity=".2" stroke="#35e0f0" stroke-width="3"/>
                      <circle cx="33" cy="26" r="6" fill="#35e0f0" fill-opacity=".2" stroke="#35e0f0" stroke-width="3"/>
                    </svg>
                  </span>
                  <b>Музыка</b>
                </span>
                <span class="zbot"><i>фонотека и плеер в отдельном окне</i><em aria-hidden="true">⟶</em></span>
              </a>
            </div>

            <!-- Второй ряд замком: две разворачиваются панелью снизу,
                 темы уходят своей страницей, копия тоже разворачивается. -->
            <div class="zrow c4">
              <button class="z panel-head" id="devices-toggle" type="button"
                      aria-expanded="false" aria-controls="devices-body" style="--a:#63f5ad">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                      <rect x="4" y="10" width="28" height="19" rx="2.5" stroke="#63f5ad" stroke-width="2.6"/>
                      <path d="M2 33h32" stroke="#63f5ad" stroke-width="2.6" stroke-linecap="round"/>
                      <rect x="30" y="20" width="14" height="22" rx="2.5" fill="#0d1321" stroke="#a8ffd6" stroke-width="2.6"/>
                      <path d="M35 38h4" stroke="#a8ffd6" stroke-width="2.2" stroke-linecap="round"/>
                    </svg>
                  </span>
                  <b>Запомнить устройства</b>
                </span>
                <span class="zbot"><i>вход без пароля на 90 дней на своих</i><em aria-hidden="true">⌄</em></span>
              </button>

              <button class="z panel-head" id="loginlog-toggle" type="button"
                      aria-expanded="false" aria-controls="loginlog-body" style="--a:#2de2ff">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                      <circle cx="24" cy="24" r="17" stroke="#2de2ff" stroke-width="2.6" stroke-opacity=".55"/>
                      <path d="M24 13v11l7.5 4.5" stroke="#7fe9ff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M24 7a17 17 0 0 1 14.6 25.7" stroke="#2de2ff" stroke-width="2.6" stroke-linecap="round"/>
                      <circle cx="24" cy="24" r="2.6" fill="#7fe9ff"/>
                    </svg>
                  </span>
                  <b>Журнал входов</b>
                </span>
                <span class="zbot"><i>кто и когда заходил, за две недели</i><em aria-hidden="true">⌄</em></span>
              </button>

              <a class="z" href="/themes" style="--a:#ff3fa4">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                      <path d="M24 6c8 0 13 5.5 13 13v7c0 3.5-2 5.5-4.5 6.5L31 38H17l-1.5-5.5C13 31.5 11 29.5 11 26v-7C11 11.5 16 6 24 6Z" stroke="#ff3fa4" stroke-width="2.4"/>
                      <path d="M24 14v18M17 20h14M18 27h12" stroke="#2de2ff" stroke-width="1.8" stroke-linecap="round"/>
                      <circle cx="24" cy="14" r="2.6" fill="#2de2ff"/>
                      <path d="M17 41h14" stroke="#ff3fa4" stroke-width="2.4" stroke-linecap="round"/>
                    </svg>
                  </span>
                  <b>Тестовые темы</b>
                </span>
                <span class="zbot"><i>витрина оформления · киберпанк</i><em aria-hidden="true">⟶</em></span>
              </a>

              <button class="z panel-head" id="backup-toggle" type="button"
                      aria-expanded="false" aria-controls="backup-body" style="--a:#4ade80">
                <span class="ztop">
                  <span class="z-ic">
                    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
                      <path d="M8 14c0-3.3 7.2-6 16-6s16 2.7 16 6-7.2 6-16 6-16-2.7-16-6Z" stroke="#63f5ad" stroke-width="2.4"/>
                      <path d="M8 14v10c0 3.3 7.2 6 16 6s16-2.7 16-6V14" stroke="#63f5ad" stroke-width="2.4"/>
                      <path d="M8 24v10c0 3.3 7.2 6 16 6s16-2.7 16-6V24" stroke="#2de2ff" stroke-width="2.4"/>
                    </svg>
                  </span>
                  <b>Резервная копия</b>
                </span>
                <span class="zbot"><i>скачать всё архивом и вернуть обратно</i><em aria-hidden="true">⌄</em></span>
              </button>
            </div>

            <!-- Панели этого ряда раскрываются снизу, во всю ширину -->
            <div class="zbody c4" id="devices-body" hidden>
              <div class="panel-body">
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
            </div>

            <div class="zbody c4" id="loginlog-body" hidden>
              <div class="panel-body">
                <div id="loginlog-list"><p class="widget-empty">Загрузка…</p></div>
              </div>
            </div>

            <div class="zbody c4" id="backup-body" hidden style="margin-bottom:32px">
              <div class="panel-body">
                <p class="bk-note" id="bk-size">считаю, сколько всего накопилось…</p>
                <div class="bk-keys">
                  <a class="btn-line" id="bk-light" href="/api/backup/export?kind=light">
                    Скачать записи</a>
                  <a class="btn-line" id="bk-full" href="/api/backup/export?kind=full">
                    Скачать всё целиком</a>
                  <button class="btn-line warn" id="bk-restore" type="button">Загрузить копию</button>
                  <input type="file" id="bk-file" accept=".zip,application/zip" hidden>
                </div>
                <p class="bk-note" id="bk-msg"></p>
                <p class="bk-note dim" id="bk-robot"></p>
              </div>
            </div>

          </div>

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
                <button class="pl-icon" id="pl-pop" type="button"
                        title="Плеер поверх сайта — не пропадёт при переходах">⧉</button>
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
            <!-- Общий движок сайта. Подключаем синхронно и до скрипта кабинета:
                 плеер тут берёт его звук, поэтому трек не обрывается, когда
                 уходишь в дроп или блокнот. -->
            <script src="/vg-player.js"></script>
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

        // ── Резервная копия ──
        {
          const head = document.getElementById("backup-toggle");
          const body = document.getElementById("backup-body");
          if (head && body) {
            const size = (n) => {
              n = n || 0;
              if (n < 1024) return n + " Б";
              if (n < 1048576) return (n / 1024).toFixed(0) + " КБ";
              if (n < 1073741824) return (n / 1048576).toFixed(1) + " МБ";
              return (n / 1073741824).toFixed(2) + " ГБ";
            };
            let asked = false;
            // Показ/скрытие делает общий обработчик .panel-head[aria-controls];
            // нам остаётся один раз подгрузить размеры при первом раскрытии.
            head.addEventListener("widget-open", async (ev) => {
              if (!ev.detail || asked) return;
              asked = true;
              try {
                const r = await fetch("/api/backup/state", { credentials: "same-origin" });
                const d = await r.json();
                document.getElementById("bk-size").innerHTML =
                  "Записи, статьи и настройки: <b>" + size(d.light.size) + "</b> (" +
                  d.light.files + " файлов).<br>Всё вместе с дропом и музыкой: <b>" +
                  size(d.full.size) + "</b> (" + d.full.files + " файлов).";
                document.getElementById("bk-robot").textContent = d.robot
                  ? "Ключ для программы задан: копию можно забирать снаружи по нему, без входа в кабинет."
                  : "Чтобы копии забирала программа с домашнего сервера, задайте на сервере ключ BACKUP_TOKEN.";
              } catch (e) {
                document.getElementById("bk-size").textContent = "Не удалось посчитать размер.";
              }
            });

            const file = document.getElementById("bk-file");
            const msg = document.getElementById("bk-msg");
            document.getElementById("bk-restore").addEventListener("click", () => {
              if (!confirm("Развернуть копию поверх нынешних данных?\\n\\n" +
                           "Файлы из архива заменят одноимённые. Лишнего не удаляем.")) return;
              file.click();
            });
            file.addEventListener("change", async () => {
              const f = file.files[0];
              file.value = "";
              if (!f) return;
              msg.textContent = "Разворачиваю копию…";
              const form = new FormData();
              form.append("file", f);
              try {
                const r = await fetch("/api/backup/import",
                  { method: "POST", credentials: "same-origin", body: form });
                const d = await r.json().catch(() => ({}));
                msg.textContent = r.ok
                  ? "Готово: вернулось " + d.files + " файлов. Обновите страницу."
                  : (d.error || "Не вышло развернуть копию.");
              } catch (e) { msg.textContent = "Сервер не ответил."; }
            });
          }
        }

        // ── Плеер ──
        {
          const box = document.getElementById("player");
          // Звук общий на весь сайт — берём его у движка, если тот поднялся.
          const audio = (window.VGP && window.VGP.audio) || document.getElementById("pl-audio");
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
              // Отдаём очередь общему движку — тогда трек не оборвётся при
              // уходе со страницы, а виджет поверх сайта подхватит его.
              if (window.VGP) {
                window.VGP.adopt(tracks.map(t => ({
                  id: "m_" + t.id, title: t.title, artist: t.artist || "", folder: "",
                  url: "/api/music/file/" + encodeURIComponent(t.id) })), index);
              }
            };

            // Кнопка ⧉ — развернуть плеер, который висит поверх сайта.
            const pop = el("pl-pop");
            if (pop) pop.addEventListener("click", () => {
              if (window.VGP) window.VGP.open();
            });

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
          const FIRST = 5;          // сразу показываем только последние пять
          let rows = null;

          // Рисуем либо короткий список, либо весь. Кнопку показываем, только
          // когда за пятью записями действительно что-то есть.
          const draw = (all) => {
            if (!rows.length) { listEl.innerHTML = '<p class="widget-empty">Нет записей</p>'; return; }
            const fails = rows.filter(e => e.kind && e.kind !== "ok").length;
            const head = fails
              ? `<p class="log-alarm">Неудачных попыток за две недели: ${fails}</p>` : "";
            const shown = all ? rows : rows.slice(0, FIRST);
            const more = !all && rows.length > FIRST
              ? `<button class="log-more" type="button">Показать все · ${rows.length}</button>` : "";
            listEl.innerHTML = head + shown.map(e => {
              const bad = e.kind && e.kind !== "ok";
              return `<div class="log-row${bad ? " log-bad" : ""}"><span class="log-ts">${esc(e.ts)}</span><span class="log-ip">${esc(e.ip)}</span><span class="log-ua">${esc(e.ua)}</span></div>`;
            }).join("") + more;
            const btn = listEl.querySelector(".log-more");
            if (btn) btn.addEventListener("click", () => draw(true));
          };

          const load = async () => {
            try {
              const r = await fetch("/api/login-log", { credentials: "same-origin" });
              rows = await r.json();
              draw(false);
            } catch {}
          };
          // Каждое открытие начинается заново с пяти: закрыл, открыл — снова пять.
          if (toggle) toggle.addEventListener("widget-open", e => {
            if (!e.detail) return;
            if (rows) draw(false); else load();
          });
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
    # Окно с кодом — значок «страны DIY». Строки подсвечиваются сверху вниз,
    # внизу мигает курсор: программа не картинка, она живёт.
    "code": _pixel_svg([
        "....................",
        "....................",
        "..KKKKKKKKKKKKKKKK..",
        "..KTTTTTTTTTTTTTTK..",
        "..KTrrTggTyyTTTTTK..",
        "..KTTTTTTTTTTTTTTK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KS111111111SSSSK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KSSS22222222SSSK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KSSS33333SSSSSSK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KS4444444SSSSSSK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KSccSSSSSSSSSSSK..",
        "..KSSSSSSSSSSSSSSK..",
        "..KKKKKKKKKKKKKKKK..",
        "....................",
        "....................",
    ], {
        "K": ("#48566b", None), "S": ("#151a22", None), "T": ("#2f3846", None),
        "r": ("#ff3b53", None), "g": ("#ffd84a", None), "y": ("#63f5ad", None),
        "1": ("#2de2ff", "px-f1"), "2": ("#63f5ad", "px-f2"),
        "3": ("#ffd84a", "px-f3"), "4": ("#2de2ff", "px-f4"),
        "c": ("#cdd8e6", "px-blink"),
    }),
    # Человек за компом — значок личного кабинета. Очки светятся тем же
    # классом, что и синяя строка на экране: это её отражение, и разойтись
    # по фазе они не могут в принципе.
    "me": _pixel_svg([
        "....................",
        "....................",
        ".MMMMMMMMM..........",
        ".MSSSSSSSM..HHHH....",
        ".MSSSSSSSM.HHHHHH...",
        ".MS22222SM.FFFFFFF..",
        ".MSSSSSSSM.FFFFFFF..",
        ".MS1111SSM.11FFFFF..",
        ".MSSSSSSSM.FFFFFFF..",
        ".MS33333SM..FFFFF...",
        ".MSSSSSSSM...fff....",
        ".MMMMMMMMM...fff....",
        "....MMM....CCCCCC...",
        "....MMM...CCCCCCCC..",
        "..........CCCCCCCCC.",
        "TTTTTTTTTTTTTTTTTTTT",
        "TTTTTTTTTTTTTTTTTTTT",
        "....................",
        "....................",
        "....................",
    ], {
        "M": ("#48566b", None), "S": ("#151a22", None), "T": ("#232a35", None),
        "F": ("#d2a07d", None), "f": ("#a97a58", None),
        "H": ("#3a2a22", None), "C": ("#2f3846", None),
        "1": ("#2de2ff", "px-f1"), "2": ("#63f5ad", "px-f2"), "3": ("#ffd84a", "px-f3"),
    }),
    # ── Себастьян: робот-дворецкий. Шесть вариантов на выбор, в деле
    # используется тот, что назван в SEBASTIAN_ICON. Все нарисованы в общем
    # пиксельном стиле полки: тёмный корпус, бирюзовые глаза, у каждого своя
    # деталь — цилиндр, бабочка, поднос, монокль.
    # 1. Классика: цилиндр, бабочка, руки по швам
    "butler1": _pixel_svg([
        "......HHHHHH......",
        "......HHHHHH......",
        "....HHHHHHHHHH....",
        "......MMMMMM......",
        ".....MMMMMMMM.....",
        ".....MeeMMeeM.....",
        ".....MMMMMMMM.....",
        "......MMwwMM......",
        ".......MMMM.......",
        "....FFFFbbFFFF....",
        "...FFFFFbbFFFFF...",
        "...FFwwFFFFwwFF...",
        "...FFFFFFFFFFFF...",
        "...FF.FFFFFF.FF...",
        "......FFFFFF......",
        "......FF..FF......",
        "......FF..FF......",
        ".....hhh..hhh.....",
    ], {
        "H": ("#151a22", None), "M": ("#48566b", None), "F": ("#2f3846", None),
        "e": ("#2de2ff", "px-blink"), "w": ("#dfe8f3", None),
        "b": ("#ff3b53", None), "h": ("#232a35", None),
    }),
    # 2. Голова-экран: вместо лица дисплей с бегущей строкой
    "butler2": _pixel_svg([
        "....MMMMMMMMMM....",
        "....MSSSSSSSSM....",
        "....MS1SS11SSM....",
        "....MSSSSSSSSM....",
        "....MS2SSSS2SM....",
        "....MSSSSSSSSM....",
        "....MS333333SM....",
        "....MSSSSSSSSM....",
        "....MMMMMMMMMM....",
        "........MM........",
        "....FFFFbbFFFF....",
        "...FFFFFbbFFFFF...",
        "...FFwwFFFFwwFF...",
        "...FFFFFFFFFFFF...",
        "...FF.FFFFFF.FF...",
        "......FFFFFF......",
        "......FF..FF......",
        ".....hhh..hhh.....",
    ], {
        "M": ("#48566b", None), "S": ("#0b2231", "px-screen"), "F": ("#2f3846", None),
        "1": ("#2de2ff", "px-f1"), "2": ("#63f5ad", "px-f2"), "3": ("#ffd84a", "px-f3"),
        "w": ("#dfe8f3", None), "b": ("#ff3b53", None), "h": ("#232a35", None),
    }),
    # 3. С подносом: в одной руке поднос с чашкой
    "butler3": _pixel_svg([
        ".....HHHHHH.......",
        "...HHHHHHHHHH.....",
        ".....MMMMMM.......",
        "....MMMMMMMM......",
        "....MeeMMeeM......",
        "....MMMMMMMM......",
        ".....MMwwMM.......",
        "......MMMM........",
        "...FFFFbbFFFF.....",
        "..FFFFFbbFFFFF....",
        "..FFwwFFFFwwFF.cc.",
        "..FFFFFFFFFFFFtccc",
        "..FF.FFFFFF.FFtttt",
        ".....FFFFFF.......",
        ".....FF..FF.......",
        "....hhh..hhh......",
    ], {
        "H": ("#151a22", None), "M": ("#48566b", None), "F": ("#2f3846", None),
        "e": ("#2de2ff", "px-blink"), "w": ("#dfe8f3", None), "b": ("#ff3b53", None),
        "h": ("#232a35", None), "t": ("#8b98ab", None), "c": ("#dfe8f3", "px-blink2"),
    }),
    # 4. Круглая голова-шар с одним большим глазом и моноклем
    "butler4": _pixel_svg([
        "......HHHHHH......",
        "....HHHHHHHHHH....",
        ".....MMMMMMMM.....",
        "....MMMMMMMMMM....",
        "....MMMeeeeMMM....",
        "....MMeEEEEeMM....",
        "....MMMeeeeMMM....",
        ".....MMMMMMMM.....",
        "......MMMMMM......",
        "........MM........",
        "....FFFFbbFFFF....",
        "...FFFFFbbFFFFF...",
        "...FFFFFFFFFFFF...",
        "...FF.FFFFFF.FF...",
        "......FFFFFF......",
        "......FF..FF......",
        ".....hhh..hhh.....",
    ], {
        "H": ("#151a22", None), "M": ("#48566b", None), "F": ("#2f3846", None),
        "e": ("#0b2231", None), "E": ("#2de2ff", "px-screen"),
        "b": ("#ffd84a", None), "h": ("#232a35", None),
    }),
    # 5. Парящий: вместо ног — подушка света
    "butler5": _pixel_svg([
        "......HHHHHH......",
        "....HHHHHHHHHH....",
        "......MMMMMM......",
        ".....MMMMMMMM.....",
        ".....MeeMMeeM.....",
        ".....MMMMMMMM.....",
        "......MMwwMM......",
        ".......MMMM.......",
        "....FFFFbbFFFF....",
        "...FFFFFbbFFFFF...",
        "...FFwwFFFFwwFF...",
        "...FFFFFFFFFFFF...",
        "....FFFFFFFFFF....",
        ".....FFFFFFFF.....",
        "......FFFFFF......",
        ".....gggggggg.....",
        "....gg......gg....",
        "..................",
    ], {
        "H": ("#151a22", None), "M": ("#48566b", None), "F": ("#2f3846", None),
        "e": ("#2de2ff", "px-blink"), "w": ("#dfe8f3", None), "b": ("#ff3b53", None),
        "g": ("#2de2ff", "px-blink2"),
    }),
    # 6. Строгий: высокий воротник, руки за спиной, глаза-щёлочки
    "butler6": _pixel_svg([
        ".....HHHHHHHH.....",
        "...HHHHHHHHHHHH...",
        ".....MMMMMMMM.....",
        "....MMMMMMMMMM....",
        "....MeeMMMMeeM....",
        "....MMMMMMMMMM....",
        ".....MMMMMMMM.....",
        "......MMMMMM......",
        "....wwwMMMMwww....",
        "...FFwwbbbbwwFF...",
        "...FFFFbbbbFFFF...",
        "...FFFFFFFFFFFF...",
        "...FFFFFFFFFFFF...",
        "....FFFFFFFFFF....",
        "......FF..FF......",
        "......FF..FF......",
        ".....hhh..hhh.....",
    ], {
        "H": ("#151a22", None), "M": ("#48566b", None), "F": ("#232a35", None),
        "e": ("#2de2ff", "px-blink"), "w": ("#dfe8f3", None),
        "b": ("#8b98ab", None), "h": ("#151a22", None),
    }),
    # Динамик — значок музыкальной вкладки. Волн две: ближняя горит всегда,
    # дальняя мигает, поэтому значок дышит «одна волна — две» и без наведения.
    "speaker": _pixel_svg([
        "......hh......",
        ".....hcc..W...",
        "....hccc.wW...",
        "hhhhcccc.wW...",
        "hccccccc.wW...",
        "hccccccc.wW...",
        "hccccccc.wW...",
        "hhhhcccc.wW...",
        "....hccc.wW...",
        ".....hcc..W...",
        "......hh......",
    ], {
        "h": ("#48566b", None), "c": ("#2f3846", None),
        "w": ("#2de2ff", None), "W": ("#2de2ff", "px-blink2"),
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
        .quota { margin-left: auto; min-width: 262px; }
        /* Две подписи вокруг шкалы: сверху сколько занято всего (папка),
           снизу сколько в корзине (кликабельно). */
        .quota-line { display: flex; align-items: center; gap: 8px; color: #8f99ab;
                      font-size: .9rem; font-family: inherit; text-align: left;
                      background: none; border: 0; padding: 0; width: 100%; }
        .quota-line b { color: #cfe2ee; font-weight: 700; }
        .quota-line .qi { width: 18px; height: 18px; flex: none; display: grid; place-items: center; }
        .quota-line .qi svg { width: 18px; height: 18px; display: block; }
        .quota-used { margin-bottom: 6px; }
        .quota-used .qi { color: #f5c344; }
        .quota-can { margin-top: 6px; cursor: pointer; transition: color .16s; }
        .quota-can .qi { color: #e8eef6; }
        .quota-can:hover { color: #ffffff; }
        .quota-can:hover .qi { color: #ffffff; }
        /* Шкала: слева обычная заливка (живые файлы), дальше белым — корзина. */
        .quota-bar { position: relative; height: 7px; background: rgba(255,255,255,.08); overflow: hidden; }
        .quota-fill { position: absolute; left: 0; top: 0; height: 100%; width: 0;
                      background: linear-gradient(90deg, #2de2ff, #63f5ad); transition: width .4s; }
        .quota-fill.hot { background: linear-gradient(90deg, #ffb35c, #ff6b81); }
        .quota-trash { position: absolute; top: 0; left: 0; height: 100%; width: 0;
                       background: rgba(255,255,255,.85); transition: width .4s, left .4s; }

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
        /* Отправка слева, возврат из папки — прижат к правому краю. */
        .composer-bar { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
        .composer-bar .up { margin-left: auto; color: #8ee9ff; border-color: rgba(45,226,255,.35); }
        .composer-bar .up:hover { color: #04121c; background: #2de2ff; border-color: #2de2ff; }

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
        /* Значок видео и звука кликабелен — метим треугольником в углу,
           иначе не понять, что по нему можно ткнуть. */
        .ico.play { position: relative; cursor: pointer; }
        .ico.play::after { content: ""; position: absolute; right: 2px; bottom: 2px;
               width: 0; height: 0; border-left: 8px solid currentColor;
               border-top: 5px solid transparent; border-bottom: 5px solid transparent; }
        .ico.img, .ico.play, .ico.doc { cursor: pointer; }
        .ico.play:hover, .ico.doc:hover { background: color-mix(in srgb, var(--tint, #7d8798) 26%, transparent); }
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
        /* Корзина с красным крестом у папки MUSIK: показывает, что удалить
           нельзя. Сам значок приглушён, крест — поверх. */
        .act.nodel { position: relative; color: #6b7385; cursor: not-allowed; }
        .act.nodel::after { content: "✕"; position: absolute; inset: 0; display: grid;
                            place-items: center; color: #ff4d4d; font-size: .82rem; font-weight: 800;
                            text-shadow: 0 0 3px rgba(0,0,0,.6); }
        .act.nodel:hover { border-color: rgba(255,90,90,.45); background: rgba(255,90,90,.08); }
        .act.on { color: #63f5ad; border-color: rgba(99,245,173,.4); }

        /* На телефоне интерфейс и так в притык к пальцу, а вот на широком
           экране компьютера всё это выглядело мелко — увеличиваем разом
           контейнер, шрифты, кнопки и строки списка. */
        @media (min-width: 860px) {
          .wrap { max-width: 1320px; padding: 44px 48px; }
          h1 { font-size: 2.6rem; }
          .quota { min-width: 340px; }
          .quota-line { font-size: 1.16rem; }
          .quota-line .qi, .quota-line .qi svg { width: 24px; height: 24px; }
          .bar { gap: 12px; margin-top: 28px; }
          .btn { padding: 12px 20px; font-size: .86rem; }
          .search { height: 44px; padding: 0 16px; font-size: .88rem; }
          .crumbs { gap: 8px; margin-top: 22px; font-size: .86rem; }
          .composer { margin-top: 22px; }
          .composer textarea { min-height: 100px; padding: 15px 17px; font-size: .9rem; }
          .items { margin-top: 24px; gap: 11px; }
          .item { grid-template-columns: 58px minmax(0, 1fr) auto; gap: 3px 18px; padding: 15px 18px; }
          .ico { width: 44px; height: 54px; font-size: .58rem; }
          .ico.dir { width: 44px; height: 44px; }
          .ico.dir svg { width: 42px; height: 42px; }
          .nm { font-size: .96rem; }
          .meta { font-size: .76rem; }
          .act { padding: 7px 10px; font-size: .92rem; }
        }

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
        /* Имя новой папки: то же поле, что и часы у ссылки, только на всю
           ширину и без стрелочек счётчика. */
        .share-row input[type=text] { flex: 1; height: 36px; padding: 0 12px; color: #f4fbff;
                     font: 600 .85rem "Cascadia Code", Consolas, monospace;
                     border: 1px solid rgba(255,255,255,.14); outline: none; background: rgba(4,10,20,.65); }
        .share-row input:focus { border-color: rgba(45,226,255,.5); }
        .share-row input[type=checkbox] { width: 17px; height: 17px; margin: 0; accent-color: #2de2ff; }
        .share-note { margin: 0 0 16px; color: #5d6d80; font-size: .72rem; line-height: 1.5; }
        /* Режим ссылки: две кнопки-переключателя, выбранная залита. Срок и
           режим независимы, поэтому и стоят отдельными блоками. */
        .sh-modes { display: flex; gap: 8px; margin-bottom: 10px; }
        .sh-mode { flex: 1; height: 38px; color: #cfe2ee; cursor: pointer;
                   font: 700 .72rem "Cascadia Code", Consolas, monospace;
                   border: 1px solid rgba(255,255,255,.16); border-radius: 9px;
                   background: rgba(255,255,255,.05); transition: .16s; }
        .sh-mode:hover { border-color: rgba(45,226,255,.5); }
        .sh-mode.on { color: #04121c; border-color: #2de2ff; background: #2de2ff; }
        .share-btns { display: flex; gap: 10px; }
        .share-btns button { flex: 1; height: 36px; font: 700 .74rem "Cascadia Code", Consolas, monospace;
                     letter-spacing: .06em; cursor: pointer; color: #cfe2ee;
                     border: 1px solid rgba(255,255,255,.16); background: rgba(255,255,255,.05); }
        .share-btns button.go { color: #04121c; border-color: #2de2ff; background: #2de2ff; }
        .share-btns button.bad { color: #ff8f8f; border-color: rgba(255,90,90,.4); }

        /* Окно корзины */
        .trash-panel { width: min(560px, 100%); }
        .trash-panel h3 { margin: 0 0 12px; font-size: 1.05rem; letter-spacing: .04em; }
        .trash-note { margin: 0 0 14px; color: #8f9bad; font-size: .78rem; line-height: 1.5; }
        .trash-note b { color: #cfe2ee; }
        .trash-list { display: flex; flex-direction: column; gap: 8px;
                      max-height: 52vh; overflow-y: auto; margin-bottom: 14px; }
        .trash-row { display: flex; align-items: center; gap: 12px; padding: 10px 12px;
                     border: 1px solid rgba(255,255,255,.1); background: rgba(4,10,20,.5); }
        .trash-info { flex: 1; min-width: 0; }
        .trash-name { color: #e6eef8; font-size: .82rem;
                      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .trash-meta { margin-top: 3px; color: #6b7c8f; font-size: .68rem; }
        .trash-acts { flex: none; display: flex; gap: 6px; }
        .trash-acts .btn { height: 30px; padding: 0 11px; font-size: .72rem; }
        .btn.bad { color: #ff9aa6; border-color: rgba(255,90,110,.35); }
        .btn.bad:hover { color: #fff; border-color: #ff5a6e; background: rgba(255,90,110,.14); }
        .trash-empty { padding: 26px 0; color: #6b7c8f; text-align: center; font-size: .82rem; }
        /* «Очистить всё» слева, «Закрыть» справа: разные по весу действия
           не должны стоять вплотную, чтобы не промахнуться. */
        .trash-keys { display: flex; justify-content: space-between; gap: 10px; }
        .trash-keys .btn { height: 34px; }
        #trash-all i { font-style: normal; margin-left: 2px; padding: 1px 6px;
                       font-size: .68rem; border-radius: 999px;
                       color: #ffd0d6; background: rgba(255,90,110,.18); }

        /* Окно ввода пароля от корзины */
        .trash-lock { width: min(390px, 100%); text-align: left; }
        .trash-lock .tl-badge { display: grid; place-items: center; width: 46px; height: 46px;
                     margin-bottom: 16px; color: #dfe9f3; border: 1px solid rgba(255,255,255,.14);
                     border-radius: 12px; background: rgba(255,255,255,.05); }
        .trash-lock .tl-badge svg { width: 24px; height: 24px; }
        .trash-lock .tl-kick { color: #2de2ff; font: 700 .68rem/1 "Cascadia Code", Consolas, monospace;
                     letter-spacing: .16em; text-transform: uppercase; }
        .trash-lock h3 { margin: 10px 0 6px; font-size: 1.4rem; letter-spacing: -.02em; }
        .trash-lock .tl-sub { margin: 0 0 18px; color: #7f8ca0; font-size: .8rem; }
        .trash-lock input { width: 100%; height: 46px; padding: 0 14px; color: #f4fbff;
                     font: 700 1rem "Cascadia Code", Consolas, monospace;
                     border: 1px solid rgba(255,255,255,.14); outline: none; background: rgba(4,10,20,.65); }
        .trash-lock input:focus { border-color: #2de2ff; box-shadow: 0 0 0 3px rgba(45,226,255,.09); }
        .trash-lock .tl-err { min-height: 16px; margin: 8px 0 12px; color: #ff6ba8; font-size: .76rem; }

        /* Карточка папки: сколько весит и каким значком её пометить */
        .fi-stat { margin: 0 0 16px; color: #7f93a8; font-size: .76rem; line-height: 1.7; }
        .fi-stat b { color: #cfe2ee; font-weight: 700; }
        .fi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 16px; }
        .fi-cell { display: grid; place-items: center; height: 56px; cursor: pointer;
                   border: 1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.03); }
        .fi-cell svg { width: 27px; height: 27px; }
        .fi-cell:hover { border-color: rgba(45,226,255,.5); background: rgba(45,226,255,.09); }
        .fi-cell.on { border-color: #2de2ff; background: rgba(45,226,255,.16); }

        /* Ссылка кодом: белое поле обязательно, иначе камера не прочтёт. */
        .qr-box { display: grid; place-items: center; gap: 8px; margin: 0 0 14px; }
        .qr-box img { width: 190px; height: 190px; padding: 8px; border-radius: 10px;
                      background: #fff; image-rendering: pixelated; }
        .qr-box span { color: #6b7c8f; font-size: .68rem; letter-spacing: .08em;
                       text-transform: uppercase; }

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
        .lightbox img, .lightbox video { max-width: 100%; max-height: 100%; object-fit: contain;
                        border: 1px solid rgba(45,226,255,.25); box-shadow: 0 24px 70px rgba(0,0,0,.7); }
        .lightbox audio { width: min(560px, calc(100% - 40px)); }
        /* Читалка PDF занимает почти весь экран, со своей прокруткой и зумом */
        .lightbox .lb-pdf { width: min(1000px, 100%); height: 100%; border: 1px solid rgba(45,226,255,.25);
                            border-radius: 4px; background: #fff; box-shadow: 0 24px 70px rgba(0,0,0,.7); }
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
            <div class="quota-line quota-used">
              <span class="qi"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6a1 1 0 0 1 1-1h4l2 2h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1Z"/></svg></span>
              <span>Занято: <b id="quota-used">—</b> из <span id="quota-all">—</span></span>
            </div>
            <div class="quota-bar">
              <div class="quota-fill" id="quota-fill"></div>
              <div class="quota-trash" id="quota-trash-seg"></div>
            </div>
            <button class="quota-line quota-can" id="trash-open" type="button" title="Открыть корзину">
              <span class="qi"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg></span>
              <span>Корзина: <b id="quota-trash">—</b></span>
            </button>
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
          <div class="composer-bar">
            <button class="btn" id="send-text" type="button">Отправить текст</button>
            <!-- Возврат из папки. В цепочку сверху попадать неудобно: она
                 мелкая и уезжает наверх, а эта кнопка всегда под рукой. -->
            <button class="btn up" id="go-up" type="button" hidden>← Назад</button>
          </div>
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
        let upTo = null;            // куда уводит кнопка «назад»
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

        /* Что можно открыть прямо на странице. Список повторяет серверный:
           там он решает, чем показывать файл по публичной ссылке. */
        const VIEW_KINDS = {
          image: ["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif", "ico"],
          video: ["mp4", "webm", "m4v", "mov", "ogv"],
          audio: ["mp3", "ogg", "wav", "m4a", "opus", "flac", "aac"],
          pdf: ["pdf"],
        };
        const viewKind = name => {
          const ext = extOf(name);
          for (const kind in VIEW_KINDS) if (VIEW_KINDS[kind].includes(ext)) return kind;
          return "";
        };
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
          video:   ["Видео", "#ff3b3b",
            '<rect x="2.5" y="7" width="27" height="18" rx="5" fill="currentColor" fill-opacity=".2"/>' +
            '<rect x="2.5" y="7" width="27" height="18" rx="5"/>' +
            '<path d="M13.5 12.3v7.4l6.4-3.7Z" fill="currentColor" stroke="none"/>'],
          // Ромб со скруглёнными углами (0.4) обрезает глобус по контуру —
          // видна только часть сферы, что попадает внутрь. Центр глобуса ниже
          // центра ромба, поэтому снизу пропадает нижняя широта.
          work:    ["Работа", "#ff9d42",
            '<defs><clipPath id="fi-work-d"><rect x="6.4" y="6.4" width="19.2" height="19.2" rx="3.84" transform="rotate(45 16 16)"/></clipPath>' +
            '<clipPath id="fi-work-g"><circle cx="16" cy="25.6" r="10.21"/></clipPath></defs>' +
            '<g clip-path="url(#fi-work-d)"><g clip-path="url(#fi-work-g)">' +
            '<path d="M16 15.39V35.81"/><ellipse cx="16" cy="25.6" rx="5.63" ry="10.21"/>' +
            '<path d="M0 20.5h32M0 25.6h32M0 30.7h32"/></g>' +
            '<circle cx="16" cy="25.6" r="10.21"/></g>' +
            '<rect x="6.4" y="6.4" width="19.2" height="19.2" rx="3.84" transform="rotate(45 16 16)"/>'],
          // Корзина — тот же значок, что стоит у «Корзина:» под шкалой. Белый.
          trash:   ["Корзина", "#e8eef6",
            '<path d="M4.5 8h23"/>' +
            '<path d="M12.5 8V5.6a1.4 1.4 0 0 1 1.4-1.4h4.2a1.4 1.4 0 0 1 1.4 1.4V8"/>' +
            '<path d="M7 8h18l-1.3 18.4a2 2 0 0 1-2 1.85h-11.4a2 2 0 0 1-2-1.85Z" fill="currentColor" fill-opacity=".14"/>' +
            '<path d="M7 8h18l-1.3 18.4a2 2 0 0 1-2 1.85h-11.4a2 2 0 0 1-2-1.85Z"/>' +
            '<path d="M13 13v9.5M16 13v9.5M19 13v9.5"/>'],
          game:    ["Игра", "#ff7ab8",
            '<rect x="3" y="11" width="26" height="14" rx="7" fill="currentColor" fill-opacity=".2"/>' +
            '<rect x="3" y="11" width="26" height="14" rx="7"/>' +
            '<path d="M9 15v6M6 18h6"/><circle cx="21.5" cy="16.3" r="1.5" fill="currentColor" stroke="none"/>' +
            '<circle cx="25" cy="19.5" r="1.5" fill="currentColor" stroke="none"/>'],
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
          const kind = viewKind(it.name);
          if (kind === "pdf") {
            // PDF открываем прямо в дропе — значок кликабелен, но без
            // треугольника: это не воспроизведение, а просмотр.
            return `<span class="ico doc" data-act="view" title="Открыть PDF"
              style="--tint:${tintOf(ext)}">PDF</span>`;
          }
          if (kind) {
            // У видео и звука миниатюры нет, но открывать их тоже надо —
            // значок становится кнопкой и получает треугольник в углу.
            return `<span class="ico play" data-act="view"
              title="${kind === "video" ? "Смотреть" : "Слушать"}"
              style="--tint:${tintOf(ext)}">${esc(label)}</span>`;
          }
          return `<span class="ico" style="--tint:${tintOf(ext)}">${esc(label)}</span>`;
        };

        /* Окно выдачи ссылки: часы и галка «без срока». Бессрочная нужна,
           чтобы картинку можно было вставить адресом в настройки другого
           сайта — там ссылка с истечением через сутки бесполезна. */
        /* Что выбрали в прошлый раз — просмотр или скачивание. Первый раз
           ставим скачивание: это то, зачем ссылку делают чаще всего. */
        const lastMode = () => {
          try { return localStorage.getItem("vgShareMode") === "view" ? "view" : "dl"; }
          catch (e) { return "dl"; }
        };
        const rememberMode = mode => {
          try { localStorage.setItem("vgShareMode", mode); } catch (e) { /* и ладно */ }
        };

        const askShare = () => new Promise(resolve => {
          const box = document.createElement("div");
          box.className = "lightbox share-ask";
          let mode = lastMode();
          box.innerHTML =
            '<div class="share-panel">' +
              '<h3>Ссылка на файл</h3>' +
              '<div class="sh-modes">' +
                '<button type="button" class="sh-mode" data-mode="dl">Скачивание</button>' +
                '<button type="button" class="sh-mode" data-mode="view">Просмотр</button>' +
              '</div>' +
              '<p class="share-note" id="sh-hint"></p>' +
              '<label class="share-row"><span>Часов</span>' +
                '<input type="number" min="1" max="720" value="24" id="sh-h"></label>' +
              '<label class="share-row check"><input type="checkbox" id="sh-f">' +
                '<span>Без срока — не истекает никогда</span></label>' +
              '<div class="share-btns">' +
                '<button type="button" class="go" id="sh-ok">СОЗДАТЬ</button>' +
                '<button type="button" id="sh-no">ОТМЕНА</button>' +
              '</div>' +
            '</div>';
          document.body.appendChild(box);
          document.body.classList.add("modal-open");
          const hours = box.querySelector("#sh-h");
          const forever = box.querySelector("#sh-f");
          const hint = box.querySelector("#sh-hint");
          const paintMode = () => {
            box.querySelectorAll(".sh-mode").forEach(b =>
              b.classList.toggle("on", b.dataset.mode === mode));
            hint.textContent = mode === "view"
              ? "Открывает страницу с картинкой или видео. Кнопка «скачать» там тоже есть."
              : "Сразу скачивает файл, без промежуточных страниц.";
          };
          paintMode();
          box.querySelectorAll(".sh-mode").forEach(b =>
            b.addEventListener("click", () => { mode = b.dataset.mode; paintMode(); }));
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
            rememberMode(mode);
            shut(Object.assign({ mode: mode }, forever.checked
              ? { forever: true }
              : { hours: parseInt(hours.value, 10) || 24 }));
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

        /* Шкала занятости: слева живые файлы обычным цветом, дальше белым —
           корзина. Обе подписи — «Занято» и «Корзина» — берут числа отсюда. */
        const paintQuota = data => {
          const quota = data.quota || 0;
          const used = data.used || 0;
          const trash = data.trash || 0;
          const active = Math.max(0, used - trash);
          const activePct = quota ? Math.min(active / quota * 100, 100) : 0;
          const trashPct = quota ? Math.min(trash / quota * 100, 100 - activePct) : 0;
          $("quota-used").textContent = fmtSize(used);
          $("quota-all").textContent = fmtSize(quota);
          $("quota-trash").textContent = fmtSize(trash);
          $("quota-fill").style.width = activePct + "%";
          $("quota-fill").classList.toggle("hot", quota && used / quota > 0.8);
          const seg = $("quota-trash-seg");
          seg.style.left = activePct + "%";
          seg.style.width = trashPct + "%";
        };

        /* Дата удаления в корзине — коротко: ДД.ММ.ГГ, чч:мм. */
        const trashWhen = t => {
          const d = new Date((t || 0) * 1000);
          const p = n => String(n).padStart(2, "0");
          return p(d.getDate()) + "." + p(d.getMonth() + 1) + "." +
                 String(d.getFullYear()).slice(2) + ", " + p(d.getHours()) + ":" + p(d.getMinutes());
        };

        /* Корзина. Первый заход просит пароль (1224), дальше сессия помнит.
           Внутри — что удалено, с весом и датой; можно вернуть или снести
           насовсем. Само чистится через месяц. */
        const trashList = () => fetch("/api/drop/trash", { credentials: "same-origin" })
          .then(r => r.status === 403 ? null : r.json());

        const renderTrash = (panel, data) => {
          const items = data.items || [];
          const rows = items.length
            ? items.map(it =>
                '<div class="trash-row">' +
                  '<div class="trash-info">' +
                    '<div class="trash-name">' + esc(it.name) + '</div>' +
                    '<div class="trash-meta">' + (it.kind === "folder" ? "папка · " : "") +
                      fmtSize(it.size) + ' · удалено ' + trashWhen(it.deleted) + '</div>' +
                  '</div>' +
                  '<div class="trash-acts">' +
                    '<button class="btn" type="button" data-restore="' + esc(it.id) + '">Вернуть</button>' +
                    '<button class="btn bad" type="button" data-purge="' + esc(it.id) + '">Удалить</button>' +
                  '</div>' +
                '</div>').join("")
            : '<p class="trash-empty">Корзина пуста.</p>';
          panel.innerHTML =
            '<h3>Корзина</h3>' +
            '<p class="trash-note">Файлы лежат здесь до месяца, потом удаляются сами. ' +
              'Всего в корзине: <b>' + fmtSize(data.trash || 0) + '</b>.</p>' +
            '<div class="trash-list">' + rows + '</div>' +
            '<div class="trash-keys">' +
              (items.length
                ? '<button class="btn bad" type="button" id="trash-all">Очистить всё' +
                  ' <i>' + items.length + '</i></button>'
                : "") +
              '<button class="btn" type="button" id="trash-close">Закрыть</button>' +
            '</div>';
        };

        // Красивое окно ввода пароля от корзины: тот же тёмный стиль, что и
        // остальные окошки дропа, с подсказкой и ошибкой прямо в панели.
        const askTrashUnlock = () => new Promise((resolve) => {
          const box = document.createElement("div");
          box.className = "lightbox share-ask";
          box.innerHTML =
            '<div class="share-panel trash-lock">' +
              '<span class="tl-badge">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg>' +
              '</span>' +
              '<div class="tl-kick">Корзина · доступ</div>' +
              '<h3>Введите пароль</h3>' +
              '<p class="tl-sub">Пароль для прав админа.</p>' +
              '<input id="tl-pass" type="password" autocomplete="current-password" placeholder="Пароль">' +
              '<p class="tl-err" id="tl-err"></p>' +
              '<div class="share-btns">' +
                '<button type="button" id="tl-no">Отмена</button>' +
                '<button type="button" class="go" id="tl-ok">Открыть</button>' +
              '</div>' +
            '</div>';
          document.body.appendChild(box);
          document.body.classList.add("modal-open");
          const input = box.querySelector("#tl-pass");
          const err = box.querySelector("#tl-err");
          const okBtn = box.querySelector("#tl-ok");
          requestAnimationFrame(() => input.focus());
          const shut = (val) => {
            box.remove();
            document.body.classList.remove("modal-open");
            document.removeEventListener("keydown", onKey);
            resolve(val);
          };
          const tryOpen = async () => {
            okBtn.disabled = true;
            err.textContent = "";
            try {
              const r = await fetch("/api/drop/trash/unlock", {
                method: "POST", credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: input.value }) });
              if (r.ok) { shut(true); return; }
              err.textContent = "Неверный пароль.";
              input.select();
            } catch { err.textContent = "Сервер недоступен."; }
            finally { okBtn.disabled = false; }
          };
          const onKey = (e) => {
            if (e.key === "Escape") shut(false);
            if (e.key === "Enter") tryOpen();
          };
          okBtn.addEventListener("click", tryOpen);
          box.querySelector("#tl-no").addEventListener("click", () => shut(false));
          box.addEventListener("click", (e) => { if (e.target === box) shut(false); });
          document.addEventListener("keydown", onKey);
        });

        const openTrash = async () => {
          let data = await trashList();
          if (!data) {                                   // закрыта — просим пароль
            const ok = await askTrashUnlock();
            if (!ok) return;
            data = await trashList();
          }
          if (!data) { toast("Корзина недоступна", true); return; }
          const m = modal("");
          const panel = m.box.querySelector(".share-panel");
          panel.classList.add("trash-panel");
          renderTrash(panel, data);
          panel.addEventListener("click", async e => {
            if (e.target.closest("#trash-close")) { m.shut(); return; }
            const rest = e.target.closest("[data-restore]");
            const purge = e.target.closest("[data-purge]");
            const all = e.target.closest("#trash-all");
            try {
              if (all) {
                // Разом — значит разом: спрашиваем один раз, но честно
                // называем, сколько и на сколько мегабайт сейчас исчезнет.
                const many = (data.items || []).length;
                if (!confirm("Выкинуть из корзины всё — " + many + " " +
                             plural(many, ["объект", "объекта", "объектов"]) +
                             " на " + fmtSize(data.trash || 0) + "?\\n" +
                             "Это не отменить.")) return;
                const done = await api("/api/drop/trash", { method: "DELETE" });
                toast("Корзина пуста — выкинуто: " + (done.gone || many));
              } else if (rest) {
                await api("/api/drop/" + rest.dataset.restore + "/restore", { method: "POST" });
                toast("Возвращено");
              } else if (purge) {
                if (!confirm("Удалить насовсем? Это не отменить.")) return;
                await api("/api/drop/trash/" + purge.dataset.purge, { method: "DELETE" });
                toast("Удалено насовсем");
              } else { return; }
            } catch (err) { toast(err.message, true); return; }
            const nd = await trashList();
            if (nd) { data = nd; renderTrash(panel, nd); }
            load();                                       // обновить шкалу занятости
          });
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

        /* Создание папки: имя и сразу выбор значка — раньше значок ставили
           отдельным шагом уже после создания, а само имя спрашивал голый
           системный prompt(), который выглядел чужеродно на сайте. */
        const askFolder = () => new Promise(resolve => {
          let icon = "folder";
          let done = false;
          const finish = value => { if (!done) { done = true; resolve(value); } };
          const cells = Object.keys(FOLDER_ICONS).map(key => {
            const [label] = FOLDER_ICONS[key];
            return `<button type="button" class="fi-cell${key === icon ? " on" : ""}" data-icon="${key}"
              title="${esc(label)}" aria-label="${esc(label)}">${folderSvg(key)}</button>`;
          }).join("");
          const m = modal(
            "<h3>Новая папка</h3>" +
            '<label class="share-row"><span>Имя</span><input type="text" id="nf-name" maxlength="60" placeholder="Название"></label>' +
            '<p class="share-note">Значок папки</p>' +
            '<div class="fi-grid">' + cells + "</div>" +
            '<div class="share-btns">' +
              '<button type="button" class="go" id="nf-ok">СОЗДАТЬ</button>' +
              '<button type="button" id="nf-no">ОТМЕНА</button>' +
            "</div>");
          // Отмена приходит и кнопкой, и Escape, и щелчком мимо панели —
          // все три ведут в исходный m.shut(), поэтому резолвим прямо в нём.
          const closeBox = m.shut;
          m.shut = () => { closeBox(); finish(null); };
          const field = m.box.querySelector("#nf-name");
          field.focus();
          m.box.querySelectorAll(".fi-cell").forEach(cell => {
            cell.addEventListener("click", () => {
              icon = cell.dataset.icon;
              m.box.querySelectorAll(".fi-cell").forEach(c => c.classList.toggle("on", c === cell));
            });
          });
          m.box.querySelector("#nf-no").addEventListener("click", () => m.shut());
          const submit = () => {
            const name = field.value.trim();
            if (!name) { field.focus(); return; }
            finish({ name, icon });
            closeBox();
          };
          m.box.querySelector("#nf-ok").addEventListener("click", submit);
          field.addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
        });

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
          const life = (item.share_mode === "view" ? "просмотр · " : "скачивание · ") +
            (item.share_expires ? "истекает " + fmtDate(item.share_expires) : "без срока");
          const m = modal(
            "<h3>Ссылка активна</h3>" +
            '<div class="lk-url">' + esc(url) + "</div>" +
            '<p class="share-note">' + esc(life) + "</p>" +
            '<div class="qr-box" id="lk-qr" hidden>' +
              '<img alt="Ссылка кодом"><span>наведи телефоном</span></div>' +
            '<div class="share-btns">' +
              '<button type="button" class="go" id="lk-copy">⧉ КОПИРОВАТЬ</button>' +
              '<button type="button" id="lk-qrbtn">QR</button>' +
              '<button type="button" class="bad" id="lk-del">УДАЛИТЬ</button>' +
            "</div>");
          // Ссылку удобно не копировать, а показать телефону кодом.
          m.box.querySelector("#lk-qrbtn").addEventListener("click", () => {
            const box = m.box.querySelector("#lk-qr");
            const img = box.querySelector("img");
            if (!img.getAttribute("src"))
              img.src = "/api/drop/qr?url=" + encodeURIComponent(url);
            box.hidden = !box.hidden;
          });
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

        /* Файл во весь экран: картинка, видео или звук. Закрыть можно
           крестиком, щелчком по фону, Escape или кнопкой «назад» — последнее
           важно на телефоне, где крестик легко не заметить и по привычке
           смахнуть назад.

           Берём файл из /api/drop/view, а не из скачивания: там он отдаётся
           потоком байтов без типа, и видео от такого не играет. */
        const openImage = item => {
          const kind = item.thumb ? "image" : (viewKind(item.name) || "image");
          const box = document.createElement("div");
          box.className = "lightbox";
          let img;
          if (kind === "video") {
            img = document.createElement("video");
            img.controls = true;
            img.autoplay = true;
            img.playsInline = true;
          } else if (kind === "audio") {
            img = document.createElement("audio");
            img.controls = true;
            img.autoplay = true;
          } else if (kind === "pdf") {
            // Читалка PDF — родной просмотрщик браузера: листается и
            // масштабируется сам. Занимает почти весь экран.
            img = document.createElement("iframe");
            img.className = "lb-pdf";
            img.title = item.name;
          } else {
            img = document.createElement("img");
            img.alt = item.name;
          }
          img.src = "/api/drop/view/" + encodeURIComponent(item.id);
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
          // В корне цепочка ни к чему — там был бы одинокий ярлык «Дроп».
          // Показываем крошки только когда зашли в папку.
          if (!crumbs.length) {
            $("crumbs").innerHTML = "";
            upTo = null;
            $("go-up").hidden = true;
            return;
          }
          const parts = ['<button class="crumb" data-go="">Дроп</button>'];
          crumbs.forEach((c, i) => {
            parts.push("<span>/</span>");
            const last = i === crumbs.length - 1;
            parts.push(`<button class="crumb${last ? " here" : ""}" data-go="${esc(c.id)}">${esc(c.name)}</button>`);
          });
          $("crumbs").innerHTML = parts.join("");
          // Куда ведёт «назад»: предпоследняя папка цепочки, а из папки
          // первого уровня — в корень. В корне кнопку прячем: оттуда некуда.
          upTo = crumbs.length > 1 ? crumbs[crumbs.length - 2].id : null;
          $("go-up").hidden = crumbs.length === 0;
        };

        const render = () => {
          const needle = $("search").value.trim().toLowerCase();
          let list = items.filter(it => !needle || it.name.toLowerCase().includes(needle));
          list.sort(SORTS[sortKey][1]);
          // Особая папка MUSIK всегда в самом низу, какую бы сортировку ни выбрали.
          list.sort((a, b) => (a.special ? 1 : 0) - (b.special ? 1 : 0));
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
                ${it.music ? `
                  ${isFolder ? "" : `<button class="act" data-act="view" title="Слушать">▶</button>`}
                  <button class="act" data-act="dl" title="Скачать">⤓</button>
                  <button class="act" data-act="ren" title="${isFolder ? "Переименовать папку" : "Переименовать трек"}">✎</button>
                  <button class="act del" data-act="del" title="Удалить из фонотеки">🗑</button>
                ` : it.special ? `
                  <button class="act" data-act="zip" title="Скачать папку архивом">⤓</button>
                  <button class="act nodel" data-act="noren" title="Эту папку переименовать нельзя">✎</button>
                  <button class="act nodel" data-act="nodel" title="Эту папку удалить нельзя">🗑</button>
                ` : `
                ${isText ? `<button class="act" data-act="copy" title="Копировать">⧉</button>` : ""}
                ${isFolder ? "" : `<button class="act${it.share ? " on" : ""}" data-act="share" title="Ссылка для скачивания">🔗</button>`}
                ${isFolder
                  ? `<button class="act" data-act="zip" title="Скачать папку архивом">⤓</button>`
                  : `<button class="act" data-act="dl" title="Скачать">⤓</button>`}
                <button class="act" data-act="ren" title="Переименовать">✎</button>
                <button class="act del" data-act="del" title="Удалить">🗑</button>
                `}
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
            paintQuota(data);
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

        // Поле ввода внутри строки живёт по своим правилам: и долгий тык, и
        // правая кнопка на нём должны работать как в обычном поле, иначе не
        // вставить имя из буфера.
        const inField = el => !!(el && el.closest && el.closest("input, textarea"));

        $("items").addEventListener("touchstart", e => {
          touching = true;
          const row = e.target.closest(".item");
          if (!row || picking) return;
          if (e.target.closest("[data-act]")) return;     // кнопки строки не трогаем
          if (inField(e.target)) return;
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
          // На поле имени правая кнопка должна открыть меню браузера с
          // «вставить», а не начать выделение строк.
          if (inField(e.target)) return;
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
        $("trash-open").addEventListener("click", openTrash);
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
          /* Курсор стоит в поле ввода — не вмешиваемся вовсе. Раньше проверка
             была только на поле заметки, и вставка имени файла при
             переименовании улетала в новое сообщение вместо самого поля. */
          const field = e.target.closest && e.target.closest("input, textarea, [contenteditable]");
          if (field && field !== $("text-area")) return;
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
          const made = await askFolder();
          if (!made) return;
          try { await api("/api/drop/folder", { method: "POST", headers: { "Content-Type": "application/json" },
                                                body: JSON.stringify({ name: made.name, icon: made.icon, parent }) }); load(); }
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

        $("go-up").addEventListener("click", () => {
          parent = upTo;
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

          if (act === "zip") {
            // Пустую папку архивировать нечего — сразу говорим, а не отдаём
            // пользователю архив на двадцать два байта.
            if (!item.count) { toast("Папка пуста", true); return; }
            toast("Собираю архив: " + item.count + " " +
                  plural(item.count, ["объект", "объекта", "объектов"]) +
                  ", " + fmtSize(item.size || 0));
            window.location.assign("/api/drop/zip/" + id);
            return;
          }

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
              const life = (data.mode === "view" ? "просмотр, " : "скачивание, ") +
                           (data.forever ? "без срока" : "живёт " + data.hours + " ч");
              try { await navigator.clipboard.writeText(data.url); toast("Ссылка скопирована — " + life); }
              catch { prompt("Ссылка (" + life + "):", data.url); }
              load();
            } catch (err) { toast(err.message, true); }
            return;
          }

          if (act === "nodel") {
            toast("Папку MUSIK удалить нельзя — она для плеера", true);
            return;
          }

          if (act === "noren") {
            toast("Папку MUSIK переименовать нельзя — по имени её находит плеер", true);
            return;
          }

          if (act === "del") {
            const what = item.music
              ? (item.kind === "folder"
                  ? "Удалить папку «" + item.name + "» из фонотеки со всеми треками?\\n" +
                    "У фонотеки нет корзины — это насовсем."
                  : "Удалить трек «" + item.name + "» из фонотеки?\\nУ фонотеки нет корзины — это насовсем.")
              : item.kind === "folder"
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
            // Пока правим имя, строку нельзя таскать: нажатие мышью в поле
            // запускало перенос файла вместо установки курсора, и вставить
            // из буфера было нечем. Разметку потом перерисует load().
            row.draggable = false;
            input.focus();
            input.select();
            let saving = false;
            const save = async () => {
              if (saving) return;
              saving = true;
              const name = input.value.trim() ? input.value.trim() + ext : "";
              if (name && name !== item.name) {
                // Треки и папки фонотеки живут не в дропе, у них свои адреса.
                // Имя трека показано как «исполнитель — название»: если тире
                // на месте, так его и разбираем обратно.
                let url = "/api/drop/" + id, patch = { name };
                if (item.music && id.startsWith("mf_")) {
                  url = "/api/music/folder/" + id.slice(3);
                } else if (item.music && id.startsWith("mt_")) {
                  const cut = name.indexOf(" — ");
                  url = "/api/music/" + id.slice(3);
                  patch = cut > 0
                    ? { artist: name.slice(0, cut), title: name.slice(cut + 3) }
                    : { title: name };
                }
                try { await api(url, { method: "PATCH", headers: { "Content-Type": "application/json" },
                                       body: JSON.stringify(patch) }); }
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
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


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
# тематике, и у каждой свой цвет, свой значок и свой вид листания по
# умолчанию: программы удобно смотреть кладкой, платы — сотами, сервера —
# барабаном. Хозяин всё равно может переключить вид руками, выбор запомнится
# для каждой тематики отдельно.
DIY_THEMES = (
    {"id": "программы",  "name": "Программы",  "color": "#2de2ff", "view": 3,
     "hint": "код, приложения и всё, что запускается"},
    {"id": "устройства", "name": "Устройства", "color": "#ffd84a", "view": 5,
     "hint": "ESP, платы, паяльник и провода"},
    {"id": "сервера",    "name": "Сервера",    "color": "#63f5ad", "view": 2,
     "hint": "машины, сети и то, что крутится круглосуточно"},
    {"id": "разное",     "name": "Разное",     "color": "#b57cff", "view": 1,
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


def _diy_safe_name(raw):
    """Имя вложения: без путей и опасных символов, но кириллицу оставляем —
    хозяин зовёт файлы по-русски, и по этим же именам ссылается в коде."""
    name = os.path.basename((raw or "").strip()).replace("\\", "").replace("/", "")
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "", name).strip(". ")
    return name[:80]


def _diy_asset_path(item_id, name):
    safe = _diy_safe_name(name)
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


def _diy_load():
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


_diy_load()


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
                    safe = _diy_safe_name(name)
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
    app.logger.exception("Не удалось завести заготовки DIY — работаем без них")


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
        "shot": _diy_safe_name(head.get("обложка") or head.get("cover") or ""),
        "link": _notebook_clean_url(head.get("ссылка") or head.get("link") or ""),
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
            fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            _log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


def _diy_can_edit():
    """Пустил бы редактор этого гостя. Отдельно от декоратора: страница
    спрашивает об этом, ничего не меняя."""
    if session.get("authenticated"):
        return True
    fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
    if fresh:
        session["authenticated"] = True
        g.new_device_cookie = fresh
        _log_login("доверенное устройство")
        return True
    return False


@app.get("/api/diy")
def diy_list_api():
    can_edit = _diy_can_edit()
    with diy_lock:
        works = [_diy_public(k, v, can_edit) for k, v in _diy_sorted(can_edit)]
    return jsonify(works=works, can_edit=can_edit, kinds=list(DIY_KINDS),
                   themes=[dict(t) for t in DIY_THEMES])


@app.post("/api/diy")
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


@app.patch("/api/diy/<item_id>")
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


@app.delete("/api/diy/<item_id>")
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


@app.post("/api/diy/<item_id>/asset")
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
    name = _diy_safe_name(upload.filename)
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


@app.delete("/api/diy/<item_id>/asset/<path:name>")
@diy_editor_required
def diy_asset_delete_api(item_id, name):
    safe = _diy_safe_name(name)
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


@app.get("/diy/asset/<item_id>/<path:name>")
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
    safe = _diy_safe_name(name)
    if safe not in known:
        return "", 404
    path = _diy_asset_path(item_id, safe)
    if not path or not os.path.exists(path):
        return "", 404
    response = send_file(path, conditional=True)
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@app.post("/api/diy/<item_id>/cover")
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


@app.delete("/api/diy/<item_id>/cover")
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


@app.get("/diy/cover/<item_id>")
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


def _diy_render_body(item_id, body):
    """Подставляет в код статьи адреса вложений: {{имя.jpg}} превращается в
    ссылку на /diy/asset/<id>/имя.jpg. Больше ничего не трогаем — остальное
    хозяин пишет как обычный HTML."""
    from urllib.parse import quote

    def swap(match):
        name = _diy_safe_name(match.group(1))
        if not name:
            return match.group(0)
        return "/diy/asset/" + item_id + "/" + quote(name)

    return re.sub(r"\{\{\s*([^{}]+?)\s*\}\}", swap, body or "")


@app.get("/diy/a/<item_id>")
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

    body_html = _diy_render_body(item_id, snapshot["body"])
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

    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0d1321">
      <meta name="description" content="__DESC__">
      __ICONLINKS__
      <title>__TITLE__ · Страна DIY</title>
      <style>
        :root { color-scheme:dark; --bg:#0d1321; --line:rgba(255,255,255,.1);
                --muted:#8e9bb0; --ink:#eaf3fb; --pc:#2de2ff; --warm:#ffd84a;
                --ok:#63f5ad; --hot:#ff7a59; --ac:__ACCENT__; }
        * { box-sizing:border-box; }
        body { margin:0; min-height:100svh; color:var(--ink);
               font-family:"Cascadia Code", Consolas, monospace;
               background:radial-gradient(circle at top left, #192a44, #0d1321 55%); }

        /* полоска прочитанного наверху */
        .prog { position:fixed; left:0; top:0; height:2px; width:0; z-index:50;
                background:linear-gradient(90deg, var(--ac), var(--ok));
                box-shadow:0 0 12px var(--ac); transition:width .1s linear; }

        .wrap { width:min(840px, calc(100% - 34px)); margin:0 auto; padding:clamp(18px,3vw,38px) 0 90px; }
        .top { display:flex; align-items:center; gap:12px; margin-bottom:26px; }
        .back { display:inline-flex; align-items:center; gap:8px; height:38px; padding:0 15px;
                color:#cdd6e6; text-decoration:none; font:600 .78rem inherit;
                background:rgba(255,255,255,.05); border:1px solid var(--line);
                border-radius:10px; transition:.16s; }
        .back:hover { color:#fff; border-color:var(--ac); background:color-mix(in srgb, var(--ac) 12%, transparent); }
        .back svg { width:15px; height:15px; }
        .tags { display:flex; flex-wrap:wrap; gap:7px; margin-bottom:15px; }
        .kind, .tag, .draft { display:inline-flex; align-items:center; padding:4px 11px;
                border-radius:999px; font:700 .62rem inherit; letter-spacing:.13em; text-transform:uppercase; }
        .kind { color:#04121c; background:var(--ac); }
        .tag { color:#cfe0f0; background:rgba(255,255,255,.06); border:1px solid var(--line); }
        .draft { color:#ffd0a0; background:rgba(255,140,60,.16); }

        h1.title { margin:0 0 12px; font-size:clamp(1.7rem,5vw,2.9rem); line-height:1.06;
                   letter-spacing:-.03em; font-weight:800; color:#eaf6ff;
                   text-shadow:0 0 30px color-mix(in srgb, var(--ac) 35%, transparent); }
        .summary { margin:0 0 22px; max-width:64ch; color:var(--muted); font-size:1rem; line-height:1.65; }
        .srcline { display:flex; flex-wrap:wrap; gap:9px; margin:0 0 26px; }
        .srcline a { display:inline-flex; align-items:center; gap:8px; height:38px; padding:0 15px;
                     color:#04121c; text-decoration:none; font:700 .76rem inherit;
                     border-radius:10px; background:var(--ac); }
        .srcline a:hover { filter:brightness(1.08); }
        .srcline a.ghost { color:#cfe0f0; background:rgba(255,255,255,.05); border:1px solid var(--line); }
        .srcline a.ghost:hover { color:#fff; border-color:var(--ac); }
        .srcline svg { width:15px; height:15px; }
        hr.sep { border:0; border-top:1px solid var(--line); margin:0 0 30px; }

        /* ── тело статьи ────────────────────────────────────────────── */
        .article { font-size:.97rem; line-height:1.78; color:#dfe8f3; }
        .article > *:first-child { margin-top:0; }
        .article h2 { margin:2.2em 0 .6em; font-size:1.42rem; font-weight:800; letter-spacing:-.02em;
                      color:#eaf6ff; scroll-margin-top:20px; }
        .article h2::before { content:""; display:inline-block; width:16px; height:3px; border-radius:2px;
                              margin-right:11px; vertical-align:middle; background:var(--ac); }
        .article h3 { margin:1.7em 0 .5em; font-size:1.1rem; font-weight:700; color:#cfeaff; }
        .article p { margin:0 0 1.1em; }
        .article a { color:var(--pc); text-underline-offset:3px; }
        .article strong, .article b { color:#fff; }
        .article ul, .article ol { margin:0 0 1.2em; padding-left:1.35em; }
        .article li { margin:.35em 0; }
        .article li::marker { color:var(--ac); }
        .article hr { border:0; border-top:1px solid var(--line); margin:2em 0; }

        /* картинки: клик открывает во весь экран */
        .article img { max-width:100%; height:auto; display:block; margin:1.5em 0; cursor:zoom-in;
                       border-radius:14px; border:1px solid var(--line);
                       box-shadow:0 18px 44px rgba(0,0,0,.4); transition:transform .2s, border-color .2s; }
        .article img:hover { transform:translateY(-2px); border-color:color-mix(in srgb, var(--ac) 45%, transparent); }
        .article figure { margin:1.5em 0; }
        .article figure img { margin:0; }
        .article figcaption { margin-top:9px; color:var(--muted); font-size:.78rem; text-align:center; }
        /* .shots — ряд картинок, сам раскладывается по ширине */
        .article .shots { display:grid; gap:12px; margin:1.5em 0;
                          grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); }
        .article .shots img, .article .shots figure { margin:0; }
        .article .phone img { max-height:560px; width:auto; margin:0 auto; }

        /* врезки */
        .article .note, .article .warn, .article .ok {
          margin:1.5em 0; padding:14px 16px 14px 46px; position:relative; border-radius:12px;
          font-size:.9rem; line-height:1.65; border:1px solid var(--line); background:rgba(255,255,255,.03); }
        .article .note::before, .article .warn::before, .article .ok::before {
          position:absolute; left:16px; top:13px; font-weight:800; }
        .article .note { border-left:3px solid var(--pc); }
        .article .note::before { content:"i"; color:var(--pc); }
        .article .warn { border-left:3px solid var(--warm); }
        .article .warn::before { content:"!"; color:var(--warm); }
        .article .ok { border-left:3px solid var(--ok); }
        .article .ok::before { content:"✓"; color:var(--ok); }

        .article blockquote { margin:1.5em 0; padding:.7em 1.2em; color:#cdd6e6;
                              border-left:3px solid var(--ac);
                              background:color-mix(in srgb, var(--ac) 7%, transparent);
                              border-radius:0 12px 12px 0; }

        /* код */
        .article pre { margin:1.5em 0; padding:16px 18px; overflow-x:auto; border-radius:12px;
                       background:rgba(4,9,18,.9); border:1px solid var(--line);
                       font-size:.84rem; line-height:1.6; color:#d6e2f0; }
        .article code { font-family:inherit; font-size:.9em; padding:.12em .42em; border-radius:6px;
                        background:rgba(255,255,255,.08); color:#cfe6ff; }
        .article pre code { background:none; padding:0; color:inherit; }

        /* таблица характеристик */
        .article table { width:100%; margin:1.5em 0; border-collapse:collapse; font-size:.86rem; }
        .article th, .article td { padding:9px 12px; text-align:left; border-bottom:1px solid var(--line); }
        .article th { color:var(--muted); font-size:.7rem; letter-spacing:.09em; text-transform:uppercase; font-weight:700; }
        .article tr:hover td { background:rgba(255,255,255,.03); }

        /* чипы и кнопки-файлы */
        .article .chips { display:flex; flex-wrap:wrap; gap:7px; margin:1.2em 0; }
        .article .chips span { padding:5px 11px; border-radius:8px; font-size:.74rem;
                               color:#cfe0f0; background:rgba(255,255,255,.05); border:1px solid var(--line); }
        .article a.dl { display:inline-flex; align-items:center; gap:9px; margin:.4em 8px .4em 0;
                        padding:11px 17px; color:#04121c; text-decoration:none; font-weight:700;
                        border-radius:11px; background:var(--warm); }
        .article a.dl:hover { filter:brightness(1.08); }
        .article a.dl::before { content:"⤓"; font-size:1.05em; }

        /* плитки и шаги */
        .article .cards { display:grid; gap:12px; margin:1.5em 0;
                          grid-template-columns:repeat(auto-fit,minmax(215px,1fr)); }
        .article .cards > div { padding:15px 16px; border-radius:13px; border:1px solid var(--line);
                                background:linear-gradient(160deg, rgba(18,28,45,.7), rgba(9,14,24,.8)); }
        .article .cards b { display:block; margin-bottom:5px; color:#eaf6ff; font-size:.92rem; }
        .article .cards p { margin:0; color:var(--muted); font-size:.82rem; line-height:1.6; }
        .article .steps { counter-reset:st; list-style:none; padding:0; margin:1.5em 0; }
        .article .steps li { counter-increment:st; position:relative; margin:0 0 13px; padding:13px 16px 13px 52px;
                             border-radius:12px; border:1px solid var(--line); background:rgba(255,255,255,.03); }
        .article .steps li::before { content:counter(st); position:absolute; left:14px; top:12px;
                             width:24px; height:24px; display:grid; place-items:center; border-radius:8px;
                             font-size:.72rem; font-weight:800; color:#04121c; background:var(--ac); }

        /* лайтбокс */
        .lb { position:fixed; inset:0; z-index:120; display:grid; place-items:center; padding:22px;
              background:rgba(3,6,12,.93); backdrop-filter:blur(4px); }
        .lb img { max-width:100%; max-height:100%; border-radius:10px; border:1px solid rgba(255,255,255,.16); }
        .lb button { position:absolute; top:16px; right:18px; width:44px; height:44px; cursor:pointer;
                     color:#eaf6ff; font-size:1.5rem; border:1px solid rgba(255,255,255,.22);
                     border-radius:9px; background:rgba(10,16,26,.85); }
        .lb button:hover { color:#04121c; background:var(--pc); }

        /* наверх */
        .up { position:fixed; right:20px; bottom:96px; z-index:40; width:42px; height:42px;
              display:grid; place-items:center; cursor:pointer; opacity:0; pointer-events:none;
              color:#cfe0f0; border:1px solid var(--line); border-radius:12px;
              background:rgba(12,20,33,.9); transition:opacity .2s, color .16s, border-color .16s; }
        .up.on { opacity:1; pointer-events:auto; }
        .up:hover { color:#fff; border-color:var(--ac); }
        .up svg { width:17px; height:17px; }

        footer { margin-top:46px; padding-top:20px; border-top:1px solid var(--line);
                 display:flex; flex-wrap:wrap; gap:12px; align-items:center;
                 color:#66707f; font-size:.75rem; }
        footer a { color:#8fa2b8; text-decoration:none; }
        footer a:hover { color:var(--pc); }
        @media (prefers-reduced-motion: reduce) { * { transition:none !important; animation:none !important; } }
      </style>
    </head>
    <body>
      <div class="prog" id="prog"></div>
      <main class="wrap">
        <div class="top">
          <a class="back" href="/diy">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg>
            Страна DIY
          </a>
        </div>
        <div class="tags">__TAGS__</div>
        <h1 class="title">__TITLE__</h1>
        __SUMMARY__
        __SRC__
        __LINKS__
        <hr class="sep">
        <article class="article" id="art">__BODY__</article>
        <footer>
          <span>vitazgio.ru · страна DIY</span>
          <a href="/diy">← ко всем творениям</a>
        </footer>
      </main>
      <button class="up" id="up" type="button" title="Наверх" aria-label="Наверх">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5m0 0-6 6m6-6 6 6"/></svg>
      </button>

      <script>
      (() => {
        "use strict";
        /* полоска прочитанного */
        const prog = document.getElementById("prog");
        const up = document.getElementById("up");
        const onScroll = () => {
          const h = document.documentElement;
          const max = h.scrollHeight - h.clientHeight;
          const k = max > 0 ? h.scrollTop / max : 0;
          prog.style.width = (k * 100) + "%";
          up.classList.toggle("on", h.scrollTop > 500);
        };
        addEventListener("scroll", onScroll, { passive: true });
        onScroll();
        up.addEventListener("click", () => scrollTo({ top: 0, behavior: "smooth" }));

        /* картинки открываются во весь экран */
        document.getElementById("art").addEventListener("click", (e) => {
          const img = e.target.closest("img");
          if (!img) return;
          const box = document.createElement("div");
          box.className = "lb";
          const big = document.createElement("img");
          big.src = img.currentSrc || img.src;
          big.alt = img.alt || "";
          const x = document.createElement("button");
          x.type = "button"; x.textContent = "×"; x.setAttribute("aria-label", "Закрыть");
          box.append(big, x);
          document.body.appendChild(box);
          const shut = () => { box.remove(); document.removeEventListener("keydown", esc); };
          const esc = (ev) => { if (ev.key === "Escape") shut(); };
          x.addEventListener("click", shut);
          box.addEventListener("click", (ev) => { if (ev.target === box) shut(); });
          document.addEventListener("keydown", esc);
        });
      })();
      </script>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
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


# ---- Блокнот: страницы-вкладки с записями ---------------------------------
# Хозяйская записная книжка. Записи трёх видов: ссылка, текст и PDF. Всё
# лежит данными в DATA_DIR и переживает деплой, как дроп и DIY.
NOTEBOOK_DIR = os.path.join(DATA_DIR, "notebook")
NOTEBOOK_PATH = os.path.join(DATA_DIR, "notebook.json")
NOTEBOOK_TEXT_MAX = 20000
NOTEBOOK_ENTRY_LIMIT = 1000
NOTEBOOK_PDF_MAX = 25 * 1024 * 1024
NOTEBOOK_TYPES = ("link", "text", "pdf")
NOTEBOOK_BORDERS = ("solid", "dashed", "dotted", "double", "none")
NOTEBOOK_WIDTHS = ("half", "full")

notebook_data: dict = {"pages": [], "entries": {}}
notebook_lock = threading.Lock()
os.makedirs(NOTEBOOK_DIR, exist_ok=True)


def _notebook_pdf_path(entry_id):
    return os.path.join(NOTEBOOK_DIR, f"{entry_id}.pdf")


def _notebook_write():
    """Вызывать под notebook_lock."""
    try:
        tmp = NOTEBOOK_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(notebook_data, fh, ensure_ascii=False)
        os.replace(tmp, NOTEBOOK_PATH)
    except OSError:
        pass


def _notebook_load():
    try:
        with open(NOTEBOOK_PATH, encoding="utf-8") as fh:
            saved = json.load(fh) or {}
        notebook_data["pages"] = saved.get("pages", [])
        notebook_data["entries"] = saved.get("entries", {})
    except (OSError, ValueError):
        pass
    if not notebook_data["pages"]:
        notebook_data["pages"] = [{"id": str(uuid.uuid4()), "name": "Заметки"}]
    for e in notebook_data["entries"].values():
        e.setdefault("note", "")
        e.setdefault("width", "half")
        e.setdefault("border", "solid")
        e.setdefault("accent", "#2de2ff")
        e.setdefault("order", 0)


_notebook_load()


def _notebook_clean_url(raw):
    url = (raw or "").strip()[:600]
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")
    return url


def _notebook_entry_public(eid, e):
    row = {
        "id": eid, "page": e.get("page"), "type": e.get("type"),
        "title": e.get("title", ""), "width": e.get("width", "half"),
        "border": e.get("border", "solid"), "accent": e.get("accent", "#2de2ff"),
        "note": e.get("note", ""), "order": e.get("order", 0),
    }
    if e.get("type") == "link":
        row["url"] = e.get("url", "")
    elif e.get("type") == "text":
        row["text"] = e.get("text", "")
    elif e.get("type") == "pdf":
        row["pdf"] = bool(e.get("pdf"))
        row["filename"] = e.get("filename", "")
    return row


def _notebook_apply(e, payload):
    """Переносит присланные поля в запись, каждое — по своим правилам."""
    if "title" in payload:
        e["title"] = (payload.get("title") or "").strip()[:160]
    if "note" in payload:
        e["note"] = (payload.get("note") or "").strip()[:4000]
    if "url" in payload and e["type"] == "link":
        e["url"] = _notebook_clean_url(payload.get("url"))
    if "text" in payload and e["type"] == "text":
        e["text"] = (payload.get("text") or "")[:NOTEBOOK_TEXT_MAX]
    if payload.get("width") in NOTEBOOK_WIDTHS:
        e["width"] = payload["width"]
    if payload.get("border") in NOTEBOOK_BORDERS:
        e["border"] = payload["border"]
    ac = (payload.get("accent") or "").strip()
    if re.match(r"^#[0-9a-fA-F]{6}$", ac):
        e["accent"] = ac


@app.get("/api/notebook")
@login_required
def notebook_get_api():
    with notebook_lock:
        pages = list(notebook_data["pages"])
        entries = [_notebook_entry_public(k, v)
                   for k, v in notebook_data["entries"].items()]
    entries.sort(key=lambda x: x["order"])
    return jsonify(pages=pages, entries=entries, borders=list(NOTEBOOK_BORDERS))


@app.post("/api/notebook/page")
@login_required
def notebook_page_add():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:40] or "Без имени"
    pid = str(uuid.uuid4())
    with notebook_lock:
        notebook_data["pages"].append({"id": pid, "name": name})
        _notebook_write()
    return jsonify(id=pid, name=name)


@app.patch("/api/notebook/page/<pid>")
@login_required
def notebook_page_rename(pid):
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:40]
    if not name:
        return jsonify(error="Пустое имя."), 400
    with notebook_lock:
        page = next((p for p in notebook_data["pages"] if p["id"] == pid), None)
        if not page:
            return jsonify(error="Страница не найдена."), 404
        page["name"] = name
        _notebook_write()
    return jsonify(ok=True)


@app.delete("/api/notebook/page/<pid>")
@login_required
def notebook_page_delete(pid):
    with notebook_lock:
        pages = notebook_data["pages"]
        if len(pages) <= 1:
            return jsonify(error="Нельзя удалить единственную страницу."), 400
        notebook_data["pages"] = [p for p in pages if p["id"] != pid]
        gone = [k for k, v in notebook_data["entries"].items() if v.get("page") == pid]
        for k in gone:
            notebook_data["entries"].pop(k, None)
        _notebook_write()
    for k in gone:
        try:
            os.remove(_notebook_pdf_path(k))
        except OSError:
            pass
    return jsonify(ok=True)


@app.post("/api/notebook/entry")
@login_required
def notebook_entry_add():
    payload = request.get_json(silent=True) or {}
    etype = payload.get("type")
    if etype not in NOTEBOOK_TYPES:
        return jsonify(error="Неизвестный тип записи."), 400
    with notebook_lock:
        if len(notebook_data["entries"]) >= NOTEBOOK_ENTRY_LIMIT:
            return jsonify(error="Слишком много записей."), 400
        pages = notebook_data["pages"]
        page = payload.get("page")
        if not any(p["id"] == page for p in pages):
            page = pages[0]["id"] if pages else None
        eid = str(uuid.uuid4())
        order = 1 + max([v.get("order", 0) for v in notebook_data["entries"].values()],
                        default=0)
        e = {"page": page, "type": etype, "title": "", "note": "",
             "width": "half", "border": "solid", "accent": "#2de2ff",
             "order": order, "created": time.time()}
        if etype == "link":
            e["url"] = ""
        elif etype == "text":
            e["text"] = ""
        elif etype == "pdf":
            e["pdf"] = False
            e["filename"] = ""
        _notebook_apply(e, payload)
        if not e["title"]:
            e["title"] = {"link": "Ссылка", "text": "Заметка", "pdf": "PDF"}[etype]
        notebook_data["entries"][eid] = e
        _notebook_write()
    return jsonify(id=eid)


@app.patch("/api/notebook/entry/<eid>")
@login_required
def notebook_entry_edit(eid):
    payload = request.get_json(silent=True) or {}
    with notebook_lock:
        e = notebook_data["entries"].get(eid)
        if not e:
            return jsonify(error="Запись не найдена."), 404
        _notebook_apply(e, payload)
        if payload.get("page") and any(p["id"] == payload["page"] for p in notebook_data["pages"]):
            e["page"] = payload["page"]
        _notebook_write()
    return jsonify(ok=True)


@app.delete("/api/notebook/entry/<eid>")
@login_required
def notebook_entry_delete(eid):
    with notebook_lock:
        gone = notebook_data["entries"].pop(eid, None)
        if gone:
            _notebook_write()
    if gone:
        try:
            os.remove(_notebook_pdf_path(eid))
        except OSError:
            pass
    return jsonify(ok=True)


@app.post("/api/notebook/entry/<eid>/pdf")
@login_required
def notebook_entry_pdf(eid):
    with notebook_lock:
        e = notebook_data["entries"].get(eid)
        if not e or e.get("type") != "pdf":
            return jsonify(error="Запись не найдена."), 404
    upload = request.files.get("file")
    if not upload:
        return jsonify(error="Файл не выбран."), 400
    if request.content_length and request.content_length > NOTEBOOK_PDF_MAX + 8192:
        return jsonify(error="PDF больше 25 МБ."), 413
    if os.path.splitext(upload.filename or "")[1].lower() != ".pdf":
        return jsonify(error="Нужен файл PDF."), 415
    dest = _notebook_pdf_path(eid)
    upload.save(dest)
    if os.path.getsize(dest) > NOTEBOOK_PDF_MAX:
        os.remove(dest)
        return jsonify(error="PDF больше 25 МБ."), 413
    fname = _diy_safe_name(upload.filename) or "файл.pdf"
    with notebook_lock:
        e = notebook_data["entries"].get(eid)
        if e:
            e["pdf"] = True
            e["filename"] = fname
            _notebook_write()
    return jsonify(ok=True, filename=fname)


@app.get("/notebook/pdf/<eid>")
@login_required
def notebook_pdf_view(eid):
    with notebook_lock:
        e = notebook_data["entries"].get(eid)
    if not e or e.get("type") != "pdf" or not e.get("pdf"):
        return "", 404
    path = _notebook_pdf_path(eid)
    if not os.path.exists(path):
        return "", 404
    response = send_file(path, mimetype="application/pdf", conditional=True)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; object-src 'self'; img-src 'self' blob:; "
        "style-src 'unsafe-inline'; frame-ancestors 'self'")
    g.frameable = True
    return response


@app.get("/notebook")
@login_required
def notebook_page():
    """Блокнот: страницы-вкладки как в браузере, записи трёх видов. Оформлен
    в едином тёмном стиле сайта — бирюзовый акцент, шрифт Cascadia."""
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0d1321">
      <meta name="robots" content="noindex, nofollow">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Блокнот · vitazgio.ru</title>
      <style>
        /* Единый тёмный стиль сайта: тот же фон, бирюзовый акцент, Cascadia.
           Белый — только значок блокнота на карточке кабинета, не страница. */
        :root { --card:#111a2b; --ink:#e9fbff; --muted:#8f99ab;
                --line:rgba(255,255,255,.1); --accent:#2de2ff; }
        * { box-sizing: border-box; }
        body { margin:0; min-height:100svh; color:var(--ink);
               font-family:"Cascadia Code", Consolas, monospace;
               background:radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .wrap { max-width:1180px; margin:0 auto; padding:clamp(18px,3vw,40px) clamp(14px,3vw,32px) 80px; }
        .top { display:flex; align-items:center; gap:14px; margin-bottom:20px; }
        .back { width:44px; height:44px; flex:none; display:grid; place-items:center;
                color:var(--accent); text-decoration:none; border:1px solid rgba(45,226,255,.3);
                border-radius:50%; background:rgba(45,226,255,.07); transition:.18s; }
        .back:hover { color:#fff; border-color:var(--accent); background:rgba(45,226,255,.18); }
        .back svg { width:20px; height:20px; }
        h1 { margin:0; font-size:clamp(1.5rem,3.5vw,2.3rem); font-weight:700; letter-spacing:-.02em;
             color:#eaf6ff; text-shadow:0 0 22px rgba(45,226,255,.35); }
        h1 span { color:var(--accent); text-shadow:0 0 22px rgba(45,226,255,.5); }

        /* Вкладки-страницы как в браузере */
        .tabs { display:flex; align-items:flex-end; gap:4px; flex-wrap:wrap;
                border-bottom:1px solid var(--line); margin-bottom:18px; }
        .tab { display:inline-flex; align-items:center; gap:8px; height:38px; padding:0 13px;
               color:var(--muted); cursor:pointer; border:1px solid var(--line);
               border-bottom:none; border-radius:8px 8px 0 0; background:rgba(255,255,255,.03);
               position:relative; top:1px; font-size:.82rem; max-width:220px; }
        .tab.on { color:#eaf6ff; background:rgba(45,226,255,.08); font-weight:600;
                  box-shadow:0 -2px 0 var(--accent) inset; }
        .tab .nm { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .tab .x { width:18px; height:18px; flex:none; display:grid; place-items:center;
                  border-radius:50%; font-size:.9rem; color:#6b7385; }
        .tab .x:hover { background:rgba(255,90,110,.18); color:#ff6b81; }
        .tab-add { width:38px; height:34px; flex:none; display:grid; place-items:center;
                   cursor:pointer; color:var(--accent); border:1px dashed rgba(45,226,255,.35);
                   border-radius:8px; background:rgba(45,226,255,.05); position:relative; top:0; font-size:1.2rem; }
        .tab-add:hover { background:rgba(45,226,255,.14); }

        .bar { display:flex; align-items:center; gap:10px; margin-bottom:16px; }
        .btn { display:inline-flex; align-items:center; gap:8px; height:38px; padding:0 16px;
               color:#04121c; cursor:pointer; font:700 .8rem inherit; letter-spacing:.03em; border:0; border-radius:9px;
               background:linear-gradient(90deg,#2de2ff,#63f5ad); }
        .btn:hover { filter:brightness(1.08); }
        .btn.ghost { color:#cfe2ee; background:rgba(255,255,255,.05); border:1px solid var(--line); }
        .btn.ghost:hover { color:#fff; border-color:var(--accent); background:rgba(45,226,255,.1); }
        .btn svg { width:16px; height:16px; }

        .grid { display:flex; flex-wrap:wrap; gap:14px; align-items:flex-start; }
        .entry { background:rgba(10,17,30,.72); border-radius:12px; padding:14px 15px;
                 box-shadow:0 8px 26px rgba(0,0,0,.28); border:2px solid var(--accent);
                 display:flex; flex-direction:column; gap:10px; }
        .entry.w-half { width:calc(50% - 7px); }
        .entry.w-full { width:100%; }
        @media (max-width:640px) { .entry.w-half { width:100%; } }
        .entry.b-dashed { border-style:dashed; }
        .entry.b-dotted { border-style:dotted; }
        .entry.b-double { border-style:double; border-width:4px; }
        .entry.b-none { border-color:transparent !important; box-shadow:0 0 0 1px var(--line), 0 8px 26px rgba(0,0,0,.28); }
        .e-head { display:flex; align-items:center; gap:10px; }
        .e-kind { flex:none; width:34px; height:34px; display:grid; place-items:center;
                  border-radius:8px; color:#04121c; font-size:.58rem; font-weight:800; }
        .e-title { flex:1; min-width:0; font-size:.9rem; font-weight:600; cursor:pointer; color:#dfe7f3;
                   overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .e-title:hover { color:var(--accent); text-decoration:underline; }
        .e-acts { flex:none; display:flex; gap:6px; }
        .e-acts button { width:30px; height:30px; display:grid; place-items:center; cursor:pointer;
                         color:#8f99ab; border:1px solid var(--line); border-radius:7px; background:rgba(255,255,255,.04); }
        .e-acts button:hover { background:rgba(45,226,255,.1); color:#fff; border-color:rgba(45,226,255,.4); }
        .e-acts button.kill { color:#ff8f9c; }
        .e-acts button.kill:hover { background:rgba(255,90,110,.12); border-color:rgba(255,90,110,.45); }
        .e-acts button svg { width:15px; height:15px; }
        .e-acts .tri svg { transition:transform .2s; }
        .e-acts .tri.open svg { transform:rotate(180deg); }
        .e-body { border-top:1px solid var(--line); padding-top:10px; color:#b8c2d4;
                  font-size:.86rem; line-height:1.55; white-space:pre-wrap; word-break:break-word; }
        .e-note-label { display:block; margin-bottom:4px; color:var(--muted); font-size:.68rem;
                        font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
        .empty { padding:50px 16px; color:var(--muted); text-align:center; }

        /* Диалоги */
        .veil { position:fixed; inset:0; z-index:60; display:grid; place-items:center; padding:18px;
                overflow:auto; background:rgba(3,6,13,.72); backdrop-filter:blur(3px); }
        .sheet { width:min(500px,100%); color:#e8fbff; border:1px solid rgba(45,226,255,.28);
                 background:linear-gradient(150deg, rgba(16,30,47,.99), rgba(20,16,37,.99));
                 border-radius:14px; padding:22px; box-shadow:0 30px 90px rgba(0,0,0,.6); }
        .sheet h3 { margin:0 0 16px; font-size:1.1rem; letter-spacing:.02em; }
        .fld { display:block; margin-bottom:13px; }
        .fld span { display:block; margin-bottom:5px; color:var(--muted); font-size:.7rem;
                    font-weight:700; letter-spacing:.06em; text-transform:uppercase; }
        .fld input, .fld textarea, .fld select { width:100%; padding:10px 12px; color:#f4fbff;
                    font:inherit; border:1px solid var(--line); border-radius:9px; background:rgba(4,10,20,.6); }
        .fld textarea { min-height:120px; resize:vertical; }
        .fld input:focus, .fld textarea:focus, .fld select:focus { outline:none; border-color:var(--accent); }
        .fld select option { background:#111a2b; color:#e9fbff; }
        .row { display:flex; gap:10px; }
        .row .fld { flex:1; }
        .types { display:flex; gap:8px; margin-bottom:14px; }
        .type-btn { flex:1; height:64px; display:flex; flex-direction:column; align-items:center;
                    justify-content:center; gap:5px; cursor:pointer; color:var(--muted);
                    border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,.03); font-size:.76rem; }
        .type-btn svg { width:20px; height:20px; }
        .type-btn.on { color:var(--accent); border-color:var(--accent); background:rgba(45,226,255,.12); }
        .swatch { display:flex; gap:7px; flex-wrap:wrap; }
        .swatch button { width:26px; height:26px; border-radius:50%; cursor:pointer; border:2px solid rgba(255,255,255,.15);
                         box-shadow:0 0 0 1px var(--line); }
        .swatch button.on { box-shadow:0 0 0 2px var(--accent); }
        .keys { display:flex; justify-content:flex-end; gap:10px; margin-top:6px; }
        .note-msg { margin:0 0 10px; color:#ff9aa6; font-size:.8rem; min-height:1em; }

        .lb { position:fixed; inset:0; z-index:80; display:grid; place-items:center; padding:18px;
              background:rgba(2,5,10,.9); }
        .lb iframe { width:min(1000px,100%); height:100%; border:1px solid rgba(45,226,255,.25);
                     border-radius:6px; background:#fff; }
        .lb .lb-x { position:absolute; top:16px; right:16px; width:44px; height:44px; cursor:pointer;
                    color:#eaf6ff; font-size:1.5rem; border:1px solid rgba(255,255,255,.22); border-radius:6px;
                    background:rgba(10,16,26,.85); }
        .lb .lb-x:hover { color:#04060b; background:#2de2ff; }
        [hidden] { display:none !important; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="top">
          <a class="back" href="/cabinet" title="В кабинет" aria-label="В кабинет"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg></a>
          <h1>Блок<span>нот</span></h1>
        </div>
        <div class="tabs" id="tabs"></div>
        <div class="bar">
          <button class="btn" id="add-entry" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Запись</button>
        </div>
        <div class="grid" id="grid"></div>
        <p class="empty" id="empty" hidden>На этой странице пусто. Нажми «Запись».</p>
      </div>
      <input type="file" id="pdf-input" accept="application/pdf" hidden>

      <script>
      (() => {
        "use strict";
        const $ = (id) => document.getElementById(id);
        const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
          (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
        const api = async (url, how, body) => {
          const r = await fetch(url, { method: how || "GET", credentials: "same-origin",
            headers: body ? { "Content-Type": "application/json" } : undefined,
            body: body ? JSON.stringify(body) : undefined });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(d.error || "Не вышло.");
          return d;
        };
        const ICON = {
          link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>',
          text: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
          pdf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2h9l5 5v15a0 0 0 0 1 0 0H6a0 0 0 0 1 0 0z"/><path d="M14 2v6h6"/></svg>',
          pen: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"><path d="m4 20 4-1 11-11-3-3L5 16z"/></svg>',
          kill: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg>',
          tri: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
        };
        const KIND_LABEL = { link: "URL", text: "ТЕКСТ", pdf: "PDF" };
        const COLORS = ["#2de2ff", "#63f5ad", "#ff6b81", "#b57cff", "#ff9d42", "#ffd84a", "#35e0f0"];

        let pages = [], entries = [], active = null;
        const open = new Set();      // раскрытые записи

        const toast = (t) => {
          document.querySelectorAll(".nb-toast").forEach((e) => e.remove());
          const el = document.createElement("div");
          el.className = "nb-toast";
          el.textContent = t;
          el.style.cssText = "position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:200;background:#1b1f27;color:#fff;padding:10px 16px;border-radius:9px;font-size:.86rem;box-shadow:0 8px 30px rgba(0,0,0,.3)";
          document.body.appendChild(el);
          setTimeout(() => el.remove(), 2600);
        };

        const load = async () => {
          const d = await api("/api/notebook");
          pages = d.pages || [];
          entries = d.entries || [];
          if (!active || !pages.some((p) => p.id === active)) active = pages[0] && pages[0].id;
          draw();
        };

        const drawTabs = () => {
          $("tabs").innerHTML = pages.map((p) =>
            '<div class="tab' + (p.id === active ? " on" : "") + '" data-tab="' + esc(p.id) + '">' +
              '<span class="nm">' + esc(p.name) + '</span>' +
              '<span class="x" data-del-page="' + esc(p.id) + '" title="Удалить страницу">×</span>' +
            '</div>').join("") +
            '<div class="tab-add" id="tab-add" title="Новая страница">+</div>';
        };

        const bodyHtml = (e) => {
          if (e.type === "text") return '<div class="e-body">' + esc(e.text || "") + '</div>';
          // у ссылки и PDF в теле — пометки
          if (e.note) return '<div class="e-body"><span class="e-note-label">Пометки</span>' + esc(e.note) + '</div>';
          return "";
        };
        const hasBody = (e) => e.type === "text" ? (e.text || "").length > 0 : (e.note || "").length > 0;

        const drawGrid = () => {
          const list = entries.filter((e) => e.page === active);
          $("empty").hidden = list.length > 0;
          $("grid").innerHTML = list.map((e) => {
            const showBody = open.has(e.id);
            const tri = hasBody(e)
              ? '<button class="tri' + (showBody ? " open" : "") + '" data-toggle="' + e.id + '" title="Показать/скрыть">' + ICON.tri + '</button>'
              : "";
            return '<div class="entry w-' + e.width + ' b-' + e.border + '" style="border-color:' + esc(e.accent) + '" data-id="' + e.id + '">' +
              '<div class="e-head">' +
                '<span class="e-kind" style="background:' + esc(e.accent) + '">' + KIND_LABEL[e.type] + '</span>' +
                '<span class="e-title" data-openentry="' + e.id + '" title="' + esc(openHint(e)) + '">' + esc(e.title) + '</span>' +
                '<span class="e-acts">' + tri +
                  '<button data-edit="' + e.id + '" title="Изменить">' + ICON.pen + '</button>' +
                  '<button class="kill" data-kill="' + e.id + '" title="Удалить">' + ICON.kill + '</button>' +
                '</span>' +
              '</div>' +
              (showBody ? bodyHtml(e) : "") +
            '</div>';
          }).join("");
        };

        const openHint = (e) => e.type === "link" ? "Открыть ссылку"
          : e.type === "text" ? "Скопировать текст" : "Открыть PDF";

        const draw = () => { drawTabs(); drawGrid(); };

        const openEntry = async (e) => {
          if (e.type === "link") {
            if (e.url) window.open(e.url, "_blank", "noopener");
            else toast("У записи нет ссылки");
          } else if (e.type === "text") {
            try { await navigator.clipboard.writeText(e.text || ""); toast("Текст скопирован"); }
            catch { toast("Не удалось скопировать"); }
          } else if (e.type === "pdf") {
            if (!e.pdf) { toast("PDF ещё не загружен — нажми «Изменить»"); return; }
            showPdf(e.id, e.title);
          }
        };

        const showPdf = (eid, title) => {
          const box = document.createElement("div");
          box.className = "lb";
          box.innerHTML = '<button class="lb-x" title="Закрыть">×</button>' +
            '<iframe src="/notebook/pdf/' + encodeURIComponent(eid) + '" title="' + esc(title) + '"></iframe>';
          document.body.appendChild(box);
          const shut = () => box.remove();
          box.querySelector(".lb-x").addEventListener("click", shut);
          box.addEventListener("click", (ev) => { if (ev.target === box) shut(); });
          document.addEventListener("keydown", function esc2(ev) {
            if (ev.key === "Escape") { shut(); document.removeEventListener("keydown", esc2); } });
        };

        // ── Диалог создания / правки ──────────────────────────────────
        let pdfPendingId = null;
        const openSheet = (entry) => {
          const fresh = !entry;
          const e = entry || { type: "link", title: "", url: "", text: "", note: "",
                               width: "half", border: "solid", accent: COLORS[0] };
          const veil = document.createElement("div");
          veil.className = "veil";
          const typeRow = fresh
            ? '<div class="types" id="f-types">' +
                ['link', 'text', 'pdf'].map((t) =>
                  '<div class="type-btn' + (t === e.type ? " on" : "") + '" data-type="' + t + '">' +
                  ICON[t] + '<span>' + ({ link: "Ссылка", text: "Текст", pdf: "PDF" }[t]) + '</span></div>').join("") +
              '</div>'
            : "";
          veil.innerHTML =
            '<section class="sheet" role="dialog" aria-modal="true">' +
              '<h3>' + (fresh ? "Новая запись" : "Изменить запись") + '</h3>' +
              typeRow +
              '<label class="fld"><span>Название</span><input id="f-title" maxlength="160" value="' + esc(e.title) + '"></label>' +
              '<div id="f-typed"></div>' +
              '<div class="row">' +
                '<label class="fld"><span>Ширина</span><select id="f-width">' +
                  '<option value="half"' + (e.width === "half" ? " selected" : "") + '>Половина (2 в ряд)</option>' +
                  '<option value="full"' + (e.width === "full" ? " selected" : "") + '>Во всю ширину</option>' +
                '</select></label>' +
                '<label class="fld"><span>Рамка</span><select id="f-border">' +
                  [["solid", "Сплошная"], ["dashed", "Пунктир"], ["dotted", "Точки"], ["double", "Двойная"], ["none", "Без рамки"]]
                    .map(([v, n]) => '<option value="' + v + '"' + (e.border === v ? " selected" : "") + '>' + n + '</option>').join("") +
                '</select></label>' +
              '</div>' +
              '<div class="fld"><span>Цвет</span><div class="swatch" id="f-swatch">' +
                COLORS.map((c) => '<button type="button" data-color="' + c + '" class="' + (c === e.accent ? "on" : "") + '" style="background:' + c + '"></button>').join("") +
              '</div></div>' +
              '<p class="note-msg" id="f-msg"></p>' +
              '<div class="keys"><button class="btn ghost" type="button" id="f-no">Отмена</button>' +
              '<button class="btn" type="button" id="f-ok">Сохранить</button></div>' +
            '</section>';
          document.body.appendChild(veil);
          const state = { veil, e: Object.assign({}, e), fresh, id: entry ? entry.id : null,
                          accent: e.accent };
          const msg = (t) => { veil.querySelector("#f-msg").textContent = t || ""; };

          const paintTyped = () => {
            const t = state.e.type;
            const box = veil.querySelector("#f-typed");
            if (t === "link") {
              box.innerHTML = '<label class="fld"><span>Ссылка</span><input id="f-url" placeholder="https://…" value="' + esc(state.e.url || "") + '"></label>' +
                '<label class="fld"><span>Пометки (по желанию)</span><textarea id="f-note" style="min-height:70px">' + esc(state.e.note || "") + '</textarea></label>';
            } else if (t === "text") {
              box.innerHTML = '<label class="fld"><span>Текст</span><textarea id="f-text">' + esc(state.e.text || "") + '</textarea></label>';
            } else {
              const has = entry && entry.pdf;
              box.innerHTML = '<label class="fld"><span>Файл PDF</span></label>' +
                '<button class="btn ghost" type="button" id="f-pdf">' + (has ? "Заменить PDF (" + esc(entry.filename || "загружен") + ")" : "Загрузить PDF") + '</button>' +
                '<p style="margin:8px 0 0;color:#5b6473;font-size:.78rem" id="f-pdf-hint">' + (has ? "" : (state.fresh ? "Сначала сохрани запись, потом загрузишь файл." : "Файл ещё не загружен.")) + '</p>' +
                '<label class="fld" style="margin-top:12px"><span>Пометки (по желанию)</span><textarea id="f-note" style="min-height:70px">' + esc(state.e.note || "") + '</textarea></label>';
            }
          };
          paintTyped();

          if (fresh) veil.querySelectorAll("#f-types .type-btn").forEach((b) =>
            b.addEventListener("click", () => {
              state.e.type = b.dataset.type;
              veil.querySelectorAll("#f-types .type-btn").forEach((x) => x.classList.toggle("on", x === b));
              paintTyped(); wirePdf();
            }));
          veil.querySelectorAll("#f-swatch button").forEach((b) =>
            b.addEventListener("click", () => {
              state.accent = b.dataset.color;
              veil.querySelectorAll("#f-swatch button").forEach((x) => x.classList.toggle("on", x === b));
            }));

          const wirePdf = () => {
            const btn = veil.querySelector("#f-pdf");
            if (btn) btn.addEventListener("click", async () => {
              if (!state.id) { await saveCore(true); if (!state.id) return; }
              pdfPendingId = state.id;
              $("pdf-input").click();
            });
          };
          wirePdf();

          const readCore = () => {
            const g = (id) => { const el = veil.querySelector(id); return el ? el.value : ""; };
            const data = { type: state.e.type, title: g("#f-title"),
              width: veil.querySelector("#f-width").value, border: veil.querySelector("#f-border").value,
              accent: state.accent };
            if (state.e.type === "link") { data.url = g("#f-url"); data.note = g("#f-note"); }
            else if (state.e.type === "text") { data.text = g("#f-text"); }
            else { data.note = g("#f-note"); }
            return data;
          };
          const saveCore = async (silent) => {
            const data = readCore();
            try {
              if (state.id) await api("/api/notebook/entry/" + state.id, "PATCH", data);
              else { const r = await api("/api/notebook/entry", "POST",
                       Object.assign({ page: active }, data)); state.id = r.id; state.fresh = false; }
            } catch (err) { msg(err.message); return; }
            if (!silent) { veil.remove(); await load(); toast("Сохранено"); }
          };
          veil.querySelector("#f-ok").addEventListener("click", () => saveCore(false));
          veil.querySelector("#f-no").addEventListener("click", () => { veil.remove(); load(); });
          veil.addEventListener("click", (ev) => { if (ev.target === veil) { veil.remove(); load(); } });
          state.reopenId = () => state.id;
          openSheet._state = state;
        };

        $("pdf-input").addEventListener("change", async (ev) => {
          const file = ev.target.files[0];
          ev.target.value = "";
          if (!file || !pdfPendingId) return;
          const form = new FormData();
          form.append("file", file);
          try {
            const r = await fetch("/api/notebook/entry/" + pdfPendingId + "/pdf",
              { method: "POST", credentials: "same-origin", body: form });
            const d = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(d.error || "Не вышло.");
            toast("PDF загружен");
            const st = openSheet._state;
            if (st && st.veil && document.body.contains(st.veil)) {
              const hint = st.veil.querySelector("#f-pdf-hint");
              const btn = st.veil.querySelector("#f-pdf");
              if (hint) hint.textContent = "";
              if (btn) btn.textContent = "Заменить PDF (" + (d.filename || "загружен") + ")";
            }
          } catch (err) { toast(err.message); }
        });

        // ── общие нажатия ─────────────────────────────────────────────
        document.addEventListener("click", async (e) => {
          const add = e.target.closest("#tab-add");
          if (add) {
            const name = prompt("Название страницы:");
            if (!name) return;
            const r = await api("/api/notebook/page", "POST", { name });
            active = r.id; await load(); return;
          }
          const delPage = e.target.closest("[data-del-page]");
          if (delPage) {
            e.stopPropagation();
            if (pages.length <= 1) { toast("Единственную страницу удалить нельзя"); return; }
            if (!confirm("Удалить страницу со всеми записями?")) return;
            try { await api("/api/notebook/page/" + delPage.dataset.delPage, "DELETE"); }
            catch (err) { toast(err.message); return; }
            await load(); return;
          }
          const tab = e.target.closest("[data-tab]");
          if (tab) { active = tab.dataset.tab; draw(); return; }
          const oe = e.target.closest("[data-openentry]");
          if (oe) { const en = entries.find((x) => x.id === oe.dataset.openentry); if (en) openEntry(en); return; }
          const tg = e.target.closest("[data-toggle]");
          if (tg) { const id = tg.dataset.toggle; if (open.has(id)) open.delete(id); else open.add(id); drawGrid(); return; }
          const ed = e.target.closest("[data-edit]");
          if (ed) { openSheet(entries.find((x) => x.id === ed.dataset.edit)); return; }
          const kl = e.target.closest("[data-kill]");
          if (kl) {
            const en = entries.find((x) => x.id === kl.dataset.kill);
            if (!confirm("Удалить «" + (en ? en.title : "") + "»?")) return;
            try { await api("/api/notebook/entry/" + kl.dataset.kill, "DELETE"); }
            catch (err) { toast(err.message); return; }
            await load(); return;
          }
        });
        // двойной клик по вкладке — переименовать
        $("tabs").addEventListener("dblclick", async (e) => {
          const tab = e.target.closest("[data-tab]");
          if (!tab) return;
          const p = pages.find((x) => x.id === tab.dataset.tab);
          const name = prompt("Переименовать страницу:", p ? p.name : "");
          if (!name) return;
          try { await api("/api/notebook/page/" + tab.dataset.tab, "PATCH", { name }); }
          catch (err) { toast(err.message); return; }
          await load();
        });
        $("add-entry").addEventListener("click", () => openSheet(null));

        load().catch(() => { $("grid").innerHTML = '<p class="empty">Не отвечает</p>'; });
      })();
      </script>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


def _soon_page(name, kicker, headline, lead, points):
    """Заготовка под раздел: страница уже есть и открывается с полки, а
    содержимое появится позже. Пустая страница выглядела бы поломкой,
    поэтому честно пишем, что здесь будет."""
    items = "".join(f"<li>{escape(p)}</li>" for p in points)
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="__LEAD__">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>__NAME__ · vitazgio.ru</title>
      <style>
        :root { color-scheme: dark; --line: rgba(255,255,255,.1); --muted: #989fb2; }
        * { box-sizing: border-box; }
        body {
          margin: 0; min-height: 100svh; display: flex; flex-direction: column;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at 12% 8%, rgba(57,126,255,.22), transparent 32rem),
            radial-gradient(circle at 88% 78%, rgba(149,65,255,.18), transparent 34rem),
            #0d1321;
          color: #f7f8fc;
        }
        .page { width: min(1380px, calc(100% - 40px)); margin: 0 auto;
                padding: clamp(24px, 5vw, 56px) 0 40px; }
        .top { position: relative; display: flex; align-items: center; gap: 14px; margin-bottom: 22px; }
        .back { display: inline-flex; align-items: center; justify-content: center;
                width: 42px; height: 42px; flex: none; color: #7ce0ff; text-decoration: none;
                border: 1px solid rgba(45,226,255,.3); border-radius: 50%;
                background: rgba(45,226,255,.07); transition: .18s; }
        .back svg { width: 20px; height: 20px; }
        .back:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.18); }
        .eyebrow { display: inline-flex; align-items: center; gap: 10px; color: #cdd2df;
                   font-size: .76rem; font-weight: 700; letter-spacing: .16em;
                   text-transform: uppercase; text-decoration: none; }
        .eyebrow::before { content: ""; width: 7px; height: 7px; border-radius: 50%;
                           background: #64e6a5; box-shadow: 0 0 16px #64e6a5; }
        .eyebrow:hover { color: #fff; }
        .mark { position: absolute; right: 0; top: 50%; transform: translateY(-62%);
                width: clamp(1.15rem, 4.7vw, 4.4rem); height: clamp(1.15rem, 4.7vw, 4.4rem); }
        h1 { position: relative; min-height: 132px; display: flex; align-items: center;
             margin: 0; padding: 28px clamp(22px, 4vw, 54px);
             font-family: "Cascadia Code", Consolas, "Courier New", monospace;
             font-size: clamp(1.15rem, 4.7vw, 4rem); font-weight: 800;
             letter-spacing: -.05em; color: #dffaff;
             border: 1px solid rgba(54,228,255,.24);
             background: linear-gradient(110deg, rgba(12,28,43,.92), rgba(20,17,38,.82));
             clip-path: polygon(0 0, calc(100% - 25px) 0, 100% 25px, 100% 100%, 25px 100%, 0 calc(100% - 25px));
             text-shadow: 2px 0 #ff3fa4, -2px 0 #21dcff; }
        .lead { max-width: 62ch; margin: 26px 0 0; color: var(--muted); font-size: 1.05rem; line-height: 1.6; }
        .soon { display: inline-block; margin-top: 26px; padding: 6px 14px;
                color: #04121a; background: #2de2ff; border-radius: 999px;
                font: 700 .7rem "Cascadia Code", Consolas, monospace;
                letter-spacing: .16em; text-transform: uppercase; }
        ul { max-width: 62ch; margin: 20px 0 0; padding-left: 20px;
             color: var(--muted); line-height: 1.75; }
        li::marker { color: #2de2ff; }
        footer { margin-top: auto; padding: 28px 0 0; color: #686f80; font-size: .82rem; }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="top">
          <a class="back" href="/" title="На главную" aria-label="На главную"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
          <a class="eyebrow" href="/">__KICKER__</a>
          <img class="mark" src="/static/icons/vg-plain.svg" alt="Vitaz Gio"
               width="512" height="512">
        </div>
        <h1>__HEADLINE__</h1>
        <div class="soon">в работе</div>
        <p class="lead">__LEAD__</p>
        <ul>__ITEMS__</ul>
        <footer>@Vitaz Gio · раздел готовится</footer>
      </main>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return (html.replace("__ICONLINKS__", ICON_LINKS)
                .replace("__NAME__", escape(name))
                .replace("__KICKER__", escape(kicker))
                .replace("__HEADLINE__", escape(headline))
                .replace("__LEAD__", escape(lead))
                .replace("__ITEMS__", items))


@app.get("/api/player/tracks")
@login_required
def player_tracks():
    """Единый список для плеера: фонотека (/music) плюс всё аудио, что лежит
    в папке MUSIK личного дропа. У каждого трека свой адрес потока."""
    tracks = []
    with music_lock:
        _music_scan()
        folder_name = {k: v["name"] for k, v in music_folders.items()}
        for k, v in sorted(music_items.items(),
                           key=lambda x: (str(x[1].get("artist", "")).lower(),
                                          str(x[1].get("title", "")).lower())):
            tracks.append({
                "id": "m_" + k, "title": v["title"], "artist": v["artist"],
                "folder": folder_name.get(v.get("folder", ""), ""),
                "url": "/api/music/file/" + k,
            })
    with drop_lock:
        tracks.extend(_drop_musik_tracks())
    return jsonify(tracks=tracks)


@app.get("/vg-player.js")
def vg_player_js():
    """Единый плеер сайта: один звук, одно состояние, красивый виджет.

    Раньше плееров было три — в кабинете, на странице музыки и во всплывающем
    окне, — и они друг о друге не знали. Теперь звук один на весь сайт: этот
    файл держит единственный <audio>, хранит состояние в localStorage и сам
    подхватывает трек с той же секунды на следующей странице. Виджет висит
    поверх всего, складывается в кружок с кольцом прогресса и таскается мышью.

    Страница музыки подключает тот же движок без своего оверлея (VGP_HEADLESS)
    и рулит им своей большой панелью — поэтому панель и виджет всегда показывают
    одно и то же."""
    js = r"""
(() => {
  "use strict";
  if (window.VGP) return;                       // второй раз не заводимся

  const KEY = "vgPlayerState";
  const POS = "vgPlayerBox";
  const headless = !!window.VGP_HEADLESS;       // движок без своего оверлея
  const lift = +(window.VGP_OFFSET || 0);       // поднять над нижней панелью

  /* ── состояние ─────────────────────────────────────────────────── */
  const audio = new Audio();
  audio.preload = "metadata";
  let queue = [];          // [{id,title,artist,folder,url}]
  let idx = -1;
  let ready = false;       // список загружен
  let shuffle = false;
  const subs = [];

  const save = () => {
    try {
      const t = queue[idx] || null;
      localStorage.setItem(KEY, JSON.stringify({
        id: t ? t.id : null,
        // адрес и подписи храним прямо тут: на новой странице трек ставится
        // сразу, не дожидаясь ответа со списком — из-за него и были заминки
        url: t ? t.url : "",
        title: t ? t.title : "",
        artist: t ? t.artist : "",
        folder: t ? t.folder : "",
        time: audio.currentTime || 0,
        playing: !audio.paused,
        vol: audio.volume,
        shuffle: shuffle,
      }));
    } catch (e) { /* приватное окно — переживём */ }
  };
  const stored = () => {
    try { return JSON.parse(localStorage.getItem(KEY) || "null"); }
    catch (e) { return null; }
  };

  /* Одна вкладка играет — остальные умолкают, как в нормальных плеерах. */
  let bus = null;
  try { bus = new BroadcastChannel("vgplayer"); } catch (e) { /* старый браузер */ }
  const shout = (what) => { if (bus) try { bus.postMessage(what); } catch (e) {} };
  if (bus) bus.onmessage = (e) => {
    if (e.data === "play" && !audio.paused) { audio.pause(); }
    if (e.data === "sync") fire();
  };

  const fire = () => { subs.forEach((f) => { try { f(state()); } catch (e) {} }); paint(); };
  const state = () => ({
    track: queue[idx] || null, idx, queue, playing: !audio.paused,
    time: audio.currentTime, duration: audio.duration, shuffle,
  });

  /* ── ядро ──────────────────────────────────────────────────────── */
  const load = (i, autoplay) => {
    if (i < 0 || i >= queue.length) return;
    idx = i;
    audio.src = queue[i].url;
    audio.load();
    if (autoplay) { shout("play"); audio.play().catch(() => fire()); }
    media();
    fire();
    save();
  };

  const api = {
    audio,
    get state() { return state(); },
    subscribe(fn) { subs.push(fn); try { fn(state()); } catch (e) {} },
    /* Кто-то другой (страница музыки) назначил очередь — принимаем её. */
    adopt(list, at) {
      queue = list.slice();
      idx = Math.max(0, at | 0);
      ready = true;
      media(); fire(); save();
    },
    playAt(i) { load(i, true); },
    playId(id) {
      const at = queue.findIndex((t) => t.id === id);
      if (at >= 0) load(at, true);
    },
    toggle() {
      if (idx < 0 && queue.length) { load(0, true); return; }
      if (audio.paused) { shout("play"); audio.play().catch(() => {}); }
      else audio.pause();
    },
    next() { if (queue.length) load(idx + 1 >= queue.length ? 0 : idx + 1, true); },
    prev() {
      if (audio.currentTime > 3) { audio.currentTime = 0; return; }
      if (queue.length) load(idx - 1 < 0 ? queue.length - 1 : idx - 1, true);
    },
    seek(t) { if (isFinite(audio.duration)) audio.currentTime = t; },
    volume(v) { audio.volume = Math.min(1, Math.max(0, v)); save(); fire(); },
    shuffle(on) {
      shuffle = on === undefined ? !shuffle : !!on;
      save(); fire();
      return shuffle;
    },
    /* Виджет сам не вылезает: его включают кнопкой в кабинете или на музыке,
       и с тех пор он ездит по всем страницам, пока его не выбросят в корзину. */
    open() {
      try { localStorage.setItem("vgPlayerOn", "1"); } catch (e) { /* и ладно */ }
      if (!box) build();
      setFolded(false);
      fetchList(true);
    },
    hide() {
      try { localStorage.setItem("vgPlayerOn", "0"); } catch (e) { /* и ладно */ }
      if (box) { box.remove(); box = null; }
    },
    reload: () => fetchList(true),
  };
  window.VGP = api;

  /* Системные кнопки (наушники, медиаклавиши, шторка) */
  const media = () => {
    if (!("mediaSession" in navigator)) return;
    const t = queue[idx];
    if (!t) return;
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: t.title || "", artist: t.artist || "vitazgio.ru",
        album: t.folder || "фонотека",
      });
      navigator.mediaSession.setActionHandler("play", () => api.toggle());
      navigator.mediaSession.setActionHandler("pause", () => api.toggle());
      navigator.mediaSession.setActionHandler("nexttrack", () => api.next());
      navigator.mediaSession.setActionHandler("previoustrack", () => api.prev());
    } catch (e) { /* не поддержали — не беда */ }
  };

  audio.addEventListener("ended", () => api.next());
  audio.addEventListener("play", () => { shout("play"); fire(); save(); });
  audio.addEventListener("pause", () => { fire(); save(); });
  audio.addEventListener("timeupdate", () => { paint(); });
  audio.addEventListener("loadedmetadata", () => fire());
  setInterval(() => { if (!audio.paused) save(); }, 3000);
  addEventListener("pagehide", save);

  /* ── список треков ─────────────────────────────────────────────── */
  const fetchList = async (force) => {
    if (ready && !force) return queue;
    let d;
    try {
      const r = await fetch("/api/player/tracks", { credentials: "same-origin" });
      if (!r.ok) { if (box) box.remove(); box = null; return []; }
      d = await r.json();
    } catch (e) { return []; }
    queue = (d.tracks || []).map((t) => ({
      id: t.id, title: t.title, artist: t.artist, folder: t.folder || "", url: t.url }));
    ready = true;
    fire();
    return queue;
  };

  /* Подхват с прошлой страницы: тот же трек, та же секунда. */
  const resume = async () => {
    const s = stored();
    if (s && typeof s.vol === "number") audio.volume = s.vol;
    if (s && s.shuffle) shuffle = true;
    if (!s || !s.id) return;

    // Сначала — звук: ставим трек из сохранённого адреса, без похода на сервер.
    if (s.url) {
      queue = [{ id: s.id, title: s.title || "", artist: s.artist || "",
                 folder: s.folder || "", url: s.url }];
      idx = 0;
      audio.src = s.url;
      audio.addEventListener("loadedmetadata", function once() {
        audio.removeEventListener("loadedmetadata", once);
        if (s.time) audio.currentTime = s.time;
        if (s.playing) audio.play().catch(() => { if (box) box.classList.add("vgp-wake"); });
      }, { once: true });
      media(); fire();
    }

    // А полный список подтянем следом — он нужен только для «дальше» и списка.
    const list = await fetchList();
    const at = list.findIndex((t) => t.id === s.id);
    if (at >= 0) {
      idx = at;
      if (!s.url) {
        audio.src = list[at].url;
        audio.addEventListener("loadedmetadata", function once() {
          audio.removeEventListener("loadedmetadata", once);
          if (s.time) audio.currentTime = s.time;
          if (s.playing) audio.play().catch(() => { if (box) box.classList.add("vgp-wake"); });
        }, { once: true });
      }
      media(); fire();
    }
  };

  /* ── виджет ────────────────────────────────────────────────────── */
  let box = null, folded = true, bin = null;
  const paintFns = [];

  /* Корзина, в которую можно выбросить сам плеер. Появляется только когда
     кружок подержали на месте — чтобы не мешала обычному перетаскиванию. */
  const showBin = () => {
    if (bin) return;
    bin = document.createElement("div");
    bin.className = "vgp-bin";
    bin.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg><span>убрать плеер</span>';
    document.body.appendChild(bin);
    requestAnimationFrame(() => bin && bin.classList.add("in"));
  };
  const hideBin = () => { if (bin) { bin.remove(); bin = null; } };
  const overBin = (x, y) => {
    if (!bin) return false;
    const r = bin.getBoundingClientRect();
    return x >= r.left - 26 && x <= r.right + 26 && y >= r.top - 26 && y <= r.bottom + 26;
  };
  const paint = () => paintFns.forEach((f) => { try { f(); } catch (e) {} });
  const setFolded = (v) => {
    folded = v;
    if (!box) return;
    box.classList.toggle("vgp-folded", folded);
    box.classList.remove("vgp-wake");
    try { localStorage.setItem("vgPlayerFold", folded ? "1" : "0"); } catch (e) {}
  };

  const CSS = `
  .vgp { position:fixed; z-index:2147483000; right:22px; bottom:22px; width:326px;
         color:#eaf6ff; font:400 13px/1.45 "Cascadia Code",Consolas,monospace;
         border-radius:18px; overflow:hidden; isolation:isolate;
         background:linear-gradient(160deg, rgba(17,29,48,.93), rgba(9,14,25,.95));
         border:1px solid rgba(45,226,255,.24);
         box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.03) inset,
                    0 0 42px rgba(45,226,255,.09);
         backdrop-filter:blur(16px) saturate(1.2);
         transition:width .34s cubic-bezier(.22,1,.36,1), height .34s cubic-bezier(.22,1,.36,1),
                    border-radius .34s, opacity .2s;
         touch-action:none; }
  .vgp *, .vgp *::before, .vgp *::after { box-sizing:border-box; }
  /* мягкое бирюзовое зарево по верхнему краю — «живой» прибор */
  .vgp::before { content:""; position:absolute; inset:-40% -20% auto -20%; height:150px; pointer-events:none;
                 background:radial-gradient(60% 100% at 50% 0%, rgba(45,226,255,.20), transparent 70%);
                 opacity:.9; }
  .vgp-head { position:relative; display:flex; align-items:center; gap:11px; padding:13px 13px 9px; cursor:grab; }
  .vgp.vgp-drag .vgp-head { cursor:grabbing; }
  .vgp-art { position:relative; width:46px; height:46px; flex:none; border-radius:13px;
             display:grid; place-items:center; overflow:hidden;
             background:linear-gradient(145deg, rgba(45,226,255,.22), rgba(99,245,173,.12));
             box-shadow:0 0 0 1px rgba(45,226,255,.28) inset; }
  /* пока молчит — нота, заиграло — живые полоски */
  .vgp-note { width:21px; height:21px; color:#8ef2ff; opacity:.85; }
  .vgp.vgp-on .vgp-note { display:none; }
  .vgp:not(.vgp-on) .vgp-eq { display:none; }
  .vgp-eq { display:flex; align-items:flex-end; gap:3px; height:20px; }
  .vgp-eq i { width:3px; height:5px; border-radius:2px; background:linear-gradient(180deg,#7df0ff,#2de2ff);
              box-shadow:0 0 7px rgba(45,226,255,.75); }
  .vgp.vgp-on .vgp-eq i { animation:vgpBar .9s ease-in-out infinite; }
  .vgp.vgp-on .vgp-eq i:nth-child(2){ animation-duration:.62s }
  .vgp.vgp-on .vgp-eq i:nth-child(3){ animation-duration:1.05s }
  .vgp.vgp-on .vgp-eq i:nth-child(4){ animation-duration:.78s }
  @keyframes vgpBar { 0%,100%{height:5px} 50%{height:19px} }
  .vgp-meta { flex:1; min-width:0; }
  .vgp-t { font-size:13.5px; font-weight:700; color:#f2fbff; white-space:nowrap;
           overflow:hidden; text-overflow:ellipsis; }
  .vgp-a { margin-top:2px; font-size:11px; color:#7f93a8; white-space:nowrap;
           overflow:hidden; text-overflow:ellipsis; }
  .vgp-x { flex:none; width:28px; height:28px; display:grid; place-items:center; cursor:pointer;
           color:#7f93a8; border:0; background:none; border-radius:9px; transition:.16s; }
  .vgp-x:hover { color:#eaf6ff; background:rgba(255,255,255,.07); }
  .vgp-x svg { width:15px; height:15px; }

  .vgp-body { padding:0 13px 13px; }
  .vgp-line { display:flex; align-items:center; gap:9px; margin-bottom:11px; }
  .vgp-time { font-size:10.5px; color:#6b7c8f; font-variant-numeric:tabular-nums; flex:none; }
  .vgp-bar { position:relative; flex:1; height:16px; display:flex; align-items:center; cursor:pointer; }
  .vgp-bar u { position:absolute; left:0; right:0; height:4px; border-radius:3px;
               background:rgba(255,255,255,.11); }
  .vgp-bar i { position:absolute; left:0; height:4px; width:0; border-radius:3px;
               background:linear-gradient(90deg,#2de2ff,#63f5ad);
               box-shadow:0 0 10px rgba(45,226,255,.5); }
  .vgp-bar b { position:absolute; left:0; width:11px; height:11px; margin-left:-5px; border-radius:50%;
               background:#eafcff; box-shadow:0 0 10px rgba(45,226,255,.9); opacity:0; transition:opacity .16s; }
  .vgp-bar:hover b, .vgp-bar.vgp-grab b { opacity:1; }

  .vgp-keys { display:flex; align-items:center; justify-content:center; gap:8px; }
  .vgp-keys button { display:grid; place-items:center; cursor:pointer; color:#cfe2ee;
                     border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.04);
                     border-radius:50%; transition:.16s; }
  .vgp-keys button:hover { color:#fff; border-color:rgba(45,226,255,.5); background:rgba(45,226,255,.12); }
  .vgp-keys .vgp-side { width:34px; height:34px; }
  .vgp-keys .vgp-side svg { width:15px; height:15px; }
  .vgp-keys .vgp-play { width:46px; height:46px; color:#04121c; border:0;
                        background:linear-gradient(160deg,#7df0ff,#26cfe8);
                        box-shadow:0 6px 20px rgba(45,226,255,.35); }
  .vgp-keys .vgp-play:hover { filter:brightness(1.08); background:linear-gradient(160deg,#8ff5ff,#2de2ff); }
  .vgp-keys .vgp-play svg { width:20px; height:20px; }
  .vgp-keys .vgp-sm { width:30px; height:30px; }
  .vgp-keys .vgp-sm svg { width:13px; height:13px; }
  .vgp-keys .vgp-sm.on { color:#63f5ad; border-color:rgba(99,245,173,.45); background:rgba(99,245,173,.12); }

  .vgp-list { max-height:0; overflow:hidden; transition:max-height .3s ease; }
  .vgp-list.open { max-height:220px; overflow-y:auto; margin-top:11px;
                   border-top:1px solid rgba(255,255,255,.08); padding-top:8px; }
  .vgp-row { display:flex; align-items:center; gap:8px; padding:7px 8px; border-radius:8px; cursor:pointer; }
  .vgp-row:hover { background:rgba(45,226,255,.08); }
  .vgp-row.on { background:rgba(45,226,255,.14); }
  .vgp-row .n { flex:1; min-width:0; }
  .vgp-row .n b { display:block; font-size:11.5px; font-weight:600; color:#dfe7f3;
                  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .vgp-row .n span { display:block; font-size:10px; color:#6b7c8f;
                     white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .vgp-row.on .n b { color:#2de2ff; }

  /* ── свёрнутый вид: кружок с кольцом прогресса ── */
  .vgp.vgp-folded { width:60px; height:60px; border-radius:50%; }
  .vgp.vgp-folded .vgp-body, .vgp.vgp-folded .vgp-meta, .vgp.vgp-folded .vgp-x { display:none; }
  .vgp.vgp-folded .vgp-head { padding:0; height:100%; justify-content:center; }
  .vgp.vgp-folded .vgp-art { width:100%; height:100%; border-radius:50%; background:none; box-shadow:none; }
  .vgp-ring { position:absolute; inset:0; display:none; }
  .vgp.vgp-folded .vgp-ring { display:block; }
  .vgp-ring circle { fill:none; stroke-width:3; }
  .vgp-ring .bg { stroke:rgba(255,255,255,.12); }
  .vgp-ring .fg { stroke:#2de2ff; stroke-linecap:round; filter:drop-shadow(0 0 5px rgba(45,226,255,.8));
                  transition:stroke-dashoffset .25s linear; }
  /* корзина под плеером: выехала — значит можно выбросить */
  .vgp-bin { position:fixed; left:50%; bottom:26px; z-index:2147483001;
             display:flex; align-items:center; gap:10px; padding:13px 20px;
             transform:translate(-50%, 26px); opacity:0; pointer-events:none;
             color:#ff9aa6; font:700 .74rem "Cascadia Code",Consolas,monospace;
             letter-spacing:.04em; border:1px dashed rgba(255,90,110,.5); border-radius:14px;
             background:rgba(20,10,14,.92); backdrop-filter:blur(8px);
             transition:transform .22s cubic-bezier(.22,1,.36,1), opacity .22s, background .16s,
                        border-color .16s, color .16s; }
  .vgp-bin.in { transform:translate(-50%, 0); opacity:1; }
  .vgp-bin.hot { color:#fff; border-style:solid; border-color:#ff5a6e;
                 background:rgba(190,40,60,.92); transform:translate(-50%, 0) scale(1.06); }
  .vgp-bin svg { width:17px; height:17px; }

  /* автоплей не пустили — зовём нажать */
  .vgp.vgp-wake { animation:vgpWake 1.4s ease-in-out infinite; }
  @keyframes vgpWake { 0%,100%{ box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 0 rgba(45,226,255,.5) }
                        50%{ box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 12px rgba(45,226,255,0) } }
  @media (max-width:560px) { .vgp { right:12px; bottom:12px; width:calc(100vw - 24px); max-width:326px; } }
  @media (prefers-reduced-motion: reduce) { .vgp, .vgp * { animation:none !important; transition:none !important; } }
  `;

  const I = {
    play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7L8 5Z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 5h4v14H7zM13 5h4v14h-4z"/></svg>',
    prev: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 6v12H5V6h2Zm12 0v12l-9-6 9-6Z"/></svg>',
    next: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 6v12h2V6h-2ZM5 6v12l9-6-9-6Z"/></svg>',
    list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
    shuf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h4v4M20 4l-6 6M16 20h4v-4M20 20l-6-6M4 4l6 6M4 20l16-16"/></svg>',
    fold: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/></svg>',
  };
  const mmss = (s) => {
    s = Math.max(0, Math.floor(s || 0));
    return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
  };

  const build = () => {
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);

    box = document.createElement("div");
    box.className = "vgp vgp-folded";
    if (lift) box.style.bottom = (22 + lift) + "px";
    box.innerHTML =
      '<div class="vgp-head">' +
        '<svg class="vgp-ring" viewBox="0 0 60 60"><circle class="bg" cx="30" cy="30" r="27"/>' +
          '<circle class="fg" cx="30" cy="30" r="27" stroke-dasharray="169.6" stroke-dashoffset="169.6"/></svg>' +
        '<div class="vgp-art">' +
          '<svg class="vgp-note" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.8"/><circle cx="16.5" cy="16" r="2.8"/></svg>' +
          '<div class="vgp-eq"><i></i><i></i><i></i><i></i></div></div>' +
        '<div class="vgp-meta"><div class="vgp-t">Фонотека</div><div class="vgp-a">ничего не играет</div></div>' +
        '<button class="vgp-x" data-fold title="Свернуть">' + I.fold + '</button>' +
      '</div>' +
      '<div class="vgp-body">' +
        '<div class="vgp-line"><span class="vgp-time" data-at>0:00</span>' +
          '<div class="vgp-bar" data-bar><u></u><i></i><b></b></div>' +
          '<span class="vgp-time" data-all>0:00</span></div>' +
        '<div class="vgp-keys">' +
          '<button class="vgp-sm" data-shuf title="Вперемешку">' + I.shuf + '</button>' +
          '<button class="vgp-side" data-prev title="Назад">' + I.prev + '</button>' +
          '<button class="vgp-play" data-play title="Играть">' + I.play + '</button>' +
          '<button class="vgp-side" data-next title="Вперёд">' + I.next + '</button>' +
          '<button class="vgp-sm" data-list title="Список">' + I.list + '</button>' +
        '</div>' +
        '<div class="vgp-list" data-rows></div>' +
      '</div>';
    document.body.appendChild(box);

    const q = (s) => box.querySelector(s);
    const rows = q("[data-rows]");

    /* положение помним между страницами */
    try {
      const p = JSON.parse(localStorage.getItem(POS) || "null");
      if (p && typeof p.x === "number") {
        box.style.left = p.x + "px"; box.style.top = p.y + "px";
        box.style.right = "auto"; box.style.bottom = "auto";
      }
      if (localStorage.getItem("vgPlayerFold") === "0") setFolded(false);
    } catch (e) {}

    /* таскаем за шапку */
    let drag = null;
    q(".vgp-head").addEventListener("pointerdown", (e) => {
      if (e.target.closest("button")) return;
      const r = box.getBoundingClientRect();
      drag = { dx: e.clientX - r.left, dy: e.clientY - r.top, moved: false, hold: 0 };
      box.classList.add("vgp-drag");
      try { q(".vgp-head").setPointerCapture(e.pointerId); } catch (err) {}
      // Подержал на месте — снизу выезжает корзина: значит плеер можно
      // выбросить. Если сразу потащил, корзина не появляется и не мешает.
      drag.hold = setTimeout(() => { if (drag && !drag.moved) showBin(); }, 420);
    });
    q(".vgp-head").addEventListener("pointermove", (e) => {
      if (!drag) return;
      const x = Math.min(innerWidth - box.offsetWidth - 6, Math.max(6, e.clientX - drag.dx));
      const y = Math.min(innerHeight - box.offsetHeight - 6, Math.max(6, e.clientY - drag.dy));
      if (Math.abs(x - (parseFloat(box.style.left) || 0)) > 2 ||
          Math.abs(y - (parseFloat(box.style.top) || 0)) > 2) {
        if (!drag.moved && !bin) clearTimeout(drag.hold);   // потащили — корзину не зовём
        drag.moved = true;
      }
      box.style.left = x + "px"; box.style.top = y + "px";
      box.style.right = "auto"; box.style.bottom = "auto";
      if (bin) bin.classList.toggle("hot", overBin(e.clientX, e.clientY));
    });
    const drop = (e) => {
      if (!drag) return;
      clearTimeout(drag.hold);
      box.classList.remove("vgp-drag");
      const moved = drag.moved;
      drag = null;
      // бросили в корзину — плеер уходит с глаз до следующего включения
      if (bin && overBin(e.clientX, e.clientY)) { hideBin(); api.hide(); return; }
      hideBin();
      try { localStorage.setItem(POS, JSON.stringify({
        x: parseFloat(box.style.left) || 0, y: parseFloat(box.style.top) || 0 })); } catch (err) {}
      // короткий тык по свёрнутому кружку — развернуть
      if (!moved && folded) { setFolded(false); fetchList(); }
    };
    q(".vgp-head").addEventListener("pointerup", drop);
    q(".vgp-head").addEventListener("pointercancel", drop);

    q("[data-fold]").addEventListener("click", () => setFolded(true));
    q("[data-play]").addEventListener("click", async () => { await fetchList(); api.toggle(); });
    q("[data-next]").addEventListener("click", () => api.next());
    q("[data-prev]").addEventListener("click", () => api.prev());
    q("[data-shuf]").addEventListener("click", () => api.shuffle());
    q("[data-list]").addEventListener("click", async () => {
      await fetchList(true);            // всегда свежий: могли докинуть треков
      rows.classList.toggle("open");
      q("[data-list]").classList.toggle("on", rows.classList.contains("open"));
      drawRows();
    });

    /* перемотка */
    const bar = q("[data-bar]");
    const seekAt = (e) => {
      const r = bar.getBoundingClientRect();
      const k = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
      if (isFinite(audio.duration)) audio.currentTime = k * audio.duration;
    };
    bar.addEventListener("pointerdown", (e) => {
      bar.classList.add("vgp-grab");
      try { bar.setPointerCapture(e.pointerId); } catch (err) {}
      seekAt(e);
    });
    bar.addEventListener("pointermove", (e) => { if (bar.classList.contains("vgp-grab")) seekAt(e); });
    const stopSeek = () => bar.classList.remove("vgp-grab");
    bar.addEventListener("pointerup", stopSeek);
    bar.addEventListener("pointercancel", stopSeek);

    const drawRows = () => {
      if (!rows.classList.contains("open")) return;
      rows.innerHTML = queue.length
        ? queue.map((t, i) =>
            '<div class="vgp-row' + (i === idx ? " on" : "") + '" data-i="' + i + '">' +
            '<div class="n"><b></b><span></span></div></div>').join("")
        : '<div class="vgp-row"><div class="n"><b>Пусто</b><span>добавь треки в фонотеку или папку MUSIK</span></div></div>';
      // текст ставим через textContent — имена файлов бывают какие угодно
      rows.querySelectorAll(".vgp-row[data-i]").forEach((el) => {
        const t = queue[+el.dataset.i];
        el.querySelector("b").textContent = t.title;
        el.querySelector("span").textContent = (t.artist || "") + (t.folder ? " · " + t.folder : "");
        el.addEventListener("click", () => { api.playAt(+el.dataset.i); drawRows(); });
      });
    };

    paintFns.push(() => {
      const t = queue[idx];
      q(".vgp-t").textContent = t ? t.title : "Фонотека";
      q(".vgp-a").textContent = t ? (t.artist || "vitazgio.ru") + (t.folder ? " · " + t.folder : "")
                                 : "ничего не играет";
      q("[data-play]").innerHTML = audio.paused ? I.play : I.pause;
      box.classList.toggle("vgp-on", !audio.paused);
      q("[data-shuf]").classList.toggle("on", shuffle);
      const k = isFinite(audio.duration) && audio.duration ? audio.currentTime / audio.duration : 0;
      q(".vgp-bar i").style.width = (k * 100) + "%";
      q(".vgp-bar b").style.left = (k * 100) + "%";
      q("[data-at]").textContent = mmss(audio.currentTime);
      q("[data-all]").textContent = mmss(audio.duration);
      q(".vgp-ring .fg").style.strokeDashoffset = String(169.6 * (1 - k));
      const cur = rows.querySelector(".vgp-row.on");
      if (rows.classList.contains("open") && (!cur || +cur.dataset.i !== idx)) drawRows();
    });
    paint();
  };

  const start = () => {
    // Показываемся только если плеер включали кнопкой. Звук при этом живёт
    // всегда: трек, начатый на музыке, продолжается и без виджета.
    let on = false;
    try { on = localStorage.getItem("vgPlayerOn") === "1"; } catch (e) { on = false; }
    if (!headless && on) build();
    resume();
  };
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start);
  else start();
})();
"""
    response = Response(js, mimetype="application/javascript; charset=utf-8")
    response.headers["Cache-Control"] = "private, max-age=300"
    return response




@app.get("/claude")
@login_required
def claude_page():
    """Разговор с Claude Code через сайт.

    Страница ничего сама не решает: она рисует вкладки и терминал, а всё
    остальное происходит на домашней машине. Закрыл вкладку браузера — разговор
    остался висеть в tmux и ждёт возвращения."""
    g.frameable = True
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <script>try{if(window.top!==window.self)document.documentElement.classList.add("embed");}catch(e){document.documentElement.classList.add("embed");}</script>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0d1321">
      <meta name="robots" content="noindex">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Claude · vitazgio.ru</title>
      <link rel="stylesheet" href="/static/vendor/xterm.css">
      <script>
        // Догружаем с CDN, если своя копия почему-то не отдалась.
        function vendorFallback(el, url) {
          el.onerror = null;
          var s = document.createElement("script");
          s.src = url;
          document.head.appendChild(s);
        }
      </script>
      <script defer src="/static/vendor/xterm.js"
              onerror="vendorFallback(this, 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js')"></script>
      <script defer src="/static/vendor/xterm-addon-fit.js"
              onerror="vendorFallback(this, 'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js')"></script>
      <style>
        :root {
          color-scheme: dark;
          --bg: #0d1321; --line: rgba(255,255,255,.1); --muted: #989fb2;
          --pc: #2de2ff; --ac: #d97757;      /* тёплый — фирменный цвет Claude */
        }
        * { box-sizing: border-box; }
        body { margin: 0; min-width: 320px; height: 100dvh; overflow: hidden;
               display: flex; flex-direction: column;
               font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
               background:
                 radial-gradient(circle at 10% 6%, rgba(217,119,87,.16), transparent 30rem),
                 radial-gradient(circle at 92% 84%, rgba(57,126,255,.16), transparent 32rem),
                 var(--bg);
               color: #f7f8fc; }
        .page { width: min(1380px, calc(100% - 28px)); margin: 0 auto; flex: 1;
                display: flex; flex-direction: column; min-height: 0;
                padding: clamp(14px, 3vw, 26px) 0 clamp(10px, 2vw, 18px); }

        .top { position: relative; display: flex; align-items: center; gap: 14px;
               flex: none; margin-bottom: 14px; }
        .back { display: inline-flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; flex: none; color: #7ce0ff; text-decoration: none;
                border: 1px solid rgba(45,226,255,.3); border-radius: 50%;
                background: rgba(45,226,255,.07); transition: .18s; }
        .back svg { width: 19px; height: 19px; }
        .back:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.18); }
        html.embed .back { display: none; }   /* встроена во вкладку «Нейронки» */
        .eyebrow { display: inline-flex; align-items: center; gap: 10px; color: #cdd2df;
                   font-size: .72rem; font-weight: 700; letter-spacing: .16em;
                   text-transform: uppercase; text-decoration: none; }
        .eyebrow::before { content: ""; width: 7px; height: 7px; border-radius: 50%;
                           background: var(--ac); box-shadow: 0 0 16px var(--ac); }
        .eyebrow:hover { color: #fff; }
        .where { margin-left: auto; color: #7c8ba0; font-size: .74rem;
                 font-family: "Cascadia Code", Consolas, monospace; }
        .where b { color: var(--ac); font-weight: 600; }
        .quality { margin-left: 10px; font-size: .72rem; color: #7c8ba0; }
        .quality.ok { color: #63f5ad; } .quality.mid { color: #ffd84a; }
        .quality.bad { color: #ff7a59; }

        /* ── вход: суточный пароль и логин на машину ─────────────────── */
        .gate { flex: 1; display: grid; place-items: center; min-height: 0; overflow: auto; }
        .card { width: min(430px, 100%); padding: 28px 26px 24px;
                border: 1px solid var(--line); border-radius: 18px;
                background: linear-gradient(160deg, rgba(24,31,46,.95), rgba(11,16,26,.95));
                box-shadow: 0 26px 60px rgba(0,0,0,.45); }
        .card h2 { margin: 0 0 6px; font-size: 1.22rem; letter-spacing: -.02em; }
        .card .sub { margin: 0 0 18px; color: var(--muted); font-size: .85rem; line-height: 1.55; }
        .card label { display: block; margin: 12px 0 5px; color: #b9c6d8;
                      font-size: .72rem; letter-spacing: .1em; text-transform: uppercase; }
        .card input { width: 100%; height: 42px; padding: 0 13px; color: #eaf3fb;
                      font: 400 .92rem "Cascadia Code", Consolas, monospace;
                      background: rgba(0,0,0,.35); border: 1px solid var(--line);
                      border-radius: 10px; }
        .card input:focus { outline: none; border-color: var(--ac);
                            box-shadow: 0 0 0 3px rgba(217,119,87,.15); }
        .card .err { min-height: 18px; margin: 12px 0 0; color: #ff8fa3; font-size: .82rem; }
        .go { width: 100%; height: 44px; margin-top: 14px; cursor: pointer;
              color: #16100c; font: 700 .92rem inherit; border: 0; border-radius: 11px;
              background: linear-gradient(160deg, #f0a184, var(--ac)); }
        .go:hover { filter: brightness(1.07); }
        .go:disabled { opacity: .55; cursor: default; }
        .note { margin: 16px 0 0; padding: 12px 13px; color: #9fb0c6; font-size: .78rem;
                line-height: 1.6; border: 1px dashed var(--line); border-radius: 11px;
                background: rgba(255,255,255,.02); }
        .note code { color: #ffd0bd; font-family: "Cascadia Code", Consolas, monospace; }

        /* ── вкладки, как в чатах кода ───────────────────────────────── */
        .work { flex: 1; display: none; flex-direction: column; min-height: 0; }
        .work.on { display: flex; }
        .tabs { flex: none; display: flex; align-items: center; gap: 6px;
                overflow-x: auto; scrollbar-width: none; padding-bottom: 2px; }
        .tabs::-webkit-scrollbar { display: none; }
        .tab { flex: none; display: inline-flex; align-items: center; gap: 8px;
               height: 36px; padding: 0 8px 0 14px; cursor: pointer; color: #a9b7c9;
               font: 600 .84rem inherit; white-space: nowrap;
               border: 1px solid var(--line); border-bottom: 0;
               border-radius: 11px 11px 0 0; background: rgba(255,255,255,.03);
               transition: color .16s, background .16s, border-color .16s; }
        .tab:hover { color: #fff; background: rgba(255,255,255,.06); }
        .tab.on { color: #fff; border-color: rgba(217,119,87,.5);
                  background: linear-gradient(180deg, rgba(217,119,87,.22), rgba(217,119,87,.05)); }
        .tab .dot { width: 7px; height: 7px; border-radius: 50%; background: #4a5568; }
        .tab.on .dot, .tab.live .dot { background: var(--ac); box-shadow: 0 0 8px var(--ac); }
        .tab .x { display: grid; place-items: center; width: 20px; height: 20px;
                  border-radius: 6px; color: #7c8ba0; font-size: .9rem; line-height: 1; }
        .tab .x:hover { color: #ff8fa3; background: rgba(255,90,110,.14); }
        .tab-add { flex: none; width: 36px; height: 36px; display: grid; place-items: center;
                   cursor: pointer; color: #9fb0c6; font-size: 1.15rem;
                   border: 1px dashed var(--line); border-bottom: 0;
                   border-radius: 11px 11px 0 0; background: rgba(255,255,255,.02); }
        .tab-add:hover { color: #fff; border-color: var(--ac); }

        .screen { flex: 1; min-height: 0; position: relative; overflow: hidden;
                  border: 1px solid var(--line); border-radius: 0 14px 14px 14px;
                  background: #05070c; padding: 10px 4px 6px 10px; }
        .screen .xterm { height: 100%; }
        .blank { position: absolute; inset: 0; display: grid; place-items: center;
                 padding: 24px; text-align: center; color: #6f7f93; font-size: .88rem;
                 line-height: 1.7; }
        .blank b { display: block; margin-bottom: 6px; color: #cfe0f0; font-size: 1rem; }

        /* ── кнопки под терминалом: на телефоне без них никак ─────────── */
        .keys { flex: none; display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
        .keys button { height: 34px; padding: 0 12px; cursor: pointer; color: #b9c6d8;
                       font: 600 .78rem "Cascadia Code", Consolas, monospace;
                       border: 1px solid var(--line); border-radius: 9px;
                       background: rgba(255,255,255,.04); }
        .keys button:hover { color: #fff; border-color: var(--ac);
                             background: rgba(217,119,87,.12); }
        .keys .gap { margin-left: auto; }
        .toast { position: fixed; left: 50%; bottom: 22px; transform: translateX(-50%);
                 padding: 10px 16px; color: #eaf3fb; font-size: .84rem; z-index: 40;
                 background: rgba(18,24,38,.96); border: 1px solid var(--line);
                 border-radius: 11px; box-shadow: 0 16px 40px rgba(0,0,0,.5); }
        .toast.bad { border-color: rgba(255,90,110,.5); color: #ffb4c0; }
        @media (max-width: 620px) {
          .where { display: none; }
          .page { width: calc(100% - 16px); }
        }
        @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="top">
          <a class="back" href="/cabinet" title="В кабинет" aria-label="В кабинет"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
          <a class="eyebrow" href="/cabinet">vitazgio.ru · claude</a>
          <span class="where" id="where"></span>
          <span class="quality" id="quality"></span>
        </div>

        <section class="gate" id="gate">
          <div class="card">
            <h2>Разговор с Claude</h2>
            <p class="sub" id="sub">Claude Code живёт на домашней машине — сайт только
              показывает её экран. Разговор идёт в tmux: закроешь вкладку, вернёшься
              позже и увидишь его целиком.</p>
            <form id="form">
              <div id="gate-day">
                <label for="f-day">Суточный пароль консоли</label>
                <input id="f-day" type="password" autocomplete="off">
              </div>
              <label for="f-user">Логин на машине</label>
              <input id="f-user" autocomplete="username">
              <label for="f-pass">Пароль</label>
              <input id="f-pass" type="password" autocomplete="current-password">
              <p class="err" id="err"></p>
              <button class="go" type="submit" id="submit">Подключиться</button>
            </form>
            <p class="note" id="note" hidden></p>
          </div>
        </section>

        <section class="work" id="work">
          <div class="tabs" id="tabs"></div>
          <div class="screen" id="screen">
            <div class="blank" id="blank"><b>Ни одной вкладки</b>
              Нажми «+» — заведём разговор.</div>
          </div>
          <div class="keys" id="keys">
            <button data-key="enter">Enter</button>
            <button data-key="up">↑</button>
            <button data-key="down">↓</button>
            <button data-key="tab">Tab</button>
            <button data-key="esc">Esc</button>
            <button data-key="ctrlc">Ctrl+C</button>
            <button data-paste>Вставить</button>
            <button class="gap" data-off>Отцепиться</button>
          </div>
        </section>
      </main>

      <script>
      (() => {
        "use strict";
        const $ = (id) => document.getElementById(id);
        const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
          (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

        let ws = null, term = null, fit = null;
        let tabs = [], open = null, spawned = false;
        let creds = null;               // логин и пароль живут только здесь

        let toastTimer = 0;
        const toast = (text, bad) => {
          document.querySelectorAll(".toast").forEach((t) => t.remove());
          const el = document.createElement("div");
          el.className = "toast" + (bad ? " bad" : "");
          el.textContent = text;
          document.body.appendChild(el);
          clearTimeout(toastTimer);
          toastTimer = setTimeout(() => el.remove(), 3400);
        };

        /* ── что настроено на сервере ─────────────────────────────────── */
        let state = { ready: false, host: "", gate: false, dir: "" };
        const boot = async () => {
          try {
            const r = await fetch("/api/claude/state", { credentials: "same-origin" });
            state = await r.json();
          } catch (e) { /* покажем как есть */ }
          if (!state.gate) $("gate-day").hidden = true;
          if (state.ready) {
            $("where").innerHTML = "машина <b>" + esc(state.host) + "</b>" +
              (state.dir ? " · " + esc(state.dir) : "");
          } else {
            $("form").hidden = true;
            $("sub").textContent = "Вкладка ещё не настроена.";
            const note = $("note");
            note.hidden = false;
            note.innerHTML = "Нужно назвать машину, на которой стоит Claude Code: " +
              "в <code>.env</code> сервера задать <code>CLAUDE_HOST</code> — адрес " +
              "домашней машины из списка NetBird, у которой открыт SSH. Рядом можно " +
              "задать <code>CLAUDE_DIR</code> — папку, в которой открывать разговор, " +
              "и <code>CLAUDE_BIN</code> — саму команду: вкладка запускает то, что " +
              "там написано, так что вместо Claude сюда встанет любой другой " +
              "консольный помощник.";
          }
        };

        /* ── терминал ─────────────────────────────────────────────────── */
        const makeTerm = () => {
          if (term) return true;
          if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
            $("blank").innerHTML = "<b>Не загрузилась библиотека терминала</b>" +
              "Проверь сеть — xterm.js не отдался ни с сайта, ни с CDN.";
            return false;
          }
          term = new Terminal({
            convertEol: true, cursorBlink: true, scrollback: 5000,
            fontFamily: '"Cascadia Code", Consolas, monospace', fontSize: 13,
            theme: { background: "#05070c", foreground: "#e6edf5", cursor: "#d97757" },
          });
          fit = new FitAddon.FitAddon();
          term.loadAddon(fit);
          term.open($("screen"));
          fit.fit();
          term.onData((d) => say({ type: "data", data: d }));
          term.onResize(() => sendSize());
          addEventListener("resize", () => { try { fit.fit(); } catch (e) {} });
          // На телефоне клавиатура съедает пол-экрана — пересчитываем размер.
          if (window.visualViewport) {
            visualViewport.addEventListener("resize", () => {
              try { fit.fit(); } catch (e) {}
            });
          }
          return true;
        };

        const sendSize = () => {
          if (!term) return;
          say({ type: "resize", cols: term.cols, rows: term.rows });
        };

        const say = (payload) => {
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
        };

        /* ── вкладки ──────────────────────────────────────────────────── */
        const drawTabs = () => {
          $("tabs").innerHTML = tabs.map((t) =>
            '<div class="tab' + (t.id === open ? " on" : "") + (t.live ? " live" : "") +
            '" data-tab="' + esc(t.id) + '"><span class="dot"></span>Разговор ' +
            esc(t.id) + '<span class="x" data-kill="' + esc(t.id) + '" title="Закрыть совсем">×</span></div>'
          ).join("") + '<div class="tab-add" id="add" title="Новый разговор">+</div>';
          $("blank").hidden = !!open;
        };

        $("tabs").addEventListener("click", (e) => {
          if (e.target.closest("#add")) { say({ type: "new" }); return; }
          const kill = e.target.closest("[data-kill]");
          if (kill) {
            const id = kill.dataset.kill;
            if (confirm("Закрыть разговор " + id + " совсем? Он не сохранится.")) {
              say({ type: "kill", tab: id });
            }
            return;
          }
          const tab = e.target.closest("[data-tab]");
          if (tab && tab.dataset.tab !== open) {
            if (term) term.clear();
            say({ type: "open", tab: tab.dataset.tab });
          }
        });

        /* ── кнопки под терминалом ────────────────────────────────────── */
        const KEYS = { enter: "\\r", up: "\\x1b[A", down: "\\x1b[B",
                       tab: "\\t", esc: "\\x1b", ctrlc: "\\x03" };
        $("keys").addEventListener("click", async (e) => {
          const key = e.target.closest("[data-key]");
          if (key) { say({ type: "data", data: KEYS[key.dataset.key] || "" });
                     if (term) term.focus(); return; }
          if (e.target.closest("[data-paste]")) {
            let text = null;
            try { text = await navigator.clipboard.readText(); }
            catch (err) { text = prompt("Вставь текст сюда (браузер не даёт прочитать буфер сам):", ""); }
            if (!text) { toast("Буфер пуст", true); return; }
            say({ type: "data", data: text });
            if (term) term.focus();
            return;
          }
          if (e.target.closest("[data-off]")) {
            // Отцепиться — не закрыть: разговор остаётся висеть на машине.
            if (ws) ws.close();
            toast("Отцепился. Разговоры остались на машине");
          }
        });

        /* ── связь ────────────────────────────────────────────────────── */
        let pingAt = null, pinger = 0;
        const quality = (ms) => {
          const el = $("quality");
          el.textContent = "● " + ms + " мс";
          el.className = "quality " + (ms < 120 ? "ok" : ms < 400 ? "mid" : "bad");
        };

        const connect = () => {
          const proto = location.protocol === "https:" ? "wss:" : "ws:";
          ws = new WebSocket(proto + "//" + location.host + "/ws/claude");

          ws.addEventListener("open", () => {
            ws.send(JSON.stringify({ type: "auth", username: creds.user, password: creds.pass }));
            clearInterval(pinger);
            pinger = setInterval(() => {
              if (ws && ws.readyState === WebSocket.OPEN) {
                pingAt = performance.now();
                say({ type: "ping" });
              }
            }, 10000);
          });

          ws.addEventListener("message", (ev) => {
            let d;
            try { d = JSON.parse(ev.data); } catch (e) { return; }
            if (d.type === "data") { if (term) term.write(d.data); return; }
            if (d.type === "ready") {
              $("gate").style.display = "none";
              $("work").classList.add("on");
              if (makeTerm()) { fit.fit(); sendSize(); term.focus(); }
              return;
            }
            if (d.type === "tabs") {
              tabs = d.tabs || [];
              open = d.open || null;
              drawTabs();
              // Первый заход и ни одного разговора — заводим сразу, чтобы не
              // встречать пустым экраном. Ровно один раз: список приходит
              // ещё и следом за созданием, и второй заход наплодил бы лишних.
              if (!spawned && !tabs.length && !open) { spawned = true; say({ type: "new" }); }
              return;
            }
            if (d.type === "open") {
              open = d.tab;
              drawTabs();
              sendSize();
              if (term) term.focus();
              return;
            }
            if (d.type === "fail") {
              toast(d.text || "Не вышло", true);
              if (!$("work").classList.contains("on")) {
                $("err").textContent = d.text || "Не вышло";
                $("submit").disabled = false;
              }
              return;
            }
            if (d.type === "pong" && pingAt !== null) {
              quality(Math.round(performance.now() - pingAt));
              pingAt = null;
            }
          });

          ws.addEventListener("close", () => {
            clearInterval(pinger);
            $("quality").textContent = "";
            $("submit").disabled = false;
            if ($("work").classList.contains("on")) {
              if (term) term.write("\\r\\n\\x1b[33mСвязь закрыта. Разговоры остались на машине — обнови страницу.\\x1b[0m\\r\\n");
              open = null;
              drawTabs();
            }
          });
        };

        /* ── вход ─────────────────────────────────────────────────────── */
        $("form").addEventListener("submit", async (e) => {
          e.preventDefault();
          $("err").textContent = "";
          $("submit").disabled = true;
          const user = $("f-user").value.trim();
          const pass = $("f-pass").value;
          if (!user || !pass) {
            $("err").textContent = "Нужны логин и пароль машины.";
            $("submit").disabled = false;
            return;
          }
          // Суточный пароль открывает консольную дверь — ту же, что у SSH в
          // кабинете. Своей двери у вкладки нет намеренно: меньше замков,
          // меньше мест, где можно ошибиться.
          if (state.gate) {
            try {
              const r = await fetch("/api/console/login", {
                method: "POST", credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: $("f-day").value }) });
              const d = await r.json().catch(() => ({}));
              if (!r.ok) {
                $("err").textContent = d.error || "Суточный пароль не подошёл.";
                $("submit").disabled = false;
                return;
              }
            } catch (err) {
              $("err").textContent = "Сервер недоступен.";
              $("submit").disabled = false;
              return;
            }
          }
          creds = { user, pass };
          $("f-pass").value = "";
          $("f-day").value = "";
          connect();
        });

        addEventListener("beforeunload", () => { if (ws) ws.close(); });

        boot();
      })();
      </script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)
@app.get("/diy")
def diy_page():
    """Страна DIY: витрина своих творений.

    Смотреть может кто угодно, добавлять — хозяин. Отдельного входа не просим:
    если сайт уже помнит устройство по кабинету, режим правки включается сам."""
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Программы, поделки и чертежи vitazgio.ru">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Страна DIY · vitazgio.ru</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #0d1321; --line: rgba(255,255,255,.1); --muted: #989fb2;
          --pc: #2de2ff; --warm: #ffd84a;
          /* Цвет выбранной тематики. Меняется скриптом при переключении полки
             и красит кнопки, полосы прокрутки и подсветку карточек. */
          --th: #2de2ff;
        }
        * { box-sizing: border-box; }
        body { margin: 0; min-width: 320px; padding-bottom: 60px;
               font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
               background:
                 radial-gradient(circle at 12% 8%, rgba(57,126,255,.22), transparent 32rem),
                 radial-gradient(circle at 88% 78%, rgba(149,65,255,.18), transparent 34rem),
                 var(--bg);
               color: #f7f8fc; }
        .page { width: min(1380px, calc(100% - 40px)); margin: 0 auto;
                padding: clamp(24px, 5vw, 52px) 0 0; }

        .top { position: relative; display: flex; align-items: center; gap: 14px; margin-bottom: 22px; }
        .back { display: inline-flex; align-items: center; justify-content: center;
                width: 42px; height: 42px; flex: none; color: #7ce0ff; text-decoration: none;
                border: 1px solid rgba(45,226,255,.3); border-radius: 50%;
                background: rgba(45,226,255,.07); transition: .18s; }
        .back svg { width: 20px; height: 20px; }
        .back:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.18); }
        .eyebrow { display: inline-flex; align-items: center; gap: 10px; color: #cdd2df;
                   font-size: .76rem; font-weight: 700; letter-spacing: .16em;
                   text-transform: uppercase; text-decoration: none; }
        .eyebrow::before { content: ""; width: 7px; height: 7px; border-radius: 50%;
                           background: #64e6a5; box-shadow: 0 0 16px #64e6a5; }
        .eyebrow:hover { color: #fff; }
        .mark { position: absolute; right: 0; top: 50%; transform: translateY(-62%);
                width: clamp(1.15rem, 4.7vw, 4.4rem); height: clamp(1.15rem, 4.7vw, 4.4rem); }

        h1 { position: relative; min-height: 118px; display: flex; align-items: center;
             margin: 0; padding: 24px clamp(20px, 4vw, 48px);
             font-family: "Cascadia Code", Consolas, monospace;
             font-size: clamp(1.1rem, 4.2vw, 3.4rem); font-weight: 800;
             letter-spacing: -.05em; color: #dffaff;
             border: 1px solid rgba(54,228,255,.24);
             background: linear-gradient(110deg, rgba(12,28,43,.92), rgba(20,17,38,.82));
             clip-path: polygon(0 0, calc(100% - 25px) 0, 100% 25px, 100% 100%, 25px 100%, 0 calc(100% - 25px));
             text-shadow: 2px 0 #ff3fa4, -2px 0 #21dcff; }

        /* Полоса хозяина. Видна, только когда сайт узнал своего. */
        .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
               margin: 22px 0 0; }
        .badge { display: inline-flex; align-items: center; gap: 8px; height: 34px;
                 padding: 0 13px; color: #04121a; background: var(--pc);
                 border-radius: 999px;
                 font: 700 .68rem "Cascadia Code", Consolas, monospace;
                 letter-spacing: .14em; text-transform: uppercase; }
        .btn { display: inline-flex; align-items: center; gap: 8px; height: 38px;
               padding: 0 16px; color: #cdd6e6; cursor: pointer;
               font: 600 .84rem inherit; white-space: nowrap;
               background: rgba(255,255,255,.05); border: 1px solid var(--line);
               border-radius: 10px; transition: .18s; }
        .btn:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.1); }
        .btn.go { color: #04121a; background: var(--pc); border-color: var(--pc); }
        .btn.go:hover { filter: brightness(1.1); }
        .btn.bad { color: #ff9aa6; border-color: rgba(255,90,110,.35); }
        .btn.bad:hover { border-color: #ff5a6e; background: rgba(255,90,110,.14); }
        .btn svg { width: 16px; height: 16px; flex: none; }
        .bar .spacer { margin-left: auto; }

        /* ── Полки и пять способов листать ──────────────────────────────
           Сверху выбираются тематики — программы, устройства, сервера,
           разное, — и у каждой свой цвет: он подхватывается через --th и
           красит кнопки, полосы прокрутки и подсветку карточек. Разметка
           карточки одна и та же, меняется только раскладка: класс на самой
           ленте решает, сетка это, барабан, кладка, веер или соты.
           Выбранный вид запоминается для каждой полки отдельно. */
        .shelfrow { display: flex; align-items: center; gap: 8px; margin: 26px 0 0; min-width: 0; }
        .shelf { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; min-width: 0; }
        .shelf .lbl, .modes .lbl { color: var(--muted); font-size: .68rem; letter-spacing: .14em;
                                   text-transform: uppercase; margin-right: 4px; }
        .shelf button { --tc: var(--pc); display: inline-flex; align-items: center; gap: 8px;
                        height: 36px; padding: 0 14px; cursor: pointer; color: #b9c6d8;
                        font: 600 .84rem inherit; border-radius: 11px;
                        border: 1px solid var(--line); background: rgba(255,255,255,.04);
                        transition: color .16s, border-color .16s, background .16s; }
        .shelf button i { font-style: normal; width: 8px; height: 8px; border-radius: 50%;
                          background: var(--tc); box-shadow: 0 0 10px var(--tc); }
        .shelf button u { text-decoration: none; color: #6f7f93;
                          font: 700 .68rem "Cascadia Code", Consolas, monospace; }
        .shelf button:hover { color: #fff;
                              border-color: color-mix(in srgb, var(--tc) 55%, transparent);
                              background: color-mix(in srgb, var(--tc) 10%, transparent); }
        .shelf button.on { color: #fff; border-color: var(--tc);
                           background: color-mix(in srgb, var(--tc) 16%, transparent);
                           box-shadow: 0 0 24px color-mix(in srgb, var(--tc) 18%, transparent); }
        .shelf button.on u { color: color-mix(in srgb, var(--tc) 80%, #ffffff); }
        .shelf-hint { margin: 8px 0 0; color: #7c8ba0; font-size: .76rem; }
        /* На телефоне полки не переносим в три ряда, а даём листать вбок:
           так шапка страницы не разъезжается на пол-экрана. */
        @media (max-width: 620px) {
          .shelf { flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none;
                   padding-bottom: 4px; }
          .shelf::-webkit-scrollbar { display: none; }
          .shelf button { flex: none; }
        }

        .modes { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin: 14px 0 4px; }
        .modes button { width: 34px; height: 34px; display: grid; place-items: center; cursor: pointer;
                        color: #9fb0c6; font: 700 .8rem "Cascadia Code", Consolas, monospace;
                        border: 1px solid var(--line); border-radius: 10px;
                        background: rgba(255,255,255,.04); transition: .16s; }
        .modes button:hover { color: #fff;
                              border-color: color-mix(in srgb, var(--th) 55%, transparent);
                              background: color-mix(in srgb, var(--th) 12%, transparent); }
        .modes button.on { color: #04121c; border-color: var(--th);
                           background: linear-gradient(160deg,
                             color-mix(in srgb, var(--th) 70%, #ffffff), var(--th)); }
        .modes .name { margin-left: 6px; color: #cfe0f0; font-size: .78rem; }
        .modes .name b { color: var(--th); }
        .navs { display: flex; gap: 8px; margin-left: auto; }
        .navs button { width: 34px; height: 34px; }

        /* Своя прокрутка на каждой полке: ползунок красится цветом тематики. */
        .grid { margin: 18px 0 0; scrollbar-width: thin;
                scrollbar-color: color-mix(in srgb, var(--th) 60%, transparent) transparent; }
        .grid::-webkit-scrollbar { height: 9px; width: 9px; }
        .grid::-webkit-scrollbar-track { background: rgba(255,255,255,.04); border-radius: 999px; }
        .grid::-webkit-scrollbar-thumb { border-radius: 999px;
                background: linear-gradient(90deg, var(--th),
                            color-mix(in srgb, var(--th) 35%, transparent)); }

        /* Карточки выплывают по очереди, когда до них доходит прокрутка. */
        .work.up, .hex.up { opacity: 0; transform: translateY(18px); }
        .work.up.seen, .hex.up.seen { opacity: 1; transform: none;
                                      transition: opacity .5s ease, transform .5s cubic-bezier(.22,1,.36,1); }

        /* 1 · сетка */
        .grid.m-grid { display: grid; gap: 18px;
                       grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }
        /* Закреплённая запись занимает две клетки — витрина начинается с неё. */
        @media (min-width: 900px) {
          .grid.m-grid .work.wide { grid-column: span 2; }
          .grid.m-grid .work.wide .shot { aspect-ratio: 21 / 9; }
        }

        /* 2 · барабан: горизонтальная лента с прилипанием и полосой хода */
        .grid.m-drum { display: flex; gap: 16px; overflow-x: auto; scroll-snap-type: x mandatory;
                       padding: 6px 2px 18px; cursor: grab; }
        .grid.m-drum.hauling { cursor: grabbing; scroll-snap-type: none; }
        .grid.m-drum.hauling .work { pointer-events: none; }
        .grid.m-drum .work { flex: none; width: min(340px, 78vw); scroll-snap-align: center;
                             transition: transform .3s ease, opacity .3s ease, border-color .2s; }
        .grid.m-drum .work.mid { transform: translateY(-6px) scale(1.03);
                                 border-color: color-mix(in srgb, var(--ac) 55%, transparent); }
        .grid.m-drum .work.far { opacity: .68; }
        .rail { position: relative; height: 4px; margin: 2px 2px 0; border-radius: 999px;
                background: rgba(255,255,255,.07); overflow: hidden; }
        .rail i { position: absolute; top: 0; bottom: 0; left: 0; border-radius: 999px;
                  background: linear-gradient(90deg, var(--th),
                              color-mix(in srgb, var(--th) 40%, transparent));
                  box-shadow: 0 0 14px color-mix(in srgb, var(--th) 45%, transparent); }
        .rail[hidden] { display: none; }

        /* 3 · кладка: колонки разной высоты, картинки во весь рост */
        .grid.m-mosaic { column-count: 3; column-gap: 16px; }
        .grid.m-mosaic .work { break-inside: avoid; margin-bottom: 16px; display: inline-flex; width: 100%; }
        /* Здесь обложка живёт своей высотой — из-за этого кладка и получается */
        .grid.m-mosaic .shot { aspect-ratio: auto; }
        .grid.m-mosaic .shot img { height: auto; max-height: 520px; object-fit: cover; }
        .grid.m-mosaic .shot-bg { display: none; }
        .grid.m-mosaic .shot.none { aspect-ratio: 16 / 11; }
        .grid.m-mosaic .work:nth-child(3n+2) .shot.none { aspect-ratio: 4 / 5; }
        .grid.m-mosaic .work:nth-child(3n+3) .shot.none { aspect-ratio: 16 / 8; }
        @media (max-width: 980px) { .grid.m-mosaic { column-count: 2; } }
        @media (max-width: 640px) { .grid.m-mosaic { column-count: 1; } }

        /* 4 · веер: боковые карточки уходят в перспективу */
        .grid.m-fan { display: flex; gap: 26px; overflow-x: auto; scroll-snap-type: x mandatory;
                      padding: 34px calc(50% - min(320px, 72vw) / 2) 40px;
                      perspective: 1200px; scrollbar-width: none; cursor: grab; }
        .grid.m-fan::-webkit-scrollbar { display: none; }
        .grid.m-fan.hauling { cursor: grabbing; scroll-snap-type: none; }
        .grid.m-fan.hauling .work { pointer-events: none; }
        .grid.m-fan .work { flex: none; width: min(320px, 72vw); scroll-snap-align: center;
                            background: linear-gradient(160deg, #141d2e, #0a1019);
                            transition: transform .25s ease, opacity .25s ease; will-change: transform; }
        /* Тень под веером: карточка в середине стоит на «полу» */
        .grid.m-fan .work::after { content: ""; position: absolute; left: 10%; right: 10%; bottom: -26px;
                                   height: 26px; border-radius: 50%; pointer-events: none;
                                   background: radial-gradient(50% 100% at 50% 0%,
                                     rgba(0,0,0,.55), transparent 70%); }

        /* 5 · соты: ряды сцеплены между собой, как настоящие */
        .grid.m-hex { display: flex; flex-wrap: wrap; gap: 10px 8px; justify-content: center;
                      padding: 16px 0 40px; }
        .grid.m-hex .hex { position: relative; width: 210px; height: 240px; cursor: pointer;
                           margin-bottom: -58px;
                           clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
                           background: linear-gradient(160deg, rgba(25,32,48,.95), rgba(10,15,26,.95));
                           display: grid; place-items: center; text-align: center; padding: 30px 20px;
                           transition: transform .22s, filter .22s; }
        .grid.m-hex .hex:nth-child(even) { margin-top: 62px; }
        .grid.m-hex .hex:hover { transform: translateY(-6px) scale(1.04); z-index: 3; }
        .grid.m-hex .hex .fill { position: absolute; inset: 0; background: center/cover no-repeat;
                                 opacity: .3; filter: saturate(1.1); transition: opacity .22s; }
        .grid.m-hex .hex:hover .fill { opacity: .5; }
        .grid.m-hex .hex .glow { position: absolute; inset: 0;
                                 background: radial-gradient(70% 60% at 50% 0%, var(--ac), transparent 70%);
                                 opacity: .22; }
        .grid.m-hex .hex .rim { position: absolute; inset: 0; z-index: 3; pointer-events: none;
                                clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%,
                                                   50% 0%, 50% 2%, 3% 26.2%, 3% 73.8%, 50% 98%,
                                                   97% 73.8%, 97% 26.2%, 50% 2%);
                                background: color-mix(in srgb, var(--ac) 55%, transparent); }
        .grid.m-hex .hex .in { position: relative; z-index: 2; }
        .grid.m-hex .hex b { display: block; font-size: .96rem; color: #f2f8ff; }
        .grid.m-hex .hex span { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;
                                overflow: hidden; margin-top: 6px; color: #93a3b8;
                                font-size: .68rem; line-height: 1.5; transition: -webkit-line-clamp .2s; }
        .grid.m-hex .hex:hover span { -webkit-line-clamp: 5; color: #b9c8da; }
        @media (max-width: 520px) {
          .grid.m-hex .hex { width: 172px; height: 198px; padding: 24px 16px; margin-bottom: -46px; }
          .grid.m-hex .hex:nth-child(even) { margin-top: 50px; }
        }
        /* Цвет карточки задаётся в шапке кода строкой «цвет:», отсюда --ac. */
        .work { --ac: var(--pc); position: relative; display: flex; flex-direction: column;
                overflow: hidden; background: rgba(25,32,48,.82);
                border: 1px solid var(--line); border-radius: 18px;
                transition: transform .2s, border-color .2s, box-shadow .2s; }
        .work::before { content: ""; position: absolute; left: 0; right: 0; top: 0; height: 3px; z-index: 2;
                        background: linear-gradient(90deg, var(--ac), transparent 78%); }
        .work:hover { transform: translateY(-4px);
                      border-color: color-mix(in srgb, var(--ac) 55%, transparent);
                      box-shadow: 0 20px 50px rgba(0,0,0,.4),
                                  0 0 34px color-mix(in srgb, var(--ac) 12%, transparent); }
        .work.draft { border-style: dashed; opacity: .82; }
        .shot { position: relative; aspect-ratio: 16 / 10; overflow: hidden; background: #0a0f18;
                border-bottom: 1px solid var(--line); }
        .shot-bg { position: absolute; inset: -12%; background: center/cover no-repeat;
                   filter: blur(18px) saturate(1.15) brightness(.55); }
        .shot img { position: relative; z-index: 1; width: 100%; height: 100%;
                    object-fit: contain; display: block; }
        /* лёгкое затемнение снизу, чтобы обложка не спорила с текстом */
        .shot::after { content: ""; position: absolute; inset: 0; z-index: 2;
                       background: linear-gradient(180deg, transparent 62%, rgba(10,15,24,.5)); }
        .tagrow { display: flex; flex-wrap: wrap; gap: 6px; }
        .tagrow i { font-style: normal; padding: 3px 9px; border-radius: 7px; font-size: .68rem;
                    color: #cfe0f0; background: rgba(255,255,255,.05);
                    border: 1px solid var(--line); }
        /* Своя обложка, когда фото нет: цвет записи, штриховка и монограмма. */
        .shot.none { display: grid; place-items: center; overflow: hidden;
                     background:
                       repeating-linear-gradient(135deg, rgba(255,255,255,.03) 0 10px, transparent 10px 20px),
                       radial-gradient(120% 100% at 20% 0%, color-mix(in srgb, var(--ac) 38%, transparent), transparent 68%),
                       linear-gradient(160deg, rgba(22,30,46,.95), rgba(9,14,24,.95)); }
        .shot.none .mono { font: 800 2.4rem "Cascadia Code", Consolas, monospace;
                           letter-spacing: -.04em; text-transform: uppercase;
                           color: color-mix(in srgb, var(--ac) 75%, #ffffff);
                           text-shadow: 0 0 26px color-mix(in srgb, var(--ac) 45%, transparent);
                           opacity: .9; }
        .body { flex: 1; display: flex; flex-direction: column; gap: 10px; padding: 16px 18px 18px; }
        .kind { align-self: flex-start; padding: 3px 10px;
                color: color-mix(in srgb, var(--kc, var(--pc)) 72%, #ffffff);
                background: color-mix(in srgb, var(--kc, var(--pc)) 14%, transparent);
                border: 1px solid color-mix(in srgb, var(--kc, var(--pc)) 28%, transparent);
                border-radius: 999px;
                font: 700 .64rem "Cascadia Code", Consolas, monospace;
                letter-spacing: .12em; text-transform: uppercase; }
        .work h2 { margin: 0; font-size: 1.18rem; letter-spacing: -.02em; }
        .work p { margin: 0; color: var(--muted); font-size: .9rem; line-height: 1.5;
                  white-space: pre-wrap; }
        .links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 2px; }
        .links a { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px;
                   color: #cfe6ff; text-decoration: none; font-size: .78rem;
                   background: rgba(255,255,255,.06); border: 1px solid var(--line);
                   border-radius: 8px; }
        .links a:hover { color: #04121a; background: var(--pc); border-color: var(--pc); }
        .flags { display: flex; gap: 6px; }
        .flag { padding: 2px 8px; border-radius: 999px;
                font: 700 .6rem "Cascadia Code", Consolas, monospace;
                letter-spacing: .1em; text-transform: uppercase; }
        .flag.hid { color: #ffd0a0; background: rgba(255,140,60,.16); }
        .flag.pin { color: #04121a; background: var(--warm); }
        /* Кнопки правки прижаты к низу: в ряду карточки разной высоты,
           и без этого «Править» гуляет по вертикали. */
        .tools { display: flex; gap: 8px; margin-top: auto; padding-top: 4px; }
        .tools .btn { height: 32px; padding: 0 12px; font-size: .78rem; }

        .empty { padding: 60px 20px; color: var(--muted); text-align: center; }

        /* Окно правки */
        .veil { position: fixed; inset: 0; z-index: 60; display: grid; place-items: center;
                padding: 20px; overflow: auto; background: rgba(6,9,16,.76); }
        .sheet { width: min(560px, 100%); padding: 24px;
                 background: linear-gradient(160deg, rgba(24,32,48,.98), rgba(12,16,26,.98));
                 border: 1px solid var(--line); border-radius: 18px; }
        .sheet h3 { margin: 0 0 18px; font-size: 1.15rem; }
        .field { display: block; margin-bottom: 14px; }
        .field span { display: block; margin-bottom: 6px; color: var(--muted);
                      font-size: .74rem; letter-spacing: .1em; text-transform: uppercase; }
        .field input, .field textarea, .field select {
          width: 100%; padding: 10px 12px; color: #f7f8fc; font: inherit;
          background: rgba(0,0,0,.35); border: 1px solid var(--line); border-radius: 10px; }
        .field textarea { min-height: 96px; resize: vertical; }
        .field input:focus, .field textarea:focus, .field select:focus {
          outline: none; border-color: var(--pc); }
        .row2 { display: flex; gap: 8px; margin-bottom: 8px; }
        .row2 input:first-child { flex: 0 0 34%; }
        .row2 input:nth-child(2) { flex: 1; }
        .row2 button { flex: none; width: 38px; }
        .checks { display: flex; flex-wrap: wrap; gap: 16px; margin: 4px 0 18px; }
        .checks label { display: inline-flex; align-items: center; gap: 8px;
                        color: #cdd6e6; font-size: .86rem; cursor: pointer; }
        .checks input { width: 17px; height: 17px; accent-color: var(--pc); }
        .cover { display: flex; align-items: center; gap: 12px; margin-bottom: 18px; }
        .cover .pic { width: 108px; aspect-ratio: 16/9; flex: none; border-radius: 8px;
                      background: #0a0f18 center/cover no-repeat; border: 1px solid var(--line); }
        .sheet-keys { display: flex; gap: 10px; }
        .sheet-keys .btn { flex: 1; justify-content: center; }
        .note { margin: 0 0 14px; color: #ff9aa6; font-size: .82rem; min-height: 1em; }

        /* Код статьи — моноширинное поле пошире: сюда ложится HTML творения. */
        .field textarea.code { min-height: 220px; font-family: "Cascadia Code", Consolas, monospace;
                               font-size: .82rem; line-height: 1.5; white-space: pre; overflow-wrap: normal; }
        .hint { margin: -8px 0 14px; color: #7f8aa0; font-size: .74rem; line-height: 1.5; }
        .hint code { padding: 1px 5px; color: #cfe6ff; background: rgba(255,255,255,.08);
                     border-radius: 5px; font-size: .92em; }
        /* Список вложений: каждое — имя (тык копирует {{имя}}), вес и «×». */
        .assets { display: flex; flex-direction: column; gap: 6px; margin: 4px 0 8px; }
        .asset { display: flex; align-items: center; gap: 10px; padding: 8px 10px;
                 background: rgba(0,0,0,.3); border: 1px solid var(--line); border-radius: 9px; }
        .asset .tk { flex: none; width: 26px; height: 26px; display: grid; place-items: center;
                     border-radius: 6px; color: #04121a; font-size: .62rem; font-weight: 800; }
        .asset .tk.img { background: #63f5ad; }
        .asset .tk.file { background: var(--warm); }
        .asset .nm { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;
                     white-space: nowrap; color: #dbe4f2; font-size: .82rem; cursor: copy;
                     font-family: "Cascadia Code", Consolas, monospace; }
        .asset .nm:hover { color: var(--pc); }
        .asset .sz { flex: none; color: var(--muted); font-size: .72rem; }
        .asset .rm { flex: none; width: 26px; height: 26px; padding: 0; cursor: pointer;
                     color: #ff9aa6; background: transparent; border: 1px solid rgba(255,90,110,.3);
                     border-radius: 7px; }
        .asset .rm:hover { background: rgba(255,90,110,.14); border-color: #ff5a6e; }
        .asset-keys { display: flex; gap: 8px; }
        .asset-keys .btn { flex: 1; justify-content: center; height: 34px; font-size: .8rem; }
        /* «Открыть» на карточке — заметная строка снизу для всех гостей. */
        .open-row { margin-top: auto; padding-top: 4px; }
        .open-row .btn { width: 100%; justify-content: center; color: #04121a;
                         background: var(--pc); border-color: var(--pc); height: 34px; }
        .open-row .btn:hover { filter: brightness(1.08); }
        .work .shot { cursor: pointer; }

        .toast { position: fixed; left: 50%; bottom: 26px; z-index: 90;
                 transform: translateX(-50%); padding: 11px 18px;
                 color: #04121a; background: var(--pc); border-radius: 10px;
                 font-weight: 700; font-size: .86rem; }
        .toast.bad { color: #fff; background: #d93a52; }

        [hidden] { display: none !important; }

        /* Окно ввода пароля — один в один как на главной у кабинета. */
        .auth-modal { position: fixed; z-index: 100; inset: 0; display: grid; place-items: center; padding: 20px; }
        .auth-backdrop { position: absolute; inset: 0; background: rgba(3,6,13,.82); backdrop-filter: blur(12px); }
        .auth-panel { position: relative; width: min(430px, 100%); padding: 38px; color: #e8fbff;
                      border: 1px solid rgba(45,226,255,.3);
                      background: linear-gradient(145deg, rgba(16,30,47,.98), rgba(20,16,37,.98));
                      clip-path: polygon(0 0, calc(100% - 22px) 0, 100% 22px, 100% 100%, 22px 100%, 0 calc(100% - 22px));
                      box-shadow: 0 32px 100px rgba(0,0,0,.65), inset 0 0 40px rgba(45,226,255,.05); }
        .auth-kicker { color: #2de2ff; font: 700 .7rem/1 "Cascadia Code", Consolas, monospace; letter-spacing: .16em; text-transform: uppercase; }
        .auth-panel h2 { margin: 16px 0 8px; font: 800 clamp(2rem,8vw,3rem)/1 "Cascadia Code", Consolas, monospace; letter-spacing: -.07em; text-shadow: 2px 0 #ff3fa4, -2px 0 #2de2ff; }
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

        @media (max-width: 620px) {
          .grid { grid-template-columns: 1fr; }
          .row2 { flex-wrap: wrap; }
          .row2 input:first-child { flex: 1 1 100%; }
          .auth-panel { padding: 34px 25px 28px; }
        }
        @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="top">
          <a class="back" href="/" title="На главную" aria-label="На главную"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
          <a class="eyebrow" href="/">vitazgio.ru · страна diy</a>
          <img class="mark" src="/static/icons/vg-plain.svg" alt="Vitaz Gio"
               width="512" height="512">
        </div>
        <h1>СТРАНА DIY</h1>

        <div class="bar" id="bar"></div>
        <div class="shelfrow"><span class="lbl">полка</span>
          <div class="shelf" id="shelf"></div></div>
        <p class="shelf-hint" id="shelfhint"></p>
        <div class="modes" id="modes"></div>
        <section class="grid m-grid" id="grid"></section>
        <div class="rail" id="rail" hidden><i></i></div>
        <p class="empty" id="empty" hidden>Пока пусто</p>
      </main>

      <input type="file" id="pick" accept="image/*" hidden>
      <input type="file" id="pick-img" accept="image/*" hidden>
      <input type="file" id="pick-file" hidden>

      <div id="auth-modal" class="auth-modal" hidden>
        <div class="auth-backdrop" data-auth-close></div>
        <section class="auth-panel" role="dialog" aria-modal="true" aria-labelledby="auth-title">
          <button class="auth-close" type="button" data-auth-close aria-label="Закрыть">×</button>
          <div class="auth-kicker">Restricted area // 01</div>
          <h2 id="auth-title">Авторизация</h2>
          <p class="auth-hint">Введите пароль для прав админа.</p>
          <form id="auth-form" class="auth-form">
            <label for="auth-password">Пароль</label>
            <input id="auth-password" name="password" type="password" autocomplete="current-password" required>
            <button class="auth-submit" type="submit">Получить доступ</button>
            <p id="auth-error" class="auth-error" role="alert"></p>
          </form>
        </section>
      </div>

      <script>
      (() => {
        "use strict";
        const $ = (id) => document.getElementById(id);
        const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
          (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
        const fmtBytes = (n) => {
          n = n || 0;
          if (n < 1024) return n + " Б";
          if (n < 1048576) return (n / 1024).toFixed(0) + " КБ";
          return (n / 1048576).toFixed(1) + " МБ";
        };

        const SVG = {
          plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
          pen: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"><path d="m4 20 4-1 11-11-3-3L5 16z"/></svg>',
          del: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg>',
          key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><circle cx="8" cy="12" r="4"/><path d="M12 12h9m-3 0v4m-3-4v3"/></svg>',
          eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6-10-6-10-6z"/><circle cx="12" cy="12" r="2.6"/></svg>',
        };

        let works = [];
        let kinds = ["разное"];
        let canEdit = false;
        let asGuest = false;      // хозяин смотрит витрину чужими глазами

        const admin = () => canEdit && !asGuest;

        let firstLoad = true;
        const load = async () => {
          const r = await fetch("/api/diy", { credentials: "same-origin" });
          const d = await r.json();
          works = d.works || [];
          kinds = d.kinds || kinds;
          if (d.themes && d.themes.length) themes = [ALL].concat(d.themes);
          canEdit = !!d.can_edit;
          // Полка могла исчезнуть между заходами — тогда возвращаемся ко «всему»
          if (theme && !themes.some((t) => t.id === theme)) theme = "";
          if (firstLoad) { mode = viewOf(theme); firstLoad = false; }
          draw();
        };

        const send = async (url, how, body) => {
          const r = await fetch(url, {
            method: how, credentials: "same-origin",
            headers: body ? { "Content-Type": "application/json" } : undefined,
            body: body ? JSON.stringify(body) : undefined,
          });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(d.error || "Не вышло.");
          return d;
        };

        let toastTimer = 0;
        const toast = (text, bad) => {
          document.querySelectorAll(".toast").forEach((t) => t.remove());
          const el = document.createElement("div");
          el.className = "toast" + (bad ? " bad" : "");
          el.textContent = text;
          document.body.appendChild(el);
          clearTimeout(toastTimer);
          toastTimer = setTimeout(() => el.remove(), 3200);
        };

        /* ── окно ввода пароля (как на главной у кабинета) ──────────── */
        const authModal = $("auth-modal");
        const authForm = $("auth-form");
        const authPass = $("auth-password");
        const authErr = $("auth-error");
        const authOkBtn = authForm.querySelector("button[type='submit']");
        const openAuth = () => {
          authModal.hidden = false;
          document.body.classList.add("modal-open");
          authErr.textContent = "";
          requestAnimationFrame(() => authPass.focus());
        };
        const closeAuth = () => {
          authModal.hidden = true;
          document.body.classList.remove("modal-open");
          authForm.reset();
          authErr.textContent = "";
        };
        authModal.querySelectorAll("[data-auth-close]").forEach((el) =>
          el.addEventListener("click", closeAuth));
        document.addEventListener("keydown", (e) => {
          if (e.key === "Escape" && !authModal.hidden) closeAuth();
        });
        authForm.addEventListener("submit", async (e) => {
          e.preventDefault();
          authErr.textContent = "";
          authOkBtn.disabled = true;
          try {
            const r = await fetch("/api/login", {
              method: "POST", credentials: "same-origin",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ password: authPass.value }) });
            const d = await r.json().catch(() => ({}));
            if (!r.ok) { authErr.textContent = d.error || "Не удалось войти."; authPass.select(); return; }
            closeAuth();
            await load();                       // режим хозяина включён — не уходим со страницы
            toast("Режим хозяина включён");
          } catch { authErr.textContent = "Сервер недоступен."; }
          finally { authOkBtn.disabled = false; }
        });

        /* ── полоса сверху ─────────────────────────────────────────── */
        const drawBar = () => {
          const bar = $("bar");
          if (!canEdit) {
            bar.innerHTML = '<button class="btn" data-act="login">' + SVG.key +
              "<span>Я хозяин</span></button>";
            return;
          }
          bar.innerHTML =
            '<span class="badge">режим хозяина</span>' +
            '<button class="btn go" data-act="new">' + SVG.plus + "<span>Добавить</span></button>" +
            '<button class="btn spacer" data-act="guest">' + SVG.eye +
            "<span>" + (asGuest ? "Вернуть правку" : "Глазами гостя") + "</span></button>";
        };

        const linkChips = (list) => (list || []).map((l) =>
          '<a href="' + esc(l.url) + '" target="_blank" rel="noopener">' +
          esc(l.label) + "</a>").join("");

        /* ── Полки и пять способов листать ────────────────────────────
           Сначала выбирается тематика, потом — как её листать. Разметка
           карточки общая, меняется раскладка и — у барабана, веера и сот —
           ещё и поведение. Для каждой полки свой запомненный вид. */
        const MODES = [
          ["Сетка", "m-grid"], ["Барабан", "m-drum"], ["Кладка", "m-mosaic"],
          ["Веер", "m-fan"], ["Соты", "m-hex"],
        ];
        const ALL = { id: "", name: "Всё", color: "#2de2ff", view: 1,
                      hint: "все творения подряд, от свежих к старым" };
        let themes = [ALL];
        let theme = "";
        let mode = 1;

        /* Что выбрано, помним по полкам: {"": 1, "программы": 3, …} */
        const VIEWS = "vgDiyViews";
        let views = {};
        try { views = JSON.parse(localStorage.getItem(VIEWS) || "{}") || {}; }
        catch (e) { views = {}; }
        try { theme = localStorage.getItem("vgDiyShelf") || ""; } catch (e) { theme = ""; }

        const themeOf = (id) => themes.find((t) => t.id === id) || ALL;

        /* Вид для полки: свой запомненный, иначе тот, что ей идёт. */
        const viewOf = (id) => {
          const saved = +views[id];
          return saved >= 1 && saved <= MODES.length ? saved : themeOf(id).view;
        };

        const rememberView = () => {
          views[theme] = mode;
          try { localStorage.setItem(VIEWS, JSON.stringify(views)); } catch (e) { /* и ладно */ }
        };

        const shotSrc = (w) => w.shot
          ? "/diy/asset/" + w.id + "/" + encodeURIComponent(w.shot)
          : (w.cover ? "/diy/cover/" + w.id : "");

        /* Записи выбранной полки. Пустая полка — значит, всё подряд. */
        const shelfList = () => {
          const list = asGuest ? works.filter((w) => !w.hidden) : works;
          return theme ? list.filter((w) => w.kind === theme) : list;
        };

        const drawShelf = () => {
          const seen = asGuest ? works.filter((w) => !w.hidden) : works;
          const count = (id) => id ? seen.filter((w) => w.kind === id).length : seen.length;
          const chip = (t) =>
            '<button data-shelf="' + esc(t.id) + '" style="--tc:' + esc(t.color) + '"' +
            (theme === t.id ? ' class="on"' : "") + "><i></i>" + esc(t.name) +
            "<u>" + count(t.id) + "</u></button>";
          $("shelf").innerHTML =
            [ALL].concat(themes.filter((t) => t.id)).map(chip).join("");
          $("shelfhint").textContent = themeOf(theme).hint;
          document.documentElement.style.setProperty("--th", themeOf(theme).color);
          // выбранную полку подтягиваем в видимую часть ленты на телефоне
          const on = $("shelf").querySelector("button.on");
          if (on && on.scrollIntoView) on.scrollIntoView({ block: "nearest", inline: "nearest" });
        };

        const drawModes = () => {
          const nav = (mode === 2 || mode === 4)
            ? '<span class="navs"><button data-step="-1" title="Назад">‹</button>' +
              '<button data-step="1" title="Вперёд">›</button></span>'
            : "";
          $("modes").innerHTML = '<span class="lbl">вид</span>' +
            MODES.map((m, i) =>
              '<button data-mode="' + (i + 1) + '"' + (mode === i + 1 ? ' class="on"' : "") +
              ' title="' + esc(m[0]) + '">' + (i + 1) + "</button>").join("") +
            '<span class="name"><b>' + MODES[mode - 1][0] + "</b></span>" + nav;
        };

        /* Веер: чем дальше карточка от середины, тем сильнее повёрнута. */
        const layFan = () => {
          const grid = $("grid");
          const mid = grid.scrollLeft + grid.clientWidth / 2;
          grid.querySelectorAll(".work").forEach((el) => {
            const c = el.offsetLeft + el.offsetWidth / 2;
            const k = Math.max(-1.6, Math.min(1.6, (c - mid) / (el.offsetWidth * 1.15)));
            el.style.transform = "rotateY(" + (-k * 34) + "deg) scale(" + (1 - Math.abs(k) * .16) + ")" +
              " translateZ(" + (-Math.abs(k) * 90) + "px)";
            el.style.opacity = String(1 - Math.abs(k) * .35);
            // Средняя карточка стоит прямо и по ней можно кликать; боковые
            // повёрнуты, и попасть в кнопку на них всё равно не выходит.
            el.style.pointerEvents = Math.abs(k) < .4 ? "auto" : "none";
          });
        };

        /* Барабан: подсвечиваем ту карточку, что сейчас в середине, и ведём
           полосу хода под лентой. */
        const layDrum = () => {
          const grid = $("grid"), rail = $("rail");
          const mid = grid.scrollLeft + grid.clientWidth / 2;
          grid.querySelectorAll(".work").forEach((el) => {
            const d = Math.abs(el.offsetLeft + el.offsetWidth / 2 - mid) / el.offsetWidth;
            el.classList.toggle("mid", d < .5);
            el.classList.toggle("far", d > 1.4);
          });
          const room = grid.scrollWidth - grid.clientWidth;
          rail.firstElementChild.style.width =
            (room > 4 ? 12 + (grid.scrollLeft / room) * 88 : 100) + "%";
        };

        const relay = () => { if (mode === 2) layDrum(); if (mode === 4) layFan(); };

        const step = (dir) => {
          const grid = $("grid");
          const card = grid.querySelector(".work");
          if (card) grid.scrollBy({ left: dir * (card.offsetWidth + 22), behavior: "smooth" });
        };

        /* Тянуть ленту мышью — на компьютере это удобнее, чем ловить полосу
           прокрутки. Пока тянем, прилипание выключено, иначе лента дёргается. */
        let haul = null;
        const hauling = (grid) => {
          grid.addEventListener("pointerdown", (e) => {
            if (e.pointerType !== "mouse" || e.button !== 0) return;
            haul = { x: e.clientX, at: grid.scrollLeft, moved: false };
          });
          grid.addEventListener("pointermove", (e) => {
            if (!haul) return;
            const by = e.clientX - haul.x;
            if (!haul.moved && Math.abs(by) < 5) return;
            haul.moved = true;
            grid.classList.add("hauling");
            grid.scrollLeft = haul.at - by;
            relay();
          });
          const stop = () => {
            if (!haul) return;
            haul = null;
            grid.classList.remove("hauling");
          };
          grid.addEventListener("pointerup", stop);
          grid.addEventListener("pointerleave", stop);
          grid.addEventListener("pointercancel", stop);
          // Обычное колесо мыши крутит ленту вбок: вертикального хода у неё нет.
          grid.addEventListener("wheel", (e) => {
            if (Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
            e.preventDefault();
            grid.scrollLeft += e.deltaY;
            relay();
          }, { passive: false });
        };

        /* Появление карточек по мере прокрутки. Наблюдатель заводится заново
           на каждую перерисовку — старые карточки к тому времени уже выкинуты. */
        let eye = null;
        const reveal = (grid) => {
          if (eye) { eye.disconnect(); eye = null; }
          const cards = [...grid.children];
          const slow = matchMedia("(prefers-reduced-motion: reduce)").matches;
          if (slow || !("IntersectionObserver" in window) || mode === 2 || mode === 4) return;
          cards.forEach((el) => el.classList.add("up"));
          eye = new IntersectionObserver((rows) => {
            rows.forEach((r) => {
              if (!r.isIntersecting) return;
              const i = cards.indexOf(r.target);
              setTimeout(() => r.target.classList.add("seen"), Math.min(i, 6) * 55);
              eye.unobserve(r.target);
            });
          }, { threshold: .12, rootMargin: "0px 0px -40px" });
          cards.forEach((el) => eye.observe(el));
        };

        const drawGrid = () => {
          const grid = $("grid");
          const list = shelfList();
          $("empty").hidden = list.length > 0;
          $("empty").textContent = admin()
            ? (theme ? "На этой полке пусто. Нажми «Добавить»."
                     : "Пока пусто. Нажми «Добавить» — и появится первая запись.")
            : (theme ? "На этой полке пока пусто" : "Пока пусто");
          grid.className = "grid " + MODES[mode - 1][1];
          $("rail").hidden = mode !== 2;
          drawShelf();
          drawModes();

          /* Соты: шестиугольники с названием и парой слов. */
          if (mode === 5) {
            grid.innerHTML = list.map((w) => {
              const src = shotSrc(w);
              return '<div class="hex" data-open="' + w.id + '"' +
                (w.accent ? ' style="--ac:' + esc(w.accent) + '"' : "") + '>' +
                (src ? '<div class="fill" style="background-image:url(' + src + ')"></div>' : "") +
                '<div class="glow"></div><div class="rim"></div>' +
                '<div class="in"><b>' + esc(w.title) + "</b>" +
                "<span>" + esc(w.summary || "") + "</span></div></div>";
            }).join("");
            reveal(grid);
            return;
          }

          grid.innerHTML = list.map((w, i) => {
            // Обложка: сперва картинка, названная в шапке кода, потом старая
            // загруженная обложка, и только если нет ни той ни другой — заглушка.
            const src = shotSrc(w);
            // Картинку показываем целиком: вертикальные скриншоты программ
            // при обрезке по центру превращались в кашу. Фон — та же картинка,
            // размытая и растянутая, чтобы не было пустых полей по бокам.
            const shot = src
              ? '<div class="shot" data-open="' + w.id + '">' +
                  '<div class="shot-bg" style="background-image:url(' + src + ')"></div>' +
                  '<img src="' + src + '" alt="" loading="lazy">' +
                '</div>'
              // Нет картинки — рисуем свою: градиент из цвета записи, косая
              // штриховка и монограмма. Пустая плашка «без фото» смотрелась
              // дырой, особенно в сотах.
              : '<div class="shot none" data-open="' + w.id + '">' +
                  '<span class="mono">' + esc((w.title || "?").trim().slice(0, 2)) + "</span>" +
                "</div>";
            const flags = [];
            if (w.hidden) flags.push('<span class="flag hid">черновик</span>');
            if (w.pinned) flags.push('<span class="flag pin">закреплено</span>');
            const tools = admin()
              ? '<div class="tools">' +
                '<button class="btn" data-edit="' + w.id + '">' + SVG.pen + "<span>Править</span></button>" +
                '<button class="btn bad" data-kill="' + w.id + '">' + SVG.del + "<span>Удалить</span></button>" +
                "</div>"
              : "";
            const tags = (w.tags || []).length
              ? '<div class="tagrow">' + w.tags.map((t) => "<i>" + esc(t) + "</i>").join("") + "</div>"
              : "";
            // Цвет записи — свой, цвет плашки с названием полки — полки.
            const shelfColor = themeOf(w.kind).color;
            const style = ' style="--kc:' + esc(shelfColor) +
              (w.accent ? ";--ac:" + esc(w.accent) : "") + '"';
            // В сетке первая закреплённая запись занимает две клетки
            const wide = (mode === 1 && i === 0 && w.pinned) ? " wide" : "";
            return '<article class="work' + (w.hidden ? " draft" : "") + wide + '"' + style + '>' + shot +
              '<div class="body">' +
              (flags.length ? '<div class="flags">' + flags.join("") + "</div>" : "") +
              '<span class="kind">' + esc(w.kind) + "</span>" +
              "<h2>" + esc(w.title) + "</h2>" +
              (w.summary ? "<p>" + esc(w.summary) + "</p>" : "") +
              tags +
              (w.links && w.links.length ? '<div class="links">' + linkChips(w.links) + "</div>" : "") +
              '<div class="open-row"><button class="btn" data-open="' + w.id + '">Открыть статью →</button></div>' +
              tools + "</div></article>";
          }).join("");

          // Барабану и вееру нужна раскладка после отрисовки
          grid.onscroll = null;
          if (mode === 2 || mode === 4) {
            grid.onscroll = relay;
            requestAnimationFrame(relay);
          }
          reveal(grid);
        };

        // Тянуть мышью умеют обе горизонтальные ленты; вешаем один раз.
        hauling($("grid"));

        /* Переключение полки, вида и стрелки листания */
        $("shelf").addEventListener("click", (e) => {
          const b = e.target.closest("[data-shelf]");
          if (!b) return;
          theme = b.dataset.shelf;
          try { localStorage.setItem("vgDiyShelf", theme); } catch (err) { /* и ладно */ }
          mode = viewOf(theme);
          $("grid").scrollLeft = 0;
          drawGrid();
        });
        $("modes").addEventListener("click", (e) => {
          const m = e.target.closest("[data-mode]");
          if (m) {
            mode = +m.dataset.mode;
            rememberView();
            $("grid").scrollLeft = 0;
            drawGrid();
            return;
          }
          const s = e.target.closest("[data-step]");
          if (s) step(+s.dataset.step);
        });
        addEventListener("keydown", (e) => {
          if (e.target.matches("input, textarea, select")) return;
          if (mode !== 2 && mode !== 4) return;
          if (e.key === "ArrowRight") step(1);
          if (e.key === "ArrowLeft") step(-1);
        });
        addEventListener("resize", relay);
        const draw = () => { drawBar(); drawGrid(); };

        /* ── окно правки ───────────────────────────────────────────── */
        let sheet = null;

        const linkRow = (label, url) =>
          '<div class="row2"><input placeholder="подпись" maxlength="40" value="' + esc(label) + '">' +
          '<input placeholder="https://…" value="' + esc(url) + '">' +
          '<button class="btn" type="button" data-drop>×</button></div>';

        const openSheet = (work) => {
          const fresh = !work;
          work = work || { title: "", summary: "", kind: kinds[0], links: [],
                           cover: false, hidden: false, pinned: false };
          const veil = document.createElement("div");
          veil.className = "veil";
          veil.innerHTML =
            '<section class="sheet" role="dialog" aria-modal="true">' +
            "<h3>" + (fresh ? "Новое творение" : "Правим запись") + "</h3>" +
            '<label class="field"><span>Название</span>' +
            '<input id="f-title" maxlength="80" value="' + esc(work.title) + '"></label>' +
            '<label class="field"><span>Полка</span><select id="f-kind">' +
            kinds.map((k) => '<option' + (k === work.kind ? " selected" : "") + ">" + esc(k) + "</option>").join("") +
            "</select></label>" +
            '<label class="field"><span>Код статьи</span>' +
            '<textarea id="f-body" class="code" spellcheck="false" ' +
            'placeholder="---&#10;кратко: о чём это в двух строках&#10;теги: ESP32, Zigbee&#10;цвет: #2de2ff&#10;обложка: главное-фото.jpg&#10;ссылка: https://github.com/…&#10;---&#10;&#10;&lt;p&gt;Текст статьи…&lt;/p&gt;">' +
            esc(work.body || "") + "</textarea></label>" +
            '<p class="hint"><b>Шапка</b> между строками из трёх дефисов задаёт короткую ' +
            'карточку: <code>кратко</code>, <code>теги</code>, <code>цвет</code>, ' +
            '<code>обложка</code> (имя фото), <code>ссылка</code>. Ниже — обычный HTML. ' +
            'Фото: <code>&lt;img src="{{плата.jpg}}"&gt;</code>, ряд фото — ' +
            '<code>&lt;div class="shots"&gt;…&lt;/div&gt;</code>, файл: ' +
            '<code>&lt;a class="dl" href="{{прошивка.zip}}"&gt;Скачать&lt;/a&gt;</code>. ' +
            'Готовые блоки: <code>note</code>, <code>warn</code>, <code>ok</code>, ' +
            '<code>cards</code>, <code>steps</code>, <code>chips</code>. ' +
            'Тык по имени вложения копирует <code>{{…}}</code>.</p>' +
            '<div class="field"><span>Фото и файлы</span>' +
            '<div class="assets" id="f-assets"></div>' +
            '<div class="asset-keys">' +
            '<button class="btn" type="button" id="f-add-img">Загрузить фото</button>' +
            '<button class="btn" type="button" id="f-add-file">Загрузить файл</button>' +
            "</div></div>" +
            '<div class="cover"><div class="pic" id="f-pic"' +
            (work.cover ? ' style="background-image:url(/diy/cover/' + work.id + '?t=' + Date.now() + ')"' : "") +
            '></div><button class="btn" type="button" id="f-shot">Фото</button>' +
            '<button class="btn bad" type="button" id="f-noshot"' +
            (work.cover ? "" : " hidden") + ">Убрать</button></div>" +
            '<div class="checks">' +
            '<label><input type="checkbox" id="f-hidden"' + (work.hidden ? " checked" : "") + "> Черновик</label>" +
            '<label><input type="checkbox" id="f-pinned"' + (work.pinned ? " checked" : "") + "> Закрепить сверху</label>" +
            "</div>" +
            '<p class="note" id="f-note"></p>' +
            '<div class="sheet-keys">' +
            '<button class="btn" type="button" id="f-no">Отмена</button>' +
            '<button class="btn go" type="button" id="f-ok">Сохранить</button>' +
            "</div></section>";
          document.body.appendChild(veil);
          sheet = { veil, work, fresh, id: work.id || null };
          sheet.assets = (work.assets || []).slice();
          veil.querySelector("#f-title").focus();

          // Список вложений: имя (тык копирует {{имя}}), вес и удаление.
          const paintAssets = () => {
            const box = veil.querySelector("#f-assets");
            if (!sheet.assets.length) {
              box.innerHTML = '<p class="hint" style="margin:0">Пока нет вложений.</p>';
              return;
            }
            box.innerHTML = sheet.assets.map((a) =>
              '<div class="asset">' +
              '<span class="tk ' + (a.kind === "image" ? "img" : "file") + '">' +
              (a.kind === "image" ? "IMG" : "ФАЙЛ") + "</span>" +
              '<span class="nm" data-copy="' + esc(a.name) + '" title="Скопировать тег">' +
              esc(a.name) + "</span>" +
              '<span class="sz">' + fmtBytes(a.size) + "</span>" +
              '<button class="rm" type="button" data-rmasset="' + esc(a.name) + '">×</button>' +
              "</div>").join("");
          };
          paintAssets();
          sheet.paintAssets = paintAssets;

          const needSaved = () => {
            if (sheet.id) return true;
            note("Сначала сохрани запись — вложения цепляются к ней.");
            return false;
          };
          veil.querySelector("#f-add-img").addEventListener("click", () => {
            if (needSaved()) $("pick-img").click();
          });
          veil.querySelector("#f-add-file").addEventListener("click", () => {
            if (needSaved()) $("pick-file").click();
          });
          veil.querySelector("#f-assets").addEventListener("click", async (e) => {
            const copy = e.target.closest("[data-copy]");
            if (copy) {
              const tag = "{{" + copy.dataset.copy + "}}";
              try { await navigator.clipboard.writeText(tag); toast("Скопировано: " + tag); }
              catch (err) { toast(tag, false); }
              return;
            }
            const rm = e.target.closest("[data-rmasset]");
            if (rm && sheet.id) {
              const name = rm.dataset.rmasset;
              try {
                await send("/api/diy/" + sheet.id + "/asset/" +
                  encodeURIComponent(name), "DELETE");
              } catch (err) { toast(err.message, true); return; }
              sheet.assets = sheet.assets.filter((a) => a.name !== name);
              paintAssets();
            }
          });

          const shut = () => { veil.remove(); sheet = null; };
          veil.addEventListener("click", (e) => { if (e.target === veil) shut(); });
          veil.querySelector("#f-no").addEventListener("click", shut);
          veil.querySelector("#f-shot").addEventListener("click", () => {
            if (!sheet.id) { note("Сначала сохрани запись — фото цепляется к ней."); return; }
            $("pick").click();
          });
          veil.querySelector("#f-noshot").addEventListener("click", async () => {
            if (!sheet.id) return;
            await send("/api/diy/" + sheet.id + "/cover", "DELETE");
            veil.querySelector("#f-pic").style.backgroundImage = "";
            veil.querySelector("#f-noshot").hidden = true;
            await load();
          });
          veil.querySelector("#f-ok").addEventListener("click", save);
          const note = (text) => { veil.querySelector("#f-note").textContent = text || ""; };
          sheet.note = note;
          sheet.shut = shut;
        };

        const readSheet = () => {
          const veil = sheet.veil;
          return {
            title: veil.querySelector("#f-title").value,
            kind: veil.querySelector("#f-kind").value,
            body: veil.querySelector("#f-body").value,
            hidden: veil.querySelector("#f-hidden").checked,
            pinned: veil.querySelector("#f-pinned").checked,
          };
        };

        const save = async () => {
          const data = readSheet();
          if (!data.title.trim()) { sheet.note("Без названия не сохранить."); return; }
          try {
            if (sheet.id) await send("/api/diy/" + sheet.id, "PATCH", data);
            else {
              const made = await send("/api/diy", "POST", data);
              sheet.id = made.id;
            }
          } catch (err) { sheet.note(err.message); return; }
          const shut = sheet.shut;
          await load();
          shut();
          toast("Сохранено");
        };

        // Фото цепляем к уже сохранённой записи: до этого ей некуда лечь.
        $("pick").addEventListener("change", async (e) => {
          const file = e.target.files[0];
          e.target.value = "";
          if (!file || !sheet || !sheet.id) return;
          const form = new FormData();
          form.append("file", file);
          try {
            const r = await fetch("/api/diy/" + sheet.id + "/cover",
              { method: "POST", credentials: "same-origin", body: form });
            const d = await r.json();
            if (!r.ok) throw new Error(d.error || "Не вышло.");
            const pic = sheet.veil.querySelector("#f-pic");
            pic.style.backgroundImage = "url(/diy/cover/" + sheet.id + "?t=" + Date.now() + ")";
            sheet.veil.querySelector("#f-noshot").hidden = false;
            toast("Фото загружено, " + Math.round(d.size / 1024) + " КБ");
            await load();
          } catch (err) { sheet.note(err.message); }
        });

        // Вложения статьи (фото и файлы). Грузятся к сохранённой записи и
        // сразу появляются в списке — оттуда хозяин копирует их имена в код.
        const uploadAsset = async (input) => {
          const file = input.files[0];
          input.value = "";
          if (!file || !sheet || !sheet.id) return;
          const form = new FormData();
          form.append("file", file);
          try {
            const r = await fetch("/api/diy/" + sheet.id + "/asset",
              { method: "POST", credentials: "same-origin", body: form });
            const d = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(d.error || "Не вышло.");
            sheet.assets = sheet.assets.filter((a) => a.name !== d.name);
            sheet.assets.push({ name: d.name, kind: d.kind, size: d.size });
            if (sheet.paintAssets) sheet.paintAssets();
            toast("Загружено: " + d.name);
          } catch (err) { if (sheet) sheet.note(err.message); }
        };
        $("pick-img").addEventListener("change", (e) => uploadAsset(e.target));
        $("pick-file").addEventListener("change", (e) => uploadAsset(e.target));

        /* ── общие нажатия ─────────────────────────────────────────── */
        document.addEventListener("click", async (e) => {
          const open = e.target.closest("[data-open]");
          if (open) {
            window.open("/diy/a/" + open.dataset.open, "_blank", "noopener");
            return;
          }
          const act = e.target.closest("[data-act]");
          if (act) {
            const what = act.dataset.act;
            if (what === "new") openSheet(null);
            if (what === "guest") { asGuest = !asGuest; draw(); }
            if (what === "login") openAuth();
            return;
          }
          const edit = e.target.closest("[data-edit]");
          if (edit) {
            openSheet(works.find((w) => w.id === edit.dataset.edit));
            return;
          }
          const kill = e.target.closest("[data-kill]");
          if (kill) {
            const work = works.find((w) => w.id === kill.dataset.kill);
            if (!confirm("Удалить «" + work.title + "»?")) return;
            try { await send("/api/diy/" + work.id, "DELETE"); }
            catch (err) { toast(err.message, true); return; }
            await load();
            toast("Удалено");
          }
        });

        document.addEventListener("keydown", (e) => {
          if (e.key === "Escape" && sheet) sheet.shut();
        });

        load().catch(() => {
          $("grid").innerHTML = '<p class="empty">не отвечает</p>';
        });
      })();
      </script>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


# ---- Резервные копии ------------------------------------------------------
# Всё, что нажито сайтом, лежит в двух папках: data (записи DIY, блокнот,
# фонотека, журнал входов) и drop_data (личный дроп). Здесь они складываются
# в один архив и оттуда же разворачиваются обратно.
#
# Два размера копии:
#   лёгкая — только записи и настройки: статьи страны DIY с фотографиями,
#            блокнот, списки и журналы. Весит мегабайты, годится «на каждый день»;
#   полная — вдобавок сами файлы дропа и музыка. Может весить гигабайты.
#
# Забирать копию может не только хозяин из кабинета, но и отдельная программа
# — например, та, что будет крутиться на домашнем гипервизоре и складывать
# копии на свой диск. Для неё есть ключ BACKUP_TOKEN: с ним архив отдаётся по
# обычному GET, без входа в кабинет. Ключ не задан — эта дверь закрыта.
BACKUP_TOKEN = os.environ.get("BACKUP_TOKEN", "").strip()
BACKUP_HEAVY = ("drop_data",)          # что попадает только в полную копию


def _backup_targets(full):
    """Какие папки кладём в архив. Возвращает [(корень, имя в архиве)]."""
    roots = [(DATA_DIR, "data")]
    if full:
        roots.append((DROP_DIR, "drop_data"))
    return [(root, alias) for root, alias in roots if os.path.isdir(root)]


def _backup_skip(path):
    """Мусор и временное в копию не берём."""
    name = os.path.basename(path)
    return (name.endswith(".tmp") or name.endswith(".part")
            or os.sep + "tmp" + os.sep in path)


def _backup_measure(full):
    """Сколько весит будущий архив — до того, как его собирать."""
    total, count = 0, 0
    for root, _ in _backup_targets(full):
        for base, _dirs, files in os.walk(root):
            for name in files:
                path = os.path.join(base, name)
                if _backup_skip(path):
                    continue
                try:
                    total += os.path.getsize(path)
                except OSError:
                    continue
                count += 1
    return total, count


def _backup_build(full):
    """Собирает архив во временный файл и возвращает путь к нему.

    Пишем на диск, а не в память: полная копия бывает в гигабайты, и держать
    её в оперативке на маленьком сервере — верный способ его уронить."""
    import zipfile

    fd, tmp = tempfile.mkstemp(prefix="vg-backup-", suffix=".zip")
    os.close(fd)
    manifest = {
        "site": "vitazgio.ru",
        "made": time.time(),
        "kind": "full" if full else "light",
        "note": "Разворачивать через кабинет → «Загрузить копию» "
                "или распаковать поверх папок data и drop_data.",
    }
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        zf.writestr("backup.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        for root, alias in _backup_targets(full):
            for base, _dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(base, name)
                    if _backup_skip(path):
                        continue
                    inside = os.path.join(alias, os.path.relpath(path, root))
                    try:
                        zf.write(path, inside)
                    except OSError:
                        continue          # файл увели прямо во время сборки
    return tmp


@app.get("/api/backup/state")
@login_required
def backup_state_api():
    """Что и сколько весит — кабинет показывает это до нажатия кнопки."""
    light_size, light_count = _backup_measure(False)
    full_size, full_count = _backup_measure(True)
    return jsonify(light={"size": light_size, "files": light_count},
                   full={"size": full_size, "files": full_count},
                   robot=bool(BACKUP_TOKEN))


@app.get("/api/backup/export")
def backup_export_api():
    """Отдаёт архив. Пускаем хозяина из кабинета или программу с ключом."""
    token = (request.args.get("token") or "").strip()
    by_token = bool(BACKUP_TOKEN) and token and hmac.compare_digest(token, BACKUP_TOKEN)
    if not by_token and not session.get("authenticated"):
        fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
        if not fresh:
            return jsonify(error="Нужен вход в кабинет."), 403
        session["authenticated"] = True
        g.new_device_cookie = fresh

    full = (request.args.get("kind") or "light") == "full"
    try:
        path = _backup_build(full)
    except OSError as e:
        return jsonify(error=f"Не удалось собрать копию: {e}"), 500

    stamp = time.strftime("%Y-%m-%d-%H%M")
    name = f"vitazgio-{'full' if full else 'light'}-{stamp}.zip"

    # Файл временный: отдаём и сразу убираем за собой.
    handle = open(path, "rb")
    try:
        os.remove(path)
    except OSError:
        pass
    response = send_file(handle, mimetype="application/zip",
                         as_attachment=True, download_name=name)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/backup/import")
@login_required
def backup_import_api():
    """Разворачивает копию обратно. Файлы кладём поверх, ничего не удаляя:
    так восстановление не может стереть больше, чем принесло."""
    import zipfile

    upload = request.files.get("file")
    if not upload:
        return jsonify(error="Архив не выбран."), 400

    fd, tmp = tempfile.mkstemp(prefix="vg-restore-", suffix=".zip")
    os.close(fd)
    try:
        upload.save(tmp)
        with zipfile.ZipFile(tmp) as zf:
            names = zf.namelist()
            if "backup.json" not in names:
                return jsonify(error="Это не копия сайта."), 400
            roots = {"data": DATA_DIR, "drop_data": DROP_DIR}
            written = 0
            for inside in names:
                if inside.endswith("/") or inside == "backup.json":
                    continue
                head, _, rest = inside.partition("/")
                target_root = roots.get(head)
                if not target_root or not rest:
                    continue
                # Защита от «..» в именах: путь обязан остаться внутри папки.
                dest = os.path.normpath(os.path.join(target_root, rest))
                if not dest.startswith(os.path.abspath(target_root) + os.sep) and \
                   not dest.startswith(target_root + os.sep):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(inside) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
                written += 1
    except zipfile.BadZipFile:
        return jsonify(error="Архив повреждён."), 400
    except OSError as e:
        return jsonify(error=f"Не удалось развернуть: {e}"), 500
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    # Перечитываем то, что только что легло на диск, чтобы сайт увидел копию
    # без перезапуска.
    with drop_lock:
        drop_items.clear()
    _drop_load_index()
    with diy_lock:
        diy_items.clear()
    _diy_load()
    with notebook_lock:
        notebook_data["pages"] = []
        notebook_data["entries"] = {}
    _notebook_load()
    with music_lock:
        music_items.clear()
        music_folders.clear()
    _music_load()
    return jsonify(ok=True, files=written)


# ---- Себастьян: разговор с дворецким через сайт ---------------------------
# Отвечает та же модель, что уже висит в памяти видеокарты дома, — новую не
# поднимаем, иначе домашнему Себастьяну не хватит места. Поэтому здесь только
# разговор: никаких инструментов и никакого управления домом, кто бы ни писал.
# Свет и розетки остаются за домашним контуром, куда с улицы ходу нет.
# Какой из шести роботов стоит на полке и в шапке чата. Меняется одной
# строкой — или переменной SEBASTIAN_ICON, без правки кода.
SEBASTIAN_ICON = os.environ.get("SEBASTIAN_ICON", "butler1")
if SEBASTIAN_ICON not in _GAME_ICONS:
    SEBASTIAN_ICON = "butler1"
_GAME_ICONS["butler"] = _GAME_ICONS[SEBASTIAN_ICON]   # под именем __ICON_BUTLER__
SEBASTIAN_HOST = os.environ.get("SEBASTIAN_OLLAMA", "").strip().rstrip("/")
SEBASTIAN_MODEL = os.environ.get("SEBASTIAN_MODEL", "sebastian").strip()
SEBASTIAN_PUBLIC = os.environ.get("SEBASTIAN_PUBLIC", "1") != "0"
SEBASTIAN_MSG_MAX = 400            # длиннее вопросы не принимаем
SEBASTIAN_REPLY_TOKENS = 200       # и ответы держим короткими
SEBASTIAN_TIMEOUT = 45
SEBASTIAN_GUEST_HOUR = 12          # сколько вопросов в час с одного адреса
SEBASTIAN_OWNER_HOUR = 60

# Одновременно пускаем только один вопрос: две модели на одной видеокарте
# душат друг друга втрое, а домашний голосовой контур важнее сайта.
sebastian_gate = threading.Semaphore(1)
sebastian_calls: dict = {}
sebastian_calls_lock = threading.Lock()

SEBASTIAN_PROMPT = """Ты Себастьян — дворецкий и голос домашнего сервера vitazgio.ru.
Отвечай по-русски, коротко и с достоинством, лёгкая ирония уместна.

О чём знаешь и охотно рассказываешь:
— Три машины: гипервизор Proxmox дома (виртуалки, видеокарта под нейросети),
  маленькая Orange Pi (умный дом круглосуточно), арендованный сервер в
  Амстердаме (домены, сертификаты, единственный вход снаружи).
— Сервисы: облако, медиатека, синхронизация файлов, мониторинг, прокси.
— Умный дом: лампы, розетки, лента, магнитола — всё на Zigbee, всё локально.
— Хозяин: Виталий, студент, собирает устройства на ESP32 и пишет прошивки.

Чего не делаешь:
— Не управляешь домом и не трогаешь устройства из этого разговора: свет,
  розетки и техника слушаются только домашнего контура. Если просят включить
  или выключить — вежливо откажи и объясни, что через сайт это не делается.
— Не называешь адреса, пароли, ключи и внутренние имена машин.
— Не выдумываешь: чего не знаешь — так и скажи."""


def _sebastian_allow(owner):
    """Не даём одному гостю занимать видеокарту весь день."""
    limit = SEBASTIAN_OWNER_HOUR if owner else SEBASTIAN_GUEST_HOUR
    who = "owner" if owner else _client_ip()
    now = time.time()
    with sebastian_calls_lock:
        hits = [t for t in sebastian_calls.get(who, []) if now - t < 3600]
        if len(hits) >= limit:
            sebastian_calls[who] = hits
            return False
        hits.append(now)
        sebastian_calls[who] = hits
        # заодно подчищаем чужие следы, чтобы словарь не рос вечно
        for key in [k for k, v in sebastian_calls.items()
                    if not v or now - v[-1] > 7200]:
            sebastian_calls.pop(key, None)
    return True


@app.get("/api/sebastian/state")
def sebastian_state_api():
    """Готов ли дворецкий отвечать — страница спрашивает при открытии."""
    ready = bool(SEBASTIAN_HOST) and SEBASTIAN_PUBLIC
    return jsonify(ready=ready, model=SEBASTIAN_MODEL if ready else "",
                   owner=bool(session.get("authenticated")))


@app.post("/api/sebastian/ask")
def sebastian_ask_api():
    if not SEBASTIAN_PUBLIC:
        return jsonify(error="Дворецкий сейчас не принимает."), 503
    if not SEBASTIAN_HOST:
        return jsonify(error="Дворецкий не на связи: сервер с моделью не указан."), 503

    payload = request.get_json(silent=True) or {}
    text = (payload.get("text") or "").strip()[:SEBASTIAN_MSG_MAX]
    if not text:
        return jsonify(error="Пустой вопрос."), 400

    owner = bool(session.get("authenticated"))
    if not _sebastian_allow(owner):
        return jsonify(error="На сегодня довольно вопросов — приходите позже."), 429

    # История нужна, чтобы разговор был связным, но держим её короткой:
    # длинный контекст съедает видеопамять, а она тут дефицит.
    history = []
    for row in (payload.get("history") or [])[-6:]:
        role = "assistant" if row.get("role") == "bot" else "user"
        body = (row.get("text") or "").strip()[:SEBASTIAN_MSG_MAX]
        if body:
            history.append({"role": role, "content": body})

    body = json.dumps({
        "model": SEBASTIAN_MODEL,
        "messages": ([{"role": "system", "content": SEBASTIAN_PROMPT}]
                     + history + [{"role": "user", "content": text}]),
        "stream": False,
        "think": False,
        "options": {"num_predict": SEBASTIAN_REPLY_TOKENS, "temperature": 0.7},
    }).encode("utf-8")

    if not sebastian_gate.acquire(timeout=20):
        return jsonify(error="Дворецкий занят домашними делами. Минуту."), 503
    try:
        from urllib import request as urlrequest, error as urlerror
        req = urlrequest.Request(SEBASTIAN_HOST + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
        try:
            with urlrequest.urlopen(req, timeout=SEBASTIAN_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urlerror.URLError:
            return jsonify(error="Дворецкий не отвечает — видимо, сервер спит."), 502
        except (ValueError, OSError):
            return jsonify(error="Дворецкий ответил невнятно."), 502
    finally:
        sebastian_gate.release()

    said = ((data.get("message") or {}).get("content") or "").strip()
    # у думающих моделей бывает служебный блок размышлений — он не для гостей
    said = re.sub(r"<think>.*?</think>", "", said, flags=re.S).strip()
    if not said:
        return jsonify(error="Дворецкий промолчал."), 502
    return jsonify(text=said[:4000])


@app.get("/sebastian")
def sebastian_page():
    """Разговор с дворецким. Открыт всем: управлять домом отсюда нельзя,
    поэтому пускать можно кого угодно."""
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0d1321">
      <meta name="description" content="Себастьян — голос домашнего сервера vitazgio.ru">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Себастьян · vitazgio.ru</title>
      <style>
        :root { color-scheme:dark; --line:rgba(255,255,255,.1); --muted:#8b97ac;
                --pc:#2de2ff; --ok:#63f5ad; --warm:#ffd84a; }
        * { box-sizing:border-box; }
        html, body { height:100%; }
        body { margin:0; color:#eaf3fb; display:flex; flex-direction:column;
               font-family:"Cascadia Code", Consolas, monospace;
               background:radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .page { flex:1; width:min(880px, calc(100% - 30px)); margin:0 auto;
                display:flex; flex-direction:column; padding:clamp(16px,3vw,32px) 0 18px; min-height:0; }

        .top { display:flex; align-items:center; gap:13px; margin-bottom:16px; }
        .back { width:42px; height:42px; flex:none; display:grid; place-items:center;
                color:var(--pc); text-decoration:none; border:1px solid rgba(45,226,255,.3);
                border-radius:50%; background:rgba(45,226,255,.07); transition:.18s; }
        .back:hover { color:#fff; border-color:var(--pc); background:rgba(45,226,255,.18); }
        .back svg { width:20px; height:20px; }
        .who { flex:1; min-width:0; }
        .who b { display:block; font-size:1.15rem; letter-spacing:-.01em; }
        .who span { display:block; margin-top:3px; color:var(--muted); font-size:.72rem; }
        .face { width:52px; height:52px; flex:none; }
        .face svg { width:100%; height:100%; display:block; }
        .state { display:inline-flex; align-items:center; gap:7px; }
        .state i { width:7px; height:7px; border-radius:50%; background:var(--muted); }
        .state.on i { background:var(--ok); box-shadow:0 0 10px var(--ok); animation:beat 2.4s ease-in-out infinite; }
        .state.off i { background:var(--warm); }
        @keyframes beat { 0%,100%{opacity:1} 50%{opacity:.45} }

        .chat { flex:1; min-height:0; overflow-y:auto; padding:16px; border:1px solid var(--line);
                border-radius:16px; background:rgba(9,14,24,.55); display:flex;
                flex-direction:column; gap:12px; }
        .msg { display:flex; gap:11px; max-width:86%; }
        .msg.me { align-self:flex-end; flex-direction:row-reverse; }
        .msg .av { width:32px; height:32px; flex:none; border-radius:10px; display:grid;
                   place-items:center; font-size:.62rem; font-weight:800; color:#04121c;
                   background:linear-gradient(160deg,#7df0ff,#26cfe8); }
        .msg.me .av { color:#eaf3fb; background:rgba(255,255,255,.08);
                      border:1px solid var(--line); }
        .msg .txt { padding:11px 14px; border-radius:14px; font-size:.88rem; line-height:1.6;
                    white-space:pre-wrap; overflow-wrap:anywhere;
                    background:rgba(255,255,255,.05); border:1px solid var(--line); }
        .msg.me .txt { background:rgba(45,226,255,.12); border-color:rgba(45,226,255,.28); }
        .msg.err .txt { color:#ffb3b3; background:rgba(255,90,90,.1); border-color:rgba(255,90,90,.3); }
        .dots span { display:inline-block; width:6px; height:6px; margin-right:4px; border-radius:50%;
                     background:var(--pc); animation:blip 1.1s ease-in-out infinite; }
        .dots span:nth-child(2){ animation-delay:.18s } .dots span:nth-child(3){ animation-delay:.36s }
        @keyframes blip { 0%,100%{opacity:.25; transform:translateY(0)} 50%{opacity:1; transform:translateY(-3px)} }

        .hints { display:flex; flex-wrap:wrap; gap:7px; margin:13px 0 0; }
        .hints button { padding:7px 12px; cursor:pointer; color:#cfe0f0; font:400 .74rem inherit;
                        border:1px solid var(--line); border-radius:9px; background:rgba(255,255,255,.04);
                        transition:.16s; }
        .hints button:hover { color:#fff; border-color:rgba(45,226,255,.5); background:rgba(45,226,255,.1); }

        .ask { display:flex; gap:9px; margin-top:12px; }
        .ask input { flex:1; height:46px; padding:0 15px; color:#f4fbff; font:400 .88rem inherit;
                     border:1px solid var(--line); border-radius:12px; outline:none;
                     background:rgba(4,10,20,.65); }
        .ask input:focus { border-color:var(--pc); }
        .ask button { width:46px; height:46px; flex:none; display:grid; place-items:center; cursor:pointer;
                      color:#04121c; border:0; border-radius:12px;
                      background:linear-gradient(160deg,#7df0ff,#26cfe8); }
        .ask button:hover { filter:brightness(1.08); }
        .ask button:disabled { opacity:.45; cursor:wait; }
        .ask svg { width:19px; height:19px; }
        .foot { margin-top:10px; color:#5d6a7d; font-size:.7rem; line-height:1.5; }
        @media (prefers-reduced-motion: reduce) { * { animation:none !important; } }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="top">
          <a class="back" href="/" title="На главную" aria-label="На главную"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
          <span class="face">__ICON_BUTLER__</span>
          <span class="who"><b>Себастьян</b>
            <span class="state" id="state"><i></i><span id="state-tx">проверяю, на месте ли…</span></span></span>
        </div>

        <div class="chat" id="chat"></div>

        <div class="hints" id="hints">
          <button type="button">Что у тебя за сервера?</button>
          <button type="button">Расскажи про умный дом</button>
          <button type="button">Чем занят хозяин?</button>
          <button type="button">Почему тебя зовут Себастьян?</button>
        </div>

        <form class="ask" id="ask">
          <input id="text" maxlength="400" autocomplete="off"
                 placeholder="Спросите дворецкого…" aria-label="Вопрос">
          <button type="submit" id="send" title="Отправить" aria-label="Отправить">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h15m0 0-6-6m6 6-6 6"/></svg>
          </button>
        </form>
        <p class="foot">Через сайт Себастьян только разговаривает: свет, розетки и техника
          слушаются домашнего контура, и снаружи туда ходу нет. Отвечает та же модель,
          что и дома, поэтому очередь — по одному вопросу за раз.</p>
      </main>

      <script>
      (() => {
        "use strict";
        const $ = (id) => document.getElementById(id);
        const chat = $("chat");
        const history = [];
        let busy = false, ready = false;

        const add = (role, text, cls) => {
          const el = document.createElement("div");
          el.className = "msg " + (role === "me" ? "me" : "bot") + (cls ? " " + cls : "");
          const av = document.createElement("span");
          av.className = "av";
          av.textContent = role === "me" ? "Я" : "С";
          const tx = document.createElement("div");
          tx.className = "txt";
          if (text === null) {
            tx.innerHTML = '<span class="dots"><span></span><span></span><span></span></span>';
          } else {
            tx.textContent = text;
          }
          el.append(av, tx);
          chat.appendChild(el);
          chat.scrollTop = chat.scrollHeight;
          return el;
        };

        const ask = async (text) => {
          if (busy || !text.trim()) return;
          busy = true; $("send").disabled = true;
          add("me", text);
          history.push({ role: "me", text: text });
          const wait = add("bot", null);
          try {
            const r = await fetch("/api/sebastian/ask", {
              method: "POST", credentials: "same-origin",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ text: text, history: history.slice(0, -1) }),
            });
            const d = await r.json().catch(() => ({}));
            wait.remove();
            if (!r.ok) { add("bot", d.error || "Что-то пошло не так.", "err"); }
            else { add("bot", d.text); history.push({ role: "bot", text: d.text }); }
          } catch (e) {
            wait.remove();
            add("bot", "Не дозвонился до дворецкого.", "err");
          } finally {
            busy = false; $("send").disabled = false; $("text").focus();
          }
        };

        $("ask").addEventListener("submit", (e) => {
          e.preventDefault();
          const t = $("text").value;
          $("text").value = "";
          ask(t);
        });
        $("hints").addEventListener("click", (e) => {
          const b = e.target.closest("button");
          if (b) ask(b.textContent.trim());
        });

        fetch("/api/sebastian/state", { credentials: "same-origin" })
          .then((r) => r.json())
          .then((d) => {
            ready = !!d.ready;
            $("state").className = "state " + (ready ? "on" : "off");
            $("state-tx").textContent = ready
              ? "на месте, слушает" : "отлучился — сервер с моделью не отвечает";
            add("bot", ready
              ? "К вашим услугам. Спрашивайте про сервера, умный дом или хозяйские затеи."
              : "Прошу прощения: домашний сервер сейчас недоступен, и отвечать мне нечем. " +
                "Загляните позже.");
          })
          .catch(() => {
            $("state").className = "state off";
            $("state-tx").textContent = "не отвечает";
          });
      })();
      </script>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return (html.replace("__ICONLINKS__", ICON_LINKS)
                .replace("__ICON_BUTLER__", _GAME_ICONS.get(SEBASTIAN_ICON, "")))


# ---- Нейросеть: чат с DeepSeek через OpenRouter ---------------------------
# Отдельная страница-чат в кабинете. В отличие от Себастьяна (тот крутится
# дома на видеокарте и потому один на всех), эта модель живёт в облаке
# OpenRouter — дома ничего не грузит, видеопамять свободна. OpenRouter говорит
# на языке OpenAI, так что запрос простой. Историю держит сам сайт: рядом с
# блокнотом, под паролем кабинета. Между запросами ни OpenRouter, ни DeepSeek
# ничего не помнят — весь разговор шлём заново каждый раз.
OPENROUTER_KEY = os.environ.get("OPENROUTER_KEY", "").strip()
OPENROUTER_URL = os.environ.get(
    "OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions").strip()
OPENROUTER_MODEL = os.environ.get(
    "OPENROUTER_MODEL", "deepseek/deepseek-chat-v3.1:free").strip()
# OpenRouter время от времени переименовывает и снимает с раздачи бесплатные
# модели DeepSeek. Держим короткий список запасных: если основная вернула
# 404, сервер сам пойдёт по списку и запомнит рабочую до перезапуска.
OPENROUTER_FALLBACKS = [
    "deepseek/deepseek-chat-v3.1:free",
    "deepseek/deepseek-r1-0528:free",
    "deepseek/deepseek-r1:free",
    "deepseek/deepseek-chat:free",
    "deepseek/deepseek-v3.2-exp:free",
]
_ai_active_model = OPENROUTER_MODEL
_ai_active_lock = threading.Lock()

def _ai_models_to_try(primary):
    seen = []
    for m in [primary] + OPENROUTER_FALLBACKS:
        if m and m not in seen:
            seen.append(m)
    return seen
# Vision-модель отдельно: у бесплатного DeepSeek картинок нет, поэтому фото
# уходит той модели, что назвал хозяин здесь. Пусто — кнопка фото прячется.
OPENROUTER_VISION_MODEL = os.environ.get("OPENROUTER_VISION_MODEL", "").strip()

AI_CHAT_PATH = os.path.join(DATA_DIR, "aichat.json")
AI_IMG_DIR = os.path.join(DATA_DIR, "aichat_img")
AI_TEXT_MAX = 8000
AI_CTX_MSGS = 16            # сколько последних реплик отдаём модели
AI_CHATS_MAX = 200         # столько чатов храним, старше — выкидываем
AI_MSGS_MAX = 600          # столько реплик на чат
AI_REPLY_TOKENS = 1400
AI_TIMEOUT = 120
AI_IMG_MAX = 4 * 1024 * 1024
AI_SYS_PROMPT = ("Ты дружелюбный и толковый собеседник на личном сайте. "
                 "Отвечай по-русски, живо и по делу. Просят код — давай рабочий "
                 "и с коротким пояснением.")

os.makedirs(AI_IMG_DIR, exist_ok=True)
ai_data: dict = {"chats": []}
ai_lock = threading.Lock()


def _ai_load():
    try:
        with open(AI_CHAT_PATH, encoding="utf-8") as fh:
            saved = json.load(fh) or {}
        ai_data["chats"] = saved.get("chats", [])
    except (OSError, ValueError):
        pass


def _ai_write():
    """Вызывать под ai_lock."""
    try:
        tmp = AI_CHAT_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ai_data, fh, ensure_ascii=False)
        os.replace(tmp, AI_CHAT_PATH)
    except OSError:
        pass


_ai_load()


def _ai_ready():
    return bool(OPENROUTER_KEY)


def _ai_find(chat_id):
    for c in ai_data["chats"]:
        if c.get("id") == chat_id:
            return c
    return None


def _ai_card(c):
    return {"id": c["id"], "title": c.get("title") or "Новый чат",
            "updated": c.get("updated", 0), "count": len(c.get("messages", [])),
            "model": c.get("model", OPENROUTER_MODEL)}


def _ai_img_path(img_id):
    return os.path.join(AI_IMG_DIR, img_id)


def _ai_drop_images(chat):
    for m in chat.get("messages", []):
        if m.get("img"):
            try:
                os.remove(_ai_img_path(m["img"]))
            except OSError:
                pass


def _sse(obj):
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


def _ai_http_error(code):
    if code == 429:
        return ("Дневной лимит бесплатных запросов исчерпан. "
                "Приходите позже или смените модель в .env.")
    if code == 401:
        return "OpenRouter не принял ключ — проверьте OPENROUTER_KEY."
    if code == 402:
        return "На счету OpenRouter не хватает средств для этой модели."
    return f"OpenRouter вернул ошибку {code}."


@app.get("/api/ai/state")
@login_required
def ai_state_api():
    """Готовность и список прошлых чатов — страница спрашивает при открытии."""
    with ai_lock:
        cards = [_ai_card(c) for c in ai_data["chats"]]
    cards.sort(key=lambda x: x["updated"], reverse=True)
    with _ai_active_lock:
        active = _ai_active_model
    return jsonify(ready=_ai_ready(), model=active,
                   vision=bool(OPENROUTER_VISION_MODEL), chats=cards)


@app.get("/api/ai/chat/<chat_id>")
@login_required
def ai_chat_get(chat_id):
    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        msgs = [{"role": m.get("role"), "text": m.get("text", ""),
                 "img": m.get("img") or "", "ts": m.get("ts", 0)}
                for m in c.get("messages", [])]
        title = c.get("title") or "Новый чат"
    return jsonify(id=chat_id, title=title, messages=msgs)


@app.post("/api/ai/chat")
@login_required
def ai_chat_new():
    cid = uuid.uuid4().hex[:12]
    now = time.time()
    chat = {"id": cid, "title": "", "model": OPENROUTER_MODEL,
            "created": now, "updated": now, "messages": []}
    with ai_lock:
        ai_data["chats"].insert(0, chat)
        if len(ai_data["chats"]) > AI_CHATS_MAX:
            for old in ai_data["chats"][AI_CHATS_MAX:]:
                _ai_drop_images(old)
            del ai_data["chats"][AI_CHATS_MAX:]
        _ai_write()
    return jsonify(id=cid, title="Новый чат")


@app.patch("/api/ai/chat/<chat_id>")
@login_required
def ai_chat_rename(chat_id):
    payload = request.get_json(silent=True) or {}
    name = (payload.get("title") or "").strip()[:80]
    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        c["title"] = name
        _ai_write()
    return jsonify(ok=True, title=name or "Новый чат")


@app.delete("/api/ai/chat/<chat_id>")
@login_required
def ai_chat_delete(chat_id):
    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        _ai_drop_images(c)
        ai_data["chats"] = [x for x in ai_data["chats"] if x is not c]
        _ai_write()
    return jsonify(ok=True)


@app.get("/api/ai/img/<img_id>")
@login_required
def ai_img_api(img_id):
    if not re.match(r"^[0-9a-f]{8,40}\.jpg$", img_id):
        return jsonify(error="нет"), 404
    path = _ai_img_path(img_id)
    if not os.path.isfile(path):
        return jsonify(error="нет"), 404
    return send_file(path, mimetype="image/jpeg")


@app.post("/api/ai/chat/<chat_id>/send")
@login_required
def ai_chat_send(chat_id):
    """Принимает реплику (текст + необязательное фото), шлёт разговор в
    OpenRouter и отдаёт ответ потоком (SSE). Пользовательскую реплику
    сохраняем СРАЗУ: даже если модель сегодня молчит из-за лимита, написанное
    не пропадёт и текст продолжит работать в следующий раз."""
    if not _ai_ready():
        return jsonify(error="Ключ OpenRouter на сервере не задан."), 503

    payload = request.get_json(silent=True) or {}
    text = (payload.get("text") or "").strip()[:AI_TEXT_MAX]
    image_data = payload.get("image") or ""
    if not text and not image_data:
        return jsonify(error="Пустое сообщение."), 400

    use_vision = bool(image_data) and bool(OPENROUTER_VISION_MODEL)
    img_id, img_b64 = None, None
    if image_data:
        m = re.match(r"^data:image/(?:png|jpe?g|webp);base64,(.+)$",
                     image_data, re.I)
        if m:
            try:
                raw = base64.b64decode(m.group(1), validate=True)
            except Exception:
                raw = b""
            if raw and len(raw) <= AI_IMG_MAX:
                img_id = uuid.uuid4().hex[:16] + ".jpg"
                try:
                    with open(_ai_img_path(img_id), "wb") as fh:
                        fh.write(raw)
                    img_b64 = base64.b64encode(raw).decode("ascii")
                except OSError:
                    img_id, img_b64 = None, None

    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        umsg = {"role": "user", "text": text, "ts": time.time()}
        if img_id:
            umsg["img"] = img_id
        c.setdefault("messages", []).append(umsg)
        if not c.get("title"):
            c["title"] = text[:60] or "Фото"
        c["updated"] = time.time()
        if len(c["messages"]) > AI_MSGS_MAX:
            for old in c["messages"][:-AI_MSGS_MAX]:
                if old.get("img"):
                    try:
                        os.remove(_ai_img_path(old["img"]))
                    except OSError:
                        pass
            c["messages"] = c["messages"][-AI_MSGS_MAX:]
        _ai_write()
        ctx = list(c["messages"][-AI_CTX_MSGS:])
    model = OPENROUTER_VISION_MODEL if use_vision else OPENROUTER_MODEL

    # Собираем разговор в формате OpenAI. Картинку прикрепляем только к самой
    # последней реплике и только когда есть vision-модель.
    api_msgs = [{"role": "system", "content": AI_SYS_PROMPT}]
    last = ctx[-1] if ctx else None
    for msg in ctx:
        if msg is last and use_vision and img_b64:
            content = []
            if msg.get("text"):
                content.append({"type": "text", "text": msg["text"]})
            content.append({"type": "image_url", "image_url": {
                "url": "data:image/jpeg;base64," + img_b64}})
            api_msgs.append({"role": "user", "content": content})
        else:
            body = msg.get("text", "")
            if not body and msg.get("img"):
                body = "[фото]"
            api_msgs.append({"role": msg.get("role", "user"), "content": body})

    req_body = json.dumps({
        "model": model,
        "messages": api_msgs,
        "stream": True,
        "max_tokens": AI_REPLY_TOKENS,
    }).encode("utf-8")

    def save_reply(full):
        with ai_lock:
            cc = _ai_find(chat_id)
            if cc is not None:
                cc.setdefault("messages", []).append(
                    {"role": "assistant", "text": full, "ts": time.time()})
                cc["updated"] = time.time()
                _ai_write()

    def gen():
        global _ai_active_model
        from urllib import request as urlrequest, error as urlerror
        headers = {"Authorization": "Bearer " + OPENROUTER_KEY,
                   "Content-Type": "application/json",
                   "HTTP-Referer": "https://vitazgio.ru",
                   "X-Title": "vitazgio.ru"}
        # Vision-запрос идёт на свою модель без замены. У обычного —
        # пробуем список: если основная 404, следующая; удачную запомним.
        with _ai_active_lock:
            primary = _ai_active_model if not use_vision else model
        candidates = [model] if use_vision else _ai_models_to_try(primary)
        resp = None
        chosen = candidates[0]
        for candidate in candidates:
            body_try = req_body if candidate == model else json.dumps({
                "model": candidate, "messages": api_msgs, "stream": True,
                "max_tokens": AI_REPLY_TOKENS}).encode("utf-8")
            req = urlrequest.Request(OPENROUTER_URL, data=body_try, headers=headers)
            try:
                resp = urlrequest.urlopen(req, timeout=AI_TIMEOUT)
                chosen = candidate
                break
            except urlerror.HTTPError as e:
                if e.code == 404 and candidate != candidates[-1]:
                    continue          # эту модель сняли — пробуем следующую
                yield _sse({"error": _ai_http_error(e.code) + f" (модель {candidate})"})
                return
            except urlerror.URLError:
                yield _sse({"error": "OpenRouter не отвечает. Попробуйте позже."})
                return
        if resp is None:
            yield _sse({"error": "Ни одна из известных бесплатных моделей не ответила."})
            return
        if not use_vision and chosen != _ai_active_model:
            with _ai_active_lock:
                _ai_active_model = chosen
            yield _sse({"model": chosen})
        acc = []
        try:
            for rawline in resp:
                line = rawline.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    obj = json.loads(chunk)
                except ValueError:
                    continue
                choices = obj.get("choices") or [{}]
                delta = (choices[0].get("delta") or {}).get("content")
                if delta:
                    acc.append(delta)
                    yield _sse({"delta": delta})
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass
        full = "".join(acc).strip()
        if full:
            save_reply(full)
            yield _sse({"done": True, "text": full})
        else:
            yield _sse({"error": "Модель промолчала — попробуйте ещё раз."})

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store",
                             "X-Accel-Buffering": "no"})


@app.get("/neuro")
@login_required
def neuro_page():
    """«Нейронки» — одна страница с двумя вкладками, как в браузере: DeepSeek
    (сине-фиолетовая) и Claude (оранжевая). Сами чаты — уже готовые страницы
    /ai и /claude; тут только верхние вкладки, которые их показывают в iframe.
    Каждая несёт свою тему, так что переключение меняет и цвет шапки."""
    html = r"""<!doctype html>
    <html lang="ru" data-tab="ds">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0b1020">
      <meta name="robots" content="noindex">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Нейронки · vitazgio.ru</title>
      <style>
        :root { color-scheme:dark; --line:rgba(255,255,255,.1);
                --ds1:#4d6bfe; --ds2:#8b7bff; --cl1:#d97757; --cl2:#f0a184;
                --ac:var(--ds1); --ac2:var(--ds2); }
        html[data-tab="cl"] { --ac:var(--cl1); --ac2:var(--cl2); }
        * { box-sizing:border-box; }
        html, body { height:100%; margin:0; }
        body { display:flex; flex-direction:column; overflow:hidden; color:#eef2fb;
               font-family:"Cascadia Code", Consolas, monospace;
               background:#0b1020; }

        /* Полоса вкладок — как шапка браузера: вкладки «стоят» на контенте. */
        .tabbar { flex:none; display:flex; align-items:flex-end; gap:6px;
                  padding:8px clamp(8px,2vw,16px) 0; border-bottom:1px solid var(--line);
                  background:linear-gradient(180deg,
                    color-mix(in srgb, var(--ac) 14%, #0b1020), #0b1020);
                  transition:background .25s; }
        .home { width:38px; height:38px; margin:0 4px 7px 0; flex:none; display:grid;
                place-items:center; color:#aeb8cf; text-decoration:none; border-radius:10px;
                border:1px solid var(--line); background:rgba(255,255,255,.04); transition:.16s; }
        .home:hover { color:#fff; border-color:color-mix(in srgb, var(--ac) 55%, transparent);
                      background:color-mix(in srgb, var(--ac) 14%, transparent); }
        .home svg { width:18px; height:18px; }

        .tab { position:relative; top:1px; display:flex; align-items:center; gap:9px; cursor:pointer;
               padding:10px 16px; max-width:210px; color:#9fa9bf; font:600 .84rem inherit;
               border:1px solid transparent; border-bottom:none;
               border-radius:12px 12px 0 0; background:transparent; transition:color .16s, background .16s; }
        .tab:hover { color:#e6ecf8; background:rgba(255,255,255,.04); }
        .tab i { width:9px; height:9px; flex:none; border-radius:50%; }
        .tab.ds i { background:linear-gradient(160deg,var(--ds1),var(--ds2)); box-shadow:0 0 10px var(--ds1); }
        .tab.cl i { background:linear-gradient(160deg,var(--cl1),var(--cl2)); box-shadow:0 0 10px var(--cl1); }
        .tab b { font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .tab.on { color:#fff; background:#0b1020; border-color:var(--line);
                  box-shadow:0 -3px 18px color-mix(in srgb, var(--ac) 22%, transparent); }
        /* язычок, «сливающий» активную вкладку с полем ниже */
        .tab.on::after { content:""; position:absolute; left:0; right:0; bottom:-1px; height:2px; background:#0b1020; }
        .tab.on::before { content:""; position:absolute; left:0; right:0; top:0; height:3px;
                          border-radius:12px 12px 0 0;
                          background:linear-gradient(90deg, var(--ac), var(--ac2)); }

        .stage { flex:1; min-height:0; position:relative; background:#0b1020; }
        .stage iframe { position:absolute; inset:0; width:100%; height:100%; border:0; display:none; }
        .stage iframe.on { display:block; }
        .stage .spin { position:absolute; inset:0; display:grid; place-items:center;
                       color:#7c8ba0; font-size:.8rem; }

        @media (max-width:560px) {
          .tab { padding:9px 12px; font-size:.8rem; }
          .tab b { max-width:96px; }
        }
      </style>
    </head>
    <body>
      <div class="tabbar">
        <a class="home" href="/cabinet" title="В кабинет" aria-label="В кабинет"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
        <button class="tab ds on" type="button" data-tab="ds"><i></i><b>DeepSeek</b></button>
        <button class="tab cl" type="button" data-tab="cl"><i></i><b>Claude</b></button>
      </div>
      <div class="stage">
        <div class="spin" id="spin">открываю…</div>
        <iframe id="fr-ds" class="on" title="DeepSeek" src="/ai" loading="eager"></iframe>
        <iframe id="fr-cl" title="Claude" data-src="/claude" loading="lazy"></iframe>
      </div>

      <script>
      (() => {
        "use strict";
        const root = document.documentElement;
        const tabs = Array.from(document.querySelectorAll(".tab"));
        const frames = { ds: document.getElementById("fr-ds"), cl: document.getElementById("fr-cl") };
        const spin = document.getElementById("spin");
        const loaded = { ds: true, cl: false };

        frames.ds.addEventListener("load", () => { if (root.getAttribute("data-tab") === "ds") spin.style.display = "none"; });
        frames.cl.addEventListener("load", () => { loaded.cl = true; if (root.getAttribute("data-tab") === "cl") spin.style.display = "none"; });

        const show = (id) => {
          root.setAttribute("data-tab", id);
          tabs.forEach((t) => t.classList.toggle("on", t.dataset.tab === id));
          Object.keys(frames).forEach((k) => frames[k].classList.toggle("on", k === id));
          // ленивое подключение второй вкладки при первом заходе
          if (!loaded[id] && frames[id].dataset.src) {
            spin.style.display = "grid";
            frames[id].src = frames[id].dataset.src;
          } else {
            spin.style.display = "none";
          }
          try { localStorage.setItem("neuroTab", id); } catch (e) {}
        };

        tabs.forEach((t) => t.addEventListener("click", () => show(t.dataset.tab)));

        let start = "ds";
        try { const s = localStorage.getItem("neuroTab"); if (s === "cl" || s === "ds") start = s; } catch (e) {}
        show(start);
      })();
      </script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


@app.get("/ai")
@login_required
def ai_page():
    """Чат с нейросетью (DeepSeek через OpenRouter). Личная страница хозяина:
    история чатов хранится на сайте под паролем кабинета, поэтому за замком.
    Разрешаем встраивание в свой же iframe — страница «Нейронки» показывает её
    вкладкой рядом с Claude."""
    g.frameable = True
    html = r"""<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <script>try{if(window.top!==window.self)document.documentElement.classList.add("embed");}catch(e){document.documentElement.classList.add("embed");}</script>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0b1020">
      <meta name="description" content="Чат с нейросетью — vitazgio.ru">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Нейросеть · vitazgio.ru</title>
      <style>
        :root { color-scheme:dark; --line:rgba(255,255,255,.1); --muted:#8b93a7;
                --ac:#4d6bfe; --ac2:#8b7bff; --ok:#63f5ad; --warm:#ffd84a;
                --panel:rgba(12,17,32,.72); }
        * { box-sizing:border-box; }
        html, body { height:100%; margin:0; }
        body { color:#eef2fb; font-family:"Cascadia Code", Consolas, monospace;
               background:radial-gradient(1100px 700px at 12% -8%, #1a2550, #0b1020 55%);
               display:flex; flex-direction:column; overflow:hidden; }
        a { color:inherit; }

        .bar { display:flex; align-items:center; gap:12px; padding:11px clamp(12px,2vw,20px);
               border-bottom:1px solid var(--line); background:rgba(8,12,24,.5); flex:none; }
        .back, .burger { width:40px; height:40px; flex:none; display:grid; place-items:center;
                 color:var(--ac); text-decoration:none; cursor:pointer;
                 border:1px solid rgba(77,107,254,.32); border-radius:11px;
                 background:rgba(77,107,254,.08); transition:.16s; }
        .back:hover, .burger:hover { color:#fff; border-color:var(--ac); background:rgba(77,107,254,.2); }
        .back svg, .burger svg { width:19px; height:19px; }
        .burger { display:none; }
        html.embed .back { display:none; }   /* встроена во вкладку «Нейронки» */
        .brand { flex:1; min-width:0; }
        .brand b { display:block; font-size:1.06rem; letter-spacing:-.01em; }
        .brand span { display:block; margin-top:2px; color:var(--muted); font-size:.68rem;
                      white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:5px;
               background:var(--muted); vertical-align:middle; }
        .dot.on { background:var(--ok); box-shadow:0 0 9px var(--ok); }
        .dot.off { background:var(--warm); }

        .wrap { flex:1; min-height:0; display:grid; grid-template-columns:264px 1fr; }
        .aside { border-right:1px solid var(--line); background:var(--panel);
                 display:flex; flex-direction:column; min-height:0; }
        .newbtn { margin:12px; height:44px; flex:none; display:flex; align-items:center;
                  justify-content:center; gap:9px; cursor:pointer; color:#eaf0ff;
                  font:700 .82rem inherit; border:1px solid rgba(77,107,254,.4);
                  border-radius:12px; background:linear-gradient(160deg, rgba(77,107,254,.22), rgba(139,123,255,.14));
                  transition:.16s; }
        .newbtn:hover { border-color:var(--ac); background:linear-gradient(160deg, rgba(77,107,254,.34), rgba(139,123,255,.2)); }
        .newbtn svg { width:17px; height:17px; }
        .list { flex:1; min-height:0; overflow-y:auto; padding:0 8px 12px;
                scrollbar-width:thin; scrollbar-color:rgba(77,107,254,.5) transparent; }
        .list::-webkit-scrollbar { width:8px; }
        .list::-webkit-scrollbar-thumb { border-radius:99px;
                background:linear-gradient(180deg, var(--ac), rgba(77,107,254,.3)); }
        .row { display:flex; align-items:center; gap:8px; padding:9px 10px; margin-bottom:4px;
               border-radius:10px; cursor:pointer; border:1px solid transparent; transition:.13s; }
        .row:hover { background:rgba(255,255,255,.05); }
        .row.on { background:rgba(77,107,254,.16); border-color:rgba(77,107,254,.4); }
        .row .ico { width:8px; height:8px; flex:none; border-radius:50%; background:var(--ac2); opacity:.6; }
        .row .meta { flex:1; min-width:0; }
        .row .ttl { display:block; font-size:.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .row .sub { display:block; margin-top:2px; color:var(--muted); font-size:.63rem; }
        .row .x { flex:none; width:24px; height:24px; display:grid; place-items:center; opacity:0;
                  color:var(--muted); border-radius:7px; transition:.13s; font-size:1rem; line-height:1; }
        .row:hover .x { opacity:.7; }
        .row .x:hover { opacity:1; color:#ff8a8a; background:rgba(255,90,90,.12); }
        .empty-list { color:var(--muted); font-size:.72rem; text-align:center; padding:24px 14px; line-height:1.6; }

        .main { display:flex; flex-direction:column; min-width:0; min-height:0; position:relative; }
        .chat { flex:1; min-height:0; overflow-y:auto; padding:clamp(14px,2.4vw,26px);
                display:flex; flex-direction:column; gap:16px;
                scrollbar-width:thin; scrollbar-color:rgba(77,107,254,.4) transparent; }
        .chat::-webkit-scrollbar { width:9px; }
        .chat::-webkit-scrollbar-thumb { border-radius:99px; background:rgba(77,107,254,.35); }
        .msg { display:flex; gap:12px; max-width:min(760px,100%); align-self:center; width:100%; }
        .msg .av { width:34px; height:34px; flex:none; border-radius:11px; display:grid;
                   place-items:center; font-size:.6rem; font-weight:800; color:#050a18;
                   background:linear-gradient(160deg,#8fa4ff,#4d6bfe); }
        .msg.me .av { color:#eef2fb; background:rgba(255,255,255,.08); border:1px solid var(--line); }
        .msg .bd { min-width:0; }
        .msg .txt { padding:12px 15px; border-radius:14px; font-size:.9rem; line-height:1.62;
                    background:rgba(255,255,255,.045); border:1px solid var(--line);
                    overflow-wrap:anywhere; }
        .msg.me { flex-direction:row-reverse; }
        .msg.me .txt { background:rgba(77,107,254,.14); border-color:rgba(77,107,254,.3); }
        .msg.err .txt { color:#ffb3b3; background:rgba(255,90,90,.1); border-color:rgba(255,90,90,.32); }
        .msg .txt img { max-width:260px; max-height:260px; border-radius:9px; display:block;
                        margin:0 0 8px; border:1px solid var(--line); }
        .msg .txt p:first-child { margin-top:0; } .msg .txt p:last-child { margin-bottom:0; }
        .txt pre { margin:9px 0; padding:11px 13px; overflow-x:auto; border-radius:10px;
                   background:rgba(3,7,18,.7); border:1px solid var(--line);
                   scrollbar-width:thin; }
        .txt pre code { font-size:.82rem; line-height:1.5; color:#d7e2ff; }
        .txt code { font-family:inherit; }
        .txt :not(pre) > code { padding:1px 6px; border-radius:6px; font-size:.84rem;
                   background:rgba(139,123,255,.16); color:#cfd6ff; }
        .txt a { color:#9db4ff; text-decoration:underline; text-underline-offset:2px; }
        .cursor::after { content:"▋"; margin-left:1px; color:var(--ac); animation:blink 1s steps(2) infinite; }
        @keyframes blink { 50% { opacity:0; } }
        .dots span { display:inline-block; width:6px; height:6px; margin-right:4px; border-radius:50%;
                     background:var(--ac); animation:blip 1.1s ease-in-out infinite; }
        .dots span:nth-child(2){ animation-delay:.18s } .dots span:nth-child(3){ animation-delay:.36s }
        @keyframes blip { 0%,100%{opacity:.25; transform:translateY(0)} 50%{opacity:1; transform:translateY(-3px)} }

        .hello { margin:auto; text-align:center; max-width:520px; padding:20px; }
        .hello h2 { margin:0 0 8px; font-size:1.35rem; font-weight:800;
                    background:linear-gradient(90deg,#a9b8ff,#8b7bff); -webkit-background-clip:text;
                    background-clip:text; -webkit-text-fill-color:transparent; }
        .hello p { margin:0 0 18px; color:var(--muted); font-size:.82rem; line-height:1.6; }
        .seeds { display:flex; flex-wrap:wrap; gap:8px; justify-content:center; }
        .seeds button { padding:9px 13px; cursor:pointer; color:#cfd8ee; font:400 .76rem inherit;
                        border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,.04);
                        transition:.15s; }
        .seeds button:hover { color:#fff; border-color:rgba(77,107,254,.5); background:rgba(77,107,254,.12); }

        .compose { flex:none; border-top:1px solid var(--line); padding:12px clamp(12px,2.4vw,26px) 14px;
                   background:rgba(8,12,24,.55); }
        .imgchip { display:inline-flex; align-items:center; gap:9px; margin-bottom:9px; padding:6px 9px;
                   border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,.04); }
        .imgchip img { width:34px; height:34px; object-fit:cover; border-radius:7px; }
        .imgchip button { cursor:pointer; color:var(--muted); background:none; border:0; font-size:1rem; }
        .imgchip button:hover { color:#ff8a8a; }
        .field { display:flex; align-items:flex-end; gap:9px; max-width:820px; margin:0 auto; }
        .attach { width:46px; height:46px; flex:none; display:grid; place-items:center; cursor:pointer;
                  color:var(--muted); border:1px solid var(--line); border-radius:13px;
                  background:rgba(255,255,255,.04); transition:.15s; }
        .attach:hover { color:var(--ac2); border-color:rgba(139,123,255,.5); }
        .attach svg { width:20px; height:20px; }
        .field textarea { flex:1; min-height:46px; max-height:190px; padding:12px 15px; resize:none;
                 color:#f4f7ff; font:400 .9rem inherit; line-height:1.5; border:1px solid var(--line);
                 border-radius:13px; outline:none; background:rgba(4,9,20,.65); }
        .field textarea:focus { border-color:var(--ac); }
        .send { width:46px; height:46px; flex:none; display:grid; place-items:center; cursor:pointer;
                color:#050a18; border:0; border-radius:13px;
                background:linear-gradient(160deg,#8fa4ff,#4d6bfe); transition:.15s; }
        .send:hover { filter:brightness(1.08); } .send:disabled { opacity:.4; cursor:not-allowed; }
        .send svg { width:20px; height:20px; }
        .note { max-width:820px; margin:8px auto 0; color:#5c6780; font-size:.66rem; text-align:center; line-height:1.5; }

        .scrim { display:none; }
        @media (max-width:760px) {
          .burger { display:grid; }
          .wrap { grid-template-columns:1fr; }
          .aside { position:absolute; z-index:20; top:0; bottom:0; left:0; width:min(300px,84vw);
                   transform:translateX(-104%); transition:transform .22s ease;
                   box-shadow:24px 0 60px rgba(0,0,0,.5); }
          .wrap.open .aside { transform:none; }
          .scrim { position:absolute; inset:0; z-index:15; background:rgba(2,5,12,.55); }
          .wrap.open .scrim { display:block; }
        }
        @media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
      </style>
    </head>
    <body>
      <div class="bar">
        <a class="back" href="/cabinet" title="В кабинет" aria-label="В кабинет"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
        <button class="burger" id="burger" type="button" aria-label="Список чатов"><svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>
        <div class="brand"><b>Нейросеть</b><span id="brand-sub"><i class="dot"></i>проверяю связь…</span></div>
      </div>

      <div class="wrap" id="wrap">
        <div class="scrim" id="scrim"></div>
        <aside class="aside">
          <button class="newbtn" id="newbtn" type="button">
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
            Новый чат
          </button>
          <div class="list" id="list"></div>
        </aside>

        <main class="main">
          <div class="chat" id="chat"></div>
          <div class="compose">
            <div id="chip-slot"></div>
            <form class="field" id="field">
              <label class="attach" id="attach" title="Прикрепить фото" hidden>
                <svg viewBox="0 0 24 24" fill="none"><path d="M21 12.5 12.5 21a5 5 0 0 1-7-7l8-8a3.5 3.5 0 0 1 5 5l-8 8a2 2 0 0 1-3-3l7.5-7.5" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>
                <input type="file" id="file" accept="image/*" hidden>
              </label>
              <textarea id="text" rows="1" placeholder="Напишите сообщение…" aria-label="Сообщение"></textarea>
              <button class="send" id="send" type="submit" title="Отправить" aria-label="Отправить">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h15m0 0-6-6m6 6-6 6"/></svg>
              </button>
            </form>
            <p class="note" id="note">История этих чатов хранится на сайте под паролем кабинета. Модель — в облаке, дома ничего не грузит.</p>
          </div>
        </main>
      </div>

      <script>
      (() => {
        "use strict";
        const $ = (id) => document.getElementById(id);
        const chat = $("chat"), list = $("list"), wrap = $("wrap");
        let chats = [], curId = null, busy = false, ready = false, vision = false, modelName = "";
        let pendImg = null;

        const esc = (s) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

        // Небольшой безопасный markdown: сначала прячем блоки кода, экранируем
        // остальное, потом возвращаем стили. Так теги из ответа не выполнятся.
        const md = (src) => {
          const blocks = [];
          let t = (src || "").replace(/```([\s\S]*?)```/g, (m, code) => {
            let body = code.replace(/^[a-zA-Z0-9_+.-]*\n/, "");
            blocks.push("<pre><code>" + esc(body.replace(/\s+$/, "")) + "</code></pre>");
            return "" + (blocks.length - 1) + "";
          });
          t = esc(t);
          t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
          t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
          t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
                        (m, txt, url) => '<a href="' + url + '" target="_blank" rel="noopener">' + txt + "</a>");
          t = t.replace(/^(\s*)[-*] +/gm, "$1• ");
          t = t.replace(/\n/g, "<br>");
          t = t.replace(/(\d+)/g, (m, i) => blocks[+i]);
          return t;
        };

        const ago = (ts) => {
          if (!ts) return "";
          const s = Math.max(0, Date.now() / 1000 - ts);
          if (s < 60) return "только что";
          if (s < 3600) return Math.floor(s / 60) + " мин";
          if (s < 86400) return Math.floor(s / 3600) + " ч";
          if (s < 604800) return Math.floor(s / 86400) + " дн";
          return new Date(ts * 1000).toLocaleDateString("ru-RU");
        };

        const scrollDown = () => { chat.scrollTop = chat.scrollHeight; };

        const bubble = (role, html, cls) => {
          const el = document.createElement("div");
          el.className = "msg " + (role === "me" ? "me" : "bot") + (cls ? " " + cls : "");
          const av = document.createElement("span");
          av.className = "av";
          av.textContent = role === "me" ? "Я" : "DS";
          const bd = document.createElement("div");
          bd.className = "bd";
          const tx = document.createElement("div");
          tx.className = "txt";
          if (html === null) tx.innerHTML = '<span class="dots"><span></span><span></span><span></span></span>';
          else tx.innerHTML = html;
          bd.appendChild(tx);
          el.append(av, bd);
          chat.appendChild(el);
          scrollDown();
          return tx;
        };

        const showHello = () => {
          chat.innerHTML = "";
          const box = document.createElement("div");
          box.className = "hello";
          box.innerHTML = '<h2>Чат с нейросетью</h2>' +
            '<p>' + (ready
              ? "Спрашивайте что угодно — модель " + esc(modelName) + " отвечает через OpenRouter. Разговор сохранится слева."
              : "Ключ OpenRouter на сервере пока не задан, поэтому отвечать нечем. Как получить ключ — в инструкции у хозяина.") + '</p>' +
            '<div class="seeds">' +
              '<button type="button">Объясни простыми словами, что такое нейросеть</button>' +
              '<button type="button">Придумай план на выходные</button>' +
              '<button type="button">Помоги написать письмо</button>' +
              '<button type="button">Дай рецепт из того, что есть в холодильнике</button>' +
            '</div>';
          chat.appendChild(box);
          box.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
            $("text").value = b.textContent;
            grow();
            submit();
          }));
        };

        const renderList = () => {
          list.innerHTML = "";
          if (!chats.length) {
            list.innerHTML = '<div class="empty-list">Пока пусто.<br>Нажмите «Новый чат».</div>';
            return;
          }
          chats.forEach((c) => {
            const row = document.createElement("div");
            row.className = "row" + (c.id === curId ? " on" : "");
            row.innerHTML = '<span class="ico"></span><span class="meta">' +
              '<span class="ttl">' + esc(c.title) + '</span>' +
              '<span class="sub">' + c.count + ' сообщ. · ' + ago(c.updated) + '</span></span>' +
              '<span class="x" title="Удалить">✕</span>';
            row.querySelector(".meta").addEventListener("click", () => openChat(c.id));
            row.querySelector(".x").addEventListener("click", (e) => { e.stopPropagation(); delChat(c.id); });
            list.appendChild(row);
          });
        };

        const closeDrawer = () => wrap.classList.remove("open");

        const loadState = async () => {
          try {
            const r = await fetch("/api/ai/state", { credentials: "same-origin" });
            const d = await r.json();
            ready = !!d.ready; vision = !!d.vision; modelName = d.model || "";
            chats = d.chats || [];
            $("brand-sub").innerHTML = '<i class="dot ' + (ready ? "on" : "off") + '"></i>' +
              (ready ? esc(modelName) : "ключ OpenRouter не задан");
            $("attach").hidden = !(ready && vision);
            renderList();
            if (chats.length) openChat(chats[0].id);
            else showHello();
          } catch (e) {
            $("brand-sub").innerHTML = '<i class="dot off"></i>не отвечает';
          }
        };

        const newChat = async () => {
          if (!ready) return;
          try {
            const r = await fetch("/api/ai/chat", { method: "POST", credentials: "same-origin" });
            const d = await r.json();
            chats.unshift({ id: d.id, title: d.title, count: 0, updated: Date.now() / 1000 });
            curId = d.id;
            renderList();
            chat.innerHTML = "";
            showHello();
            closeDrawer();
            $("text").focus();
          } catch (e) {}
        };

        const openChat = async (id) => {
          curId = id;
          renderList();
          closeDrawer();
          chat.innerHTML = '<div class="hello"><p>Загружаю…</p></div>';
          try {
            const r = await fetch("/api/ai/chat/" + id, { credentials: "same-origin" });
            const d = await r.json();
            chat.innerHTML = "";
            if (!d.messages || !d.messages.length) { showHello(); return; }
            d.messages.forEach((m) => {
              const isMe = m.role === "user";
              let html = "";
              if (m.img) html += '<img src="/api/ai/img/' + encodeURIComponent(m.img) + '" alt="фото">';
              html += isMe ? esc(m.text).replace(/\n/g, "<br>") : md(m.text);
              bubble(isMe ? "me" : "bot", html);
            });
          } catch (e) {
            chat.innerHTML = "";
            bubble("bot", "Не удалось открыть чат.", "err");
          }
        };

        const delChat = async (id) => {
          if (!confirm("Удалить этот чат целиком?")) return;
          try {
            await fetch("/api/ai/chat/" + id, { method: "DELETE", credentials: "same-origin" });
          } catch (e) {}
          chats = chats.filter((c) => c.id !== id);
          if (curId === id) { curId = null; chat.innerHTML = ""; }
          if (chats.length && !curId) openChat(chats[0].id);
          else if (!chats.length) { curId = null; showHello(); }
          renderList();
        };

        const bumpCard = () => {
          const c = chats.find((x) => x.id === curId);
          if (c) { c.updated = Date.now() / 1000; c.count = (c.count || 0) + 1; }
          chats.sort((a, b) => b.updated - a.updated);
          renderList();
        };

        const submit = async () => {
          if (busy || !ready) return;
          const ta = $("text");
          const text = ta.value.trim();
          const img = pendImg;
          if (!text && !img) return;
          if (!curId) { await newChat(); }
          if (!curId) return;

          // если открыт экран-приветствие — очищаем его перед первой репликой
          if (chat.querySelector(".hello")) chat.innerHTML = "";

          busy = true; $("send").disabled = true;
          let meHtml = "";
          if (img) meHtml += '<img src="' + img + '" alt="фото">';
          if (text) meHtml += esc(text).replace(/\n/g, "<br>");
          bubble("me", meHtml);
          ta.value = ""; grow(); clearImg();
          bumpCard();
          const out = bubble("bot", null);

          let acc = "";
          try {
            const r = await fetch("/api/ai/chat/" + curId + "/send", {
              method: "POST", credentials: "same-origin",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ text: text, image: img || undefined }),
            });
            if (!r.ok || !r.body) {
              const d = await r.json().catch(() => ({}));
              out.parentElement.parentElement.classList.add("err");
              out.textContent = d.error || "Не удалось отправить.";
              busy = false; $("send").disabled = false; return;
            }
            const reader = r.body.getReader();
            const dec = new TextDecoder();
            let buf = "";
            out.classList.add("cursor");
            for (;;) {
              const { value, done } = await reader.read();
              if (done) break;
              buf += dec.decode(value, { stream: true });
              let i;
              while ((i = buf.indexOf("\n\n")) >= 0) {
                const frame = buf.slice(0, i); buf = buf.slice(i + 2);
                const line = frame.split("\n").find((l) => l.startsWith("data:"));
                if (!line) continue;
                let ev;
                try { ev = JSON.parse(line.slice(5).trim()); } catch (e) { continue; }
                if (ev.model) { modelName = ev.model; $("brand-sub").innerHTML = '<i class="dot on"></i>' + esc(modelName); }
                else if (ev.delta) { acc += ev.delta; out.innerHTML = md(acc); scrollDown(); }
                else if (ev.error) {
                  out.classList.remove("cursor");
                  out.parentElement.parentElement.classList.add("err");
                  out.textContent = ev.error;
                }
                else if (ev.done && ev.text) { acc = ev.text; out.innerHTML = md(acc); }
              }
            }
            out.classList.remove("cursor");
            if (!acc && !out.textContent) out.textContent = "Пустой ответ.";
            bumpCard();
          } catch (e) {
            out.classList.remove("cursor");
            out.parentElement.parentElement.classList.add("err");
            out.textContent = "Оборвалась связь с сервером.";
          } finally {
            busy = false; $("send").disabled = false; $("text").focus();
          }
        };

        // ── ввод ──
        const grow = () => { const ta = $("text"); ta.style.height = "auto"; ta.style.height = Math.min(190, ta.scrollHeight) + "px"; };
        $("text").addEventListener("input", grow);
        $("text").addEventListener("keydown", (e) => {
          if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
        });
        $("field").addEventListener("submit", (e) => { e.preventDefault(); submit(); });
        $("newbtn").addEventListener("click", newChat);
        $("burger").addEventListener("click", () => wrap.classList.toggle("open"));
        $("scrim").addEventListener("click", closeDrawer);

        // ── фото: ужимаем в браузере, чтобы не гонять гигантские файлы ──
        const clearImg = () => { pendImg = null; $("chip-slot").innerHTML = ""; $("file").value = ""; };
        $("file").addEventListener("change", () => {
          const f = $("file").files[0];
          if (!f) return;
          const img = new Image();
          const rd = new FileReader();
          rd.onload = () => { img.onload = () => {
            const max = 1024, sc = Math.min(1, max / Math.max(img.width, img.height));
            const cv = document.createElement("canvas");
            cv.width = Math.round(img.width * sc); cv.height = Math.round(img.height * sc);
            cv.getContext("2d").drawImage(img, 0, 0, cv.width, cv.height);
            pendImg = cv.toDataURL("image/jpeg", 0.85);
            $("chip-slot").innerHTML = "";
            const chip = document.createElement("div");
            chip.className = "imgchip";
            chip.innerHTML = '<img src="' + pendImg + '" alt=""><span>фото готово</span><button type="button" title="Убрать">✕</button>';
            chip.querySelector("button").addEventListener("click", clearImg);
            $("chip-slot").appendChild(chip);
          }; img.src = rd.result; };
          rd.readAsDataURL(f);
        });

        loadState();
      })();
      </script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


@app.get("/servers")
def servers_page():
    """Хозяйство: три машины, их роли и что на них крутится.

    Страница открыта всем, поэтому наружу не выносим ни публичный адрес VPS,
    ни адреса mesh-сети — только домашние 192.168.x, которые одинаковы у
    половины страны и ничего не выдают."""
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#0d1321">
      <meta name="description" content="Домашний кластер vitazgio.ru: VPS, Proxmox и Orange Pi — что где крутится">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>Хозяйство · vitazgio.ru</title>
      <style>
        :root { color-scheme: dark;
                --bg:#0d1321; --line:rgba(255,255,255,.1); --muted:#8b97ac;
                --pc:#2de2ff; --ok:#63f5ad; --warm:#ffd84a; --hot:#ff7a59; --vio:#b57cff; }
        * { box-sizing: border-box; }
        body { margin:0; min-width:320px; color:#eaf3fb; padding-bottom:70px;
               font-family:"Cascadia Code", Consolas, monospace;
               background:radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .page { width:min(1180px, calc(100% - 36px)); margin:0 auto; padding:clamp(18px,3vw,40px) 0 0; }

        .top { position:relative; display:flex; align-items:center; gap:14px; margin-bottom:22px; }
        .back { width:44px; height:44px; flex:none; display:grid; place-items:center;
                color:var(--pc); text-decoration:none; border:1px solid rgba(45,226,255,.3);
                border-radius:50%; background:rgba(45,226,255,.07); transition:.18s; }
        .back:hover { color:#fff; border-color:var(--pc); background:rgba(45,226,255,.18); }
        .back svg { width:20px; height:20px; }
        .eyebrow { display:inline-flex; align-items:center; gap:10px; color:#cdd2df;
                   font-size:.74rem; font-weight:700; letter-spacing:.16em;
                   text-transform:uppercase; text-decoration:none; }
        .eyebrow::before { content:""; width:7px; height:7px; border-radius:50%;
                           background:var(--ok); box-shadow:0 0 16px var(--ok); }
        .eyebrow:hover { color:#fff; }
        .mark { position:absolute; right:0; top:50%; transform:translateY(-55%);
                width:clamp(1.2rem,4.4vw,3.4rem); height:clamp(1.2rem,4.4vw,3.4rem); }

        h1 { position:relative; min-height:112px; display:flex; align-items:center; margin:0;
             padding:22px clamp(20px,4vw,46px);
             font-size:clamp(1.1rem,4.2vw,3.2rem); font-weight:800; letter-spacing:-.05em;
             color:#dffaff; border:1px solid rgba(54,228,255,.24);
             background:linear-gradient(110deg, rgba(12,28,43,.92), rgba(20,17,38,.82));
             clip-path:polygon(0 0, calc(100% - 25px) 0, 100% 25px, 100% 100%, 25px 100%, 0 calc(100% - 25px));
             text-shadow:2px 0 #ff3fa4, -2px 0 #21dcff; }
        .lead { max-width:70ch; margin:22px 0 0; color:var(--muted); font-size:.94rem; line-height:1.65; }

        /* ── сводка цифрами ─────────────────────────────────────────── */
        .tally { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
                 gap:12px; margin:26px 0 0; }
        .tile { padding:16px 18px; border:1px solid var(--line); border-radius:14px;
                background:linear-gradient(160deg, rgba(18,28,45,.8), rgba(10,15,26,.85));
                position:relative; overflow:hidden; }
        .tile::after { content:""; position:absolute; inset:auto -30% -60% -30%; height:90px;
                       background:radial-gradient(60% 100% at 50% 100%, var(--tc,var(--pc)), transparent 70%);
                       opacity:.14; }
        .tile b { display:block; font-size:1.9rem; font-weight:800; letter-spacing:-.03em;
                  color:var(--tc,var(--pc)); font-variant-numeric:tabular-nums; }
        .tile span { display:block; margin-top:4px; color:var(--muted); font-size:.7rem;
                     letter-spacing:.1em; text-transform:uppercase; }

        h2.sec { display:flex; align-items:center; gap:14px; margin:46px 0 18px;
                 font-size:1.05rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase;
                 color:#a9b6c9; }
        h2.sec::after { content:""; flex:1; height:1px;
                        background:linear-gradient(90deg, rgba(255,255,255,.16), transparent); }

        /* ── схема сети ─────────────────────────────────────────────── */
        .mapbox { padding:8px 4px 4px; border:1px solid var(--line); border-radius:16px;
                  background:linear-gradient(160deg, rgba(15,24,40,.75), rgba(9,14,24,.85));
                  overflow-x:auto; }
        .mapbox svg { display:block; width:100%; min-width:660px; height:auto; }
        .n-box { fill:rgba(14,24,40,.95); stroke:rgba(255,255,255,.14); }
        .n-box.pc  { stroke:rgba(45,226,255,.55); }
        .n-box.ok  { stroke:rgba(99,245,173,.5); }
        .n-box.vio { stroke:rgba(181,124,255,.5); }
        .n-t  { fill:#eaf3fb; font:700 13px "Cascadia Code",monospace; }
        .n-s  { fill:#7f8ea3; font:400 10.5px "Cascadia Code",monospace; }
        .wire { stroke:rgba(255,255,255,.14); stroke-width:1.6; fill:none; }
        .wire.lit { stroke:rgba(45,226,255,.34); }
        .wire.warm { stroke:rgba(255,216,74,.32); }
        .wire.dim { stroke:rgba(255,255,255,.14); stroke-dasharray:5 6; }
        .pkt { fill:var(--pc); filter:drop-shadow(0 0 5px var(--pc)); }
        .pkt.g { fill:var(--ok); filter:drop-shadow(0 0 5px var(--ok)); }
        .pkt.w { fill:var(--warm); filter:drop-shadow(0 0 5px var(--warm)); }
        .pkt.d { fill:#8b97ac; }
        .n-box.big { fill:rgba(20,32,52,.95); stroke:rgba(255,255,255,.22); }
        .lane { fill:#7f8ea3; font:700 10.5px "Cascadia Code",monospace; letter-spacing:.06em; }
        .lane.warmtx { fill:#b39a55; }
        .note-tx { fill:#5d6a7d; font:400 10px "Cascadia Code",monospace; }
        .pulse { animation:pulse 2.6s ease-in-out infinite; transform-origin:center; }
        @keyframes pulse { 0%,100%{opacity:.35} 50%{opacity:1} }

        /* ── карточки машин ─────────────────────────────────────────── */
        .rigs { display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(330px,1fr)); }
        .rig { position:relative; display:flex; flex-direction:column; overflow:hidden;
               border:1px solid var(--line); border-radius:18px;
               background:linear-gradient(160deg, rgba(18,28,45,.86), rgba(9,14,24,.9));
               transition:transform .25s, border-color .25s, box-shadow .25s; }
        .rig:hover { transform:translateY(-4px); border-color:color-mix(in srgb, var(--ac) 55%, transparent);
                     box-shadow:0 22px 50px rgba(0,0,0,.45), 0 0 34px color-mix(in srgb, var(--ac) 12%, transparent); }
        .rig::before { content:""; position:absolute; left:0; right:0; top:0; height:3px;
                       background:linear-gradient(90deg, var(--ac), transparent 75%); }
        .rig-head { display:flex; align-items:center; gap:13px; padding:18px 18px 12px; }
        .rig-ico { width:46px; height:46px; flex:none; display:grid; place-items:center;
                   border-radius:13px; color:var(--ac);
                   background:color-mix(in srgb, var(--ac) 13%, transparent);
                   box-shadow:0 0 0 1px color-mix(in srgb, var(--ac) 30%, transparent) inset; }
        .rig-ico svg { width:24px; height:24px; }
        .rig-name { flex:1; min-width:0; }
        .rig-name b { display:block; font-size:1.06rem; font-weight:800; letter-spacing:-.01em; }
        .rig-name span { display:block; margin-top:3px; color:var(--muted); font-size:.7rem;
                         letter-spacing:.1em; text-transform:uppercase; }
        .dot { width:9px; height:9px; flex:none; border-radius:50%; background:var(--ok);
               box-shadow:0 0 12px var(--ok); animation:beat 2.4s ease-in-out infinite; }
        @keyframes beat { 0%,100%{ transform:scale(1); opacity:1 } 50%{ transform:scale(.7); opacity:.55 } }

        .specs { padding:0 18px; display:grid; gap:9px; }
        .spec { display:flex; align-items:center; gap:10px; font-size:.78rem; }
        .spec .k { flex:none; width:82px; color:#6f7d92; font-size:.68rem;
                   letter-spacing:.08em; text-transform:uppercase; }
        .spec .v { flex:1; min-width:0; color:#dce6f3; }
        .meter { flex:1; height:5px; border-radius:3px; background:rgba(255,255,255,.08); overflow:hidden; }
        .meter i { display:block; height:100%; width:0; border-radius:3px;
                   background:linear-gradient(90deg, var(--ac), color-mix(in srgb, var(--ac) 35%, #ffffff));
                   transition:width 1.1s cubic-bezier(.22,1,.36,1); }

        .svc { display:flex; flex-wrap:wrap; gap:6px; padding:14px 18px 18px; margin-top:auto; }
        .svc i { font-style:normal; padding:4px 9px; border-radius:7px; font-size:.68rem;
                 color:#cfe0f0; background:rgba(255,255,255,.05); border:1px solid var(--line); }
        .svc i.hi { color:#04121c; background:var(--ac); border-color:var(--ac); font-weight:700; }
        .vm { margin:12px 18px 0; padding:11px 13px; border-radius:12px;
              border:1px dashed rgba(255,255,255,.14); background:rgba(255,255,255,.02); }
        .vm b { display:block; font-size:.82rem; margin-bottom:3px; }
        .vm span { color:var(--muted); font-size:.7rem; line-height:1.5; }

        /* ── конвейер Себастьяна ────────────────────────────────────── */
        .flow { display:flex; align-items:stretch; gap:0; flex-wrap:wrap;
                border:1px solid var(--line); border-radius:16px; overflow:hidden;
                background:linear-gradient(160deg, rgba(16,26,42,.8), rgba(9,14,24,.86)); }
        .step { flex:1 1 150px; min-width:150px; padding:18px 16px; position:relative;
                border-right:1px solid var(--line); }
        .step:last-child { border-right:0; }
        .step .num { color:var(--sc,var(--pc)); font-size:.66rem; font-weight:800; letter-spacing:.16em; }
        .step b { display:block; margin:7px 0 5px; font-size:.92rem; }
        .step span { display:block; color:var(--muted); font-size:.72rem; line-height:1.5; }
        .step em { display:inline-block; margin-top:8px; font-style:normal; padding:3px 8px;
                   border-radius:6px; font-size:.66rem; color:#04121c; background:var(--sc,var(--pc)); font-weight:700; }
        .step::after { content:""; position:absolute; left:0; right:0; bottom:0; height:2px;
                       background:linear-gradient(90deg, transparent, var(--sc,var(--pc)), transparent);
                       opacity:0; }
        .flow.run .step::after { animation:sweep 4.4s linear infinite; }
        .flow.run .step:nth-child(2)::after { animation-delay:.55s }
        .flow.run .step:nth-child(3)::after { animation-delay:1.1s }
        .flow.run .step:nth-child(4)::after { animation-delay:1.65s }
        .flow.run .step:nth-child(5)::after { animation-delay:2.2s }
        @keyframes sweep { 0%,88%{opacity:0} 6%,20%{opacity:.9} 40%{opacity:0} }

        /* ── дом ────────────────────────────────────────────────────── */
        .home { display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); }
        .card { padding:18px; border:1px solid var(--line); border-radius:16px;
                background:linear-gradient(160deg, rgba(17,27,44,.8), rgba(9,14,24,.86)); }
        .card h3 { margin:0 0 10px; font-size:.95rem; letter-spacing:.02em; }
        .card p { margin:0; color:var(--muted); font-size:.8rem; line-height:1.65; }
        .card ul { margin:10px 0 0; padding-left:18px; color:var(--muted); font-size:.8rem; line-height:1.75; }
        .card li::marker { color:var(--pc); }

        .plans { display:grid; gap:10px; }
        .plan { display:flex; align-items:flex-start; gap:12px; padding:13px 15px;
                border:1px solid var(--line); border-radius:12px; background:rgba(255,255,255,.02); }
        .plan .tick { flex:none; width:22px; height:22px; display:grid; place-items:center;
                      border-radius:6px; font-size:.62rem; font-weight:800; color:#04121c; background:var(--warm); }
        .plan b { display:block; font-size:.84rem; margin-bottom:3px; }
        .plan span { color:var(--muted); font-size:.74rem; line-height:1.55; }

        footer { margin-top:44px; padding-top:20px; border-top:1px solid var(--line);
                 color:#66707f; font-size:.74rem; }

        /* появление при прокрутке */
        .rise { opacity:0; transform:translateY(18px); transition:opacity .6s ease, transform .6s cubic-bezier(.22,1,.36,1); }
        .rise.in { opacity:1; transform:none; }
        @media (prefers-reduced-motion: reduce) {
          * { animation:none !important; transition:none !important; }
          .rise { opacity:1; transform:none; }
        }
      </style>
    </head>
    <body>
      <main class="page">
        <div class="top">
          <a class="back" href="/" title="На главную" aria-label="На главную"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
          <a class="eyebrow" href="/">vitazgio.ru · хозяйство</a>
          <img class="mark" src="/static/icons/vg-plain.svg" alt="Vitaz Gio" width="512" height="512">
        </div>
        <h1>ХОЗЯЙСТВО</h1>
        <p class="lead">Три машины, связанные в одну систему: арендованный сервер в Амстердаме
          держит домены и сертификаты, домашний Proxmox тянет виртуалки и видеокарту под
          нейросети, а маленькая Orange Pi круглосуточно рулит умной квартирой. Между собой
          они общаются по своей mesh-сети, наружу — только через один шлюз.</p>

        <div class="tally rise">
          <div class="tile" style="--tc:#2de2ff"><b data-count="3">0</b><span>машины</span></div>
          <div class="tile" style="--tc:#63f5ad"><b data-count="2">0</b><span>виртуалки</span></div>
          <div class="tile" style="--tc:#b57cff"><b data-count="10" data-suffix=" ГБ">0</b><span>видеопамять</span></div>
          <div class="tile" style="--tc:#ffd84a"><b data-count="20" data-prefix="~">0</b><span>сервисов</span></div>
          <div class="tile" style="--tc:#ff7a59"><b data-count="16" data-suffix=" шт">0</b><span>умных устройств</span></div>
        </div>

        <h2 class="sec">Как это связано</h2>
        <div class="mapbox rise">
          <svg viewBox="0 0 980 420" role="img"
               aria-label="Схема: два пути в интернет — прямой из квартиры и через свой сервер">
            <defs>
              <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0 0 L10 5 L0 10 z" fill="rgba(255,255,255,.28)"/>
              </marker>
            </defs>

            <!-- ── провода ────────────────────────────────────────────
                 Верхняя ветка: сервисы уходят наружу только через свой
                 сервер. Нижняя: обычный домашний трафик идёт напрямую. -->
            <path id="p1" class="wire lit" d="M470 118 H590"/>                       <!-- туннели → VPS -->
            <path id="p2" class="wire lit" d="M822 118 C868 118, 880 150, 880 196"/> <!-- VPS → интернет -->
            <path id="p3" class="wire warm" d="M300 300 H880 M880 300 V244"/>        <!-- роутер → интернет напрямую -->
            <path id="p4" class="wire lit" d="M194 148 C194 118, 218 118, 250 118"/> <!-- Proxmox → туннели -->
            <path id="p5" class="wire lit" d="M194 232 C194 118, 218 118, 250 118"/> <!-- Orange Pi → туннели -->
            <path id="p6" class="wire dim" d="M194 190 H236 M236 190 V290"/> <!-- машины ↔ роутер -->
            <path id="p7" class="wire warm" d="M330 346 C314 346, 300 340, 300 330"/>        <!-- устройства → роутер -->

            <!-- бегущие пакеты: на каждом проводе свои -->
            <circle r="3.4" class="pkt"><animateMotion dur="1.9s" repeatCount="indefinite"><mpath href="#p1"/></animateMotion></circle>
            <circle r="3.4" class="pkt"><animateMotion dur="1.9s" begin=".95s" repeatCount="indefinite"><mpath href="#p1"/></animateMotion></circle>
            <circle r="3.4" class="pkt"><animateMotion dur="2.1s" repeatCount="indefinite"><mpath href="#p2"/></animateMotion></circle>
            <circle r="3.4" class="pkt w"><animateMotion dur="2.6s" repeatCount="indefinite"><mpath href="#p3"/></animateMotion></circle>
            <circle r="3.4" class="pkt w"><animateMotion dur="2.6s" begin="1.3s" repeatCount="indefinite"><mpath href="#p3"/></animateMotion></circle>
            <circle r="3" class="pkt g"><animateMotion dur="2.3s" repeatCount="indefinite"><mpath href="#p4"/></animateMotion></circle>
            <circle r="3" class="pkt g"><animateMotion dur="2.8s" begin=".7s" repeatCount="indefinite"><mpath href="#p5"/></animateMotion></circle>
            <circle r="2.6" class="pkt d"><animateMotion dur="3.4s" repeatCount="indefinite"><mpath href="#p6"/></animateMotion></circle>
            <circle r="3" class="pkt w"><animateMotion dur="2.2s" repeatCount="indefinite"><mpath href="#p7"/></animateMotion></circle>

            <!-- ── верхняя ветка: сервисы ─────────────────────────── -->
            <text class="lane" x="250" y="74">через свой сервер · снаружи видно только его</text>

            <g>
              <rect class="n-box ok" x="26" y="88" width="168" height="60" rx="14"/>
              <circle cx="47" cy="112" r="4" fill="#63f5ad" class="pulse"/>
              <text class="n-t" x="63" y="116">Proxmox</text>
              <text class="n-s" x="39" y="134">виртуалки и видеокарта</text>
            </g>

            <g>
              <rect class="n-box" x="26" y="202" width="168" height="60" rx="14"/>
              <circle cx="47" cy="226" r="4" fill="#ffd84a" class="pulse"/>
              <text class="n-t" x="63" y="230">Orange Pi</text>
              <text class="n-s" x="39" y="248">умный дом · MQTT</text>
            </g>

            <g>
              <rect class="n-box vio" x="250" y="88" width="220" height="60" rx="14"/>
              <circle cx="271" cy="112" r="4" fill="#b57cff" class="pulse"/>
              <text class="n-t" x="287" y="116">NetBird · SSH-туннели</text>
              <text class="n-s" x="265" y="134">закрытый канал между машинами</text>
            </g>

            <g>
              <rect class="n-box pc" x="590" y="88" width="232" height="60" rx="14"/>
              <circle cx="611" cy="112" r="4" fill="#2de2ff" class="pulse"/>
              <text class="n-t" x="627" y="116">Сервер · Амстердам</text>
              <text class="n-s" x="605" y="134">домены, сертификаты, выход в сеть</text>
            </g>

            <!-- ── интернет ───────────────────────────────────────── -->
            <g>
              <rect class="n-box big" x="806" y="196" width="148" height="48" rx="14"/>
              <text class="n-t" x="880" y="226" text-anchor="middle">Интернет</text>
            </g>

            <!-- ── нижняя ветка: квартира ─────────────────────────── -->
            <text class="lane warmtx" x="300" y="278">обычный домашний трафик · напрямую, без сервера</text>

            <g>
              <rect class="n-box" x="156" y="290" width="144" height="56" rx="14"/>
              <text class="n-t" x="228" y="314" text-anchor="middle">Роутер</text>
              <text class="n-s" x="228" y="332" text-anchor="middle">квартира</text>
            </g>

            <g>
              <rect class="n-box" x="330" y="318" width="330" height="56" rx="14"/>
              <text class="n-t" x="348" y="342">Умный дом и техника</text>
              <text class="n-s" x="348" y="360">наружу ходят сами, мимо сервера</text>
            </g>

            <text class="note-tx" x="26" y="398">Пунктиром — та же домашняя сеть: машины стоят дома,
              но наружу выходят только своим каналом.</text>
          </svg>
        </div>

        <h2 class="sec">Машины</h2>
        <section class="rigs">

          <article class="rig rise" style="--ac:#63f5ad">
            <div class="rig-head">
              <span class="rig-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg></span>
              <span class="rig-name"><b>Proxmox</b><span>главный сервер · дома</span></span>
              <span class="dot" title="в строю"></span>
            </div>
            <div class="specs">
              <div class="spec"><span class="k">Процессор</span><span class="v">Intel i5-10505 · 6 ядер</span></div>
              <div class="spec"><span class="k">Память</span><span class="meter"><i data-fill="50"></i></span><span class="v" style="flex:none">16 ГБ</span></div>
              <div class="spec"><span class="k">Видео</span><span class="meter"><i data-fill="100"></i></span><span class="v" style="flex:none">10 ГБ</span></div>
              <div class="spec"><span class="k">Роль</span><span class="v">виртуалки, диски и проброс видеокарты</span></div>
            </div>
            <div class="vm">
              <b>Ubuntu VM</b>
              <span>Docker: Nextcloud, Jellyfin, Syncthing. Сюда проброшена видеокарта —
                на ней живёт весь голосовой ИИ.</span>
            </div>
            <div class="vm">
              <b>Windows 10 VM</b>
              <span>Будится по сети (Wake-on-LAN) и управляется по SSH прямо из умного дома.</span>
            </div>
            <div class="svc">
              <i class="hi">CMP 50HX 10 ГБ</i><i>Nextcloud</i><i>Jellyfin</i><i>Syncthing</i><i>Docker</i><i>Gitea (в планах)</i>
            </div>
          </article>

          <article class="rig rise" style="--ac:#2de2ff">
            <div class="rig-head">
              <span class="rig-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.7 2.6 15.3 0 18M12 3c-2.6 2.7-2.6 15.3 0 18"/></svg></span>
              <span class="rig-name"><b>VPS</b><span>шлюз наружу · Амстердам</span></span>
              <span class="dot" title="в строю"></span>
            </div>
            <div class="specs">
              <div class="spec"><span class="k">Роль</span><span class="v">единственная дверь из интернета внутрь</span></div>
              <div class="spec"><span class="k">Домены</span><span class="meter"><i data-fill="80"></i></span><span class="v" style="flex:none">10</span></div>
              <div class="spec"><span class="k">Сертификаты</span><span class="v">Let's Encrypt, обновляются сами</span></div>
              <div class="spec"><span class="k">Потоки</span><span class="v">Syncthing проброшен напрямую, TCP и UDP</span></div>
            </div>
            <div class="vm">
              <b>Nginx Proxy Manager</b>
              <span>Раздаёт запросы по поддоменам на нужную машину внутри mesh-сети.
                Панель управления наружу не смотрит — только через свою сеть.</span>
            </div>
            <div class="svc">
              <i class="hi">Nginx Proxy Manager</i><i>Let's Encrypt</i><i>NetBird</i><i>Syncthing relay</i>
            </div>
          </article>

          <article class="rig rise" style="--ac:#ffd84a">
            <div class="rig-head">
              <span class="rig-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg></span>
              <span class="rig-name"><b>Orange Pi Zero 3</b><span>мозг квартиры · дома</span></span>
              <span class="dot" title="в строю"></span>
            </div>
            <div class="specs">
              <div class="spec"><span class="k">Система</span><span class="v">Armbian, поверх — CasaOS как оболочка Docker</span></div>
              <div class="spec"><span class="k">Работает</span><span class="meter"><i data-fill="100"></i></span><span class="v" style="flex:none">24/7</span></div>
              <div class="spec"><span class="k">Питание</span><span class="v">пара ватт — потому и не выключается</span></div>
              <div class="spec"><span class="k">Роль</span><span class="v">умный дом, Zigbee, MQTT, мониторинг</span></div>
            </div>
            <div class="vm">
              <b>Почему отдельная машина</b>
              <span>Свет и розетки должны слушаться даже когда большой сервер выключен
                или на нём идут работы. Маленькая плата на это и поставлена.</span>
            </div>
            <div class="svc">
              <i class="hi">Home Assistant</i><i>Zigbee2MQTT</i><i>Mosquitto</i><i>Uptime Kuma</i><i>Glances</i><i>веб-терминал</i>
            </div>
          </article>

        </section>

        <h2 class="sec">Себастьян · голосовой дворецкий</h2>
        <p class="lead" style="margin-top:0">Свой голосовой помощник целиком на домашнем железе:
          ничего не уходит наружу, всё крутится на одной видеокарте. От вопроса до ответа
          голосом — от 3.7 секунды.</p>
        <div class="flow rise">
          <div class="step" style="--sc:#2de2ff"><span class="num">01</span><b>Слышит</b>
            <span>Микрофон отдаёт запись распознавалке речи.</span><em>Whisper</em></div>
          <div class="step" style="--sc:#63f5ad"><span class="num">02</span><b>Разбирает</b>
            <span>Расшифровка уходит в языковую модель на видеокарте.</span><em>1–1.5 с</em></div>
          <div class="step" style="--sc:#b57cff"><span class="num">03</span><b>Думает</b>
            <span>Модель отвечает и сама решает, дёрнуть ли инструмент: погода, время, свет.</span><em>Ollama · qwen3</em></div>
          <div class="step" style="--sc:#ffd84a"><span class="num">04</span><b>Делает</b>
            <span>Команды уходят в умный дом через отдельный сервис с белым списком устройств.</span><em>16 устройств</em></div>
          <div class="step" style="--sc:#ff7a59"><span class="num">05</span><b>Отвечает</b>
            <span>Синтез речи своим голосом — слепок голоса считается один раз при старте.</span><em>XTTS v2</em></div>
        </div>

        <h2 class="sec">Умная квартира</h2>
        <div class="home">
          <div class="card rise">
            <h3>Zigbee вместо Wi-Fi</h3>
            <p>Лампы, розетки и удлинители держатся на своей сети Zigbee: она не забивает
              Wi-Fi и живёт, даже когда роутер перезагружается. Каждое устройство с питанием
              от розетки заодно работает ретранслятором — сеть тем крепче, чем её больше.</p>
          </div>
          <div class="card rise">
            <h3>Своё железо</h3>
            <p>Часть устройств собрана руками на ESP32 — их прошивки лежат в
              <a href="/diy" style="color:var(--pc)">стране DIY</a>:</p>
            <ul>
              <li>лента-«корона» на 5 метров с пультом на кнопках</li>
              <li>автомагнитола как домашний усилитель, через ИК-светодиод</li>
              <li>панель мониторинга сервера с экраном и кнопками</li>
              <li>реле под столом с термометром и управлением вентилятором</li>
            </ul>
          </div>
          <div class="card rise">
            <h3>Правило простое</h3>
            <p>Всё, что можно сделать локально, делается локально. Облака подключены
              только там, где без них никак. Свет продолжает включаться, даже если
              интернет отвалился совсем.</p>
          </div>
        </div>

        <h2 class="sec">Что дальше</h2>
        <div class="plans rise">
          <div class="plan"><span class="tick">1</span><span><b>Резервные копии по-взрослому</b>
            <span>Отдельный диск под Proxmox Backup Server для виртуалок и restic для мелких машин.</span></span></div>
          <div class="plan"><span class="tick">2</span><span><b>Свой Gitea на домене</b>
            <span>Зеркало репозиториев с GitHub и сборка прямо дома, без чужих раннеров.</span></span></div>
          <div class="plan"><span class="tick">3</span><span><b>Память до 32 ГБ</b>
            <span>Вторая планка — виртуалкам и нейросети станет заметно свободнее.</span></span></div>
          <div class="plan"><span class="tick">4</span><span><b>Магнитола на Zigbee</b>
            <span>Переезд с Wi-Fi на ESP32-C6: меньше проводов в логике, одна сеть на всё.</span></span></div>
        </div>

        <footer>Адресов на странице нет намеренно — ни публичных, ни домашних. Наружу смотрит
          один сервер, всё остальное живёт в закрытой сети и снаружи не видно.</footer>
      </main>

      <script>
      (() => {
        "use strict";
        const slow = matchMedia("(prefers-reduced-motion: reduce)").matches;

        /* подписи в схеме — по своим рамкам
           Схема нарисована в жёстких координатах, а шрифт у всех разный:
           где-то буквы шире, и строка вылезала за коробку. Поэтому меряем
           каждую подпись и, если не влезла, ужимаем ровно по месту. */
        const fitFlow = () => {
          document.querySelectorAll(".mapbox svg g").forEach((g) => {
            const box = g.querySelector("rect");
            if (!box) return;
            const edge = +box.getAttribute("x") + +box.getAttribute("width");
            g.querySelectorAll("text").forEach((t) => {
              t.removeAttribute("textLength");
              if (t.getAttribute("text-anchor") === "middle") return;
              const room = edge - +t.getAttribute("x") - 12;
              let wide = 0;
              try { wide = t.getComputedTextLength(); } catch (e) { return; }
              if (room > 20 && wide > room) {
                t.setAttribute("textLength", room);
                t.setAttribute("lengthAdjust", "spacingAndGlyphs");
              }
            });
          });
        };
        fitFlow();
        if (document.fonts && document.fonts.ready) document.fonts.ready.then(fitFlow);
        addEventListener("resize", fitFlow);

        /* появление блоков при прокрутке */
        const rise = document.querySelectorAll(".rise");
        if (slow || !("IntersectionObserver" in window)) {
          rise.forEach((el) => el.classList.add("in"));
          document.querySelectorAll("[data-fill]").forEach((el) => { el.style.width = el.dataset.fill + "%"; });
          document.querySelectorAll("[data-count]").forEach((el) => {
            el.textContent = (el.dataset.prefix || "") + el.dataset.count + (el.dataset.suffix || ""); });
          document.querySelector(".flow").classList.add("run");
          return;
        }

        const io = new IntersectionObserver((items) => {
          items.forEach((it) => {
            if (!it.isIntersecting) return;
            it.target.classList.add("in");
            io.unobserve(it.target);
            // полоски наливаются, цифры набегают — только когда блок виден
            it.target.querySelectorAll("[data-fill]").forEach((b, i) =>
              setTimeout(() => { b.style.width = b.dataset.fill + "%"; }, 120 + i * 90));
            it.target.querySelectorAll("[data-count]").forEach((n) => countUp(n));
            if (it.target.classList.contains("flow")) it.target.classList.add("run");
          });
        }, { threshold: .18 });
        rise.forEach((el) => io.observe(el));

        const countUp = (el) => {
          const to = +el.dataset.count || 0;
          const pre = el.dataset.prefix || "", suf = el.dataset.suffix || "";
          const t0 = performance.now(), ms = 900;
          const tick = (t) => {
            const k = Math.min(1, (t - t0) / ms);
            const eased = 1 - Math.pow(1 - k, 3);
            el.textContent = pre + Math.round(to * eased) + suf;
            if (k < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        };
      })();
      </script>
      <script src="/vg-player.js" defer></script>
    </body>
    </html>
    """
    return html.replace("__ICONLINKS__", ICON_LINKS)


@app.get("/music")
@login_required
def music_page():
    """Фонотека. Вся под паролем кабинета — и слушать, и менять.

    Саму страницу теперь тоже держим под паролем (login_required): без входа
    открыть нельзя, как кабинет. С незнакомого устройства — редирект на
    главную, где карточка «Музыка» показывает окно авторизации.


    Открытой её делать не стали: выкладывать в общий доступ скачанную музыку
    — это раздача чужого, и претензии прилетают именно за раздачу.

    Сама страница отдаётся кому угодно, но без пароля она пуста: список и
    файлы сервер не выдаёт. Кнопки правки появляются, только когда сервер в
    ответе на список сказал can_edit — запрет живёт на сервере, здесь лишь
    чтобы не мозолить глаза."""
    html = """<!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Фонотека vitazgio.ru">
      __ICONLINKS__
      <link rel="manifest" href="/manifest.webmanifest">
      <title>vitazgio.ru — музыка</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #0d1321;
          --surface: rgba(25, 32, 48, 0.82);
          --line: rgba(255, 255, 255, 0.1);
          --text: #f7f8fc;
          --muted: #989fb2;
          --pc: #2de2ff;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0; min-width: 320px;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at 12% 8%, rgba(57, 126, 255, .22), transparent 32rem),
            radial-gradient(circle at 88% 78%, rgba(149, 65, 255, .18), transparent 34rem),
            var(--bg);
          color: var(--text);
          /* Запас под стопку внизу, пока скрипт не померил её точно:
             она висит поверх и иначе накрыла бы последний трек в списке. */
          padding-bottom: 140px;
        }
        .mpage { width: min(1380px, calc(100% - 40px)); margin: 0 auto;
                 padding: clamp(20px, 4vw, 44px) 0 24px; }

        .mtop { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
        .mtop-left { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
        .popout { display: inline-flex; align-items: center; gap: 8px; height: 36px; padding: 0 14px;
                  color: #04121c; cursor: pointer; font: 700 .74rem "Cascadia Code", Consolas, monospace;
                  letter-spacing: .04em; border: 0; border-radius: 999px;
                  background: linear-gradient(90deg, #2de2ff, #65f2bd); }
        .popout:hover { filter: brightness(1.08); }
        .popout svg { width: 15px; height: 15px; }
        .back { display: inline-flex; align-items: center; justify-content: center;
                width: 42px; height: 42px; flex: none; color: #7ce0ff; text-decoration: none;
                border: 1px solid rgba(45,226,255,.3); border-radius: 50%;
                background: rgba(45,226,255,.07); transition: .18s; }
        .back svg { width: 20px; height: 20px; }
        .back:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.18); }
        .eyebrow { display: inline-flex; align-items: center; gap: 10px; color: #cdd2df;
                   font-size: .76rem; font-weight: 700; letter-spacing: .16em;
                   text-transform: uppercase; text-decoration: none; }
        .eyebrow::before { content: ""; width: 7px; height: 7px; border-radius: 50%;
                           background: #64e6a5; box-shadow: 0 0 16px #64e6a5; }
        .eyebrow:hover { color: #fff; }
        /* Только буквы, без свечения и подложки. */
        .hero-mark { flex: none; width: clamp(1.6rem, 4vw, 2.6rem);
                     height: clamp(1.6rem, 4vw, 2.6rem); }

        /* Строка пути и кнопок. Текста тут по минимуму: где я нахожусь и что
           могу сделать — остальное показывают сами значки. */
        .mbar { display: flex; align-items: center; justify-content: space-between;
                gap: 12px; flex-wrap: wrap; margin: clamp(18px, 3vw, 30px) 0 16px; }
        .crumbs { display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
                  min-width: 0; font-size: .92rem; }
        .crumb { padding: 4px 2px; color: var(--muted); background: none; border: 0;
                 font: inherit; cursor: pointer; }
        .crumb:hover { color: var(--pc); }
        .crumb.last { color: var(--text); font-weight: 700; cursor: default; }
        .crumb-sep { color: #4a5568; }

        .mtools { display: flex; align-items: center; gap: 8px; }
        .tbtn { display: inline-flex; align-items: center; gap: 7px; height: 38px;
                padding: 0 14px; color: #cdd6e6; font: 600 .84rem inherit;
                white-space: nowrap; cursor: pointer;
                background: rgba(255,255,255,.05); border: 1px solid var(--line);
                border-radius: 10px; transition: .18s; }
        .tbtn:hover { color: #fff; border-color: var(--pc); background: rgba(45,226,255,.1); }
        .tbtn svg { width: 16px; height: 16px; flex: none; }
        .tbtn--key { color: #8ee9ff; }
        .tbtn--on { color: #04121a; background: var(--pc); border-color: var(--pc); }

        /* Папки — плитки. Крупная цель для пальца, подпись одна. */
        .mgrid { display: grid; gap: 10px; margin-bottom: 18px;
                 grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); }
        .folder { position: relative; display: flex; align-items: center; gap: 10px;
                  padding: 14px; text-align: left; color: var(--text); cursor: pointer;
                  background: var(--surface); border: 1px solid var(--line);
                  border-radius: 14px; font: 600 .92rem inherit; transition: .18s; }
        .folder:hover { border-color: var(--pc); transform: translateY(-2px); }
        .folder svg { width: 22px; height: 22px; color: var(--pc); flex: none; }
        .folder-name { min-width: 0; overflow: hidden; text-overflow: ellipsis;
                       white-space: nowrap; }
        .folder-num { margin-left: auto; color: var(--muted); font-weight: 500;
                      font-size: .8rem; }
        .folder.picked { border-color: var(--pc); background: rgba(45,226,255,.12); }

        .mlist { display: flex; flex-direction: column;
                 border: 1px solid var(--line); border-radius: 14px; overflow: hidden;
                 background: rgba(15, 20, 32, .6); }
        .row { display: grid; grid-template-columns: 34px 1fr auto;
               align-items: center; gap: 12px; padding: 11px 14px; cursor: pointer;
               border-bottom: 1px solid rgba(255,255,255,.05); transition: background .15s; }
        .row:last-child { border-bottom: 0; }
        .row:hover { background: rgba(255,255,255,.04); }
        .row.picked { background: rgba(45,226,255,.13); }
        .row.playing .row-title { color: var(--pc); }
        .row-num { color: #55607a; font-size: .78rem; text-align: right;
                   font-variant-numeric: tabular-nums; }
        .row.playing .row-num { color: var(--pc); }
        .row-main { min-width: 0; }
        .row-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                     font-weight: 600; font-size: .95rem; }
        .row-artist { overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                      color: var(--muted); font-size: .78rem; }
        .row-size { color: #55607a; font-size: .76rem; font-variant-numeric: tabular-nums; }

        .empty { padding: 42px 16px; color: var(--muted); text-align: center; font-size: .92rem; }

        /* Низ страницы — стопка: заливка, полоса выделения, плеер. Стоят друг
           над другом, а не перекрывают: музыка играет и во время разбора
           треков, и прятать у неё кнопки незачем. Высоту стопки страница
           меряет сама и отводит под неё отступ снизу. */
        .stack { position: fixed; z-index: 40; inset: auto 0 0 0; }

        .dock { padding: 12px max(20px, calc((100vw - 1380px) / 2)) 14px;
                background: rgba(10, 14, 24, .92); backdrop-filter: blur(14px);
                border-top: 1px solid var(--line); }
        .dock-grid { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
                     align-items: center; gap: 14px; }
        .now { min-width: 0; }
        .now-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                     font-weight: 700; font-size: .95rem; }
        .now-artist { overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                      color: var(--muted); font-size: .78rem; }
        .keys { display: flex; align-items: center; gap: 10px; }
        .kbtn { display: grid; place-items: center; width: 40px; height: 40px;
                color: #cdd6e6; background: rgba(255,255,255,.05);
                border: 1px solid var(--line); border-radius: 50%; cursor: pointer;
                transition: .18s; }
        .kbtn:hover { color: #fff; border-color: var(--pc); }
        .kbtn svg { width: 17px; height: 17px; }
        .kbtn--play { width: 52px; height: 52px; color: #04121a;
                      background: var(--pc); border-color: var(--pc); }
        .kbtn--play svg { width: 21px; height: 21px; }
        .kbtn--play:hover { color: #04121a; filter: brightness(1.12); }
        .kbtn.on { color: var(--pc); border-color: var(--pc); }
        .side { display: flex; align-items: center; justify-content: flex-end; gap: 10px; }

        .seek { display: flex; align-items: center; gap: 10px; margin-top: 10px;
                color: #6f7a92; font-size: .74rem; font-variant-numeric: tabular-nums; }
        .bar { position: relative; flex: 1; height: 16px; cursor: pointer; }
        .bar::before { content: ""; position: absolute; inset: 7px 0 auto;
                       height: 4px; border-radius: 2px; background: rgba(255,255,255,.12); }
        .bar i { position: absolute; top: 7px; left: 0; height: 4px; width: 0;
                 border-radius: 2px; background: var(--pc); }
        .bar b { position: absolute; top: 3px; left: 0; width: 12px; height: 12px;
                 margin-left: -6px; border-radius: 50%; background: #fff; opacity: 0;
                 transition: opacity .15s; }
        .bar:hover b, .bar.grab b { opacity: 1; }
        .vol { width: 96px; }

        /* Полоса выделения — как в личном дропе, чтобы рука помнила одно. */
        .selbar { display: flex; align-items: center; gap: 10px;
                  padding: 12px max(20px, calc((100vw - 1380px) / 2));
                  background: rgba(12, 18, 30, .96); border-top: 1px solid var(--pc); }
        .selbar .count { margin-right: auto; color: #8ee9ff; font-weight: 700;
                         font-size: .88rem; white-space: nowrap; }
        .selbar .tbtn { flex: 0 1 auto; min-width: 0; overflow: hidden; }
        .selbar .tbtn span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .shut { display: grid; place-items: center; width: 38px; height: 38px; flex: none;
                color: #cdd6e6; background: rgba(255,255,255,.05);
                border: 1px solid var(--line); border-radius: 10px; cursor: pointer;
                font-size: 1.1rem; line-height: 1; }
        .shut:hover { color: #fff; border-color: #ff5a6e; background: rgba(255,90,110,.14); }

        /* Полоса заливки: показываем только когда есть что показывать. */
        .queue { padding: 12px max(20px, calc((100vw - 1380px) / 2)) 14px;
                 background: rgba(12, 18, 30, .96); border-top: 1px solid var(--pc); }
        .queue-line { display: flex; align-items: center; gap: 12px;
                      font-size: .84rem; color: #cdd6e6; }
        .queue-name { min-width: 0; overflow: hidden; text-overflow: ellipsis;
                      white-space: nowrap; color: var(--muted); }
        .queue-num { margin-left: auto; color: #8ee9ff; font-weight: 700;
                     font-variant-numeric: tabular-nums; white-space: nowrap; }
        .queue-bar { height: 4px; margin-top: 9px; border-radius: 2px;
                     background: rgba(255,255,255,.12); overflow: hidden; }
        .queue-bar i { display: block; height: 100%; width: 0; background: var(--pc);
                       transition: width .15s; }

        .modal { position: fixed; z-index: 60; inset: 0; display: grid; place-items: center;
                 padding: 20px; background: rgba(6, 9, 16, .74); }
        .sheet { width: min(420px, 100%); padding: 24px;
                 background: linear-gradient(160deg, rgba(24,32,48,.98), rgba(12,16,26,.98));
                 border: 1px solid var(--line); border-radius: 16px; }
        .sheet h2 { margin: 0 0 6px; font-size: 1.2rem; }
        .sheet p { margin: 0 0 16px; color: var(--muted); font-size: .86rem; }
        .sheet input { width: 100%; height: 42px; padding: 0 12px; color: var(--text);
                       background: rgba(0,0,0,.35); border: 1px solid var(--line);
                       border-radius: 10px; font: inherit; }
        .sheet input:focus { outline: none; border-color: var(--pc); }
        .sheet-keys { display: flex; gap: 10px; margin-top: 16px; }
        .sheet-keys .tbtn { flex: 1; justify-content: center; }
        .sheet .err { margin: 10px 0 0; color: #ff7b8c; font-size: .82rem; min-height: 1em; }

        [hidden] { display: none !important; }

        @media (max-width: 760px) {
          .dock-grid { grid-template-columns: 1fr; gap: 10px; }
          .keys { justify-content: center; }
          .side { justify-content: center; }
          .vol { width: 130px; }
          .mgrid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
          .selbar { flex-wrap: wrap; }
          .selbar .count { flex: 1 0 100%; margin: 0 0 4px; }
          .selbar .tbtn { flex: 1; justify-content: center; padding: 0 8px; }
        }
        @media (prefers-reduced-motion: reduce) {
          * { transition: none !important; animation: none !important; }
        }
      </style>
    </head>
    <body>
      <main class="mpage">
        <header class="mtop">
          <div class="mtop-left">
            <a class="back" href="/" title="На главную" aria-label="На главную"><svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5m0 0 6-6m-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
            <a class="eyebrow" href="/">vitazgio.ru · музыка</a>
            <button class="popout" type="button"
                    onclick="if(window.VGP)window.VGP.open()"
                    title="Плеер поверх сайта — не пропадёт при переходе на другую страницу">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M21 3l-9 9M10 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/></svg>
              <span>Плеер поверх сайта</span>
            </button>
          </div>
          <img class="hero-mark" src="/static/icons/vg-plain.svg" alt="Vitaz Gio"
               width="512" height="512">
        </header>

        <div class="mbar">
          <nav class="crumbs" id="crumbs" aria-label="Где я"></nav>
          <div class="mtools" id="tools"></div>
        </div>

        <section class="mgrid" id="folders"></section>
        <section class="mlist" id="tracks"></section>
      </main>

      <div class="stack" id="stack">
      <div class="queue" id="queue" hidden>
        <div class="queue-line">
          <span id="queue-name" class="queue-name">…</span>
          <span id="queue-num" class="queue-num"></span>
        </div>
        <div class="queue-bar"><i id="queue-fill"></i></div>
      </div>
      <div class="selbar" id="selbar" hidden></div>
      <div class="dock" id="dock">
        <div class="dock-grid">
          <div class="now">
            <div class="now-title" id="now-title">тишина</div>
            <div class="now-artist" id="now-artist">выберите трек</div>
          </div>
          <div class="keys">
            <button class="kbtn" id="k-prev" type="button" aria-label="Предыдущий"></button>
            <button class="kbtn kbtn--play" id="k-play" type="button" aria-label="Слушать"></button>
            <button class="kbtn" id="k-next" type="button" aria-label="Следующий"></button>
          </div>
          <div class="side">
            <button class="kbtn" id="k-shuffle" type="button" aria-label="Вперемешку"></button>
            <button class="kbtn" id="k-repeat" type="button" aria-label="Повтор"></button>
            <button class="kbtn" id="k-mute" type="button" aria-label="Звук"></button>
            <div class="bar vol" id="vol"><i></i><b></b></div>
          </div>
        </div>
        <div class="seek">
          <span id="t-at">0:00</span>
          <div class="bar" id="seek"><i></i><b></b></div>
          <span id="t-all">0:00</span>
        </div>
      </div>
      </div>

      <div class="modal" id="modal" hidden>
        <section class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title">
          <h2 id="sheet-title">Вход в фонотеку</h2>
          <p id="sheet-note">Введите пароль для прав админа.</p>
          <input id="sheet-input" type="password" autocomplete="current-password">
          <p class="err" id="sheet-err" role="alert"></p>
          <div class="sheet-keys">
            <button class="tbtn" id="sheet-no" type="button"><span>Отмена</span></button>
            <button class="tbtn tbtn--on" id="sheet-ok" type="button"><span>Готово</span></button>
          </div>
        </section>
      </div>

      <audio id="audio" preload="metadata"></audio>
      <input type="file" id="pick-files" accept="audio/*,.mp3,.m4a,.flac,.ogg,.opus,.wav,.aac" multiple hidden>
      <input type="file" id="pick-dir" webkitdirectory directory multiple hidden>

      <!-- Тот же движок, что и на всех страницах. Подключаем синхронно, чтобы
           window.VGP существовал к моменту запуска скрипта страницы. Виджет
           поднимаем над нижней панелью плеера, чтобы не налезал на неё. -->
      <script>window.VGP_OFFSET = 168;</script>
      <script src="/vg-player.js"></script>

      <script>
      (() => {
        "use strict";

        const SVG = {
          play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>',
          pause: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 5h4v14H6zM14 5h4v14h-4z"/></svg>',
          prev: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 5h2v14H7zm11 0v14l-9-7z"/></svg>',
          next: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M15 5h2v14h-2zM6 5l9 7-9 7z"/></svg>',
          shuffle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h4v4M20 4l-6 6M4 20l16-16M16 20h4v-4M4 4l5 5"/></svg>',
          repeat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11V9a4 4 0 0 1 4-4h9M17 2l3 3-3 3M20 13v2a4 4 0 0 1-4 4H7M7 22l-3-3 3-3"/></svg>',
          loud: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 9h4l5-4v14l-5-4H4z"/><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M17 8a5 5 0 0 1 0 8"/></svg>',
          mute: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 9h4l5-4v14l-5-4H4z"/><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="m17 9 5 6m0-6-5 6"/></svg>',
          folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
          plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
          up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>',
          key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="12" r="4"/><path d="M12 12h9m-3 0v4m-3-4v3"/></svg>',
          copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/></svg>',
          cut: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="6" cy="18" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8 16 18 4M16 16 6 4"/></svg>',
          paste: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"><path d="M9 4h6v3H9z"/><path d="M15 5h3v15H6V5h3"/></svg>',
          del: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg>',
          pen: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="m4 20 4-1 11-11-3-3L5 16z"/></svg>',
        };

        const $ = (id) => document.getElementById(id);
        // Звук у сайта один: берём <audio> общего движка, если он поднялся.
        // Тогда трек, начатый здесь, продолжает играть в дропе или блокноте
        // с той же секунды, а панель внизу показывает то же, что и виджет.
        const audio = (window.VGP && window.VGP.audio) || $("audio");

        let tracks = [];
        let folders = [];
        let canEdit = false;
        let locked = true;        // фонотека вся под паролем, и слушать тоже
        let here = "";            // в какой папке смотрим
        let quota = { used: 0, all: 0 };

        // ── что сейчас играет ───────────────────────────────────────────
        let queueIds = [];        // порядок воспроизведения
        let atIndex = -1;
        let shuffle = false;
        let repeat = false;

        // ── выделение и буфер ───────────────────────────────────────────
        let picking = false;
        const picked = new Set();
        let clip = null;          // { op: "copy" | "cut", ids: [...] }

        const byId = (id) => tracks.find((t) => t.id === id);
        const kids = (folder) => folders.filter((f) => f.parent === folder);
        const inside = (folder) => tracks.filter((t) => t.folder === folder);

        /* Сколько треков в папке вместе со вложенными: на плитке нужен
           общий счёт, иначе папка с одними подпапками выглядит пустой. */
        const deepCount = (folder) => {
          let sum = inside(folder).length;
          kids(folder).forEach((f) => { sum += deepCount(f.id); });
          return sum;
        };

        const clock = (sec) => {
          if (!isFinite(sec) || sec < 0) sec = 0;
          const m = Math.floor(sec / 60), s = Math.floor(sec % 60);
          return m + ":" + String(s).padStart(2, "0");
        };
        const weight = (bytes) => {
          if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " МБ";
          return Math.max(1, Math.round(bytes / 1024)) + " КБ";
        };

        // ── чтение с сервера ────────────────────────────────────────────
        const load = async () => {
          const res = await fetch("/api/music", { headers: { "Accept": "application/json" } });
          if (res.status === 403) {
            locked = true;
            tracks = [];
            folders = [];
            canEdit = false;
            draw();
            return;
          }
          const data = await res.json();
          locked = false;
          tracks = data.tracks || [];
          folders = data.folders || [];
          canEdit = !!data.can_edit;
          quota = { used: data.used || 0, all: data.quota || 0 };
          if (here && !folders.some((f) => f.id === here)) here = "";
          draw();
        };

        // ── отрисовка ───────────────────────────────────────────────────
        const drawCrumbs = () => {
          const chain = [];
          let cur = here;
          const guard = new Set();
          while (cur && !guard.has(cur)) {
            guard.add(cur);
            const f = folders.find((x) => x.id === cur);
            if (!f) break;
            chain.unshift(f);
            cur = f.parent;
          }
          const parts = ['<button class="crumb' + (chain.length ? '' : ' last') +
                         '" data-go="">Вся музыка</button>'];
          chain.forEach((f, i) => {
            parts.push('<span class="crumb-sep">/</span>');
            const last = i === chain.length - 1;
            parts.push('<button class="crumb' + (last ? ' last' : '') + '" data-go="' +
                       f.id + '">' + esc(f.name) + '</button>');
          });
          $("crumbs").innerHTML = parts.join("");
        };

        const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
          ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

        const tool = (id, icon, text, extra) =>
          '<button class="tbtn' + (extra || "") + '" data-act="' + id + '">' +
          icon + '<span>' + text + '</span></button>';

        const drawTools = () => {
          const parts = [];
          if (locked) {
            $("tools").innerHTML = tool("unlock", SVG.key, "Войти", " tbtn--key");
            return;
          }
          if (here) parts.push(tool("up", SVG.up, "Назад"));
          if (canEdit) {
            // «Папка» создаёт пустую, «Альбом» заливает готовую с диска —
            // одинаковые слова тут путали бы больше, чем помогали.
            parts.push(tool("newdir", SVG.plus, "Папка"));
            parts.push(tool("upload", SVG.up, "Треки"));
            parts.push(tool("uploaddir", SVG.folder, "Альбом"));
            if (here) parts.push(tool("rename", SVG.pen, "Имя"));
          }
          $("tools").innerHTML = parts.join("");
        };

        const drawFolders = () => {
          const list = kids(here);
          $("folders").innerHTML = list.map((f) =>
            '<button class="folder" data-dir="' + f.id + '">' + SVG.folder +
            '<span class="folder-name">' + esc(f.name) + '</span>' +
            '<span class="folder-num">' + deepCount(f.id) + '</span></button>').join("");
        };

        const drawTracks = () => {
          if (locked) {
            $("tracks").innerHTML =
              '<div class="empty">фонотека под паролем' +
              '<br><br><button class="tbtn tbtn--key" data-act="unlock" ' +
              'style="margin:0 auto">' + SVG.key + '<span>Войти</span></button></div>';
            return;
          }
          const list = inside(here);
          if (!list.length) {
            $("tracks").innerHTML = '<div class="empty">' +
              (kids(here).length ? "здесь только папки" : "пусто") + '</div>';
            return;
          }
          $("tracks").innerHTML = list.map((t, i) =>
            '<div class="row" data-id="' + t.id + '">' +
            '<div class="row-num">' + (i + 1) + '</div>' +
            '<div class="row-main"><div class="row-title">' + esc(t.title) + '</div>' +
            '<div class="row-artist">' + esc(t.artist || "неизвестен") + '</div></div>' +
            '<div class="row-size">' + weight(t.size) + '</div></div>').join("");
          paint();
        };

        const paint = () => {
          const nowId = queueIds[atIndex];
          document.querySelectorAll(".row").forEach((row) => {
            const id = row.dataset.id;
            row.classList.toggle("picked", picked.has(id));
            row.classList.toggle("playing", id === nowId);
          });
          drawSelbar();
        };

        const draw = () => {
          drawCrumbs();
          drawTools();
          drawFolders();
          drawTracks();
        };

        /* Полоса внизу живёт в двух видах. Пока треки выбраны — что с ними
           сделать. Как только сложили в буфер, выбор снимается и остаётся
           одна кнопка: вставить сюда. Так буфер переживает переход по папкам
           и видно, что он не пуст. */
        const drawSelbar = () => {
          const bar = $("selbar");
          const marked = picking && picked.size;
          if (!marked && !clip) { bar.hidden = true; measure(); return; }
          bar.hidden = false;
          if (marked) {
            bar.innerHTML = '<span class="count">' + picked.size + '</span>' +
              tool("copy", SVG.copy, "Копия") +
              tool("cut", SVG.cut, "Вырезать") +
              tool("kill", SVG.del, "Удалить") +
              '<button class="shut" data-act="off" aria-label="Снять выбор">&times;</button>';
          } else {
            bar.innerHTML = '<span class="count">в буфере ' + clip.ids.length + '</span>' +
              tool("paste", SVG.paste, "Вставить сюда", " tbtn--on") +
              '<button class="shut" data-act="off" aria-label="Очистить буфер">&times;</button>';
          }
          measure();
        };

        const stopPicking = () => {
          if (picking && picked.size) { picking = false; picked.clear(); }
          else { clip = null; }
          paint();
        };

        /* Стопка внизу растёт и сжимается, поэтому отступ под неё считаем
           по факту, а не подбираем на глаз в стилях. */
        const measure = () => {
          document.body.style.paddingBottom = ($("stack").offsetHeight + 18) + "px";
        };
        addEventListener("resize", measure);

        // ── плеер ───────────────────────────────────────────────────────
        const buildQueue = (startId) => {
          const list = inside(here).map((t) => t.id);
          if (!list.length) return;
          if (shuffle) {
            for (let i = list.length - 1; i > 0; i--) {
              const j = Math.floor(Math.random() * (i + 1));
              [list[i], list[j]] = [list[j], list[i]];
            }
            const at = list.indexOf(startId);
            if (at > 0) { list.splice(at, 1); list.unshift(startId); }
          }
          queueIds = list;
          atIndex = Math.max(0, list.indexOf(startId));
        };

        const play = (id) => {
          if (!queueIds.includes(id)) buildQueue(id);
          else atIndex = queueIds.indexOf(id);
          const t = byId(id);
          if (!t) return;
          audio.src = "/api/music/file/" + id;
          audio.play().catch(() => {});
          $("now-title").textContent = t.title;
          $("now-artist").textContent = t.artist || "неизвестен";
          document.title = t.title + " — vitazgio.ru";
          // Отдаём очередь общему движку: с ней виджет на других страницах
          // знает, что играет, и умеет листать дальше.
          if (window.VGP) {
            const folderName = {};
            folders.forEach((f) => { folderName[f.id] = f.name; });
            window.VGP.adopt(queueIds.map((qid) => {
              const q = byId(qid) || {};
              return { id: "m_" + qid, title: q.title || "", artist: q.artist || "",
                       folder: folderName[q.folder] || "", url: "/api/music/file/" + qid };
            }), atIndex);
          }
          paint();
        };

        const step = (dir) => {
          if (!queueIds.length) return;
          let next = atIndex + dir;
          if (next < 0) next = queueIds.length - 1;
          if (next >= queueIds.length) {
            if (!repeat && dir > 0) { audio.pause(); return; }
            next = 0;
          }
          play(queueIds[next]);
        };

        const setPlayIcon = () => {
          $("k-play").innerHTML = audio.paused ? SVG.play : SVG.pause;
          $("k-play").setAttribute("aria-label", audio.paused ? "Слушать" : "Пауза");
        };

        // ── ползунки: одна механика на перемотку и громкость ────────────
        const slider = (el, read, write) => {
          const at = (e) => {
            const box = el.getBoundingClientRect();
            const k = Math.min(1, Math.max(0, (e.clientX - box.left) / box.width));
            write(k);
          };
          el.addEventListener("pointerdown", (e) => {
            el.classList.add("grab");
            try { el.setPointerCapture(e.pointerId); } catch (err) { /* обойдёмся */ }
            at(e);
          });
          el.addEventListener("pointermove", (e) => { if (el.classList.contains("grab")) at(e); });
          const stop = (e) => {
            if (!el.classList.contains("grab")) return;
            el.classList.remove("grab");
            try { el.releasePointerCapture(e.pointerId); } catch (err) { /* уже */ }
          };
          el.addEventListener("pointerup", stop);
          el.addEventListener("pointercancel", stop);
          el.show = (k) => {
            k = Math.min(1, Math.max(0, k || 0));
            el.querySelector("i").style.width = (k * 100) + "%";
            el.querySelector("b").style.left = (k * 100) + "%";
          };
          return el;
        };

        const seek = slider($("seek"), null, (k) => {
          if (isFinite(audio.duration)) audio.currentTime = k * audio.duration;
        });
        const vol = slider($("vol"), null, (k) => {
          audio.volume = k; audio.muted = false;
          try { localStorage.setItem("vgVolume", String(k)); } catch (e) { /* и ладно */ }
          vol.show(k); setMuteIcon();
        });

        const setMuteIcon = () => {
          const off = audio.muted || audio.volume === 0;
          $("k-mute").innerHTML = off ? SVG.mute : SVG.loud;
          $("k-mute").classList.toggle("on", off);
        };

        audio.addEventListener("timeupdate", () => {
          $("t-at").textContent = clock(audio.currentTime);
          if (isFinite(audio.duration)) seek.show(audio.currentTime / audio.duration);
        });
        audio.addEventListener("loadedmetadata", () => {
          $("t-all").textContent = clock(audio.duration);
        });
        audio.addEventListener("ended", () => {
          if (repeat && queueIds.length === 1) { audio.currentTime = 0; audio.play(); return; }
          step(1);
        });
        audio.addEventListener("play", setPlayIcon);
        audio.addEventListener("pause", setPlayIcon);

        $("k-play").addEventListener("click", () => {
          if (!queueIds.length) {
            const first = inside(here)[0];
            if (first) play(first.id);
            return;
          }
          if (audio.paused) audio.play().catch(() => {}); else audio.pause();
        });
        $("k-prev").addEventListener("click", () => {
          // Привычка из плееров: первые секунды «назад» — это к началу трека.
          if (audio.currentTime > 3) { audio.currentTime = 0; return; }
          step(-1);
        });
        $("k-next").addEventListener("click", () => step(1));
        $("k-shuffle").addEventListener("click", () => {
          shuffle = !shuffle;
          $("k-shuffle").classList.toggle("on", shuffle);
          const nowId = queueIds[atIndex];
          if (nowId) buildQueue(nowId);
        });
        $("k-repeat").addEventListener("click", () => {
          repeat = !repeat;
          $("k-repeat").classList.toggle("on", repeat);
        });
        $("k-mute").addEventListener("click", () => {
          audio.muted = !audio.muted;
          setMuteIcon();
          vol.show(audio.muted ? 0 : audio.volume);
        });

        $("k-prev").innerHTML = SVG.prev;
        $("k-next").innerHTML = SVG.next;
        $("k-shuffle").innerHTML = SVG.shuffle;
        $("k-repeat").innerHTML = SVG.repeat;
        setPlayIcon();
        let startVol = 0.8;
        try {
          const saved = parseFloat(localStorage.getItem("vgVolume"));
          if (isFinite(saved)) startVol = saved;
        } catch (e) { /* хранилище может быть закрыто */ }
        audio.volume = startVol;
        vol.show(startVol);
        setMuteIcon();

        // ── клики по списку ─────────────────────────────────────────────
        let holdTimer = 0;
        let holdFrom = null;

        const rowId = (e) => {
          const row = e.target.closest(".row");
          return row ? row.dataset.id : null;
        };

        $("tracks").addEventListener("click", (e) => {
          const id = rowId(e);
          if (!id) return;
          if (picking) {
            if (picked.has(id)) picked.delete(id); else picked.add(id);
            if (!picked.size) picking = false;
            paint();
            return;
          }
          play(id);
        });

        // Долгое нажатие — вход в выделение. То же, что в личном дропе.
        $("tracks").addEventListener("pointerdown", (e) => {
          if (!canEdit || picking) return;
          const id = rowId(e);
          if (!id) return;
          holdFrom = { x: e.clientX, y: e.clientY };
          holdTimer = setTimeout(() => {
            picking = true;
            picked.add(id);
            paint();
            if (navigator.vibrate) navigator.vibrate(15);
          }, 420);
        });
        const holdOff = () => { clearTimeout(holdTimer); holdTimer = 0; holdFrom = null; };
        $("tracks").addEventListener("pointermove", (e) => {
          if (!holdFrom) return;
          if (Math.abs(e.clientX - holdFrom.x) > 12 || Math.abs(e.clientY - holdFrom.y) > 12) holdOff();
        });
        $("tracks").addEventListener("pointerup", holdOff);
        $("tracks").addEventListener("pointercancel", holdOff);
        $("tracks").addEventListener("contextmenu", (e) => {
          if (!canEdit) return;
          const id = rowId(e);
          if (!id) return;
          e.preventDefault();
          picking = true;
          picked.add(id);
          paint();
        });

        $("folders").addEventListener("click", (e) => {
          const key = e.target.closest("[data-dir]");
          if (!key) return;
          here = key.dataset.dir;
          queueIds = [];
          atIndex = -1;
          draw();
        });

        $("crumbs").addEventListener("click", (e) => {
          const key = e.target.closest("[data-go]");
          if (!key) return;
          here = key.dataset.go;
          queueIds = [];
          atIndex = -1;
          draw();
        });

        // ── окошко с вопросом ───────────────────────────────────────────
        let sheetDone = null;
        const ask = (title, note, value, secret) => new Promise((done) => {
          sheetDone = done;
          $("sheet-title").textContent = title;
          $("sheet-note").textContent = note;
          $("sheet-err").textContent = "";
          const box = $("sheet-input");
          box.type = secret ? "password" : "text";
          box.value = value || "";
          $("modal").hidden = false;
          box.focus();
          box.select();
        });
        const shut = (answer) => {
          $("modal").hidden = true;
          const done = sheetDone;
          sheetDone = null;
          if (done) done(answer);
        };
        $("sheet-ok").addEventListener("click", () => shut($("sheet-input").value));
        $("sheet-no").addEventListener("click", () => shut(null));
        $("sheet-input").addEventListener("keydown", (e) => {
          if (e.key === "Enter") shut($("sheet-input").value);
          if (e.key === "Escape") shut(null);
        });

        const send = async (url, how, body) => {
          const res = await fetch(url, {
            method: how,
            headers: body ? { "Content-Type": "application/json" } : undefined,
            body: body ? JSON.stringify(body) : undefined,
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.error || "Не вышло.");
          return data;
        };

        // ── очередь заливки: строго по одному файлу ─────────────────────
        // Разом браузер не вытягивает: десяток параллельных отправок съедали
        // память и вкладка падала. Здесь всегда одна отправка, файл уходит
        // потоком — в память страницы он не читается вовсе.
        const uploads = [];
        let uploading = false;
        let sent = 0;
        let planned = 0;

        const drawQueue = (name, part) => {
          const box = $("queue");
          if (!uploading) { box.hidden = true; return; }
          box.hidden = false;
          $("queue-name").textContent = name;
          $("queue-num").textContent = sent + " / " + planned;
          $("queue-fill").style.width = Math.round(part * 100) + "%";
          measure();
        };

        const putOne = (file, folder) => new Promise((done, fail) => {
          const form = new FormData();
          form.append("file", file);
          form.append("folder", folder);
          const req = new XMLHttpRequest();
          req.open("POST", "/api/music");
          req.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) drawQueue(file.name, e.loaded / e.total);
          });
          req.addEventListener("load", () => {
            let data = {};
            try { data = JSON.parse(req.responseText); } catch (e) { /* пустой ответ */ }
            if (req.status >= 200 && req.status < 300) done(data);
            else fail(new Error(data.error || ("Сервер ответил " + req.status)));
          });
          req.addEventListener("error", () => fail(new Error("Связь оборвалась.")));
          req.addEventListener("abort", () => fail(new Error("Отменено.")));
          req.send(form);
        });

        const runQueue = async () => {
          if (uploading) return;
          uploading = true;
          const failed = [];
          while (uploads.length) {
            const job = uploads.shift();
            drawQueue(job.file.name, 0);
            let ok = false;
            // Оборвалось — не бросаем всю пачку: три попытки с паузой, и дальше.
            for (let tryNo = 1; tryNo <= 3 && !ok; tryNo++) {
              try {
                await putOne(job.file, job.folder);
                ok = true;
              } catch (err) {
                if (tryNo === 3) failed.push(job.file.name);
                else await new Promise((r) => setTimeout(r, tryNo * 1200));
              }
            }
            sent++;
            drawQueue(job.file.name, 1);
          }
          uploading = false;
          drawQueue("", 0);
          sent = 0;
          planned = 0;
          await load();
          if (failed.length) {
            alert("Не залилось: " + failed.slice(0, 6).join(", ") +
                  (failed.length > 6 ? " и ещё " + (failed.length - 6) : ""));
          }
        };

        const enqueue = (files, folder) => {
          // Уже лежащее не перезаливаем: сверяем имя и размер.
          const known = new Set(tracks.map((t) => t.title.toLowerCase()));
          const fresh = Array.prototype.filter.call(files, (f) => {
            const ext = f.name.lastIndexOf(".");
            const stem = (ext > 0 ? f.name.slice(0, ext) : f.name).toLowerCase();
            return f.size > 0 && !known.has(stem);
          });
          if (!fresh.length) return;
          fresh.forEach((f) => uploads.push({ file: f, folder }));
          planned += fresh.length;
          runQueue();
        };

        $("pick-files").addEventListener("change", (e) => {
          enqueue(e.target.files, here);
          e.target.value = "";
        });

        // Папку с музыкой раскладываем как есть: подпапки станут подпапками.
        $("pick-dir").addEventListener("change", async (e) => {
          const files = Array.prototype.slice.call(e.target.files);
          e.target.value = "";
          if (!files.length) return;
          const made = new Map();
          made.set("", here);
          const dirFor = async (path) => {
            if (made.has(path)) return made.get(path);
            const cut = path.lastIndexOf("/");
            const up = cut < 0 ? "" : path.slice(0, cut);
            const name = cut < 0 ? path : path.slice(cut + 1);
            const parent = await dirFor(up);
            const made2 = await send("/api/music/folder", "POST", { name, parent });
            made.set(path, made2.id);
            return made2.id;
          };
          for (const f of files) {
            const rel = f.webkitRelativePath || f.name;
            const parts = rel.split("/");
            parts.pop();
            // Верхнюю папку выбора не дублируем — кладём её содержимое сюда.
            if (parts.length) parts.shift();
            let dir = here;
            try { dir = await dirFor(parts.join("/")); } catch (err) { dir = here; }
            uploads.push({ file: f, folder: dir });
            planned++;
          }
          await load();
          runQueue();
        });

        // ── кнопки ──────────────────────────────────────────────────────
        const parentOf = (id) => {
          const f = folders.find((x) => x.id === id);
          return f ? f.parent : "";
        };

        const acts = {
          up: () => { here = parentOf(here); queueIds = []; atIndex = -1; draw(); },
          unlock: async () => {
            const pass = await ask("Вход в фонотеку",
              "Введите пароль для прав админа.", "", true);
            if (pass === null) return;
            const res = await fetch("/api/login", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ password: pass }),
            });
            if (!res.ok) {
              const data = await res.json().catch(() => ({}));
              alert(data.error || "Неверный пароль.");
              return;
            }
            await load();
          },
          newdir: async () => {
            const name = await ask("Новая папка", "Как назвать?", "", false);
            if (!name) return;
            await send("/api/music/folder", "POST", { name, parent: here });
            await load();
          },
          rename: async () => {
            const f = folders.find((x) => x.id === here);
            if (!f) return;
            const name = await ask("Имя папки", "Как назвать?", f.name, false);
            if (!name) return;
            await send("/api/music/folder/" + here, "PATCH", { name });
            await load();
          },
          upload: () => $("pick-files").click(),
          uploaddir: () => $("pick-dir").click(),
          copy: () => { clip = { op: "copy", ids: [...picked] }; picked.clear(); picking = false; paint(); },
          cut: () => { clip = { op: "cut", ids: [...picked] }; picked.clear(); picking = false; paint(); },
          paste: async () => {
            if (!clip) return;
            await send("/api/music/op", "POST",
              { op: clip.op === "cut" ? "move" : "copy", ids: clip.ids, target: here });
            clip = null;
            await load();
          },
          kill: async () => {
            if (!picked.size) return;
            if (!confirm("Удалить " + picked.size + "?")) return;
            await send("/api/music/op", "POST", { op: "delete", ids: [...picked] });
            picked.clear();
            picking = false;
            await load();
          },
          off: () => stopPicking(),
        };

        document.addEventListener("click", (e) => {
          const key = e.target.closest("[data-act]");
          if (!key) return;
          const run = acts[key.dataset.act];
          if (run) Promise.resolve(run()).catch((err) => alert(err.message));
        });

        document.addEventListener("keydown", (e) => {
          if (e.target.matches("input")) return;
          if (e.code === "Space") { e.preventDefault(); $("k-play").click(); }
          if (e.key === "Escape" && picking) stopPicking();
          if (e.key === "ArrowRight" && e.altKey) step(1);
          if (e.key === "ArrowLeft" && e.altKey) step(-1);
        });

        measure();
        load().catch(() => {
          $("tracks").innerHTML = '<div class="empty">фонотека не отвечает</div>';
        });
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
      <title>vitazgio.ru</title>
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

        /* Верхняя строка героя: слева подпись с доменом, справа знак сайта.
           Знак вынут из потока: он ростом со шрифт вывески, и в общей строке
           растягивал её с восемнадцати пикселей до семидесяти — от этого
           страница уезжала вниз, а подпись отрывалась от заголовка. Теперь
           строка снова по высоте подписи, а знак висит поверх и заходит
           вверх в поле страницы, которое там и так пустовало. */
        .hero-top {
          position: relative;
          display: flex;
          align-items: center;
          margin-bottom: 22px;
        }

        .hero-mark {
          position: absolute;
          right: 0;
          top: 50%;
          /* Чуть выше середины строки: ровно по центру нижний край буквы G
             ложился на верхнюю линию панели. Смещение в долях от роста, а не
             в пикселях, — знак масштабируется вместе с вывеской. */
          transform: translateY(-62%);
          width: clamp(1.15rem, 4.7vw, 4.4rem);
          height: clamp(1.15rem, 4.7vw, 4.4rem);
          /* Никакого свечения и подложки — только сами буквы. */
        }

        .eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 10px;
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

        /* Барабан крутит скрипт, а не браузер: своей прокрутки у полосы нет.
           С нативной не выходило гладко — она доводит ленту до карточки после
           каждого маха, а поверх этого шла подмена копий, и вместе получалось
           дёрганье. pan-y оставляет браузеру вертикаль: страница листается
           пальцем как обычно, вбок распоряжаемся мы.

           Стойка задаёт колонку — ту же, что у панели заголовка, — и служит
           точкой отсчёта для стрелок. Раньше окно барабана было во всю
           ширину окна с широкими полями: слева лента вставала вровень с
           панелью, а справа уезжала за край экрана. Теперь обрезаем ровно
           по колонке, и обе стороны совпадают с панелью. */
        .services-deck {
          position: relative;
          width: min(1380px, calc(100% - 40px));
          margin: 0 auto;
        }

        .services-wrap {
          overflow: hidden;
          padding: 14px 0 36px;
          touch-action: pan-y;
          cursor: grab;
          /* Без этого зажатая мышь выделяла текст карточки вместо прокрутки. */
          user-select: none;
          -webkit-user-select: none;
        }
        .services-wrap.dragging { cursor: grabbing; }
        .services { will-change: transform; }

        /* Стрелки живут в полях по бокам колонки, за уровнем панели.
           Треугольник приплюснутый: основание жирное, высота маленькая.
           Отступ наружу появляется только когда экран шире колонки —
           на узком поля всего по 20 пикселей, и клин садится в них впритык. */
        .drum-arrow {
          position: absolute;
          top: 50%;
          /* Минус 11 — половина разницы верхнего и нижнего полей окна:
             так стрелка встаёт по центру карточек, а не по центру стойки. */
          transform: translateY(calc(-50% - 11px));
          width: 24px;
          height: 58px;
          display: grid;
          place-items: center;
          padding: 0;
          border: 0;
          background: none;
          color: rgba(120, 208, 255, .62);
          cursor: pointer;
          transition: color .2s ease;
        }

        .drum-arrow:hover, .drum-arrow:focus-visible { color: #2de2ff; outline: none; }
        .drum-arrow:active { color: #fff; }
        .drum-arrow--prev { right: 100%; margin-right: clamp(0px, (100vw - 1420px) / 2, 26px); }
        .drum-arrow--next { left: 100%; margin-left: clamp(0px, (100vw - 1420px) / 2, 26px); }

        .drum-arrow b {
          display: block;
          width: 14px;
          height: 40px;
          background: currentColor;
          filter: drop-shadow(0 0 7px currentColor);
          transition: transform .2s ease;
        }

        .drum-arrow--prev b { clip-path: polygon(100% 0, 100% 100%, 0 50%); }
        .drum-arrow--next b { clip-path: polygon(0 0, 0 100%, 100% 50%); }
        .drum-arrow--prev:hover b { transform: translateX(-2px); }
        .drum-arrow--next:hover b { transform: translateX(2px); }

        /* Не сетка, а лента: карточки одной ширины идут в строку и
           прокручиваются по кругу, как барабан. Ужимать их под число
           сервисов больше не нужно — добавится восьмой, просто станет
           на один оборот длиннее. Сама закольцовка живёт в скрипте. */
        .services {
          display: flex;
          gap: 14px;
          width: max-content;
          margin: 0;
        }
        .service { flex: none; width: 264px; }

        /* Картинки внутри карточки браузер норовит утащить как файл, а сама
           карточка — ссылка, её он тащит как адрес. И то и другое обрывало
           поток событий указателя, из-за чего лента переставала крутиться. */
        .service img, .service svg { -webkit-user-drag: none; pointer-events: none; }

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
          display: flex; flex-wrap: wrap; justify-content: center;
          gap: 18px; margin-top: 18px;
        }
        /* Значки в «Рубке» вдвое крупнее и с подписью под каждым. Каждый —
           это ячейка-колонка: сверху квадратная кнопка, снизу ярлык. */
        .pick-cell {
          display: flex; flex-direction: column; align-items: center; gap: 10px;
          width: clamp(112px, 20vw, 156px);
        }
        .pick-cell .pick { width: 100%; }
        .pick-label {
          font: 700 .82rem "Cascadia Code", Consolas, monospace;
          letter-spacing: .22em; color: #93a1b8; transition: color .2s;
        }
        .pick-cell:hover .pick-label,
        .pick-cell:focus-within .pick-label { color: #eaf3ff; }
        /* Красный замок в углу карточки: она под паролем. Со знакомого
           устройства скрипт его убирает. */
        .pick-lock {
          position: absolute; top: 8px; right: 8px; z-index: 4;
          width: 24px; height: 24px; display: grid; place-items: center;
          color: #ff4d4d; filter: drop-shadow(0 0 6px rgba(255,60,60,.55));
        }
        .pick-lock svg { width: 100%; height: 100%; }
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
        .pick--music   { --pc: #2de2ff; }
        .pick--butler  { --pc: #b57cff; }
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
        /* Покачиваются все пять, на один и тот же угол, но с разной скоростью.
           Разница нарочно мелкая: в такт полка выглядела бы одним механизмом,
           а так каждая кнопка живёт сама по себе, и глаз это ловит, даже если
           не может объяснить. */
        .pick--pad .pick-art svg   { animation: pxTilt 3s ease-in-out infinite; }
        .pick--diy .pick-art svg   { animation: pxTilt 3.2s ease-in-out infinite; }
        .pick--rack .pick-art svg  { animation: pxTilt 3.45s ease-in-out infinite; }
        .pick--music .pick-art svg { animation: pxTilt 3.6s ease-in-out infinite; }
        .pick--butler .pick-art svg { animation: pxTilt 3.25s ease-in-out infinite; }
        .pick--me .pick-art svg    { animation: pxTilt 3.85s ease-in-out infinite; }

        /* Бегущая подсветка: строки кода на экране и отблеск в очках. */
        @keyframes pxFlow { 0%, 100% { opacity: .2; } 18% { opacity: 1; } }
        .pick-art .px-f1 { animation: pxFlow 1.6s linear infinite; }
        .pick-art .px-f2 { animation: pxFlow 1.6s linear infinite .4s; }
        .pick-art .px-f3 { animation: pxFlow 1.6s linear infinite .8s; }
        .pick-art .px-f4 { animation: pxFlow 1.6s linear infinite 1.2s; }
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
          /* Знак ростом со шрифт вывески, а он здесь свой — повторяем размер. */
          .hero-mark { width: clamp(1.6rem, 8.8vw, 2.9rem); height: clamp(1.6rem, 8.8vw, 2.9rem); }
          /* Отступ до панели держит строка целиком, а не подпись внутри неё —
             иначе к нему прибавлялся отступ строки и выходило вдвое больше. */
          .hero-top { margin-bottom: 18px; }
          .eyebrow { font-size: .95rem; letter-spacing: .12em; }
          .eyebrow::before { width: 9px; height: 9px; }
          .arcade-bar-line { font-size: .86rem; letter-spacing: .26em; }
          /* Пять кнопок в строку на телефоне не влезают — раскладываем
             тремя и двумя, ширину считаем от полосы, а не подбираем. */
          .arcade-picks { gap: 12px; }
          .arcade-picks .pick-cell { width: calc((100% - 24px) / 3); max-width: 130px; }
          .pick-label { font-size: .68rem; letter-spacing: .14em; }
          footer { font-size: .95rem; }
          .service { width: 78vw; min-height: 280px; }
          /* На телефоне листают пальцем, а поля по бокам всего 20 пикселей —
             стрелкам там не встать, да и незачем. */
          .drum-arrow { display: none; }
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
          <div class="hero-top">
            <div class="eyebrow">vitazgio.ru · мои домены</div>
            <img class="hero-mark" src="/static/icons/vg-plain.svg" alt="Vitaz Gio"
                 width="512" height="512">
          </div>
          <h1 id="page-title" class="cyber-terminal" aria-label="Мои веб-сервисы, Vitazgio Network, Domain Control">
            <span class="terminal-prompt" aria-hidden="true">&gt;</span>
            <span id="cyber-text" class="cyber-text" data-text="МОИ ВЕБ-СЕРВИСЫ" aria-hidden="true">МОИ ВЕБ-СЕРВИСЫ</span>
            <span class="terminal-cursor" aria-hidden="true"></span>
          </h1>
        </section>

        <div class="services-deck">
          <button class="drum-arrow drum-arrow--prev" type="button" hidden
                  data-drum="-1" aria-label="Предыдущий сервис"><b></b></button>
          <button class="drum-arrow drum-arrow--next" type="button" hidden
                  data-drum="1" aria-label="Следующий сервис"><b></b></button>
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
               aria-label="Открыть GitHub">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>GitHub</h2><p>Исходники проектов и история правок</p><span class="domain">github.com</span></div>
            </a>

            <a class="service service--gitea" href="https://git.vitazgio.ru"
               aria-label="Открыть Gitea">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4.209 4.603c-.247 0-.525.02-.84.088-.333.07-1.28.283-2.054 1.027C-.403 7.25.035 9.685.089 10.052c.065.446.263 1.687 1.21 2.768 1.749 2.141 5.513 2.092 5.513 2.092s.462 1.103 1.168 2.119c.955 1.263 1.936 2.248 2.89 2.367 2.406 0 7.212-.004 7.212-.004s.458.004 1.08-.394c.535-.324 1.013-.893 1.013-.893s.492-.527 1.18-1.73c.21-.37.385-.729.538-1.068 0 0 2.107-4.471 2.107-8.823-.042-1.318-.367-1.55-.443-1.627-.156-.156-.366-.153-.366-.153s-4.475.252-6.792.306c-.508.011-1.012.023-1.512.027v4.474l-.634-.301c0-1.39-.004-4.17-.004-4.17-1.107.016-3.405-.084-3.405-.084s-5.399-.27-5.987-.324c-.187-.011-.401-.032-.648-.032zm.354 1.832h.111s.271 2.269.6 3.597C5.549 11.147 6.22 13 6.22 13s-.996-.119-1.641-.348c-.99-.324-1.409-.714-1.409-.714s-.73-.511-1.096-1.52C1.444 8.73 2.021 7.7 2.021 7.7s.32-.859 1.47-1.145c.395-.106.863-.12 1.072-.12zm8.33 2.554c.26.003.509.127.509.127l.868.422-.529 1.075a.686.686 0 0 0-.614.359.685.685 0 0 0 .072.756l-.939 1.924a.69.69 0 0 0-.66.527.687.687 0 0 0 .347.763.686.686 0 0 0 .867-.206.688.688 0 0 0-.069-.882l.916-1.874a.667.667 0 0 0 .237-.02.657.657 0 0 0 .271-.137 8.826 8.826 0 0 1 1.016.512.761.761 0 0 1 .286.282c.073.21-.073.569-.073.569-.087.29-.702 1.55-.702 1.55a.692.692 0 0 0-.676.477.681.681 0 1 0 1.157-.252c.073-.141.141-.282.214-.431.19-.397.515-1.16.515-1.16.035-.066.218-.394.103-.814-.095-.435-.48-.638-.48-.638-.467-.301-1.116-.58-1.116-.58s0-.156-.042-.27a.688.688 0 0 0-.148-.241l.516-1.062 2.89 1.401s.48.218.583.619c.073.282-.019.534-.069.657-.24.587-2.1 4.317-2.1 4.317s-.232.554-.748.588a1.065 1.065 0 0 1-.393-.045l-.202-.08-4.31-2.1s-.417-.218-.49-.596c-.083-.31.104-.691.104-.691l2.073-4.272s.183-.37.466-.497a.855.855 0 0 1 .35-.077z"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Gitea</h2><p>Свой git на домашнем сервере</p><span class="domain">git.vitazgio.ru</span></div>
            </a>
          </div>
        </nav>
        </div>

        <!-- Полка с двумя кнопками: стойка ведёт в кабинет, геймпад — в игры.
             Обе без единой буквы: подпись даёт aria-label и всплывающая
             подсказка, а глазу хватает пиксельного значка. -->
        <section class="arcade-bar" aria-label="Рубка">
          <div class="arcade-bar-line"><span>РУБКА</span></div>
          <!-- Порядок задан: игры, страна DIY, хозяйство, музыка, кабинет.
               Стойка переехала сюда из кабинета — теперь она про сервера,
               а у кабинета свой значок: человек за компом. -->
          <div class="arcade-picks">
            <span class="pick-cell pick--pad">
              <button class="pick pick--pad" type="button" data-games
                      title="Игры" aria-label="Открыть игры">
                <span class="pick-art">__ICON_PAD__</span>
                <span class="pick-glow"></span>
              </button>
              <span class="pick-label">GAMES</span>
            </span>
            <span class="pick-cell pick--diy">
              <a class="pick pick--diy" href="/diy"
                 title="Страна DIY" aria-label="Открыть страну DIY">
                <span class="pick-art">__ICON_CODE__</span>
                <span class="pick-glow"></span>
              </a>
              <span class="pick-label">DIY</span>
            </span>
            <span class="pick-cell pick--rack">
              <a class="pick pick--rack" href="/servers"
                 title="Хозяйство" aria-label="Открыть рассказ о серверах">
                <span class="pick-art">__ICON_RACK__</span>
                <span class="pick-glow"></span>
              </a>
              <span class="pick-label">SERVERS</span>
            </span>
            <span class="pick-cell pick--butler">
              <a class="pick pick--butler" href="/sebastian"
                 title="Себастьян" aria-label="Поговорить с дворецким">
                <span class="pick-art">__ICON_BUTLER__</span>
                <span class="pick-glow"></span>
              </a>
              <span class="pick-label">SEBASTIAN</span>
            </span>
            <span class="pick-cell pick--music">
              <a class="pick pick--music" href="/music" id="music-pick"
                 title="Музыка" aria-label="Открыть музыку">
                <span class="pick-art">__ICON_SPEAKER__</span>
                <span class="pick-glow"></span>
                <span class="pick-lock" title="Под паролем" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><rect x="4.5" y="10.5" width="15" height="10" rx="2.2" fill="currentColor"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9" stroke="currentColor" stroke-width="2.2"/></svg></span>
              </a>
              <span class="pick-label">MUSIC</span>
            </span>
            <span class="pick-cell pick--me">
              <button class="pick pick--me" type="button" id="cabinet-pick"
                      title="Личный кабинет" aria-label="Открыть личный кабинет">
                <span class="pick-art">__ICON_ME__</span>
                <span class="pick-glow"></span>
                <span class="pick-lock" title="Под паролем" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><rect x="4.5" y="10.5" width="15" height="10" rx="2.2" fill="currentColor"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9" stroke="currentColor" stroke-width="2.2"/></svg></span>
              </button>
              <span class="pick-label">TOP SECRET</span>
            </span>
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
          <p class="auth-hint">Введите пароль для прав админа.</p>
          <form id="auth-form" class="auth-form">
            <label for="auth-password">Пароль</label>
            <input id="auth-password" name="password" type="password" autocomplete="current-password" required>
            <button class="auth-submit" type="submit">Получить доступ</button>
            <p id="auth-error" class="auth-error" role="alert"></p>
          </form>
        </section>
      </div>
      <script>
        /* Барабан сервисов: лента бесконечно едет вбок, а прокрутку ей
           даём мы сами, а не браузер.

           Почему сами. С нативной прокруткой лента дёргалась: браузер после
           каждого маха доводил её до ближайшей карточки, а мы поверх этого
           подменяли копии — и подмена посреди инерции оставляла пустое
           место, потому что перерисовать уехавшее он не успевал.

           Как устроено. Есть одно число — на сколько лента сдвинута. Для
           показа оно заворачивается в пределы одного набора: дальше картинка
           всё равно повторяется. Копий набора столько, чтобы окно было
           закрыто карточками при любом сдвиге. Двигаем через transform: он
           не заставляет браузер пересчитывать раскладку.

           Отпустил палец — лента идёт свободным выбегом с трением. Как
           только скорость падает до GRAB, её подхватывает магнит: считает,
           где лента встала бы сама, округляет до ближайшей карточки и
           доводит туда. Подхват происходит на ходу, задолго до остановки,
           поэтому щелчка в конце не видно — лента просто плавно причаливает
           карточкой к левому краю, ровно как при загрузке страницы. */
        (() => {
          const wrap = document.querySelector(".services-wrap");
          const row = document.querySelector(".services");
          if (!wrap || !row) return;

          const GAP = 14;
          const MAX_SPEED = 4.8;      // пикселей на миллисекунду, потолок разгона
          const FRICTION = 0.955;     // сколько скорости остаётся за кадр в 16 мс
          const GRAB = 1.35;          // на этой скорости магнит подхватывает ленту
          const DRAG_SLOP = 8;        // сдвиг, после которого это уже не тык
          const NUDGE = 1.6;          // скорость доводки по стрелке, px за мс
          // Скорость тает по одному закону, значит весь остаток пути — это
          // текущая скорость, помноженная на постоянную времени.
          const TAU = 16 / Math.log(1 / FRICTION);

          const originals = Array.prototype.slice.call(row.children);
          const arrows = Array.prototype.slice.call(
            document.querySelectorAll(".drum-arrow"));
          // Карточка — ссылка, и браузер тащит её как адрес. Перетаскивание
          // обрывало поток событий указателя: на компьютере зажатая мышь
          // подсвечивала карточку, а лента при этом стояла.
          originals.forEach((card) => { card.draggable = false; });
          let clones = [];
          let setWidth = 0;
          let pitch = 0;              // шаг: карточка вместе с зазором
          let offset = 0;             // на сколько лента сдвинута влево
          let speed = 0;
          let alive = false;
          let raf = 0;

          const measure = () => originals.reduce(
            (sum, card) => sum + card.getBoundingClientRect().width + GAP, 0);

          const addCopy = () => {
            originals.forEach((card) => {
              const twin = card.cloneNode(true);
              twin.setAttribute("aria-hidden", "true");
              twin.setAttribute("tabindex", "-1");
              twin.dataset.twin = "1";
              row.appendChild(twin);
              clones.push(twin);
            });
          };

          /* Само число сдвига не трогаем — заворачиваем только то, что
             показываем. Иначе доводка до карточки спотыкалась бы каждый раз,
             когда лента переваливает через конец набора. */
          const place = () => {
            const shown = ((offset % setWidth) + setWidth) % setWidth;
            row.style.transform = "translate3d(" + (-shown).toFixed(2) + "px,0,0)";
          };

          const stopMotion = () => {
            if (raf) cancelAnimationFrame(raf);
            raf = 0;
            speed = 0;
          };

          /* Доводка: едем к цели с замедлением к концу. Время подбираем под
             ту скорость, с какой лента подошла, — тогда стыка со свободным
             выбегом не видно. У этого замедления скорость наибольшая в самом
             начале и вдвое выше средней, отсюда двойка в формуле.

             Замедление именно квадратичное, а не более крутое: у крутого
             длинный хвост — на последние двадцать пикселей уходило почти
             полсекунды, и это читалось как «встало и потом дощёлкнуло». */
          const easeTo = (target, entry) => {
            const from = offset;
            const dist = target - from;
            const way = Math.abs(dist);
            if (way < 0.5) { stopMotion(); offset = target; place(); return; }
            const time = Math.max(140, Math.min(800, 2 * way / Math.max(entry, 0.2)));
            const t0 = performance.now();
            stopMotion();
            const step = (now) => {
              const k = Math.min(1, (now - t0) / time);
              const ease = 1 - (1 - k) * (1 - k);
              offset = from + dist * ease;
              place();
              raf = k < 1 ? requestAnimationFrame(step) : 0;
            };
            raf = requestAnimationFrame(step);
          };

          /* Магнит: прикидываем, где лента остановилась бы сама, округляем
             до ближайшей карточки и причаливаем туда с той же скоростью. */
          const magnet = () => {
            if (!alive || !pitch) return;
            const stopAt = offset + speed * TAU;
            easeTo(Math.round(stopAt / pitch) * pitch, Math.abs(speed));
          };

          /* Свободный выбег. Пока лента идёт быстрее GRAB, ей никто не
             мешает — крутится сколько накрутили. Замедлилась — передаём
             магниту, и он доводит её до карточки уже на ходу. */
          const coast = () => {
            if (!alive) return;
            if (Math.abs(speed) <= GRAB) { magnet(); return; }
            let last = performance.now();
            const step = (now) => {
              const dt = Math.min(48, now - last);
              last = now;
              offset += speed * dt;
              speed *= Math.pow(FRICTION, dt / 16);
              place();
              if (Math.abs(speed) <= GRAB) { raf = 0; magnet(); return; }
              raf = requestAnimationFrame(step);
            };
            if (raf) cancelAnimationFrame(raf);
            raf = requestAnimationFrame(step);
          };

          /* Шаг по стрелке: ровно одна карточка от текущего положения. */
          const nudge = (dir) => {
            if (!alive || !pitch) return;
            speed = 0;
            easeTo((Math.round(offset / pitch) + dir) * pitch, NUDGE);
          };

          const build = () => {
            clones.forEach((twin) => twin.remove());
            clones = [];
            stopMotion();
            alive = false;
            offset = 0;
            row.style.transform = "";
            arrows.forEach((key) => { key.hidden = true; });
            setWidth = measure();
            pitch = originals[0].getBoundingClientRect().width + GAP;
            // Видимая ширина — без боковых полей. По полной ширине блока
            // считать нельзя: на мониторе 2560 поля съедают по 590 пикселей,
            // и лента в 1932 казалась помещающейся, хотя видно от неё 1380.
            const pad = getComputedStyle(wrap);
            const room = wrap.clientWidth
              - parseFloat(pad.paddingLeft) - parseFloat(pad.paddingRight);
            // Всё влезло — крутить нечего.
            if (setWidth - GAP <= room + 1) return;
            // Копий столько, чтобы окно было закрыто при любом сдвиге:
            // видно участок от сдвига до сдвига плюс ширина окна, а сдвиг
            // меньше длины набора. Одна лишняя копия — на всякий случай.
            const need = Math.ceil((setWidth + room) / setWidth) + 1;
            for (let i = 1; i < need; i++) addCopy();
            alive = true;
            arrows.forEach((key) => { key.hidden = false; });
            place();
          };

          /* ── Палец и мышь ──────────────────────────────────────────── */
          let dragging = false;
          let lastX = 0;
          let lastT = 0;
          let travelled = 0;
          let pointer = 0;
          let held = false;           // взят ли захват указателя

          const onDown = (e) => {
            if (!alive || e.button > 0) return;
            dragging = true;
            pointer = e.pointerId;
            lastX = e.clientX;
            lastT = e.timeStamp;
            travelled = 0;
            held = false;
            stopMotion();
            wrap.classList.add("dragging");
          };

          const onMove = (e) => {
            if (!dragging) return;
            const dx = e.clientX - lastX;
            const dt = Math.max(1, e.timeStamp - lastT);
            offset -= dx;
            travelled += Math.abs(dx);
            /* Захват нужен, чтобы палец, уехавший за пределы полосы, всё
               равно продолжал крутить ленту. Но берём его только когда
               протяжка уже началась: пока указатель захвачен, браузер
               адресует щелчок самой полосе, и тык по карточке не открывал
               сервис. Иногда захват не даётся — например, если событие
               пришло не от живого указателя; тогда обойдёмся без него. */
            if (!held && travelled > DRAG_SLOP) {
              held = true;
              try { wrap.setPointerCapture(pointer); } catch (err) { /* обойдёмся */ }
            }
            // Скорость считаем по последнему отрезку, но с оглядкой на
            // прежнюю: от одного дёрганого кадра лента не должна улетать.
            const raw = -dx / dt;
            speed = Math.max(-MAX_SPEED, Math.min(MAX_SPEED, speed * 0.4 + raw * 0.6));
            lastX = e.clientX;
            lastT = e.timeStamp;
            place();
          };

          const onUp = () => {
            if (!dragging) return;
            dragging = false;
            wrap.classList.remove("dragging");
            if (held) {
              held = false;
              try { wrap.releasePointerCapture(pointer); } catch (err) { /* уже отпущен */ }
            }
            coast();
          };

          wrap.addEventListener("pointerdown", onDown);
          wrap.addEventListener("pointermove", onMove);
          wrap.addEventListener("pointerup", onUp);
          wrap.addEventListener("pointercancel", onUp);
          // Последний рубеж против нативного переноса: у картинок его гасит
          // стиль, у ссылки — свойство, но с выделенного текста он всё равно
          // может начаться, и тогда лента замирает на полпути.
          wrap.addEventListener("dragstart", (e) => e.preventDefault());

          arrows.forEach((key) => {
            key.addEventListener("click", () => nudge(Number(key.dataset.drum)));
          });

          // Протащил ленту — значит не по карточке жал, переход отменяем.
          wrap.addEventListener("click", (e) => {
            if (travelled > DRAG_SLOP) { e.preventDefault(); e.stopPropagation(); }
          }, true);

          // Окно обрезает ленту, но остаётся прокручиваемым: браузер может
          // сам увести его вбок, подтягивая карточку под фокус. Держим на нуле,
          // иначе его сдвиг сложится с нашим и раскладка поедет.
          wrap.addEventListener("scroll", () => { if (wrap.scrollLeft) wrap.scrollLeft = 0; });

          // Колесо: вбок крутим ленту, вниз оставляем странице. Доводку
          // запускаем, когда колесо замерло, — иначе она мешала бы крутить.
          let wheelIdle = 0;
          wrap.addEventListener("wheel", (e) => {
            if (!alive) return;
            const dx = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX
                     : (e.shiftKey ? e.deltaY : 0);
            if (!dx) return;
            e.preventDefault();
            stopMotion();
            offset += dx;
            place();
            clearTimeout(wheelIdle);
            wheelIdle = setTimeout(() => { speed = 0; magnet(); }, 140);
          }, { passive: false });

          /* Переход табом по ссылкам: своей прокрутки у полосы нет, поэтому
             подводим ленту к карточке сами, иначе фокус уезжал бы за экран. */
          wrap.addEventListener("focusin", (e) => {
            if (!alive) return;
            const card = e.target.closest(".service");
            if (!card) return;
            const box = card.getBoundingClientRect();
            const view = wrap.getBoundingClientRect();
            const pad = parseFloat(getComputedStyle(wrap).paddingLeft);
            if (box.left >= view.left + pad - 1 && box.right <= view.right) return;
            speed = 0;
            easeTo(Math.round((offset + box.left - view.left - pad) / pitch) * pitch, NUDGE);
          });

          build();

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
          const cabinetPick = document.getElementById("cabinet-pick");
          const musicPick = document.getElementById("music-pick");
          const modal = document.getElementById("auth-modal");
          const form = document.getElementById("auth-form");
          const password = document.getElementById("auth-password");
          const error = document.getElementById("auth-error");
          const submit = form.querySelector("button[type='submit']");

          // Куда уйти после входа. Обе закрытые карточки — кабинет и музыка —
          // открывают одно окно; отличается только пункт назначения.
          let authDest = "/cabinet";
          let lastTrigger = cabinetPick;

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
            if (lastTrigger) lastTrigger.focus();
          };

          // Помнит устройство — сразу пускаем, не помнит — просим пароль.
          const guard = (dest, el) => async (event) => {
            if (event) event.preventDefault();
            authDest = dest;
            lastTrigger = el;
            try {
              const response = await fetch("/api/session/probe", { credentials: "same-origin" });
              const result = await response.json();
              if (result.trusted) {
                window.location.assign(dest);
                return;
              }
            } catch {}
            openModal();
          };

          cabinetPick.addEventListener("click", guard("/cabinet", cabinetPick));
          if (musicPick) musicPick.addEventListener("click", guard("/music", musicPick));
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
              window.location.assign(authDest);
            } catch {
              error.textContent = "Сервер недоступен. Повторите попытку.";
            } finally {
              submit.disabled = false;
            }
          });
        })();

        // Красный замок на «Музыке» и «Кабинете» снимаем, если сервер помнит
        // это устройство: тогда пароль не спросят, и замку неоткуда взяться.
        (async () => {
          try {
            const r = await fetch("/api/session/probe", { credentials: "same-origin" });
            const d = await r.json();
            if (d && d.trusted) {
              document.querySelectorAll(".pick-lock").forEach((el) => el.remove());
            }
          } catch {}
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
      <script src="/vg-player.js" defer></script>
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
