import base64
import codecs
import gzip
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
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
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
    {"ip": "100.104.208.57", "name": "proxmox_vps", "ssh_enabled": True},
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


# Дроп и фонотека делят ОДНО хранилище на 30 ГБ (DROP_QUOTA). Раньше у музыки
# был свой лимит на 2 ГБ, из-за чего гигабайты треков не входили в «Занято»
# дропа, а загрузка упиралась в «нет места в фонотеке», хотя на диске место
# было. Эти помощники берут занятое каждой половиной СВОИМ локом и без
# вложенности — правило одно: сначала music_lock, потом drop_lock (или
# каждый отдельно), но никогда наоборот, иначе взаимоблокировка.
def _music_used_safe():
    with music_lock:
        return _music_used()


def _drop_used_safe():
    with drop_lock:
        return _drop_used()


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


DEBTS_PATH = os.path.join(DATA_DIR, "debts.json")
debts_lock = threading.Lock()
debts_data = {"users": [], "entries": []}


def _today_iso():
    return datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y-%m-%d")


def _debts_load():
    global debts_data
    try:
        with open(DEBTS_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    debts_data = {
        "users": raw.get("users") if isinstance(raw.get("users"), list) else [],
        "entries": raw.get("entries") if isinstance(raw.get("entries"), list) else [],
    }


def _debts_write_locked():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DEBTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(debts_data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, DEBTS_PATH)


def _debt_hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def _debt_password_matches(user, password):
    visible = user.get("password_plain")
    if isinstance(visible, str) and visible:
        return hmac.compare_digest(visible, password)
    try:
        salt = base64.b64decode(user.get("salt", ""))
        expected = base64.b64decode(user.get("password_hash", ""))
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def _debt_find_user_by_password(password):
    if not isinstance(password, str) or not password:
        return None
    with debts_lock:
        for user in debts_data["users"]:
            if _debt_password_matches(user, password):
                return {"id": user["id"], "name": user.get("name", "Должник")}
    return None


def _debt_amount_cents(raw):
    text = str(raw or "").strip().replace(" ", "").replace(",", ".")
    if not re.fullmatch(r"\d+(?:\.\d{1,2})?", text):
        raise ValueError("Введите сумму числом, максимум 2 знака после точки.")
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ValueError("Введите сумму числом.")
    if value <= 0 or value > Decimal("10000000"):
        raise ValueError("Сумма должна быть больше нуля и меньше 10 000 000.")
    return int((value * Decimal("100")).quantize(Decimal("1")))


def _debt_clean_date(raw):
    text = (str(raw or "").strip() or _today_iso())
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Дата должна быть в формате ГГГГ-ММ-ДД.")
    return text


def _debt_user_total_locked(user_id):
    total = 0
    for entry in debts_data["entries"]:
        if entry.get("user_id") != user_id:
            continue
        amount = int(entry.get("amount_cents") or 0)
        total += amount if entry.get("kind") == "debt" else -amount
    return total


def _debt_entry_public_locked(entry):
    user = next((u for u in debts_data["users"] if u.get("id") == entry.get("user_id")), None)
    return {
        "id": entry.get("id"),
        "user_id": entry.get("user_id"),
        "user_name": user.get("name", "Должник") if user else "Должник",
        "date": entry.get("date") or _today_iso(),
        "kind": entry.get("kind") if entry.get("kind") in ("debt", "return") else "debt",
        "amount_cents": int(entry.get("amount_cents") or 0),
        "comment": entry.get("comment") or "—",
        "created": entry.get("created") or "",
    }


def _debt_user_public_locked(user):
    user_id = user.get("id")
    entries = [e for e in debts_data["entries"] if e.get("user_id") == user_id]
    return {
        "id": user_id,
        "name": user.get("name", "Должник"),
        "password": user.get("password_plain") or "",
        "total_cents": _debt_user_total_locked(user_id),
        "entry_count": len(entries),
        "created": user.get("created") or "",
    }


def _debts_snapshot_locked(user_id=None):
    users = [_debt_user_public_locked(u) for u in debts_data["users"]]
    users.sort(key=lambda u: u["name"].lower())
    entries = [_debt_entry_public_locked(e) for e in debts_data["entries"] if user_id is None or e.get("user_id") == user_id]
    entries.sort(key=lambda e: (e["date"], e["created"]), reverse=True)
    total = sum(u["total_cents"] for u in users if user_id is None or u["id"] == user_id)
    return {"users": users, "entries": entries, "total_cents": total, "today": _today_iso()}


def _debts_owner_unlocked():
    return bool(session.get("debts_owner_authenticated") and session.get("debts_owner_day") == _today_iso())


def debts_owner_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            _log_login("доверенное устройство")
        if not _debts_owner_unlocked():
            return jsonify(error="Нужен ежедневный пароль."), 403
        return view(*args, **kwargs)
    return wrapped


def debtor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("debtor_id"):
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


_debts_load()


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


# ---- Скорость: сжатие и кэш статики ---------------------------------------
# Страницы сайта — это HTML со встроенными CSS и JS, кабинет тянет 142 КБ.
# Текст жмётся вчетверо, поэтому дешевле всего просто отдавать его сжатым:
# 142 КБ → 31 КБ, а на стороне сервера это 3-4 мс на страницу. Уровень 6 —
# золотая середина: девятка выигрывает 0.2 КБ, а стоит втрое дороже.
GZIP_LEVEL = 6
GZIP_MIN_BYTES = 1024          # мелочь жать смысла нет, накладные съедят выигрыш
GZIP_FILE_MAX = 512 * 1024     # файл с диска ради сжатия читаем только мелкий
GZIP_TYPES = {
    "text/html", "text/css", "text/plain", "text/javascript",
    "application/javascript", "application/json", "application/manifest+json",
    "image/svg+xml", "application/xml", "text/xml",
}
# Статика (иконки, логотипы) менялась последний раз в прошлой жизни, но
# отдавалась с no-cache — браузер переспрашивал каждую при каждом заходе.
# Сутки, как у уже настроенных /icon-*.png.
STATIC_MAX_AGE = 86400


@app.after_request
def compress_response(response):
    """Жмёт текстовые ответы и разрешает кэшировать статику.

    Осторожно обходим всё, что жать нельзя:
    — потоковые ответы (SSE-чат нейронки: сжатие копило бы буфер, и живая
      печать превратилась бы в один рывок в конце);
    — send_file (музыка, видео, PDF): там direct_passthrough и Range-запросы,
      сжатие сломало бы перемотку;
    — 206 Partial Content и 304 Not Modified;
    — уже сжатое (картинки, аудио, архивы) — второй проход только раздувает.
    """
    # Flask сам проставляет статике no-cache, поэтому именно перезаписываем:
    # setdefault тут молча ничего бы не сделал.
    if request.path.startswith("/static/") and response.status_code == 200:
        response.headers["Cache-Control"] = f"public, max-age={STATIC_MAX_AGE}"

    # is_streamed True и у SSE-генератора, и у файла с диска, поэтому одного
    # флага мало. Различаем по direct_passthrough: он поднят только у файлов.
    # Настоящий поток (генератор SSE) — is_streamed без passthrough: его не
    # трогаем, иначе живая печать в чате скопится в один рывок.
    if (response.status_code != 200
            or (response.is_streamed and not response.direct_passthrough)
            or "Content-Encoding" in response.headers
            or (response.mimetype or "") not in GZIP_TYPES):
        return response

    accepted = request.headers.get("Accept-Encoding", "")
    if "gzip" not in accepted.lower():
        return response

    # send_file отдаёт файл потоком (direct_passthrough) — чтобы сжать, его
    # придётся втянуть в память. Для svg и offline.html это копейки, но для
    # музыки и видео было бы дико: их спасает и проверка типа выше, и лимит.
    if response.direct_passthrough:
        if (response.content_length or 0) > GZIP_FILE_MAX:
            return response
        response.direct_passthrough = False

    data = response.get_data()
    if len(data) < GZIP_MIN_BYTES:
        return response

    response.set_data(gzip.compress(data, GZIP_LEVEL))
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(response.get_data()))
    # Кэш обязан различать сжатый и несжатый ответ, иначе прокси однажды
    # отдаст gzip тому, кто его не просил.
    response.headers.add("Vary", "Accept-Encoding")
    return response


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
    if isinstance(password, str) and password_matches(password):
        _rate_clear(login_attempts, login_attempts_lock, client)
        session.clear()
        session["authenticated"] = True
        session.permanent = False
        _log_login()
        return jsonify(redirect=url_for("cabinet"))

    debtor = _debt_find_user_by_password(password)
    if debtor:
        _rate_clear(login_attempts, login_attempts_lock, client)
        session.clear()
        session["debtor_id"] = debtor["id"]
        session.permanent = False
        _log_login(f"вход должника: {debtor['name']}")
        return jsonify(redirect=url_for("debts_me_page"))

    _rate_hit(login_attempts, login_attempts_lock, client)
    _log_login("неверный пароль", kind="fail")
    return jsonify(error="Неверный пароль."), 401


@app.post("/api/debts/unlock")
def debts_unlock_api():
    if not session.get("authenticated"):
        fresh = _device_check(request.cookies.get(DEVICE_COOKIE))
        if not fresh:
            return jsonify(error="Нужен вход в кабинет."), 403
        session["authenticated"] = True
        g.new_device_cookie = fresh
        _log_login("доверенное устройство")

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
        return jsonify(error="Неверный ежедневный пароль."), 401

    _rate_clear(console_login_attempts, console_login_attempts_lock, client)
    session["debts_owner_authenticated"] = True
    session["debts_owner_day"] = _today_iso()
    return jsonify(ok=True)


@app.get("/api/debts")
@debts_owner_required
def debts_api():
    with debts_lock:
        return jsonify(_debts_snapshot_locked())


@app.post("/api/debts/users")
@debts_owner_required
def debts_user_create_api():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    password = payload.get("password", "")
    if not name:
        return jsonify(error="Введите имя."), 400
    if len(name) > 60:
        return jsonify(error="Имя слишком длинное."), 400
    if not isinstance(password, str) or len(password.strip()) < 3:
        return jsonify(error="Пароль должен быть хотя бы 3 символа."), 400
    password = password.strip()
    if password_matches(password):
        return jsonify(error="Не используй пароль владельца для должника."), 400

    salt, password_hash = _debt_hash_password(password)
    now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")
    user_id = uuid.uuid4().hex
    with debts_lock:
        if any(u.get("name", "").lower() == name.lower() for u in debts_data["users"]):
            return jsonify(error="Такой человек уже есть."), 400
        if any(_debt_password_matches(u, password) for u in debts_data["users"]):
            return jsonify(error="Такой пароль уже занят."), 400
        debts_data["users"].append({
            "id": user_id,
            "name": name,
            "password_plain": password,
            "salt": salt,
            "password_hash": password_hash,
            "created": now,
        })
        _debts_write_locked()
        snapshot = _debts_snapshot_locked()
        snapshot["selected_id"] = user_id
        return jsonify(snapshot)


@app.post("/api/debts/entries")
@debts_owner_required
def debts_entry_create_api():
    payload = request.get_json(silent=True) or {}
    user_id = str(payload.get("user_id") or "")
    kind = str(payload.get("kind") or "debt")
    if kind not in ("debt", "return"):
        return jsonify(error="Неверный тип записи."), 400
    try:
        amount_cents = _debt_amount_cents(payload.get("amount"))
        entry_date = _debt_clean_date(payload.get("date"))
    except ValueError as err:
        return jsonify(error=str(err)), 400
    comment = str(payload.get("comment") or "").strip()[:220] or "—"
    now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")

    with debts_lock:
        if not any(u.get("id") == user_id for u in debts_data["users"]):
            return jsonify(error="Выберите человека."), 400
        debts_data["entries"].append({
            "id": uuid.uuid4().hex,
            "user_id": user_id,
            "kind": kind,
            "date": entry_date,
            "amount_cents": amount_cents,
            "comment": comment,
            "created": now,
        })
        _debts_write_locked()
        return jsonify(_debts_snapshot_locked())


@app.delete("/api/debts/entries/<entry_id>")
@debts_owner_required
def debts_entry_delete_api(entry_id):
    with debts_lock:
        before = len(debts_data["entries"])
        debts_data["entries"] = [e for e in debts_data["entries"] if e.get("id") != entry_id]
        if len(debts_data["entries"]) == before:
            return jsonify(error="Запись не найдена."), 404
        _debts_write_locked()
        return jsonify(_debts_snapshot_locked())


@app.get("/api/debts/me")
def debts_me_api():
    user_id = session.get("debtor_id")
    if not user_id:
        return jsonify(error="Нужен вход."), 403
    with debts_lock:
        user = next((u for u in debts_data["users"] if u.get("id") == user_id), None)
        if not user:
            session.pop("debtor_id", None)
            return jsonify(error="Пользователь не найден."), 404
        snapshot = _debts_snapshot_locked(user_id)
        snapshot["me"] = _debt_user_public_locked(user)
        return jsonify(snapshot)


@app.delete("/api/debts/users/<user_id>")
@debts_owner_required
def debts_user_delete_api(user_id):
    with debts_lock:
        before = len(debts_data["users"])
        debts_data["users"] = [u for u in debts_data["users"] if u.get("id") != user_id]
        if len(debts_data["users"]) == before:
            return jsonify(error="Пользователь не найден."), 404
        debts_data["entries"] = [e for e in debts_data["entries"] if e.get("user_id") != user_id]
        _debts_write_locked()
        return jsonify(_debts_snapshot_locked())


@app.post("/api/debts/users/<user_id>/password")
@debts_owner_required
def debts_user_password_api(user_id):
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password.strip()) < 3:
        return jsonify(error="Пароль должен быть хотя бы 3 символа."), 400
    password = password.strip()
    if password_matches(password):
        return jsonify(error="Не используй пароль владельца для должника."), 400
    salt, password_hash = _debt_hash_password(password)
    with debts_lock:
        user = next((u for u in debts_data["users"] if u.get("id") == user_id), None)
        if not user:
            return jsonify(error="Пользователь не найден."), 404
        if any(u.get("id") != user_id and _debt_password_matches(u, password) for u in debts_data["users"]):
            return jsonify(error="Такой пароль уже занят."), 400
        user["password_plain"] = password
        user["salt"] = salt
        user["password_hash"] = password_hash
        _debts_write_locked()
        return jsonify(_debts_snapshot_locked())


@app.get("/debts/me")
@debtor_required
def debts_me_page():
    return _debts_page_html(owner=False)


@app.get("/debts")
@login_required
def debts_page():
    return _debts_page_html(owner=True)


def _debts_page_html(owner=True):
    mode = "owner" if owner else "debtor"
    title = "Долги" if owner else "Мои долги"
    back_href = "/cabinet" if owner else "/"
    owner_unlocked = owner and _debts_owner_unlocked()
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>{title} · vitazgio.ru</title>
  <style>
    :root{{--bg:#08111f;--panel:#0c1628;--line:#1d3151;--text:#f4fbff;--muted:#8aa2c7;--cyan:#35e0f0;--green:#63f5ad;--pink:#ff4fb3;--yellow:#f6c04a;}}
    *{{box-sizing:border-box}} body{{margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0,#142947 0,#08111f 46%,#060b14 100%);color:var(--text);font:15px/1.45 "Segoe UI",Arial,sans-serif;}}
    body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(transparent 96%,rgba(53,224,240,.08) 97%);background-size:100% 4px;opacity:.45}}
    a{{color:inherit}} button,input,select{{font:inherit}} .wrap{{width:min(1480px,calc(100vw - 56px));margin:0 auto;padding:36px 0 54px;position:relative;z-index:1}}
    .head{{display:flex;align-items:center;gap:18px;margin-bottom:28px}} .back{{width:44px;height:44px;border-radius:50%;border:1px solid rgba(53,224,240,.55);display:grid;place-items:center;text-decoration:none;color:var(--cyan);background:rgba(53,224,240,.08);font-size:25px}}
    h1{{margin:0;font-size:clamp(34px,4vw,58px);line-height:1;font-weight:900;letter-spacing:0}} h1 span{{color:var(--cyan);text-shadow:0 0 22px rgba(53,224,240,.35)}} .tag{{margin-left:auto;color:var(--green);font-weight:800;text-transform:uppercase;letter-spacing:.08em;font-size:12px}}
    .unlock{{max-width:520px;border:1px solid var(--line);background:rgba(12,22,40,.82);padding:26px;margin-top:58px;box-shadow:inset 3px 0 0 var(--cyan)}} .unlock h2,.panel h2{{margin:0 0 10px;font-size:22px}} .muted{{color:var(--muted)}} .hidden{{display:none!important}}
    .grid{{display:grid;grid-template-columns:330px 1fr;gap:18px}} .panel{{border:1px solid var(--line);background:rgba(12,22,40,.78);padding:20px;min-width:0}} .panel.accent{{box-shadow:inset 3px 0 0 var(--cyan)}}
    .total{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:18px}} .stat{{border:1px solid var(--line);background:rgba(7,14,27,.82);padding:16px}} .stat b{{display:block;font-size:28px;color:var(--cyan)}} .stat i{{font-style:normal;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}}
    form{{display:grid;gap:10px}} label{{display:grid;gap:6px;color:#b8c8e8;font-weight:800;font-size:12px;text-transform:uppercase;letter-spacing:.06em}} input,select{{width:100%;border:1px solid #28405f;background:#071021;color:var(--text);padding:11px 12px;outline:none}} input:focus,select:focus{{border-color:var(--cyan);box-shadow:0 0 0 2px rgba(53,224,240,.14)}} .row{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
    .btn{{border:1px solid rgba(53,224,240,.7);background:rgba(53,224,240,.16);color:var(--text);padding:11px 14px;font-weight:900;cursor:pointer}} .btn:hover{{background:rgba(53,224,240,.24)}} .btn.danger{{border-color:rgba(255,79,179,.55);background:rgba(255,79,179,.12)}} .btn.small{{padding:7px 9px;font-size:12px}}
    .people{{display:grid;gap:8px;margin:16px 0}} .person{{border:1px solid #223956;background:#081427;color:var(--text);padding:12px;text-align:left;cursor:pointer;display:grid;gap:4px}} .person.active{{border-color:var(--cyan);box-shadow:inset 3px 0 0 var(--cyan)}} .person b{{font-size:16px}} .person i{{font-style:normal;color:var(--muted);font-size:12px}}
    .pass-box{{border-top:1px solid #1a2d49;margin-top:14px;padding-top:14px;display:grid;gap:10px}}
    .entry-form{{grid-template-columns:1.1fr .8fr .8fr 1.4fr auto;align-items:end;margin-bottom:18px}} .history{{width:100%;border-collapse:collapse}} .history th,.history td{{border-bottom:1px solid #1a2d49;padding:11px 8px;text-align:left;vertical-align:top}} .history th{{color:#86a1cc;font-size:12px;text-transform:uppercase;letter-spacing:.08em}} .sum{{font-weight:900;color:var(--cyan);white-space:nowrap}} .sum.minus{{color:var(--green)}} .empty{{padding:28px;border:1px dashed #294260;color:var(--muted);text-align:center}}
    .err{{min-height:20px;color:#ff7aa9;font-weight:800}} .ok{{color:var(--green)}} .debtor-card{{max-width:960px;margin:auto}} .debtor-card .history{{margin-top:16px}}
    @media (max-width:980px){{.wrap{{width:min(100vw - 24px,760px);padding-top:20px}}.grid{{grid-template-columns:1fr}}.total{{grid-template-columns:1fr}}.entry-form{{grid-template-columns:1fr}}.tag{{display:none}}}}
  </style>
</head>
<body data-mode="{mode}">
  <main class="wrap">
    <header class="head"><a class="back" href="{back_href}" aria-label="Назад">‹</a><h1>{title.split()[0]} <span>{' '.join(title.split()[1:])}</span></h1><div class="tag">vitazgio.ru</div></header>

    <section class="unlock" id="unlock" {'hidden' if not owner or owner_unlocked else ''}>
      <h2>Ежедневный пароль</h2>
      <p class="muted">Вход в управление долгами закрыт тем же дневным паролем, что и запоминание устройств.</p>
      <form id="unlock-form"><input id="unlock-pass" type="password" autocomplete="off" placeholder="Пароль на сегодня"><button class="btn" type="submit">Открыть</button><div class="err" id="unlock-err"></div></form>
    </section>

    <section id="owner-app" class="grid {'hidden' if not owner or not owner_unlocked else ''}">
      <aside class="panel accent">
        <h2>Люди</h2>
        <form id="user-form">
          <label>Имя<input id="user-name" maxlength="60" autocomplete="off"></label>
          <label>Пароль для входа<input id="user-pass" type="password" autocomplete="new-password"></label>
          <button class="btn" type="submit">Создать</button>
          <div class="err" id="user-err"></div>
        </form>
        <div class="people" id="people"></div>
        <form class="pass-box" id="pass-form" hidden>
          <label>Пароль выбранного<input id="edit-pass" autocomplete="off" placeholder="старый скрыт — задай новый"></label>
          <button class="btn small" type="submit">Сохранить пароль</button>
          <div class="err" id="pass-err"></div>
        </form>
        <button class="btn danger small" id="delete-user" type="button">Удалить выбранного</button>
      </aside>
      <section>
        <div class="total">
          <div class="stat"><i>общий долг</i><b id="total-all">0</b></div>
          <div class="stat"><i>выбранный</i><b id="total-user">0</b></div>
          <div class="stat"><i>записей</i><b id="entry-count">0</b></div>
        </div>
        <div class="panel">
          <h2>Добавить строку</h2>
          <form class="entry-form" id="entry-form">
            <label>Дата<input id="entry-date" type="date"></label>
            <label>Тип<select id="entry-kind"><option value="debt">Долг</option><option value="return">Вернул</option></select></label>
            <label>Сумма<input id="entry-amount" inputmode="decimal" placeholder="450"></label>
            <label>Комментарий<input id="entry-comment" maxlength="220" placeholder="если пусто — прочерк"></label>
            <button class="btn" type="submit">Записать</button>
          </form>
          <div class="err" id="entry-err"></div>
          <div id="history"></div>
        </div>
      </section>
    </section>

    <section id="debtor-app" class="panel accent debtor-card {'hidden' if owner else ''}">
      <div class="total">
        <div class="stat"><i>к оплате</i><b id="me-total">0</b></div>
        <div class="stat"><i>записей</i><b id="me-count">0</b></div>
        <div class="stat"><i>режим</i><b>просмотр</b></div>
      </div>
      <h2 id="me-name">История</h2>
      <div id="me-history"></div>
    </section>
  </main>
  <script>
  (() => {{
    "use strict";
    const mode = document.body.dataset.mode;
    const $ = id => document.getElementById(id);
    const esc = s => String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
    const money = cents => {{
      const sign = cents < 0 ? "-" : "";
      const value = Math.abs(cents || 0) / 100;
      return sign + value.toLocaleString("ru-RU", {{minimumFractionDigits: 0, maximumFractionDigits: 2}}) + " ₽";
    }};
    let data = {{users:[],entries:[],total_cents:0,today:""}};
    let selected = null;

    async function api(path, opts={{}}) {{
      const response = await fetch(path, {{
        credentials: "same-origin",
        headers: {{"Content-Type":"application/json"}},
        ...opts
      }});
      const result = await response.json().catch(() => ({{}}));
      if (!response.ok) throw new Error(result.error || "Ошибка сервера.");
      return result;
    }}

    function rowHtml(entry, canDelete) {{
      const cls = entry.kind === "return" ? "sum minus" : "sum";
      const label = entry.kind === "return" ? "вернул" : "долг";
      return `<tr><td>${{esc(entry.date)}}</td><td>${{esc(entry.user_name)}}</td><td>${{label}}</td><td class="${{cls}}">${{money(entry.kind === "return" ? -entry.amount_cents : entry.amount_cents)}}</td><td>${{esc(entry.comment || "—")}}</td><td>${{canDelete ? `<button class="btn danger small" data-del="${{esc(entry.id)}}">удалить</button>` : ""}}</td></tr>`;
    }}

    function tableHtml(entries, canDelete) {{
      if (!entries.length) return `<div class="empty">Пока нет записей.</div>`;
      return `<table class="history"><thead><tr><th>Дата</th><th>Кто</th><th>Тип</th><th>Сумма</th><th>Комментарий</th><th></th></tr></thead><tbody>${{entries.map(e => rowHtml(e, canDelete)).join("")}}</tbody></table>`;
    }}

    function renderOwner() {{
      if (!selected && data.users.length) selected = data.users[0].id;
      if (selected && !data.users.some(u => u.id === selected)) selected = data.users[0]?.id || null;
      $("total-all").textContent = money(data.total_cents);
      $("entry-count").textContent = String(data.entries.length);
      const active = data.users.find(u => u.id === selected);
      $("total-user").textContent = active ? money(active.total_cents) : "0 ₽";
      $("people").innerHTML = data.users.length ? data.users.map(u => `<button class="person ${{u.id === selected ? "active" : ""}}" data-user="${{esc(u.id)}}" type="button"><b>${{esc(u.name)}}</b><i>${{money(u.total_cents)}} · пароль: ${{esc(u.password || "скрыт")}} · записей: ${{u.entry_count}}</i></button>`).join("") : `<div class="empty">Создай первого человека.</div>`;
      $("pass-form").hidden = !active;
      if (active) $("edit-pass").value = active.password || "";
      const shown = selected ? data.entries.filter(e => e.user_id === selected) : data.entries;
      $("history").innerHTML = tableHtml(shown, true);
      $("entry-date").value = data.today || new Date().toISOString().slice(0,10);
    }}

    async function loadOwner() {{
      data = await api("/api/debts");
      renderOwner();
    }}

    async function loadDebtor() {{
      const me = await api("/api/debts/me");
      $("me-total").textContent = money(me.me.total_cents);
      $("me-count").textContent = String(me.entries.length);
      $("me-name").textContent = me.me.name;
      $("me-history").innerHTML = tableHtml(me.entries, false);
    }}

    if (mode === "owner") {{
      $("unlock-form")?.addEventListener("submit", async e => {{
        e.preventDefault();
        $("unlock-err").textContent = "";
        try {{
          await api("/api/debts/unlock", {{method:"POST", body:JSON.stringify({{password:$("unlock-pass").value}})}});
          $("unlock").classList.add("hidden");
          $("owner-app").classList.remove("hidden");
          await loadOwner();
        }} catch (err) {{
          $("unlock-err").textContent = err.message;
        }}
      }});
      $("user-form").addEventListener("submit", async e => {{
        e.preventDefault();
        $("user-err").textContent = "";
        try {{
          data = await api("/api/debts/users", {{method:"POST", body:JSON.stringify({{name:$("user-name").value, password:$("user-pass").value}})}});
          $("user-name").value = ""; $("user-pass").value = "";
          selected = data.selected_id || selected;
          renderOwner();
        }} catch (err) {{ $("user-err").textContent = err.message; }}
      }});
      $("entry-form").addEventListener("submit", async e => {{
        e.preventDefault();
        $("entry-err").textContent = "";
        try {{
          data = await api("/api/debts/entries", {{method:"POST", body:JSON.stringify({{user_id:selected, date:$("entry-date").value, kind:$("entry-kind").value, amount:$("entry-amount").value, comment:$("entry-comment").value}})}});
          $("entry-amount").value = ""; $("entry-comment").value = ""; $("entry-kind").value = "debt";
          renderOwner();
        }} catch (err) {{ $("entry-err").textContent = err.message; }}
      }});
      $("people").addEventListener("click", e => {{
        const btn = e.target.closest("[data-user]");
        if (!btn) return;
        selected = btn.dataset.user;
        renderOwner();
      }});
      $("pass-form").addEventListener("submit", async e => {{
        e.preventDefault();
        if (!selected) return;
        $("pass-err").textContent = "";
        try {{
          data = await api("/api/debts/users/" + encodeURIComponent(selected) + "/password", {{method:"POST", body:JSON.stringify({{password:$("edit-pass").value}})}});
          renderOwner();
        }} catch (err) {{ $("pass-err").textContent = err.message; }}
      }});
      $("history").addEventListener("click", async e => {{
        const btn = e.target.closest("[data-del]");
        if (!btn) return;
        data = await api("/api/debts/entries/" + encodeURIComponent(btn.dataset.del), {{method:"DELETE"}});
        renderOwner();
      }});
      $("delete-user").addEventListener("click", async () => {{
        if (!selected || !confirm("Удалить человека и всю его историю?")) return;
        data = await api("/api/debts/users/" + encodeURIComponent(selected), {{method:"DELETE"}});
        selected = null;
        renderOwner();
      }});
      if (!$("owner-app").classList.contains("hidden")) loadOwner().catch(err => $("entry-err").textContent = err.message);
    }} else {{
      loadDebtor().catch(err => $("me-history").innerHTML = `<div class="empty">${{esc(err.message)}}</div>`);
    }}
  }})();
  </script>
</body>
</html>"""


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
            {"id": k, "name": v["name"], "parent": v.get("parent", ""),
             "fav": bool(v.get("fav"))}
            for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower())
        ]
        fav_folder = next((k for k, v in music_folders.items() if v.get("fav")), "")
    # Место общее с дропом: показываем занятое всем хранилищем из 30 ГБ.
    drop_used = _drop_used_safe()
    return jsonify(tracks=tracks, folders=folders,
                   used=drop_used + used, music=used, quota=DROP_QUOTA,
                   limit=MUSIC_MAX_SIZE, fav_folder=fav_folder,
                   can_edit=bool(session.get("authenticated")))


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
    drop_used = _drop_used_safe()          # место общее с дропом (30 ГБ)
    with music_lock:
        _music_scan()
        if drop_used + _music_used() > DROP_QUOTA:
            return jsonify(error="В хранилище больше нет места."), 507
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
        if "fav" in payload:
            # Избранная папка одна на всю фонотеку: ставим звезду этой,
            # снимаем со всех остальных. Она открывается при заходе и она же
            # играет в мини-плеере кабинета.
            if payload.get("fav"):
                for f in music_folders.values():
                    f["fav"] = False
                folder["fav"] = True
            else:
                folder["fav"] = False
        _music_write_index()
        return jsonify(ok=True, name=folder["name"], parent=folder.get("parent", ""),
                       fav=bool(folder.get("fav")))


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
    # Папка внутри MUSIK — это папка ФОНОТЕКИ, а не склад дропа. MUSIK
    # показывает не свои вложения, а папки фонотеки (id с «mf_»), поэтому
    # обычная папка дропа тут просто не показалась бы — «создал, а её нет».
    # Заводим настоящую папку фонотеки, туда же потом лягут загруженные треки.
    if parent == DROP_MUSIK_ID or (parent or "").startswith("mf_"):
        inside = "" if parent == DROP_MUSIK_ID else parent[3:]
        with music_lock:
            if inside and inside not in music_folders:
                inside = ""
            if _music_folder_depth(inside) >= MUSIC_MAX_DEPTH:
                return jsonify(error="Глубже вкладывать некуда."), 400
            fid = str(uuid.uuid4())
            music_folders[fid] = {"name": name, "parent": inside, "added": time.time()}
            _music_write_index()
        return jsonify(id="mf_" + fid, name=name)
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
    music_used = _music_used_safe()        # музыка тоже в общем лимите 30 ГБ
    with drop_lock:
        _drop_sweep_uploads()
        # MUSIK и папки внутри неё — приёмник фонотеки, а не склад дропа
        if not music_target and parent and drop_items.get(parent, {}).get("kind") != "folder":
            parent = None
        reserved = sum(u["size"] for u in drop_uploads.values())
        if _drop_used() + music_used + reserved + size > DROP_QUOTA:
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
    music_used = _music_used_safe()        # музыка тоже в общем лимите 30 ГБ
    with drop_lock:
        if _drop_used() + music_used + actual > DROP_QUOTA:
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
    # Место общее с дропом: дроп занят + вся музыка + новый файл против 30 ГБ.
    drop_used = _drop_used_safe()
    with music_lock:
        if drop_used + _music_used() + size > DROP_QUOTA:
            _music_unlink(tmp_path)
            return jsonify(error="В хранилище кончилось место."), 507
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
        music_used = _music_used()
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
        used, trash = _drop_used() + music_used, _drop_trash_bytes()
    return jsonify(items=items,
                   breadcrumbs=[{"id": DROP_MUSIK_ID, "name": "MUSIK"}] + chain,
                   used=used, music=music_used, quota=DROP_QUOTA, trash=trash,
                   music_view=True)


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
    music_used = _music_used_safe()        # музыка делит хранилище с дропом
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
            used=_drop_used() + music_used,
            music=music_used,
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
    html = (Path(__file__).parent / "templates" / "cabinet.html").read_text(encoding="utf-8")
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

    html = (Path(__file__).parent / "templates" / "themes.html").read_text(encoding="utf-8")
    return html.replace("__NODES__", "".join(cards)) \
               .replace("__ICONLINKS__", ICON_LINKS)


@app.get("/drop")
@login_required
def drop_page():
    html = (Path(__file__).parent / "templates" / "drop.html").read_text(encoding="utf-8")
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
    html = (Path(__file__).parent / "templates" / "notebook.html").read_text(encoding="utf-8")
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
    в папке MUSIK личного дропа. У каждого трека свой адрес потока.

    Выбор папки: без параметра играет избранная папка (звезда) или вся
    музыка. `?folder=<id>` — конкретная папка фонотеки с подпапками;
    `?folder=__all__` — вся музыка вопреки избранному. В ответе ещё и всё
    дерево папок (`folders`) — по нему плеер рисует выбор папок."""
    pick = (request.args.get("folder") or "").strip()
    tracks = []
    with music_lock:
        _music_scan()
        folder_name = {k: v["name"] for k, v in music_folders.items()}
        folders = [{"id": k, "name": v["name"], "parent": v.get("parent", "")}
                   for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower())]
        fav_id = next((k for k, v in music_folders.items() if v.get("fav")), "")
        if pick and pick in music_folders:
            allowed = _music_subtree(pick)          # выбрали конкретную папку
        elif pick == "__all__":
            allowed = None                          # вся музыка
        elif fav_id:
            allowed = _music_subtree(fav_id)        # избранная по умолчанию
        else:
            allowed = None                          # избранной нет — вся музыка
        for k, v in sorted(music_items.items(),
                           key=lambda x: (str(x[1].get("artist", "")).lower(),
                                          str(x[1].get("title", "")).lower())):
            if allowed is not None and v.get("folder", "") not in allowed:
                continue
            tracks.append({
                "id": "m_" + k, "title": v["title"], "artist": v["artist"],
                "folder": folder_name.get(v.get("folder", ""), ""),
                "url": "/api/music/file/" + k,
            })
    # Папку MUSIK из дропа (аудио, лежащее прямо в дропе) добавляем только
    # когда показываем всю музыку — при выборе конкретной папки её не мешаем.
    if allowed is None:
        with drop_lock:
            tracks.extend(_drop_musik_tracks())
    return jsonify(tracks=tracks, folders=folders, fav=fav_id, pick=pick)


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
    js = (Path(__file__).parent / "templates" / "vg_player.js.tpl").read_text(encoding="utf-8")
    response = Response(js, mimetype="application/javascript; charset=utf-8")
    # Движок ОБЯЗАН перепроверяться при каждой загрузке страницы, а не жить
    # своей жизнью в кэше. Раньше стояло max-age=300 без ETag: после деплоя
    # страница приезжала новая (её кнопки зовут VGP.popOut), а движок браузер
    # ещё пять минут брал старый, из кэша, где popOut ещё не было. Кнопка
    # «вынести в окно» при этом молча падала с «popOut is not a function».
    # no-cache — это не «не кэшировать», а «кэшируй, но каждый раз спрашивай»:
    # ETag не изменился — прилетает пустой 304, трафика столько же.
    response.set_etag(hashlib.md5(js.encode("utf-8")).hexdigest())
    response.headers["Cache-Control"] = "private, no-cache"
    return response.make_conditional(request)


@app.get("/player/pop")
@login_required
def player_pop_page():
    """Плеер в настоящем отдельном окне браузера — «вынести» из виджета.

    Раньше «вынести поверх экрана» значило Document Picture-in-Picture:
    красиво, но окно живёт вместе со вкладкой-открывашкой и закрывается
    (а с ним и звук), стоит там перейти на другую страницу сайта — обычная
    многостраничная навигация именно так и работает. Здесь — обычное
    window.open на отдельный адрес: это настоящее отдельное окно, вкладка
    его не касается, что бы там дальше ни открывали. Тот же движок
    (vg-player.js), просто с флагом VGP_POPUP — сам разворачивается на весь
    вьюпорт окна и всегда виден, без сворачивания в кружок."""
    html = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Плеер · vitazgio.ru</title>
<link rel="icon" href="/icon-32.png">
<style>
  html, body { margin: 0; height: 100%; background: #0b0f18; overflow: hidden; }
</style>
</head>
<body>
<script>window.VGP_POPUP = true;</script>
<script src="/vg-player.js"></script>
</body>
</html>"""
    return Response(html, mimetype="text/html; charset=utf-8")


@app.get("/claude")
@login_required
def claude_page():
    """Разговор с Claude Code через сайт.

    Страница ничего сама не решает: она рисует вкладки и терминал, а всё
    остальное происходит на домашней машине. Закрыл вкладку браузера — разговор
    остался висеть в tmux и ждёт возвращения."""
    g.frameable = True
    html = """<!doctype html>
    <html lang="ru" data-net="%%NET%%">
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
    html = (Path(__file__).parent / "templates" / "diy.html").read_text(encoding="utf-8")
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
# Известные рабочие бесплатные модели на разных провайдерах: держим их как
# первый эшелон, если из .env ничего не задано. Список пополняется живым
# ответом от /api/v1/models — тем моделям, у которых prompt/completion == 0.
OPENROUTER_FALLBACKS = [
    "minimax/minimax-m3:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "openrouter/auto",                    # роутер сам выберет живую бесплатную
    "qwen/qwen3-coder:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "google/gemma-3-27b-it:free",
    "google/gemma-2-9b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "openai/gpt-oss-120b:free",
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-chat-v3.1:free",   # вдруг вернутся
    "deepseek/deepseek-r1:free",
]
_ai_active_model = OPENROUTER_MODEL
_ai_active_lock = threading.Lock()
_ai_discovered = []            # что вернул /models на прошлом запросе
_ai_discovered_at = 0
_AI_DISCOVER_TTL = 900          # секунд между обращениями к каталогу


def _ai_discover():
    """Смотрит каталог OpenRouter и запоминает id всех бесплатных моделей."""
    global _ai_discovered, _ai_discovered_at
    if not OPENROUTER_KEY:
        return []
    if time.time() - _ai_discovered_at < _AI_DISCOVER_TTL and _ai_discovered:
        return _ai_discovered
    from urllib import request as urlrequest, error as urlerror
    base = OPENROUTER_URL.rsplit("/chat/completions", 1)[0]
    req = urlrequest.Request(base + "/models",
                             headers={"Authorization": "Bearer " + OPENROUTER_KEY})
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urlerror.URLError, ValueError, OSError):
        return _ai_discovered
    free = []
    for m in data.get("data", []):
        pr = m.get("pricing") or {}
        try:
            if float(pr.get("prompt", 0)) == 0 and float(pr.get("completion", 0)) == 0:
                mid = m.get("id")
                if mid:
                    free.append(mid)
        except (TypeError, ValueError):
            continue
    if free:
        _ai_discovered = free
        _ai_discovered_at = time.time()
    return _ai_discovered


def _ai_models_to_try(primary):
    """Порядок: сначала указанная (из .env или прошлая удачная), затем
    живой каталог бесплатных, потом наши запасные, без повторов."""
    seen, order = set(), []
    def add(m):
        if m and m not in seen:
            seen.add(m); order.append(m)
    add(primary)
    for m in _ai_discover():
        add(m)
    for m in OPENROUTER_FALLBACKS:
        add(m)
    return order
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
AI_IMG_COUNT_MAX = 6                # столько фото за одну реплику
AI_PDF_MAX = 8 * 1024 * 1024        # исходный файл
AI_PDF_TEXT_MAX = 6000              # столько текста из PDF отдаём модели
AI_SYS_PROMPT = ("Ты дружелюбный и толковый собеседник на личном сайте. "
                 "Отвечай по-русски, живо и по делу. Просят код — давай рабочий "
                 "и с коротким пояснением.")

os.makedirs(AI_IMG_DIR, exist_ok=True)
ai_data: dict = {"chats": [], "folders": []}
ai_lock = threading.Lock()
AI_FOLDERS_MAX = 40


def _ai_load():
    try:
        with open(AI_CHAT_PATH, encoding="utf-8") as fh:
            saved = json.load(fh) or {}
        ai_data["chats"] = saved.get("chats", [])
        ai_data["folders"] = saved.get("folders", [])
    except (OSError, ValueError):
        pass
    for c in ai_data["chats"]:
        c.setdefault("folder", "")


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
            "model": c.get("model", OPENROUTER_MODEL), "folder": c.get("folder", ""),
            "pinned": bool(c.get("pinned"))}


def _ai_wants_reasoning(model_id):
    """Показ размышлений просим только у моделей, которые их реально умеют
    (MiniMax, NVIDIA/Nemotron) — остальным лишний параметр может не
    понравиться, а откатной список моделей общий для всех сетей."""
    return bool(re.search(r"minimax|nemotron|nvidia", model_id or "", re.I))


def _ai_smart_title(text):
    """Короткий заголовок из первой реплики: без markdown-мусора, обрезан по
    границе слова, а не насрединеслова."""
    t = re.sub(r"[`*_#>\[\]]", "", (text or "")).strip()
    t = re.sub(r"\s+", " ", t)
    if not t:
        return ""
    if len(t) <= 60:
        return t
    cut = t[:60]
    sp = cut.rfind(" ")
    if sp > 30:
        cut = cut[:sp]
    return cut.strip() + "…"


def _ai_pdf_extract(raw):
    """Вытаскивает текст из PDF для моделей без своего PDF-чтения. Ограничено
    по длине — иначе один документ съест весь контекст разговора."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        parts, total = [], 0
        for page in reader.pages:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            if t:
                parts.append(t)
                total += len(t)
            if total >= AI_PDF_TEXT_MAX:
                break
        text = "\n".join(parts).strip()
        if len(text) > AI_PDF_TEXT_MAX:
            text = text[:AI_PDF_TEXT_MAX].rstrip() + "…[обрезано]"
        return text
    except Exception:
        return ""


def _ai_find_folder(fid):
    for f in ai_data["folders"]:
        if f.get("id") == fid:
            return f
    return None


def _ai_img_path(img_id):
    return os.path.join(AI_IMG_DIR, img_id)


def _ai_store_image(data_url):
    """Разбирает data:image-URL, сохраняет файл на диск, возвращает
    (id, base64) или (None, None), если картинка кривая/слишком большая."""
    m = re.match(r"^data:image/(?:png|jpe?g|webp);base64,(.+)$", data_url or "", re.I)
    if not m:
        return None, None
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:                                        # noqa: BLE001
        return None, None
    if not raw or len(raw) > AI_IMG_MAX:
        return None, None
    img_id = uuid.uuid4().hex[:16] + ".jpg"
    try:
        with open(_ai_img_path(img_id), "wb") as fh:
            fh.write(raw)
    except OSError:
        return None, None
    return img_id, base64.b64encode(raw).decode("ascii")


def _ai_msg_imgs(m):
    """Все id картинок сообщения — новый список imgs плюс старое одиночное img."""
    ids = list(m.get("imgs") or [])
    if m.get("img") and m["img"] not in ids:
        ids.append(m["img"])
    return ids


def _ai_drop_images(chat):
    for m in chat.get("messages", []):
        for iid in _ai_msg_imgs(m):
            try:
                os.remove(_ai_img_path(iid))
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
    """Готовность, список прошлых чатов и папок — страница спрашивает при открытии."""
    with ai_lock:
        cards = [_ai_card(c) for c in ai_data["chats"]]
        folders = [{"id": f["id"], "name": f.get("name", ""), "created": f.get("created", 0)}
                   for f in ai_data["folders"]]
    cards.sort(key=lambda x: x["updated"], reverse=True)
    folders.sort(key=lambda x: x["created"])
    with _ai_active_lock:
        active = _ai_active_model
    return jsonify(ready=_ai_ready(), model=active,
                   vision=bool(OPENROUTER_VISION_MODEL), chats=cards, folders=folders)


@app.get("/api/ai/chat/<chat_id>")
@login_required
def ai_chat_get(chat_id):
    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        msgs = [{"role": m.get("role"), "text": m.get("text", ""),
                 "imgs": _ai_msg_imgs(m), "model": m.get("model") or "",
                 "pdf_name": m.get("pdf_name") or "", "ts": m.get("ts", 0),
                 "reasoning": m.get("reasoning") or "",
                 "reasoning_secs": m.get("reasoning_secs") or 0}
                for m in c.get("messages", [])]
        title = c.get("title") or "Новый чат"
    return jsonify(id=chat_id, title=title, messages=msgs)


@app.post("/api/ai/chat")
@login_required
def ai_chat_new():
    cid = uuid.uuid4().hex[:12]
    now = time.time()
    chat = {"id": cid, "title": "", "model": OPENROUTER_MODEL, "folder": "",
            "pinned": False, "created": now, "updated": now, "messages": []}
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
    """Переименовать чат и/или переложить его в другую папку (folder="" — вон из папки)."""
    payload = request.get_json(silent=True) or {}
    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        if "title" in payload:
            c["title"] = (payload.get("title") or "").strip()[:80]
        if "folder" in payload:
            fid = (payload.get("folder") or "").strip()
            if fid and not _ai_find_folder(fid):
                return jsonify(error="Папка не найдена."), 404
            c["folder"] = fid
        if "pinned" in payload:
            c["pinned"] = bool(payload.get("pinned"))
        _ai_write()
    return jsonify(ok=True, title=c.get("title") or "Новый чат",
                   folder=c.get("folder", ""), pinned=bool(c.get("pinned")))


@app.get("/api/ai/folder")
@login_required
def ai_folder_list():
    with ai_lock:
        folders = [{"id": f["id"], "name": f.get("name", "")} for f in ai_data["folders"]]
    return jsonify(folders=folders)


@app.post("/api/ai/folder")
@login_required
def ai_folder_new():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:40]
    if not name:
        return jsonify(error="Название папки не может быть пустым."), 400
    fid = uuid.uuid4().hex[:10]
    with ai_lock:
        if len(ai_data["folders"]) >= AI_FOLDERS_MAX:
            return jsonify(error="Слишком много папок."), 400
        ai_data["folders"].append({"id": fid, "name": name, "created": time.time()})
        _ai_write()
    return jsonify(id=fid, name=name)


@app.patch("/api/ai/folder/<fid>")
@login_required
def ai_folder_rename(fid):
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()[:40]
    if not name:
        return jsonify(error="Название папки не может быть пустым."), 400
    with ai_lock:
        f = _ai_find_folder(fid)
        if not f:
            return jsonify(error="Папка не найдена."), 404
        f["name"] = name
        _ai_write()
    return jsonify(ok=True, name=name)


@app.delete("/api/ai/folder/<fid>")
@login_required
def ai_folder_delete(fid):
    """Удаляет папку. Чаты внутри не трогаем — просто выкладываем их обратно
    в общий список (folder=""), чтобы удаление папки не роняло разговоры."""
    with ai_lock:
        f = _ai_find_folder(fid)
        if not f:
            return jsonify(error="Папка не найдена."), 404
        ai_data["folders"] = [x for x in ai_data["folders"] if x is not f]
        for c in ai_data["chats"]:
            if c.get("folder") == fid:
                c["folder"] = ""
        _ai_write()
    return jsonify(ok=True)


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


def _ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model):
    """Строит сообщения для OpenRouter и возвращает функцию-генератор SSE.
    Общий код для отправки нового сообщения и для «Перегенерировать».

    Если клиент оборвал соединение (кнопка «Стоп»), генератор получает
    GeneratorExit прямо на текущем yield — ловим это в finally и всё равно
    сохраняем то, что успели получить: иначе после «Стоп» история чата
    разъезжалась бы с тем, что человек реально увидел на экране."""
    api_msgs = [{"role": "system", "content": AI_SYS_PROMPT}]
    last = ctx[-1] if ctx else None
    for msg in ctx:
        if msg is last and use_vision and imgs_b64:
            content = []
            if msg.get("text"):
                content.append({"type": "text", "text": msg["text"]})
            for b64 in imgs_b64:
                content.append({"type": "image_url", "image_url": {
                    "url": "data:image/jpeg;base64," + b64}})
            api_msgs.append({"role": "user", "content": content})
        else:
            body = msg.get("text", "")
            if msg.get("pdf_text"):
                # PDF когда-то приложили к этой реплике — модель без своего
                # чтения PDF получает вытащенный текст прямо в сообщении,
                # так разговор про документ продолжается и на следующих ходах.
                body = (f"[Файл: {msg.get('pdf_name') or 'документ.pdf'}]\n"
                        f"{msg['pdf_text']}\n\n{body}").strip()
            if not body and _ai_msg_imgs(msg):
                body = "[фото]"
            api_msgs.append({"role": msg.get("role", "user"), "content": body})

    def _body_for(candidate):
        body = {"model": candidate, "messages": api_msgs, "stream": True,
                "max_tokens": AI_REPLY_TOKENS}
        # Показ размышлений просим только у моделей, которые их реально
        # умеют (MiniMax, NVIDIA/Nemotron) — остальным лишний параметр
        # может не понравиться, а откатной список моделей общий.
        if _ai_wants_reasoning(candidate):
            body["reasoning"] = {"enabled": True}
        return json.dumps(body).encode("utf-8")

    req_body = _body_for(model)

    def save_reply(full, used_model, reasoning="", reasoning_secs=0):
        with ai_lock:
            cc = _ai_find(chat_id)
            if cc is not None:
                msg = {"role": "assistant", "text": full, "model": used_model, "ts": time.time()}
                if reasoning:
                    msg["reasoning"] = reasoning
                    msg["reasoning_secs"] = reasoning_secs
                cc.setdefault("messages", []).append(msg)
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
        if requested_model:
            # Вкладка назвала свою модель. Ставим её первой, но если она
            # молчит — дальше по общему списку, чтобы чат не встал колом.
            candidates = _ai_models_to_try(requested_model)
        elif use_vision:
            candidates = [model]
        else:
            candidates = _ai_models_to_try(primary)
        resp = None
        chosen = candidates[0]
        for candidate in candidates:
            body_try = req_body if candidate == model else _body_for(candidate)
            req = urlrequest.Request(OPENROUTER_URL, data=body_try, headers=headers)
            try:
                resp = urlrequest.urlopen(req, timeout=AI_TIMEOUT)
                chosen = candidate
                break
            except urlerror.HTTPError as e:
                detail = ""
                try:
                    body = json.loads(e.read().decode("utf-8", "replace"))
                    detail = ((body.get("error") or {}).get("message") or "").strip()
                except Exception:
                    pass
                # 400/402/404/429 — модель переименовали, сняли или упёрлись
                # в лимит: пробуем следующую из списка, пока они есть.
                if e.code in (400, 402, 404, 429) and candidate != candidates[-1]:
                    continue
                msg_txt = _ai_http_error(e.code) + f" (модель {candidate})"
                if detail:
                    msg_txt += " — " + detail[:200]
                yield _sse({"error": msg_txt})
                return
            except urlerror.URLError:
                yield _sse({"error": "OpenRouter не отвечает. Попробуйте позже."})
                return
        if resp is None:
            yield _sse({"error": "Ни одна из известных бесплатных моделей не ответила."})
            return
        if not use_vision and chosen != (requested_model or _ai_active_model):
            if not requested_model:
                with _ai_active_lock:
                    _ai_active_model = chosen
            yield _sse({"model": chosen})

        acc = []
        racc = []                      # текст размышлений (если модель умеет)
        think_start = time.time()
        think_secs = {"v": 0}
        content_started = {"v": False}
        saved = {"done": False}

        def save_once():
            if saved["done"]:
                return
            full = "".join(acc).strip()
            if full:
                saved["done"] = True
                save_reply(full, chosen, "".join(racc).strip(), think_secs["v"])

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
                delta = choices[0].get("delta") or {}
                rtext = delta.get("reasoning") or delta.get("reasoning_content")
                if rtext:
                    racc.append(rtext)
                    yield _sse({"reasoning": rtext})
                ctext = delta.get("content")
                if ctext:
                    if not content_started["v"]:
                        content_started["v"] = True
                        think_secs["v"] = round(time.time() - think_start, 1)
                    acc.append(ctext)
                    yield _sse({"delta": ctext})
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass
            save_once()   # доходит и через «Стоп» (GeneratorExit), и штатно

        full = "".join(acc).strip()
        if full:
            yield _sse({"done": True, "text": full})
        else:
            yield _sse({"error": "Модель промолчала — попробуйте ещё раз."})

    return gen


@app.post("/api/ai/chat/<chat_id>/send")
@login_required
def ai_chat_send(chat_id):
    """Принимает реплику (текст + необязательное фото или PDF), шлёт разговор
    в OpenRouter и отдаёт ответ потоком (SSE). Пользовательскую реплику
    сохраняем СРАЗУ: даже если модель сегодня молчит из-за лимита, написанное
    не пропадёт и текст продолжит работать в следующий раз."""
    if not _ai_ready():
        return jsonify(error="Ключ OpenRouter на сервере не задан."), 503

    payload = request.get_json(silent=True) or {}
    text = (payload.get("text") or "").strip()[:AI_TEXT_MAX]
    # Фото: новый список images, плюс совместимость со старым одиночным image.
    images_in = payload.get("images")
    if not isinstance(images_in, list):
        images_in = [payload.get("image")] if payload.get("image") else []
    images_in = [x for x in images_in if x][:AI_IMG_COUNT_MAX]
    pdf_data = payload.get("pdf") or ""
    pdf_name = (payload.get("pdf_name") or "").strip()[:120]
    if not text and not images_in and not pdf_data:
        return jsonify(error="Пустое сообщение."), 400

    img_ids, imgs_b64 = [], []
    for data_url in images_in:
        iid, b64 = _ai_store_image(data_url)
        if iid:
            img_ids.append(iid)
            imgs_b64.append(b64)
    use_vision = bool(imgs_b64) and bool(OPENROUTER_VISION_MODEL)

    pdf_text = ""
    if pdf_data:
        m = re.match(r"^data:application/pdf;base64,(.+)$", pdf_data, re.I)
        if m:
            try:
                raw = base64.b64decode(m.group(1), validate=True)
            except Exception:
                raw = b""
            if raw and len(raw) <= AI_PDF_MAX:
                pdf_text = _ai_pdf_extract(raw)
        if not pdf_text:
            return jsonify(error="Не удалось прочитать текст из PDF."), 400

    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        umsg = {"role": "user", "text": text, "ts": time.time()}
        if img_ids:
            umsg["imgs"] = img_ids
        if pdf_text:
            umsg["pdf_name"] = pdf_name or "документ.pdf"
            umsg["pdf_text"] = pdf_text
        c.setdefault("messages", []).append(umsg)
        if not c.get("title"):
            c["title"] = (_ai_smart_title(text)
                          or (("PDF: " + pdf_name) if pdf_name else "")
                          or "Фото")
        c["updated"] = time.time()
        if len(c["messages"]) > AI_MSGS_MAX:
            for old in c["messages"][:-AI_MSGS_MAX]:
                for iid in _ai_msg_imgs(old):
                    try:
                        os.remove(_ai_img_path(iid))
                    except OSError:
                        pass
            c["messages"] = c["messages"][-AI_MSGS_MAX:]
        _ai_write()
        ctx = list(c["messages"][-AI_CTX_MSGS:])
        chat_title = c.get("title") or "Новый чат"

    requested_model = (payload.get("model") or "").strip()
    model = OPENROUTER_VISION_MODEL if use_vision else (requested_model or OPENROUTER_MODEL)
    gen = _ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model)

    def with_title():
        # Заголовок чата на первой реплике вычисляется здесь же, на сервере
        # (автогенерация из текста) — отдаём его первым кадром, чтобы список
        # слева в браузере обновился сразу, а не только после перезагрузки.
        yield _sse({"title": chat_title})
        yield from gen()

    return Response(with_title(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store",
                             "X-Accel-Buffering": "no"})


@app.post("/api/ai/chat/<chat_id>/regenerate")
@login_required
def ai_chat_regenerate(chat_id):
    """Стирает последний ответ нейронки и просит его заново — тем же вопросом
    (тем же текстом/фото/PDF, что уже лежат в истории)."""
    if not _ai_ready():
        return jsonify(error="Ключ OpenRouter на сервере не задан."), 503
    payload = request.get_json(silent=True) or {}
    requested_model = (payload.get("model") or "").strip()

    with ai_lock:
        c = _ai_find(chat_id)
        if not c:
            return jsonify(error="Чат не найден."), 404
        msgs = c.get("messages", [])
        if msgs and msgs[-1].get("role") == "assistant":
            msgs.pop()
            c["updated"] = time.time()
            _ai_write()
        if not msgs or msgs[-1].get("role") != "user":
            return jsonify(error="Нечего перегенерировать — нет вопроса."), 400
        ctx = list(msgs[-AI_CTX_MSGS:])
        last_imgs = _ai_msg_imgs(ctx[-1]) if ctx else []

    imgs_b64 = []
    if last_imgs and OPENROUTER_VISION_MODEL:
        for iid in last_imgs:
            try:
                with open(_ai_img_path(iid), "rb") as fh:
                    imgs_b64.append(base64.b64encode(fh.read()).decode("ascii"))
            except OSError:
                pass
    use_vision = bool(imgs_b64)

    model = OPENROUTER_VISION_MODEL if use_vision else (requested_model or OPENROUTER_MODEL)
    gen = _ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model)
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
    <html lang="ru" data-tab="mm">
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
                --mm1:#ff3d9a; --mm2:#ff8fc4;   /* MiniMax: розовый */
                --nv1:#76c900; --nv2:#39ff14;   /* NVIDIA: зелёный */
                --cl1:#d97757; --cl2:#f0a184;   /* Claude: оранжевый */
                --ac:var(--mm1); --ac2:var(--mm2); }
        html[data-tab="nv"] { --ac:var(--nv1); --ac2:var(--nv2); }
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
        .tab.mm i { background:linear-gradient(160deg,var(--mm1),var(--mm2)); box-shadow:0 0 10px var(--mm1); }
        .tab.nv i { background:linear-gradient(160deg,var(--nv1),var(--nv2)); box-shadow:0 0 10px var(--nv1); }
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
        <button class="tab mm on" type="button" data-tab="mm"><i></i><b>MiniMax</b></button>
        <button class="tab nv" type="button" data-tab="nv"><i></i><b>NVIDIA</b></button>
        <button class="tab cl" type="button" data-tab="cl"><i></i><b>Claude</b></button>
      </div>
      <div class="stage">
        <div class="spin" id="spin">открываю…</div>
        <iframe id="fr-mm" class="on" title="MiniMax" src="/ai?m=minimax%2Fminimax-m3%3Afree" loading="eager" allow="clipboard-write"></iframe>
        <iframe id="fr-nv" title="NVIDIA" data-src="/ai?m=nvidia%2Fnemotron-3-ultra-550b-a55b%3Afree" allow="clipboard-write"></iframe>
        <iframe id="fr-cl" title="Claude" data-src="/claude"></iframe>
      </div>

      <script>
      (() => {
        "use strict";
        const root = document.documentElement;
        const tabs = Array.from(document.querySelectorAll(".tab"));
        const frames = { mm: document.getElementById("fr-mm"),
                         nv: document.getElementById("fr-nv"),
                         cl: document.getElementById("fr-cl") };
        const spin = document.getElementById("spin");
        const loaded = { mm: true, nv: false, cl: false };

        frames.mm.addEventListener("load", () => { if (root.getAttribute("data-tab") === "mm") spin.style.display = "none"; });
        frames.nv.addEventListener("load", () => { loaded.nv = true; if (root.getAttribute("data-tab") === "nv") spin.style.display = "none"; });
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

        let start = "mm";
        try { const s = localStorage.getItem("neuroTab"); if (s === "cl" || s === "nv" || s === "mm") start = s; } catch (e) {}
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
    _preset = (request.args.get("m") or "").strip()
    _low = _preset.lower()
    _net = ("minimax" if "minimax" in _low else
            "nvidia" if ("nvidia" in _low or "nemotron" in _low) else
            "deepseek" if "deepseek" in _low else "")
    """Чат с нейросетью (DeepSeek через OpenRouter). Личная страница хозяина:
    история чатов хранится на сайте под паролем кабинета, поэтому за замком.
    Разрешаем встраивание в свой же iframe — страница «Нейронки» показывает её
    вкладкой рядом с Claude."""
    g.frameable = True
    html = (Path(__file__).parent / "templates" / "ai.html").read_text(encoding="utf-8")
    return html.replace("__ICONLINKS__", ICON_LINKS).replace("%%PRESET%%", _preset.replace("\"", "\\\"")).replace("%%NET%%", _net)


@app.get("/servers")
def servers_page():
    """Хозяйство: три машины, их роли и что на них крутится.

    Страница открыта всем, поэтому наружу не выносим ни публичный адрес VPS,
    ни адреса mesh-сети — только домашние 192.168.x, которые одинаковы у
    половины страны и ничего не выдают."""
    html = (Path(__file__).parent / "templates" / "servers.html").read_text(encoding="utf-8")
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
    html = (Path(__file__).parent / "templates" / "music.html").read_text(encoding="utf-8")
    return html.replace("__ICONLINKS__", ICON_LINKS)


@app.route("/")
def home():
    html = (Path(__file__).parent / "templates" / "home.html").read_text(encoding="utf-8")
    for name, svg in _GAME_ICONS.items():
        html = html.replace("__ICON_%s__" % name.upper(), svg)
    html = html.replace("__ICONLINKS__", ICON_LINKS)
    return html


if __name__ == "__main__":
    # На домашнем сервере (за NAT) слушаем все интерфейсы. На VPS реверс-прокси
    # (nginx-proxy-manager) сидит на bridge-сети докера, а не на network_mode:
    # host — до хоста он достаёт через docker0-шлюз, а не через loopback.
    # Поэтому там в .env стоит BIND_HOST=172.17.0.1 (см. CLAUDE.md), а не
    # 127.0.0.1 — с loopback'ом bridge-контейнер достучаться бы не смог.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=5000, threaded=True)
