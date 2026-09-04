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

from blueprints.ai import create_ai_blueprint
from blueprints.backup_sebastian import create_backup_sebastian_blueprint
from blueprints.debts import create_debts_blueprint
from blueprints.diy import create_diy_blueprint
from blueprints.drop import create_drop_blueprint
from blueprints.home import create_home_blueprint
from blueprints.music import create_music_blueprint
from blueprints.notebook import create_notebook_blueprint
from blueprints.pwa import ICON_LINKS, create_pwa_blueprint
from blueprints.remote import create_remote_blueprint

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

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _template(name):
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")


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
            return redirect(url_for("home.home"))
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
                return redirect(url_for("home.home"))
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
        return jsonify(redirect=url_for("debts.debts_me_page"))

    _rate_hit(login_attempts, login_attempts_lock, client)
    _log_login("неверный пароль", kind="fail")
    return jsonify(error="Неверный пароль."), 401


@app.post("/logout")
def logout():
    # Доверие устройству намеренно переживает выход: «Выйти» закрывает кабинет,
    # а не отзывает устройство. Отзыв — снять галку или нажать корзину в списке.
    session.clear()
    return redirect(url_for("home.home"))


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




@app.get("/api/metrics")
@login_required
def metrics_api():
    with metrics_lock:
        result = []
        for t in METRICS_TARGETS:
            d = metrics_data.get(t["ip"])
            result.append({"ip": t["ip"], "name": t["name"], "data": d})
    return jsonify(result)




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


def _music_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass


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
def _drop_public_item(token):
    """Файл по токену ссылки, либо пусто. Из-под замка выходим сразу:
    держать его на время отдачи файла незачем."""
    with drop_lock:
        item_id = _drop_share_lookup(token)
        item = drop_items.get(item_id) if item_id else None
    return (item_id, item) if item else (None, None)
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


def _soon_page(name, kicker, headline, lead, points):
    """Заготовка под раздел: страница уже есть и открывается с полки, а
    содержимое появится позже. Пустая страница выглядела бы поломкой,
    поэтому честно пишем, что здесь будет."""
    items = "".join(f"<li>{escape(p)}</li>" for p in points)
    html = _template("soon.html")
    return (html.replace("__ICONLINKS__", ICON_LINKS)
                .replace("__NAME__", escape(name))
                .replace("__KICKER__", escape(kicker))
                .replace("__HEADLINE__", escape(headline))
                .replace("__LEAD__", escape(lead))
                .replace("__ITEMS__", items))




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


app.register_blueprint(create_home_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    game_icons=_GAME_ICONS,
    login_required=login_required,
    netbird_devices=NETBIRD_DEVICES,
    arcade_games=ARCADE_GAMES,
    arcade_top=ARCADE_TOP,
    arcade_keep=ARCADE_KEEP,
    arcade_value_max=ARCADE_VALUE_MAX,
    arcade_submit_window=ARCADE_SUBMIT_WINDOW,
    arcade_submit_max=ARCADE_SUBMIT_MAX,
    arcade_scores=arcade_scores,
    arcade_lock=arcade_lock,
    arcade_submit_attempts=arcade_submit_attempts,
    arcade_submit_lock=arcade_submit_lock,
    arcade_clean_name=_arcade_clean_name,
    arcade_sort=_arcade_sort,
    arcade_save=_arcade_save,
    arcade_public=_arcade_public,
    client_ip=_client_ip,
    rate_blocked=_rate_blocked,
    rate_hit=_rate_hit,
    rate_clear=_rate_clear,
    console_login_attempts=console_login_attempts,
    console_login_attempts_lock=console_login_attempts_lock,
    console_login_window_seconds=CONSOLE_LOGIN_WINDOW_SECONDS,
    console_login_max_attempts=CONSOLE_LOGIN_MAX_ATTEMPTS,
    log_login=_log_login,
    ssh_gate_password_prefix=SSH_GATE_PASSWORD_PREFIX,
    console_password_today=console_password_today,
))

app.register_blueprint(create_debts_blueprint(
    template=_template,
    login_required=login_required,
    debts_owner_required=debts_owner_required,
    debtor_required=debtor_required,
    debts_lock=debts_lock,
    debts_data=lambda: debts_data,
    debts_owner_unlocked=_debts_owner_unlocked,
    debts_snapshot_locked=_debts_snapshot_locked,
    debts_write_locked=_debts_write_locked,
    debt_hash_password=_debt_hash_password,
    debt_password_matches=_debt_password_matches,
    debt_user_public_locked=_debt_user_public_locked,
    debt_amount_cents=_debt_amount_cents,
    debt_clean_date=_debt_clean_date,
    today_iso=_today_iso,
    password_matches=password_matches,
    device_check=_device_check,
    device_cookie=DEVICE_COOKIE,
    client_ip=_client_ip,
    rate_blocked=_rate_blocked,
    rate_hit=_rate_hit,
    rate_clear=_rate_clear,
    console_login_attempts=console_login_attempts,
    console_login_attempts_lock=console_login_attempts_lock,
    console_login_window_seconds=CONSOLE_LOGIN_WINDOW_SECONDS,
    console_login_max_attempts=CONSOLE_LOGIN_MAX_ATTEMPTS,
    console_password_today=console_password_today,
    log_login=_log_login,
))

app.register_blueprint(create_notebook_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    notebook_data=notebook_data,
    notebook_lock=notebook_lock,
    notebook_borders=NOTEBOOK_BORDERS,
    notebook_types=NOTEBOOK_TYPES,
    notebook_entry_limit=NOTEBOOK_ENTRY_LIMIT,
    notebook_pdf_max=NOTEBOOK_PDF_MAX,
    notebook_pdf_path=_notebook_pdf_path,
    notebook_write=_notebook_write,
    notebook_entry_public=_notebook_entry_public,
    notebook_apply=_notebook_apply,
    diy_safe_name=_diy_safe_name,
))

app.register_blueprint(create_diy_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    escape=escape,
    diy_editor_required=diy_editor_required,
    diy_items=diy_items,
    diy_lock=diy_lock,
    diy_kinds=DIY_KINDS,
    diy_themes=DIY_THEMES,
    diy_body_max=DIY_BODY_MAX,
    diy_asset_limit=DIY_ASSET_LIMIT,
    diy_asset_max=DIY_ASSET_MAX,
    diy_asset_side=DIY_ASSET_SIDE,
    diy_image_ext=DIY_IMAGE_EXT,
    diy_max_image=DIY_MAX_IMAGE,
    diy_cover_side=DIY_COVER_SIDE,
    diy_can_edit=_diy_can_edit,
    diy_public=_diy_public,
    diy_sorted=_diy_sorted,
    diy_clean_links=_diy_clean_links,
    diy_write_index=_diy_write_index,
    diy_cover_path=_diy_cover_path,
    diy_asset_dir=_diy_asset_dir,
    diy_asset_path=_diy_asset_path,
    diy_safe_name=_diy_safe_name,
    diy_card=_diy_card,
    diy_head=_diy_head,
))

app.register_blueprint(create_music_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    music_editor_required=music_editor_required,
    music_items=music_items,
    music_folders=music_folders,
    music_lock=music_lock,
    music_scan=_music_scan,
    music_write_index=_music_write_index,
    music_used=_music_used,
    drop_used_safe=_drop_used_safe,
    drop_quota=DROP_QUOTA,
    music_max_size=MUSIC_MAX_SIZE,
    music_safe_name=_music_safe_name,
    music_exts=MUSIC_EXTS,
    music_dir=lambda: MUSIC_DIR,
    music_chunk=MUSIC_CHUNK,
    music_unlink=_music_unlink,
    music_twin=_music_twin,
    music_split=_music_split,
    music_folder_depth=_music_folder_depth,
    music_max_depth=MUSIC_MAX_DEPTH,
    music_subtree=_music_subtree,
    music_drop_file=_music_drop_file,
    music_mimes=MUSIC_MIMES,
    drop_lock=drop_lock,
    drop_musik_tracks=_drop_musik_tracks,
))

app.register_blueprint(create_drop_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    escape=escape,
    login_required=login_required,
    logger=app.logger,
    drop_items=drop_items,
    drop_uploads=drop_uploads,
    drop_lock=drop_lock,
    drop_jobs=drop_jobs,
    drop_jobs_lock=drop_jobs_lock,
    drop_folder_icons=DROP_FOLDER_ICONS,
    drop_max_size=DROP_MAX_SIZE,
    drop_quota=DROP_QUOTA,
    drop_text_preview=DROP_TEXT_PREVIEW,
    drop_musik_id=DROP_MUSIK_ID,
    drop_zip_chunk=DROP_ZIP_CHUNK,
    drop_ops=DROP_OPS,
    drop_path=_drop_path,
    drop_tmp_path=_drop_tmp_path,
    drop_write_index=_drop_write_index,
    drop_used=_drop_used,
    drop_children=_drop_children,
    drop_folder_stats=_drop_folder_stats,
    drop_trash=_drop_trash,
    drop_trash_ok=_drop_trash_ok,
    drop_path_to_root=_drop_path_to_root,
    drop_is_descendant=_drop_is_descendant,
    drop_share_lookup=_drop_share_lookup,
    drop_sweep_uploads=_drop_sweep_uploads,
    drop_sweep_trash=_drop_sweep_trash,
    drop_trash_roots=_drop_trash_roots,
    drop_trash_bytes=_drop_trash_bytes,
    drop_trash_subtree_bytes=_drop_trash_subtree_bytes,
    drop_discard=_drop_discard,
    drop_thumb_path=_drop_thumb_path,
    drop_can_thumb=_drop_can_thumb,
    drop_make_thumb=_drop_make_thumb,
    drop_human_size=_drop_human_size,
    drop_view_kind=_drop_view_kind,
    drop_share_mode=_drop_share_mode,
    drop_send=_drop_send,
    drop_text_name=_drop_text_name,
    drop_music_take=_drop_music_take,
    drop_music_view=_drop_music_view,
    drop_music_send=_drop_music_send,
    drop_music_delete=_drop_music_delete,
    drop_zip_name=_drop_zip_name,
    drop_zip_plan=_drop_zip_plan,
    drop_zip_length=_drop_zip_length,
    drop_zip_time=_drop_zip_time,
    drop_job_set=_drop_job_set,
    drop_jobs_sweep=_drop_jobs_sweep,
    drop_unique_name=_drop_unique_name,
    music_used_safe=_music_used_safe,
    music_lock=music_lock,
    music_items=music_items,
    music_folders=music_folders,
    music_folder_depth=_music_folder_depth,
    music_max_depth=MUSIC_MAX_DEPTH,
    music_write_index=_music_write_index,
    music_used_raw=_music_used,
))

app.register_blueprint(create_backup_sebastian_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    device_check=_device_check,
    device_cookie=DEVICE_COOKIE,
    backup_token=lambda: BACKUP_TOKEN,
    backup_measure=lambda *args, **kwargs: _backup_measure(*args, **kwargs),
    backup_build=lambda *args, **kwargs: _backup_build(*args, **kwargs),
    data_dir=lambda: DATA_DIR,
    drop_dir=lambda: DROP_DIR,
    drop_lock=drop_lock,
    drop_items=drop_items,
    drop_load_index=lambda *args, **kwargs: _drop_load_index(*args, **kwargs),
    diy_lock=diy_lock,
    diy_items=diy_items,
    diy_load=lambda *args, **kwargs: _diy_load(*args, **kwargs),
    notebook_lock=notebook_lock,
    notebook_data=notebook_data,
    notebook_load=lambda *args, **kwargs: _notebook_load(*args, **kwargs),
    music_lock=music_lock,
    music_items=music_items,
    music_folders=music_folders,
    music_load=lambda *args, **kwargs: _music_load(*args, **kwargs),
    sebastian_host=lambda: SEBASTIAN_HOST,
    sebastian_model=lambda: SEBASTIAN_MODEL,
    sebastian_public=lambda: SEBASTIAN_PUBLIC,
    sebastian_msg_max=SEBASTIAN_MSG_MAX,
    sebastian_reply_tokens=SEBASTIAN_REPLY_TOKENS,
    sebastian_timeout=SEBASTIAN_TIMEOUT,
    sebastian_prompt=SEBASTIAN_PROMPT,
    sebastian_gate=sebastian_gate,
    sebastian_allow=lambda *args, **kwargs: _sebastian_allow(*args, **kwargs),
    sebastian_icon_svg=lambda: _GAME_ICONS.get(SEBASTIAN_ICON, ""),
))

app.register_blueprint(create_ai_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    claude_ready=_claude_ready,
    claude_host_name=_claude_host_name,
    claude_dir=CLAUDE_DIR,
    ssh_gate_password_prefix=SSH_GATE_PASSWORD_PREFIX,
    ai_data=ai_data,
    ai_lock=ai_lock,
    ai_active_lock=_ai_active_lock,
    ai_active_model=lambda: _ai_active_model,
    ai_ready=lambda: _ai_ready(),
    openrouter_model=lambda: OPENROUTER_MODEL,
    openrouter_vision_model=lambda: OPENROUTER_VISION_MODEL,
    ai_folders_max=AI_FOLDERS_MAX,
    ai_chats_max=AI_CHATS_MAX,
    ai_msgs_max=AI_MSGS_MAX,
    ai_ctx_msgs=AI_CTX_MSGS,
    ai_text_max=AI_TEXT_MAX,
    ai_img_count_max=AI_IMG_COUNT_MAX,
    ai_pdf_max=AI_PDF_MAX,
    ai_card=_ai_card,
    ai_find=_ai_find,
    ai_find_folder=_ai_find_folder,
    ai_write=_ai_write,
    ai_drop_images=_ai_drop_images,
    ai_msg_imgs=_ai_msg_imgs,
    ai_img_path=_ai_img_path,
    ai_store_image=_ai_store_image,
    ai_pdf_extract=_ai_pdf_extract,
    ai_smart_title=_ai_smart_title,
    ai_run_stream=lambda *args, **kwargs: _ai_run_stream(*args, **kwargs),
    sse=_sse,
))

app.register_blueprint(create_remote_blueprint(
    sock=sock,
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    netbird_devices=NETBIRD_DEVICES,
    netbird_status=netbird_status,
    netbird_status_lock=netbird_status_lock,
    ssh_gate_password_prefix=SSH_GATE_PASSWORD_PREFIX,
    console_password_today=console_password_today,
    client_ip=_client_ip,
    rate_blocked=_rate_blocked,
    rate_hit=_rate_hit,
    rate_clear=_rate_clear,
    console_login_attempts=console_login_attempts,
    console_login_attempts_lock=console_login_attempts_lock,
    console_login_window_seconds=CONSOLE_LOGIN_WINDOW_SECONDS,
    console_login_max_attempts=CONSOLE_LOGIN_MAX_ATTEMPTS,
    log_login=_log_login,
    ssh_enabled_ips=ssh_enabled_ips,
    rdp_enabled_ips=rdp_enabled_ips,
    vnc_enabled_ips=vnc_enabled_ips,
    claude_ready=lambda: _claude_ready(),
    claude_host=lambda: CLAUDE_HOST,
    claude_host_name=lambda: _claude_host_name(),
    claude_dir=CLAUDE_DIR,
    claude_bin=CLAUDE_BIN,
    claude_tabs_max=CLAUDE_TABS_MAX,
    claude_prefix=CLAUDE_PREFIX,
    claude_name_re=CLAUDE_NAME_RE,
    claude_run=lambda *args, **kwargs: _claude_run(*args, **kwargs),
    claude_tabs=lambda *args, **kwargs: _claude_tabs(*args, **kwargs),
    claude_free_name=lambda *args, **kwargs: _claude_free_name(*args, **kwargs),
    guacd_host=GUACD_HOST,
    guacd_port=GUACD_PORT,
    rdp_quality=RDP_QUALITY,
    guac_handshake=lambda *args, **kwargs: _guac_handshake(*args, **kwargs),
    guac_handshake_vnc=lambda *args, **kwargs: _guac_handshake_vnc(*args, **kwargs),
    wol_relay=lambda *args, **kwargs: _wol_relay(*args, **kwargs),
    wol_broadcasts=WOL_BROADCASTS,
))

app.register_blueprint(create_pwa_blueprint(
    template=_template,
    login_required=login_required,
    drop_lock=drop_lock,
    drop_items=drop_items,
    drop_max_size=DROP_MAX_SIZE,
    drop_quota=DROP_QUOTA,
    drop_path=_drop_path,
    drop_used=_drop_used,
    drop_write_index=_drop_write_index,
))


if __name__ == "__main__":
    # На домашнем сервере (за NAT) слушаем все интерфейсы. На VPS реверс-прокси
    # (nginx-proxy-manager) сидит на bridge-сети докера, а не на network_mode:
    # host — до хоста он достаёт через docker0-шлюз, а не через loopback.
    # Поэтому там в .env стоит BIND_HOST=172.17.0.1 (см. CLAUDE.md), а не
    # 127.0.0.1 — с loopback'ом bridge-контейнер достучаться бы не смог.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=5000, threaded=True)
