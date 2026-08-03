import base64
import codecs
import hashlib
import hmac
import io
import json
import os
import platform
import re
import secrets
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

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("VITAZGIO_SESSION_SECRET", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
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
    {"ip": "100.104.188.141", "name": "NOUTBOOK", "rdp_enabled": True},
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

login_log: deque = deque(maxlen=100)
login_log_lock = threading.Lock()

# Машины для сбора метрик через SSH
METRICS_TARGETS = [
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
    {
        "ip": "100.104.111.39",
        "name": "ubuntuvitaz1",
        "user_env": "METRICS_UBUNTUVITAZ1_USER",
        "pass_env": "METRICS_UBUNTUVITAZ1_PASS",
    },
]
METRICS_INTERVAL = 30
metrics_data: dict = {t["ip"]: None for t in METRICS_TARGETS}
metrics_lock = threading.Lock()

# Команда сбора метрик (CPU%, RAM%, disk%, uptime_sec, temp_C)
_METRICS_CMD = (
    "awk '/^cpu /{u=$2+$4;t=$2+$3+$4+$5;if(t>0)printf \"%.1f\\n\",u/t*100;else print 0}' /proc/stat; "
    "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0)printf \"%.1f\\n\",(t-a)/t*100;else print 0}' /proc/meminfo; "
    "df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %'; "
    "awk '{printf \"%.0f\\n\",$1}' /proc/uptime; "
    "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{printf \"%.1f\\n\",$1/1000}' || echo ''"
)


def _collect_metrics_for(target: dict) -> dict | None:
    user = os.environ.get(target["user_env"])
    passwd = os.environ.get(target["pass_env"])
    if not user or not passwd:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target["ip"], username=user, password=passwd,
                       timeout=6, look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command(_METRICS_CMD, timeout=8)
        lines = stdout.read().decode(errors="replace").strip().splitlines()
        result = {
            "cpu": float(lines[0]) if len(lines) > 0 and lines[0] else None,
            "ram": float(lines[1]) if len(lines) > 1 and lines[1] else None,
            "disk": int(lines[2]) if len(lines) > 2 and lines[2].isdigit() else None,
            "uptime": int(lines[3]) if len(lines) > 3 and lines[3].isdigit() else None,
            "temp": float(lines[4]) if len(lines) > 4 and lines[4] else None,
            "ts": time.time(),
        }
        return result
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

DROP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drop_data")
DROP_INDEX_PATH = os.path.join(DROP_DIR, "index.json")
DROP_MAX_ITEMS = 20
DROP_MAX_SIZE = 10 * 1024 * 1024
DROP_TTL_SECONDS = 7 * 24 * 3600

drop_items: dict = {}
drop_lock = threading.Lock()
os.makedirs(DROP_DIR, exist_ok=True)


def _drop_path(item_id):
    return os.path.join(DROP_DIR, f"{item_id}.bin")


def _drop_write_index():
    """Вызывать под drop_lock."""
    tmp = DROP_INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(drop_items, fh, ensure_ascii=False)
    os.replace(tmp, DROP_INDEX_PATH)


def _drop_discard(item_id):
    """Вызывать под drop_lock."""
    drop_items.pop(item_id, None)
    try:
        os.remove(_drop_path(item_id))
    except OSError:
        pass


def _drop_prune_expired():
    """Вызывать под drop_lock. Возвращает число удалённых."""
    now = time.time()
    stale = [k for k, v in drop_items.items() if now - v["created"] > DROP_TTL_SECONDS]
    for item_id in stale:
        _drop_discard(item_id)
    return len(stale)


def _drop_make_room():
    """Вызывать под drop_lock: освобождает место под новый элемент."""
    while len(drop_items) >= DROP_MAX_ITEMS:
        _drop_discard(min(drop_items, key=lambda k: drop_items[k]["created"]))


def _drop_load_index():
    try:
        with open(DROP_INDEX_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        saved = {}
    for item_id, meta in saved.items():
        if os.path.exists(_drop_path(item_id)):
            drop_items[item_id] = meta
    for fname in os.listdir(DROP_DIR):
        if fname.endswith(".bin") and fname[:-4] not in drop_items:
            try:
                os.remove(os.path.join(DROP_DIR, fname))
            except OSError:
                pass
    _drop_prune_expired()
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


def _client_ip():
    """Реальный адрес клиента: до приложения трафик идёт через NPM."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


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

clipboard_store: dict = {"text": "", "version": 0}
clipboard_lock = threading.Lock()

_deploy_cache: dict = {"data": None, "ts": 0.0}
_deploy_cache_lock = threading.Lock()
DEPLOY_CACHE_TTL = 60
GITHUB_REPO = "VITAZGIO/vitazgio.ru"


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


def _log_login(note=""):
    with login_log_lock:
        ua = request.headers.get("User-Agent", "")[:100]
        login_log.append({
            "ip": _client_ip(),
            "ts": datetime.now(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M:%S"),
            "ua": f"{ua} · {note}" if note else ua,
        })


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
    client = request.remote_addr or "unknown"
    now = time.monotonic()

    with login_attempts_lock:
        attempts = login_attempts[client]
        while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not password_matches(password):
        with login_attempts_lock:
            login_attempts[client].append(now)
        return jsonify(error="Неверный пароль."), 401

    with login_attempts_lock:
        login_attempts.pop(client, None)
    session.clear()
    session["authenticated"] = True
    session.permanent = False
    _log_login()
    return jsonify(redirect=url_for("cabinet"))


@app.post("/logout")
def logout():
    # Выход должен и правда выходить: если оставить токен, следующий же заход
    # молча пустит обратно и кнопка станет бессмысленной.
    raw = request.cookies.get(DEVICE_COOKIE) or ""
    if "." in raw:
        _device_forget(raw.split(".", 1)[0])
    session.clear()
    g.clear_device_cookie = True
    return redirect(url_for("home"))


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

    client = request.remote_addr or "unknown"
    now = time.monotonic()

    with console_login_attempts_lock:
        attempts = console_login_attempts[client]
        while attempts and now - attempts[0] > CONSOLE_LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= CONSOLE_LOGIN_MAX_ATTEMPTS:
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not hmac.compare_digest(password, console_password_today()):
        with console_login_attempts_lock:
            console_login_attempts[client].append(now)
        return jsonify(error="Неверный пароль."), 401

    with console_login_attempts_lock:
        console_login_attempts.pop(client, None)
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


rdp_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES}
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


def _guac_handshake(guac_sock, hostname, username, password, width, height):
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
        _guac_handshake(guac_sock, ip, username, password, width, height)
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


@app.post("/api/wol")
@login_required
def wol():
    payload = request.get_json(silent=True) or {}
    mac = payload.get("mac", "")
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        return jsonify(error="Неверный MAC-адрес."), 400
    mac_bytes = bytes.fromhex(mac_clean)
    packet = b"\xff" * 6 + mac_bytes * 16
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(packet, ("255.255.255.255", 9))
            s.sendto(packet, ("192.168.1.255", 9))
    except OSError as e:
        return jsonify(error=str(e)), 500
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
        return jsonify(list(reversed(list(login_log))))


@app.post("/api/devices/trust")
@login_required
def device_trust():
    if not SSH_GATE_PASSWORD_PREFIX:
        return jsonify(error="Суточный пароль не настроен на сервере."), 503

    client = request.remote_addr or "unknown"
    now = time.monotonic()
    with console_login_attempts_lock:
        attempts = console_login_attempts[client]
        while attempts and now - attempts[0] > CONSOLE_LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= CONSOLE_LOGIN_MAX_ATTEMPTS:
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    password = (request.get_json(silent=True) or {}).get("password", "")
    if not isinstance(password, str) or not hmac.compare_digest(password, console_password_today()):
        with console_login_attempts_lock:
            console_login_attempts[client].append(now)
        return jsonify(error="Неверный суточный пароль."), 401

    with console_login_attempts_lock:
        console_login_attempts.pop(client, None)

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


@app.get("/api/deploy-logs")
@login_required
def deploy_logs_api():
    now = time.monotonic()
    with _deploy_cache_lock:
        if _deploy_cache["data"] is not None and now - _deploy_cache["ts"] < DEPLOY_CACHE_TTL:
            return jsonify(_deploy_cache["data"])
    try:
        headers = {"User-Agent": "vitazgio-site/1.0", "Accept": "application/vnd.github.v3+json"}
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/commits?per_page=8", headers=headers
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            commits = json.loads(resp.read())
        req2 = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs?per_page=10", headers=headers
        )
        with urllib.request.urlopen(req2, timeout=8) as resp:
            runs_data = json.loads(resp.read())
        run_by_sha = {}
        for run in runs_data.get("workflow_runs", []):
            sha = run.get("head_sha", "")
            if sha and sha not in run_by_sha:
                run_by_sha[sha] = {
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "url": run.get("html_url"),
                }
        result = []
        for c in commits:
            sha = c["sha"]
            result.append({
                "sha": sha[:7],
                "message": c["commit"]["message"].split("\n")[0][:80],
                "author": c["commit"]["author"]["name"],
                "date": c["commit"]["author"]["date"],
                "url": c["html_url"],
                "run": run_by_sha.get(sha),
            })
        with _deploy_cache_lock:
            _deploy_cache["data"] = result
            _deploy_cache["ts"] = time.monotonic()
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e)), 502


@app.post("/api/drop/text")
@login_required
def drop_upload_text():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not text:
        return jsonify(error="Текст пустой."), 400
    data = text.encode("utf-8")
    if len(data) > DROP_MAX_SIZE:
        return jsonify(error="Слишком большой."), 413
    item_id = str(uuid.uuid4())
    name = f"Текст {datetime.now().strftime('%d.%m %H:%M')}"
    with drop_lock:
        _drop_prune_expired()
        _drop_make_room()
        try:
            with open(_drop_path(item_id), "wb") as fh:
                fh.write(data)
        except OSError as e:
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        drop_items[item_id] = {"name": name, "content_type": "text/plain; charset=utf-8",
                               "size": len(data), "created": time.time(), "is_text": True}
        _drop_write_index()
    return jsonify(id=item_id, name=name)


@app.post("/api/drop/upload")
@login_required
def drop_upload_file():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Файл не выбран."), 400
    if request.content_length and request.content_length > DROP_MAX_SIZE + 8192:
        return jsonify(error="Файл слишком большой (макс 10 МБ)."), 413
    item_id = str(uuid.uuid4())
    name = f.filename or "файл"
    path = _drop_path(item_id)
    try:
        f.save(path)
        size = os.path.getsize(path)
    except OSError as e:
        return jsonify(error=f"Не удалось сохранить: {e}"), 500
    if size > DROP_MAX_SIZE:
        try:
            os.remove(path)
        except OSError:
            pass
        return jsonify(error="Файл слишком большой (макс 10 МБ)."), 413
    with drop_lock:
        _drop_prune_expired()
        _drop_make_room()
        drop_items[item_id] = {"name": name, "content_type": f.content_type or "application/octet-stream",
                               "size": size, "created": time.time(), "is_text": False}
        _drop_write_index()
    return jsonify(id=item_id, name=name)


@app.get("/api/drop/list")
@login_required
def drop_list_api():
    with drop_lock:
        if _drop_prune_expired():
            _drop_write_index()
        items = [
            {"id": k, "name": v["name"], "size": v["size"],
             "created": v["created"], "is_text": v["is_text"]}
            for k, v in sorted(drop_items.items(), key=lambda x: -x[1]["created"])
        ]
    return jsonify(items)


@app.get("/api/drop/download/<item_id>")
@login_required
def drop_download(item_id):
    with drop_lock:
        item = drop_items.get(item_id)
    if not item:
        return "Не найдено", 404
    return send_file(
        _drop_path(item_id),
        mimetype=item["content_type"],
        as_attachment=True,
        download_name=item["name"],
    )


@app.delete("/api/drop/<item_id>")
@login_required
def drop_delete(item_id):
    with drop_lock:
        if item_id in drop_items:
            _drop_discard(item_id)
            _drop_write_index()
    return jsonify(ok=True)


@app.get("/api/clipboard")
@login_required
def clipboard_get():
    with clipboard_lock:
        return jsonify(text=clipboard_store["text"], version=clipboard_store["version"])


@app.post("/api/clipboard")
@login_required
def clipboard_set():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if len(text) > 100_000:
        return jsonify(error="Текст слишком длинный."), 400
    with clipboard_lock:
        clipboard_store["text"] = text
        clipboard_store["version"] += 1
        ver = clipboard_store["version"]
    return jsonify(ok=True, version=ver)


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
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100svh; color: #e9fbff; font-family: "Cascadia Code", Consolas, monospace; background: radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .cabinet { min-height: 100svh; padding: clamp(24px, 4vw, 54px); background: linear-gradient(135deg, rgba(10,18,32,.25), transparent 60%); }
        .cabinet-header { display: flex; align-items: center; gap: 20px; }
        h1 { margin: 0; font-size: clamp(2.1rem, 5vw, 4.2rem); letter-spacing: -.07em; text-shadow: 2px 0 #ff3fa4, -2px 0 #2de2ff; }
        .logout-form { margin: 0; }
        .logout-button { padding: 10px 16px; color: #dffaff; font: 700 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.07); cursor: pointer; }
        .logout-button:hover { border-color: #2de2ff; background: rgba(45,226,255,.14); }
        [hidden] { display: none !important; }
        .workspace { width: 50%; min-width: 560px; margin-top: clamp(28px, 5vw, 56px); }
        .netbird { border: 1px solid rgba(255,112,38,.24); background: rgba(10,17,30,.72); box-shadow: 0 24px 70px rgba(0,0,0,.24); }
        .netbird-toggle { width: 100%; display: flex; align-items: center; gap: 16px; padding: 18px; text-align: left; border: 0; background: linear-gradient(100deg, rgba(255,105,22,.09), rgba(45,226,255,.035)); }
        .netbird-toggle:hover { border: 0; background: linear-gradient(100deg, rgba(255,105,22,.16), rgba(45,226,255,.07)); }
        .netbird-logo { width: 54px; height: 54px; padding: 6px; object-fit: contain; border-radius: 14px; background: #050608; }
        .netbird-title { display: block; color: #f8fbff; font-size: 1.25rem; font-weight: 800; }
        .netbird-count { display: block; margin-top: 5px; color: #8f99ab; font-size: .74rem; letter-spacing: .08em; text-transform: uppercase; }
        .netbird-arrow { margin-left: auto; color: #ff782f; font-size: 1.3rem; transition: transform .25s ease; }
        .netbird-toggle[aria-expanded="true"] .netbird-arrow { transform: rotate(180deg); }
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
        .gate-submit { width: 100%; height: 46px; margin-top: 12px; color: #1a0d04; font: 800 .8rem "Cascadia Code", Consolas, monospace; letter-spacing: .06em; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); cursor: pointer; }
        .gate-error { min-height: 18px; margin: 10px 0 0; color: #ff6ba8; font-size: .78rem; }
        .gate-close { position: absolute; top: 12px; right: 14px; padding: 5px; color: #7d8799; font-size: 1.3rem; border: 0; background: none; cursor: pointer; }

        .term-overlay { position: fixed; z-index: 100; inset: 0; display: flex; flex-direction: column; background: #05070c; }
        .term-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; color: #c4cad5; font-size: .82rem; background: rgba(255,255,255,.04); border-bottom: 1px solid rgba(255,255,255,.08); }
        .term-close { padding: 7px 12px; color: #dffaff; font: 700 .76rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.16); background: transparent; cursor: pointer; }
        .term-close:hover { background: rgba(255,255,255,.08); }
        .term-body { flex: 1; padding: 10px; overflow: hidden; }
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

        /* ── Новые виджеты ── */
        .widget { margin-top: 14px; border: 1px solid rgba(45,226,255,.14); background: rgba(10,17,30,.72); }
        .widget-toggle { width: 100%; display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; color: #e8fbff; font: 700 .88rem "Cascadia Code", Consolas, monospace; text-align: left; border: 0; background: transparent; cursor: pointer; }
        .widget-toggle:hover { background: rgba(45,226,255,.05); }
        .widget-arrow { color: #2de2ff; font-size: 1.1rem; transition: transform .25s; }
        .widget-toggle[aria-expanded="true"] .widget-arrow { transform: rotate(180deg); }
        .widget-body { padding: 0 18px 16px; }
        .widget-empty { color: #4a5060; font-size: .8rem; margin: 0; padding: 4px 0; }

        /* Метрики */
        .metrics-grid { display: flex; flex-direction: column; gap: 14px; }
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

        /* Аптайм */
        .uptime-widget { padding: 14px 18px 18px; }
        .uptime-title { font: 700 .88rem "Cascadia Code", Consolas, monospace; color: #8f99ab; margin-bottom: 12px; }
        .uptime-value { display: flex; gap: 18px; flex-wrap: wrap; }
        .uptime-unit { display: flex; flex-direction: column; align-items: center; min-width: 44px; }
        .uptime-num { font: 800 2.2rem "Cascadia Code", Consolas, monospace; color: #2de2ff; letter-spacing: -.04em; line-height: 1; }
        .uptime-lbl { font-size: .62rem; color: #6b7385; text-transform: uppercase; letter-spacing: .08em; margin-top: 4px; }

        /* Деплой */
        .deploy-item { display: grid; grid-template-columns: 64px 1fr auto; gap: 6px 10px; align-items: baseline; padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,.06); font-size: .78rem; }
        .deploy-item:last-child { border-bottom: 0; }
        .deploy-sha { color: #69e8ff; font-family: Consolas, monospace; white-space: nowrap; }
        .deploy-msg { color: #c4cad5; word-break: break-word; }
        .deploy-meta { color: #6b7385; font-size: .7rem; white-space: nowrap; text-align: right; }
        .ds { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
        .ds-ok { background: #63f5ad; } .ds-fail { background: #ff6b81; } .ds-run { background: #fbbf24; } .ds-none { background: #4a5060; }

        /* Дроп */
        .drop-zone { border: 2px dashed rgba(45,226,255,.22); padding: 16px; text-align: center; color: #6b7385; font-size: .8rem; cursor: pointer; transition: all .2s; }
        .drop-zone:hover, .drop-zone.drag-over { border-color: #2de2ff; color: #2de2ff; background: rgba(45,226,255,.04); }
        .drop-textarea { width: 100%; height: 74px; margin-top: 10px; padding: 9px; color: #e8fbff; font: .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); background: rgba(4,10,20,.65); resize: vertical; outline: none; }
        .drop-textarea:focus { border-color: #2de2ff; }
        .drop-send-btn { margin-top: 8px; padding: 8px 16px; color: #0d1321; font: 700 .74rem "Cascadia Code", Consolas, monospace; letter-spacing: .04em; background: linear-gradient(90deg,#2de2ff,#69e8ff); border: 0; cursor: pointer; }
        .drop-list { margin-top: 12px; }
        .drop-file { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,.06); }
        .drop-file:last-child { border-bottom: 0; }
        .drop-fname { flex: 1; color: #c4cad5; font-size: .78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .drop-fsize { color: #6b7385; font-size: .7rem; white-space: nowrap; }
        .drop-btn { padding: 4px 9px; font: 600 .7rem "Cascadia Code", Consolas, monospace; border: 1px solid; cursor: pointer; background: transparent; }
        .drop-btn-dl { color: #2de2ff; border-color: rgba(45,226,255,.3); }
        .drop-btn-dl:hover { background: rgba(45,226,255,.1); }
        .drop-btn-rm { color: #ff6b81; border-color: rgba(255,107,129,.3); }
        .drop-btn-rm:hover { background: rgba(255,107,129,.1); }

        /* Буфер обмена */
        .cb-area { width: 100%; height: 96px; padding: 10px; color: #e8fbff; font: .8rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); background: rgba(4,10,20,.65); resize: vertical; outline: none; }
        .cb-area:focus { border-color: #2de2ff; }
        .cb-actions { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
        .cb-btn { padding: 7px 14px; font: 700 .72rem "Cascadia Code", Consolas, monospace; border: 1px solid; cursor: pointer; background: transparent; }
        .cb-push { color: #ff782f; border-color: rgba(255,120,47,.35); }
        .cb-push:hover { background: rgba(255,120,47,.1); }
        .cb-copy { color: #63f5ad; border-color: rgba(99,245,173,.3); }
        .cb-copy:hover { background: rgba(99,245,173,.08); }
        .cb-info { font-size: .7rem; color: #6b7385; margin: 6px 0 0; }

        /* Журнал входов */
        .log-row { display: grid; grid-template-columns: 150px 1fr; gap: 4px 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.06); font-size: .76rem; }
        .log-row:last-child { border-bottom: 0; }
        .log-ts { color: #6b7385; white-space: nowrap; }
        .log-ip { color: #69e8ff; }
        .log-ua { color: #4a5060; font-size: .68rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; grid-column: 1 / -1; }

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
          <h1>Личный кабинет</h1>
          <form class="logout-form" action="/logout" method="post"><button class="logout-button" type="submit">Выйти</button></form>
        </header>
        <div class="workspace">
          <section class="netbird">
          <button id="netbird-toggle" class="netbird-toggle" type="button" aria-expanded="false" aria-controls="netbird-devices">
            <img class="netbird-logo" src="/static/netbird-official.png" alt="">
            <span><span class="netbird-title">NetBird</span><span class="netbird-count">8 устройств</span></span>
            <span class="netbird-arrow" aria-hidden="true">⌄</span>
          </button>
          <div id="netbird-devices" hidden>
            <ul class="device-list">{{DEVICE_ITEMS}}</ul>
          </div>
          </section>

          <!-- Метрики Linux-машин -->
          <section class="widget">
            <button class="widget-toggle" id="metrics-toggle" type="button" aria-expanded="false" aria-controls="metrics-body">
              Метрики машин <span class="widget-arrow">⌄</span>
            </button>
            <div id="metrics-body" hidden class="widget-body">
              <div class="metrics-grid" id="metrics-grid"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

          <!-- Сервер жив уже -->
          <section class="widget">
            <div class="uptime-widget">
              <div class="uptime-title">Сервер жив уже</div>
              <div class="uptime-value">
                <div class="uptime-unit"><span class="uptime-num" id="up-d">…</span><span class="uptime-lbl">дней</span></div>
                <div class="uptime-unit"><span class="uptime-num" id="up-h">…</span><span class="uptime-lbl">часов</span></div>
                <div class="uptime-unit"><span class="uptime-num" id="up-m">…</span><span class="uptime-lbl">минут</span></div>
                <div class="uptime-unit"><span class="uptime-num" id="up-s">…</span><span class="uptime-lbl">секунд</span></div>
              </div>
            </div>
          </section>

          <!-- Логи деплоя -->
          <section class="widget">
            <button class="widget-toggle" id="deploy-toggle" type="button" aria-expanded="false" aria-controls="deploy-body">
              Логи деплоя <span class="widget-arrow">⌄</span>
            </button>
            <div id="deploy-body" hidden class="widget-body">
              <div id="deploy-list"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

          <!-- Личный дроп -->
          <section class="widget">
            <button class="widget-toggle" id="drop-toggle" type="button" aria-expanded="false" aria-controls="drop-body">
              Личный дроп <span class="widget-arrow">⌄</span>
            </button>
            <div id="drop-body" hidden class="widget-body">
              <div class="drop-zone" id="drop-zone">Перетащи файл сюда или <u>нажми для выбора</u></div>
              <input type="file" id="drop-file-input" style="display:none" multiple>
              <textarea class="drop-textarea" id="drop-text" placeholder="Или вставь текст сюда…"></textarea>
              <button class="drop-send-btn" id="drop-send-text" type="button">Отправить текст</button>
              <div class="drop-list" id="drop-list"></div>
            </div>
          </section>

          <!-- Буфер обмена -->
          <section class="widget">
            <button class="widget-toggle" id="cb-toggle" type="button" aria-expanded="false" aria-controls="cb-body">
              Буфер обмена <span class="widget-arrow">⌄</span>
            </button>
            <div id="cb-body" hidden class="widget-body">
              <textarea class="cb-area" id="cb-area" placeholder="Скопированный текст появится здесь…"></textarea>
              <div class="cb-actions">
                <button class="cb-btn cb-push" id="cb-push" type="button">Отправить на сервер</button>
                <button class="cb-btn cb-copy" id="cb-copy" type="button">Копировать</button>
              </div>
              <p class="cb-info" id="cb-info">Синхронизация каждые 3 сек</p>
            </div>
          </section>

          <!-- Журнал входов -->
          <section class="widget">
            <button class="widget-toggle" id="loginlog-toggle" type="button" aria-expanded="false" aria-controls="loginlog-body">
              Журнал входов <span class="widget-arrow">⌄</span>
            </button>
            <div id="loginlog-body" hidden class="widget-body">
              <div id="loginlog-list"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

          <!-- Запомненные устройства -->
          <section class="widget" style="margin-bottom:32px">
            <button class="widget-toggle" id="devices-toggle" type="button" aria-expanded="false" aria-controls="devices-body">
              Запомнить устройства <span class="widget-arrow">⌄</span>
            </button>
            <div id="devices-body" hidden class="widget-body">
              <label class="dev-remember">
                <input type="checkbox" id="dev-remember-cb">
                <span>Запомнить это устройство</span>
              </label>
              <p class="dev-hint" id="dev-hint">Вход в кабинет без пароля на 90 дней. Снять галку — устройство забудется.</p>
              <div class="dev-confirm" id="dev-confirm" hidden>
                <input type="password" id="dev-daily" inputmode="numeric" placeholder="Суточный пароль" autocomplete="off">
                <button class="dev-confirm-btn" id="dev-confirm-btn" type="button">Подтвердить</button>
              </div>
              <p class="dev-error" id="dev-error"></p>
              <div id="devices-list"><p class="widget-empty">Загрузка…</p></div>
            </div>
          </section>

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
        <div id="term-body" class="term-body"></div>
      </div>

      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
      <script defer src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
      <script defer src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
      <script defer src="https://cdn.jsdelivr.net/npm/guacamole-common-js@1.5.0/dist/cjs/guacamole-common.min.js"></script>
      <script>
        (() => {
          const toggle = document.getElementById("netbird-toggle");
          const devices = document.getElementById("netbird-devices");
          const timers = new WeakMap();

          toggle.addEventListener("click", () => {
            const expanded = toggle.getAttribute("aria-expanded") === "true";
            toggle.setAttribute("aria-expanded", String(!expanded));
            devices.hidden = expanded;
          });

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

          const openRdp = (ip, name, username, password, protocol = "rdp") => {
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
            const tunnel = new GuacAuthTunnel(ip, { type: "auth", username, password, width, height }, protocol);
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
            closeRdpLogin();
            if (device) openRdp(device.ip, device.name, username, password);
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

        // ── Раскрытие виджетов ──
        document.querySelectorAll(".widget-toggle").forEach(btn => {
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
          if (toggle) toggle.addEventListener("widget-open", e => {
            if (e.detail) { render(); timer = setInterval(render, 32000); }
            else { clearInterval(timer); }
          });
        }

        // ── Аптайм ──
        {
          const dEl = document.getElementById("up-d");
          const hEl = document.getElementById("up-h");
          const mEl = document.getElementById("up-m");
          const sEl = document.getElementById("up-s");
          const pad = n => String(n).padStart(2, "0");
          let base = null, startTs = null;
          const tick = () => {
            if (base === null) return;
            const total = base + Math.floor((Date.now() - startTs) / 1000);
            dEl.textContent = Math.floor(total / 86400);
            hEl.textContent = pad(Math.floor((total % 86400) / 3600));
            mEl.textContent = pad(Math.floor((total % 3600) / 60));
            sEl.textContent = pad(total % 60);
          };
          fetch("/api/uptime", { credentials: "same-origin" })
            .then(r => r.json()).then(d => {
              if (d.seconds == null) { dEl.closest(".uptime-value").textContent = "нет данных"; return; }
              base = d.seconds; startTs = Date.now();
              tick(); setInterval(tick, 1000);
            }).catch(() => { if (dEl) dEl.closest(".uptime-value").textContent = "нет данных"; });
        }

        // ── Логи деплоя ──
        {
          const toggle = document.getElementById("deploy-toggle");
          const list = document.getElementById("deploy-list");
          const si = run => {
            if (!run) return '<span class="ds ds-none"></span>';
            const c = run.conclusion, s = run.status;
            if (c === "success") return '<span class="ds ds-ok"></span>';
            if (c === "failure") return '<span class="ds ds-fail"></span>';
            if (s === "in_progress") return '<span class="ds ds-run"></span>';
            return '<span class="ds ds-none"></span>';
          };
          let loaded = false;
          const load = async () => {
            list.innerHTML = '<p class="widget-empty">Загрузка…</p>';
            try {
              const r = await fetch("/api/deploy-logs", { credentials: "same-origin" });
              const data = await r.json();
              if (!Array.isArray(data)) throw new Error(data.error || "ошибка");
              list.innerHTML = data.map(c => {
                const dt = new Date(c.date).toLocaleString("ru-RU",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});
                return `<div class="deploy-item"><a class="deploy-sha" href="${c.url}" target="_blank" rel="noopener">${esc(c.sha)}</a><span class="deploy-msg">${si(c.run)}${esc(c.message)}</span><span class="deploy-meta">${esc(c.author)}<br>${dt}</span></div>`;
              }).join("");
            } catch(e) { list.innerHTML = `<p class="widget-empty">Ошибка: ${esc(e.message)}</p>`; }
          };
          if (toggle) toggle.addEventListener("widget-open", e => { if (e.detail && !loaded) { loaded = true; load(); } });
        }

        // ── Личный дроп ──
        {
          const toggle = document.getElementById("drop-toggle");
          const zone = document.getElementById("drop-zone");
          const fi = document.getElementById("drop-file-input");
          const ta = document.getElementById("drop-text");
          const sendBtn = document.getElementById("drop-send-text");
          const listEl = document.getElementById("drop-list");
          const fmt = b => b < 1024 ? b+"Б" : b < 1048576 ? (b/1024).toFixed(1)+"КБ" : (b/1048576).toFixed(1)+"МБ";
          const renderList = async () => {
            try {
              const r = await fetch("/api/drop/list", { credentials: "same-origin" });
              const items = await r.json();
              if (!items.length) { listEl.innerHTML = '<p class="widget-empty">Пусто</p>'; return; }
              listEl.innerHTML = items.map(it =>
                `<div class="drop-file"><span class="drop-fname" title="${esc(it.name)}">${esc(it.name)}</span><span class="drop-fsize">${fmt(it.size)}</span><a class="drop-btn drop-btn-dl" href="/api/drop/download/${it.id}" download="${esc(it.name)}">↓</a><button class="drop-btn drop-btn-rm" data-id="${it.id}">✕</button></div>`
              ).join("");
              listEl.querySelectorAll("[data-id]").forEach(btn => btn.addEventListener("click", async () => {
                await fetch(`/api/drop/${btn.dataset.id}`, { method:"DELETE", credentials:"same-origin" });
                renderList();
              }));
            } catch {}
          };
          const uploadFile = async file => {
            zone.textContent = `Загрузка ${file.name}…`;
            const fd = new FormData(); fd.append("file", file);
            try {
              const r = await fetch("/api/drop/upload", { method:"POST", credentials:"same-origin", body:fd });
              if (!r.ok) throw new Error((await r.json()).error);
              zone.innerHTML = 'Перетащи файл сюда или <u>нажми для выбора</u>';
              renderList();
            } catch(e) {
              zone.textContent = "Ошибка: " + e.message;
              setTimeout(() => { zone.innerHTML = 'Перетащи файл сюда или <u>нажми для выбора</u>'; }, 2500);
            }
          };
          let listLoaded = false;
          if (toggle) toggle.addEventListener("widget-open", e => { if (e.detail && !listLoaded) { listLoaded = true; renderList(); } });
          if (zone) {
            zone.addEventListener("click", () => fi.click());
            zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
            zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
            zone.addEventListener("drop", e => { e.preventDefault(); zone.classList.remove("drag-over"); if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]); });
          }
          if (fi) fi.addEventListener("change", () => { if (fi.files[0]) { uploadFile(fi.files[0]); fi.value=""; } });
          if (sendBtn) sendBtn.addEventListener("click", async () => {
            const text = ta.value.trim(); if (!text) return;
            try {
              const r = await fetch("/api/drop/text", { method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({text}) });
              if (!r.ok) throw new Error((await r.json()).error);
              ta.value = ""; renderList();
            } catch(e) { alert("Ошибка: " + e.message); }
          });
        }

        // ── Буфер обмена ──
        {
          const toggle = document.getElementById("cb-toggle");
          const area = document.getElementById("cb-area");
          const pushBtn = document.getElementById("cb-push");
          const copyBtn = document.getElementById("cb-copy");
          const info = document.getElementById("cb-info");
          let lastVer = -1, timer = null;
          const poll = async () => {
            try {
              const r = await fetch("/api/clipboard", { credentials: "same-origin" });
              const d = await r.json();
              if (d.version !== lastVer) { lastVer = d.version; area.value = d.text; if (info) info.textContent = "Обновлено: " + new Date().toLocaleTimeString("ru-RU"); }
            } catch {}
          };
          if (toggle) toggle.addEventListener("widget-open", e => {
            if (e.detail) { poll(); timer = setInterval(poll, 3000); }
            else { clearInterval(timer); }
          });
          if (pushBtn) pushBtn.addEventListener("click", async () => {
            try {
              await fetch("/api/clipboard", { method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({text:area.value}) });
              lastVer = -1;
              if (info) info.textContent = "Отправлено: " + new Date().toLocaleTimeString("ru-RU");
            } catch {}
          });
          if (copyBtn) copyBtn.addEventListener("click", async () => {
            try { await navigator.clipboard.writeText(area.value); const o=copyBtn.textContent; copyBtn.textContent="Скопировано ✓"; setTimeout(()=>{copyBtn.textContent=o;},1500); } catch {}
          });
        }

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
              listEl.innerHTML = data.map(e =>
                `<div class="log-row"><span class="log-ts">${esc(e.ts)}</span><span class="log-ip">${esc(e.ip)}</span><span class="log-ua">${esc(e.ua)}</span></div>`
              ).join("");
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
    return html.replace("{{DEVICE_ITEMS}}", device_items)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Витрина сервисов vitazgio.ru">
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
          padding: clamp(32px, 6vw, 76px) 0 28px;
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

        .services {
          display: grid;
          grid-template-columns: repeat(5, minmax(210px, 1fr));
          gap: 14px;
          min-width: 1110px;
          max-width: 1380px;
          margin: 0 auto;
        }

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
        .domain { color: var(--accent); font-size: .74rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }

        footer {
          width: min(1380px, calc(100% - 40px));
          display: flex;
          justify-content: space-between;
          gap: 20px;
          margin: auto auto 0;
          padding-top: 28px;
          color: #686f80;
          font-size: .82rem;
        }

        [hidden] { display: none !important; }

        .secret-trigger {
          position: fixed;
          z-index: 50;
          right: 0;
          bottom: 0;
          width: 64px;
          height: 64px;
          padding: 0;
          opacity: 0;
          border: 0;
          background: transparent;
          cursor: default;
        }

        .secret-trigger:focus-visible { opacity: .14; outline: 1px solid #2de2ff; }

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
          .cyber-terminal { min-height: 126px; padding-inline: 18px; }
          .terminal-prompt { margin-right: .2em; }
          .cyber-text { letter-spacing: -.08em; }
          .services { grid-template-columns: repeat(5, 78vw); min-width: max-content; }
          .service { min-height: 280px; scroll-snap-align: center; }
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
          </div>
        </nav>

        <footer><span>© 2026 vitazgio.ru · Основан 2:12 04.05.2026</span></footer>
      </main>
      <button id="secret-trigger" class="secret-trigger" type="button" aria-label="Открыть личный кабинет"></button>
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
          const trigger = document.getElementById("secret-trigger");
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

          trigger.addEventListener("click", openModal);
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

        // ── Konami code + змейка ──
        (() => {
          const SEQ = ["ArrowUp","ArrowUp","ArrowDown","ArrowDown","ArrowLeft","ArrowRight","ArrowLeft","ArrowRight","b","a"];
          let pos = 0;
          document.addEventListener("keydown", e => {
            if (e.key === SEQ[pos]) { pos++; if (pos === SEQ.length) { pos = 0; startSnake(); } }
            else { pos = e.key === SEQ[0] ? 1 : 0; }
          });

          const startSnake = () => {
            if (document.getElementById("snake-overlay")) return;
            const overlay = document.createElement("div");
            overlay.id = "snake-overlay";
            Object.assign(overlay.style, {
              position:"fixed", inset:"0", zIndex:"9999", background:"rgba(5,7,12,.97)",
              display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
              fontFamily:"Consolas,monospace",
            });
            const info = document.createElement("div");
            info.style.cssText = "color:#6b7385;font-size:.75rem;margin-bottom:12px;letter-spacing:.06em";
            info.textContent = "↑↓←→ — движение   Escape — выход";
            const scoreEl = document.createElement("div");
            scoreEl.style.cssText = "color:#2de2ff;font-size:1.1rem;font-weight:700;margin-bottom:10px;letter-spacing:.04em";
            scoreEl.textContent = "ОЧКИ: 0";
            const canvas = document.createElement("canvas");
            const SZ = 20, COLS = 24, ROWS = 20;
            canvas.width = COLS * SZ; canvas.height = ROWS * SZ;
            canvas.style.cssText = "border:1px solid rgba(45,226,255,.2);";
            const msgEl = document.createElement("div");
            msgEl.style.cssText = "color:#ff782f;font-size:1rem;font-weight:700;margin-top:14px;min-height:24px;letter-spacing:.04em";
            overlay.append(info, scoreEl, canvas, msgEl);
            document.body.appendChild(overlay);
            const ctx = canvas.getContext("2d");
            let snake, dir, nextDir, food, score, running, raf;
            const rnd = n => Math.floor(Math.random() * n);
            const reset = () => {
              snake = [{x:12,y:10},{x:11,y:10},{x:10,y:10}];
              dir = {x:1,y:0}; nextDir = {x:1,y:0};
              food = {x:rnd(COLS), y:rnd(ROWS)};
              score = 0; running = true; msgEl.textContent = "";
              scoreEl.textContent = "ОЧКИ: 0";
            };
            const draw = () => {
              ctx.fillStyle = "#05070c"; ctx.fillRect(0,0,canvas.width,canvas.height);
              // Grid
              ctx.strokeStyle = "rgba(255,255,255,.04)"; ctx.lineWidth = .5;
              for (let x=0;x<COLS;x++) { ctx.beginPath(); ctx.moveTo(x*SZ,0); ctx.lineTo(x*SZ,canvas.height); ctx.stroke(); }
              for (let y=0;y<ROWS;y++) { ctx.beginPath(); ctx.moveTo(0,y*SZ); ctx.lineTo(canvas.width,y*SZ); ctx.stroke(); }
              // Food
              ctx.fillStyle = "#ff782f";
              ctx.fillRect(food.x*SZ+3, food.y*SZ+3, SZ-6, SZ-6);
              // Snake
              snake.forEach((s,i) => {
                ctx.fillStyle = i===0 ? "#2de2ff" : `rgba(45,226,255,${0.75 - i*0.02})`;
                ctx.fillRect(s.x*SZ+1, s.y*SZ+1, SZ-2, SZ-2);
              });
            };
            let last = 0;
            const SPEED = 130;
            const step = ts => {
              if (!running) return;
              raf = requestAnimationFrame(step);
              if (ts - last < SPEED) return;
              last = ts;
              dir = nextDir;
              const head = { x: (snake[0].x + dir.x + COLS) % COLS, y: (snake[0].y + dir.y + ROWS) % ROWS };
              if (snake.some(s => s.x===head.x && s.y===head.y)) {
                running = false;
                msgEl.textContent = `GAME OVER — очков: ${score}. Enter — заново`;
                draw(); return;
              }
              snake.unshift(head);
              if (head.x===food.x && head.y===food.y) {
                score++;
                scoreEl.textContent = `ОЧКИ: ${score}`;
                food = {x:rnd(COLS), y:rnd(ROWS)};
              } else { snake.pop(); }
              draw();
            };
            const keyFn = e => {
              const m = {ArrowUp:{x:0,y:-1},ArrowDown:{x:0,y:1},ArrowLeft:{x:-1,y:0},ArrowRight:{x:1,y:0}};
              if (e.key === "Escape") { cancelAnimationFrame(raf); overlay.remove(); document.removeEventListener("keydown",keyFn); return; }
              if (e.key === "Enter" && !running) { reset(); raf = requestAnimationFrame(step); return; }
              const nd = m[e.key];
              if (nd && !(nd.x===-dir.x && nd.y===-dir.y)) { nextDir = nd; e.preventDefault(); }
            };
            document.addEventListener("keydown", keyFn);
            reset();
            raf = requestAnimationFrame(step);
          };
        })();
      </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    # На домашнем сервере (за NAT) слушаем все интерфейсы. На VPS с публичным
    # адресом ставим BIND_HOST=127.0.0.1, чтобы снаружи можно было попасть
    # только через реверс-прокси, а не напрямую по IP без TLS.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=5000, threaded=True)
