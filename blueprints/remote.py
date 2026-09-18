"""blueprints/remote.py — кабинет /cabinet, уведомления /notifications,
устройства NetBird /netbird, консоль/RDP/VNC/Claude по вебсокетам (задача
38, docs/structure-plan.md).

Самое рискованное место разреза: вебсокеты, paramiko, guacd — тестами не
покрыть (`tests/test_docs.py` и остальной pytest не открывают реальное
TCP-соединение к guacd/SSH), проверено вручную после переноса — консоль,
RDP, VNC и вкладка Claude подключаются как раньше.

Что переехало сюда целиком (было самодостаточно в app.py, ничего другое
не читало):
- уведомления (`notifications_data`/`notifications_lock` и вся логика) —
  `notification_add` нужен и `blueprints/debts.py` (заявка на пополнение
  создаёт уведомление владельцу) — импортирован оттуда напрямую, как
  `notebook_data` в задаче 35;
- вкладка Claude по SSH: `CLAUDE_BIN`/`CLAUDE_TABS_MAX`/`CLAUDE_PREFIX`/
  `CLAUDE_NAME_RE`/`CLAUDE_DIR` и функции `claude_run`/`claude_tabs`/
  `claude_free_name`. `CLAUDE_HOST` и функции `claude_ready`/
  `claude_host_name` ОСТАЛИСЬ в app.py — им нужен `ssh_enabled_ips`,
  который живёт там же (список машин с SSH, общий с `/api/console/login`
  и не только этой вкладкой); `blueprints/ai.py` тоже читает `claude_ready`/
  `claude_host_name`/`claude_dir` — как и раньше, через фабрику app.py
  (при регистрации `create_ai_blueprint`), только теперь app.py берёт
  `claude_dir` отсюда, а не объявляет сам;
- guacd/RDP/VNC handshake (`GUACD_HOST`/`GUACD_PORT`/`RDP_QUALITY`/
  `guac_handshake`/`guac_handshake_vnc` и их байт-протокольные хелперы);
- Wake-on-LAN через домашний ретранслятор (`WOL_RELAY_*`/`WOL_BROADCASTS`/
  `wol_relay`).

Что осталось аргументами фабрики (общее с другими фичами, не переехало
целиком): `netbird_devices`/`netbird_status`/`netbird_status_lock` —
последние два мутирует фоновый опрос в app.py; `sftp_enabled_ips` — общий
с `blueprints/files.py` (задача 39, ещё не переехал); `ssh_enabled_ips`/
`rdp_enabled_ips`/`vnc_enabled_ips` — множества IP по протоколам, тоже
считаются в app.py рядом с `ssh_enabled_ips` (см. выше про Claude);
`claude_ready`/`claude_host`/`claude_host_name` — см. выше.
"""

import codecs
import hmac
import json
import os
import re
import shlex
import socket
import threading
import time
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import paramiko
from flask import Blueprint, jsonify, request, session

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
from core.storage import DATA_DIR
from core.templates import template

# Значки перед именем устройства во вкладке NetBird — эскизы в цвет текста
# (currentColor, без фона), масштаб под строку списка.
_NETBIRD_ICONS = {
    "phone": (
        '<svg class="dev-ic" viewBox="0 0 32 32" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M22,29H10a3,3,0,0,1-3-3V6a3,3,0,0,1,3-3H22a3,3,0,0,1,3,3V26A3,3,0,0,1,22,29Z'
        'M10,5A1,1,0,0,0,9,6V26a1,1,0,0,0,1,1H22a1,1,0,0,0,1-1V6a1,1,0,0,0-1-1Z"/>'
        '<path d="M18,7H14a2,2,0,0,1-2-2V4a1,1,0,0,1,1-1h6a1,1,0,0,1,1,1V5A2,2,0,0,1,18,7Z"/>'
        '</svg>'
    ),
    "laptop": (
        '<svg class="dev-ic" viewBox="0 0 32 32" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M29,24V6.44A1.46,1.46,0,0,0,27.5,5H4.5A1.46,1.46,0,0,0,3,6.44V24H0v0.44A2.55,2.55,0,0,0,2.5,27h27'
        'A2.55,2.55,0,0,0,32,24.44V24H29ZM4,6.44A0.46,0.46,0,0,1,4.5,6h23a0.46,0.46,0,0,1,.5.44V24H4V6.44Z'
        'M2.5,26a1.63,1.63,0,0,1-1.41-1H14v1H2.5Zm27,0H18V25H30.91A1.63,1.63,0,0,1,29.5,26Z"/>'
        '<path d="M5,23H27V7H5V23ZM6,8H26V22H6V8Z"/>'
        '</svg>'
    ),
    "pc": (
        '<svg class="dev-ic" viewBox="0 0 612 612" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M578.766,51.487v-0.895h-2.996H35.93h-2.996v0.895C15.272,52.701,2.095,66.753,0,83.808v3.002v355.724'
        'c0,6.898,1.795,12.712,4.791,17.949c6.893,12.137,17.068,18.269,31.14,18.269h197.012v49.695h-37.425'
        'c-9.281,0-16.467,7.218-16.467,16.48c0,9.262,7.186,16.479,16.467,16.479h220.666c9.281,0,16.768-7.218,16.768-16.479'
        'c0-9.263-7.486-16.48-16.768-16.48h-37.425v-49.695H575.77c14.078,0,24.343-6.132,31.14-18.269'
        'c3.085-5.493,5.091-11.37,5.091-17.949V86.811v-3.002C609.905,66.753,595.833,52.701,578.766,51.487z'
        'M578.766,86.811v355.724c0,2.108-0.895,3.002-2.996,3.002H35.93c-2.095,0-2.996-0.894-2.996-3.002V86.811v-3.002'
        'h545.831V86.811z"/>'
        '</svg>'
    ),
    "server": (
        '<svg class="dev-ic" viewBox="0 0 1800 1800" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M1713.195,662.483H86.805c-46.621,0-84.549,37.929-84.549,84.55v315.328c0,46.615,37.928,84.54,84.549,84.54'
        'h1626.391c46.625,0,84.55-37.925,84.55-84.54V747.033C1797.745,700.412,1759.82,662.483,1713.195,662.483z'
        'M1734.746,1062.361c0,11.882-9.668,21.541-21.551,21.541H86.805c-11.883,0-21.55-9.659-21.55-21.541V747.033'
        'c0-11.883,9.667-21.55,21.55-21.55h1626.391c11.883,0,21.551,9.667,21.551,21.55V1062.361z"/>'
        '<circle cx="262.693" cy="904.687" r="53.448"/>'
        '<circle cx="447.018" cy="904.687" r="53.451"/>'
        '<circle cx="631.339" cy="904.687" r="53.451"/>'
        '<path d="M1567.738,873.181H927.254c-17.394,0-31.5,14.102-31.5,31.497c0,17.402,14.106,31.5,31.5,31.5h640.484'
        'c17.394,0,31.5-14.098,31.5-31.5C1599.238,887.283,1585.132,873.181,1567.738,873.181z"/>'
        '<path d="M1713.195,1315.578H86.805c-46.621,0-84.549,37.934-84.549,84.551v315.329c0,46.616,37.928,84.54,84.549,84.54'
        'h1626.391c46.625,0,84.55-37.924,84.55-84.54v-315.329C1797.745,1353.512,1759.82,1315.578,1713.195,1315.578z'
        'M1734.746,1715.458c0,11.882-9.668,21.542-21.551,21.542H86.805c-11.883,0-21.55-9.66-21.55-21.542v-315.329'
        'c0-11.883,9.667-21.551,21.55-21.551h1626.391c11.883,0,21.551,9.668,21.551,21.551V1715.458z"/>'
        '<circle cx="262.693" cy="1557.784" r="53.445"/>'
        '<circle cx="447.018" cy="1557.784" r="53.451"/>'
        '<circle cx="631.339" cy="1557.784" r="53.451"/>'
        '<path d="M1567.738,1526.275H927.254c-17.394,0-31.5,14.107-31.5,31.5c0,17.402,14.106,31.5,31.5,31.5h640.484'
        'c17.394,0,31.5-14.098,31.5-31.5C1599.238,1540.383,1585.132,1526.275,1567.738,1526.275z"/>'
        '</svg>'
    ),
}

# ---- Уведомления -----------------------------------------------------------
# Это общий журнал для кабинета: сейчас в него пишут заявки на взносы, позже
# тем же помощником сможет пользоваться Telegram-бот.
NOTIFICATIONS_PATH = os.path.join(DATA_DIR, "notifications.json")
NOTIFICATIONS_LIMIT = 500
notifications_lock = threading.Lock()
notifications_data = []


def _notifications_load():
    try:
        with open(NOTIFICATIONS_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return
    if not isinstance(saved, list):
        return
    notifications_data.extend(row for row in saved if isinstance(row, dict))


def _notifications_write_locked():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = NOTIFICATIONS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(notifications_data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, NOTIFICATIONS_PATH)


def notifications_snapshot_locked():
    rows = [dict(row) for row in notifications_data]
    rows.sort(key=lambda row: str(row.get("created") or ""), reverse=True)
    return {
        "items": rows,
        "unread_count": sum(1 for row in rows if not row.get("read")),
    }


def notification_add(title, text, href="/cabinet", kind="info"):
    now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")
    with notifications_lock:
        notifications_data.append({
            "id": uuid.uuid4().hex,
            "title": str(title).strip()[:120],
            "text": str(text).strip()[:500],
            "href": str(href).strip()[:300] or "/cabinet",
            "kind": str(kind).strip()[:40] or "info",
            "read": False,
            "created": now,
        })
        if len(notifications_data) > NOTIFICATIONS_LIMIT:
            del notifications_data[:-NOTIFICATIONS_LIMIT]
        _notifications_write_locked()


def notification_mark_read(notification_id):
    with notifications_lock:
        notification = next((row for row in notifications_data if row.get("id") == notification_id), None)
        if not notification:
            return None
        if not notification.get("read"):
            notification["read"] = True
            _notifications_write_locked()
        return notifications_snapshot_locked()


def notifications_mark_all_read():
    with notifications_lock:
        changed = False
        for row in notifications_data:
            if not row.get("read"):
                row["read"] = True
                changed = True
        if changed:
            _notifications_write_locked()
        return notifications_snapshot_locked()


def notifications_clear():
    with notifications_lock:
        if notifications_data:
            notifications_data.clear()
            _notifications_write_locked()
        return notifications_snapshot_locked()


_notifications_load()

# ---- Вкладка Claude: разговор с Claude Code через сайт ---------------------
# CLAUDE_HOST и claude_ready()/claude_host_name() остались в app.py — им
# нужен ssh_enabled_ips, который живёт там же.
CLAUDE_DIR = os.environ.get("CLAUDE_DIR", "").strip()
# Команда, которую вкладка запускает внутри tmux. По умолчанию claude, но
# ничего специфичного для него тут нет: поставь сюда другую — вкладка будет
# разговаривать с ней. Так же встанет любой другой консольный помощник.
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude").strip() or "claude"
CLAUDE_TABS_MAX = 8                     # больше и не нужно, и память не резиновая
CLAUDE_PREFIX = "vg-"                   # чтобы не путать со своими сессиями tmux
CLAUDE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$")


def claude_run(client, command, timeout=10):
    """Разовая команда по SSH. Возвращает (код, вывод)."""
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return stdout.channel.recv_exit_status(), (out + err).strip()
    except (paramiko.SSHException, OSError, EOFError) as e:
        return 1, str(e)


def claude_tabs(client):
    """Список вкладок — это список сессий tmux с нашим префиксом."""
    code, out = claude_run(
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


def claude_free_name(tabs):
    """Первое свободное имя вида «1», «2», …"""
    taken = {t["id"] for t in tabs}
    for n in range(1, CLAUDE_TABS_MAX + 1):
        if str(n) not in taken:
            return str(n)
    return None


# ---- guacd: протокол Guacamole для RDP/VNC по вебсокету --------------------
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


GUACD_HOST = os.environ.get("GUACD_HOST", "127.0.0.1")
GUACD_PORT = int(os.environ.get("GUACD_PORT", "4822"))

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


def guac_handshake(guac_sock, hostname, username, password, width, height, quality="medium"):
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


def guac_handshake_vnc(guac_sock, hostname, password, width, height):
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


# ---- Wake-on-LAN через домашний ретранслятор -------------------------------
WOL_RELAY_HOST = os.environ.get("WOL_RELAY_HOST", "100.104.221.91")   # домашний сервер
WOL_RELAY_USER = os.environ.get("WOL_RELAY_USER") or os.environ.get("METRICS_UBUNTUSERVER_USER")
WOL_RELAY_PASS = os.environ.get("WOL_RELAY_PASS") or os.environ.get("METRICS_UBUNTUSERVER_PASS")
WOL_BROADCASTS = ("255.255.255.255", "192.168.1.255")


def wol_relay(hex_packet):
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


def create_remote_blueprint(
    *,
    sock,
    netbird_devices,
    netbird_status,
    netbird_status_lock,
    ssh_enabled_ips,
    sftp_enabled_ips,
    rdp_enabled_ips,
    vnc_enabled_ips,
    claude_ready,
    claude_host,
    claude_host_name,
):
    remote_bp = Blueprint("remote", __name__)

    @remote_bp.get("/api/netbird/status")
    @login_required
    def netbird_status_api():
        with netbird_status_lock:
            return jsonify(netbird_status)

    @remote_bp.post("/api/console/login")
    @login_required
    def console_login():
        if not SSH_GATE_PASSWORD_PREFIX:
            return jsonify(error="Консоль не настроена."), 503

        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), console_password_today().encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            log_login("неверный суточный пароль (консоль)", kind="fail")
            return jsonify(error="Неверный пароль."), 401

        rate_clear(console_login_attempts, console_login_attempts_lock, client)
        session["console_authenticated"] = True
        return jsonify(ok=True)

    @sock.route("/ws/console/<ip>", bp=remote_bp)
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

    @sock.route("/ws/claude", bp=remote_bp)
    def claude_ws(ws):
        """Один канал на весь разговор: и список вкладок, и сам терминал."""
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        if not claude_ready():
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
            client.connect(claude_host, username=username, password=password,
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

        code, _out = claude_run(client, "command -v tmux >/dev/null 2>&1")
        if code != 0:
            ws.send(json.dumps({"type": "fail",
                                "text": "На машине нет tmux. Поставь: sudo apt install tmux"}))
            client.close()
            ws.close()
            return
        code, _out = claude_run(client, f"command -v {shlex.quote(CLAUDE_BIN)} >/dev/null 2>&1")
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
            say({"type": "tabs", "tabs": claude_tabs(client), "open": state["tab"]})

        def tabs_out_when(name):
            def wait():
                for _ in range(16):
                    if stop_event.is_set():
                        return
                    tabs = claude_tabs(client)
                    if name in {t["id"] for t in tabs}:
                        say({"type": "tabs", "tabs": tabs, "open": state["tab"]})
                        return
                    time.sleep(0.25)
                tabs_out()

            threading.Thread(target=wait, daemon=True).start()

        def close_tab_channel():
            channel = state["channel"]
            state["channel"] = None
            state["tab"] = None
            if channel:
                try:
                    channel.close()
                except Exception:
                    pass

        def open_tab(name):
            if not CLAUDE_NAME_RE.match(name or ""):
                say({"type": "fail", "text": "Странное имя вкладки."})
                return
            tabs = claude_tabs(client)
            if name not in {t["id"] for t in tabs} and len(tabs) >= CLAUDE_TABS_MAX:
                say({"type": "fail", "text": f"Больше {CLAUDE_TABS_MAX} вкладок сразу не держим."})
                return

            close_tab_channel()
            session_name = shlex.quote(CLAUDE_PREFIX + name)
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

        def kill_tab(name):
            if not CLAUDE_NAME_RE.match(name or ""):
                return
            if state["tab"] == name:
                close_tab_channel()
            claude_run(client, f"tmux kill-session -t {shlex.quote(CLAUDE_PREFIX + name)} 2>/dev/null || true")
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
            say({"type": "ready", "host": claude_host_name(), "dir": CLAUDE_DIR})
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
                    tabs = claude_tabs(client)
                    name = claude_free_name(tabs)
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

    @sock.route("/ws/rdp/<ip>", bp=remote_bp)
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
            guac_handshake(guac_sock, ip, username, password, width, height, quality)
        except Exception as e:
            print(f"[rdp] handshake error ({ip}): {e}", flush=True)
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

    @sock.route("/ws/vnc/<ip>", bp=remote_bp)
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
            guac_handshake_vnc(guac_sock, ip, password, width, height)
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

    @remote_bp.post("/api/pc/shutdown")
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

    @remote_bp.post("/api/wol")
    @login_required
    def wol():
        payload = request.get_json(silent=True) or {}
        mac = payload.get("mac", "")
        mac_clean = mac.replace(":", "").replace("-", "").upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            return jsonify(error="Неверный MAC-адрес."), 400

        packet_hex = "ff" * 6 + (mac_clean.lower() * 16)
        problem = wol_relay(packet_hex)
        if problem:
            return jsonify(error=f"Не удалось разбудить: {problem}"), 502

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                for addr in WOL_BROADCASTS:
                    s.sendto(bytes.fromhex(packet_hex), (addr, 9))
        except OSError:
            pass
        return jsonify(ok=True)

    def _device_kind(device):
        """МОБИЛА — телефон, НОУТ — ноутбук по имени; для остальных смотрим на
        разрешённый протокол: RDP — обычно ПК, SSH — сервер/одноплатник."""
        # Явно заданный значок (kind) важнее догадок: у машины, которой не
        # разрешён ни один протокол, угадывать не по чему.
        if device.get("kind"):
            return device["kind"]
        name_lower = device["name"].lower()
        if "mobil" in name_lower:
            return "phone"
        if "nout" in name_lower:
            return "laptop"
        if device.get("rdp_enabled"):
            return "pc"
        if device.get("ssh_enabled"):
            return "server"
        if device.get("vnc_enabled"):
            return "phone"
        return None

    def _netbird_device_items():
        return "".join(
            f'<li class="device" data-ip="{device["ip"]}">'
            f'<button class="copy-ip" type="button" data-ip="{device["ip"]}">{device["ip"]}</button>'
            f'<span class="device-name">{_NETBIRD_ICONS.get(_device_kind(device), "")}'
            f'<span class="device-name-text" title="{device["name"]}">{device["name"]}</span></span>'
            f'<span class="device-lastseen" data-lastseen>—</span>'
            # Молния (WOL) — не своя колонка, а довесок к пингу: у большинства
            # устройств её нет, и отдельный столбец стоял бы пустым зазором.
            f'<span class="device-ping">'
            f'<span class="device-status" data-status>проверка…</span>'
            + (
                f'<button class="wol-btn" type="button" data-mac="{device["wol_mac"]}" title="Wake-on-LAN">⚡</button>'
                if device.get("wol_mac") else ''
            )
            + '</span>'
            + (
                # Телефон — не машина с логином: там нечего спрашивать, экран
                # отдаёт сам агент. Ссылкой, а не кнопкой с модалкой, поэтому
                # класс `screen-btn` — обработчик кнопок подключения её
                # намеренно не трогает.
                f'<a class="connect-btn screen-btn" href="/phone" data-ip="{device["ip"]}" title="Экран телефона">ЭКРАН</a>'
                if device.get("agent_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="ssh">SSH</button>'
                if device.get("ssh_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="rdp">RDP</button>'
                if device.get("rdp_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="vnc">VNC</button>'
                if device.get("vnc_enabled")
                else '<span class="connect-btn-empty"></span>'
            )
            # Файлы по SFTP — только там, где есть SSH-сервер. Остальным
            # (телефон, винды без OpenSSH) кнопка стоит местом на будущее.
            # files_hidden — те, кому доступ не планируется вовсе: там не
            # «СКОРО», а честно пустое место, чтобы не обещать лишнего.
            + (
                '<span class="smb-btn-empty"></span>'
                if device.get("files_hidden")
                else f'<a class="smb-btn" href="/files/{device["ip"]}" title="Файлы по SFTP">SFTP</a>'
                if device["ip"] in sftp_enabled_ips
                else '<button class="smb-btn" type="button" disabled title="Файлы сюда пока не настроены">СКОРО</button>'
            )
            + "</li>"
            for device in netbird_devices
        )

    @remote_bp.get("/cabinet")
    @login_required
    def cabinet():
        return template("cabinet.html").replace("__ICONLINKS__", ICON_LINKS)

    @remote_bp.get("/notifications")
    @login_required
    def notifications_page():
        return template("notifications.html").replace("__ICONLINKS__", ICON_LINKS)

    @remote_bp.get("/api/notifications")
    @login_required
    def notifications_api():
        with notifications_lock:
            return jsonify(notifications_snapshot_locked())

    @remote_bp.post("/api/notifications/<notification_id>/read")
    @login_required
    def notification_read_api(notification_id):
        snapshot = notification_mark_read(notification_id)
        if snapshot is None:
            return jsonify(error="Уведомление не найдено."), 404
        return jsonify(snapshot)

    @remote_bp.post("/api/notifications/read-all")
    @login_required
    def notifications_read_all_api():
        return jsonify(notifications_mark_all_read())

    @remote_bp.delete("/api/notifications")
    @login_required
    def notifications_clear_api():
        return jsonify(notifications_clear())

    @remote_bp.get("/netbird")
    @login_required
    def netbird_page():
        html = template("netbird.html")
        return (html.replace("{{DEVICE_ITEMS}}", _netbird_device_items())
                    .replace("{{DEVICE_COUNT}}", str(len(netbird_devices)))
                    # Список машин, где живёт SFTP — чтобы кнопка «SFTP» в
                    # оверлее RDP/консоли знала, для какого IP пробовать
                    # подключиться теми же учётными данными, а для какого
                    # промолчать (VNC-устройства, телефон).
                    .replace("{{SFTP_IPS}}", json.dumps(sorted(sftp_enabled_ips)))
                    .replace("__ICONLINKS__", ICON_LINKS))

    return remote_bp
