import gzip
import hashlib
import hmac
import os
import platform
import re
import secrets
import shutil
import subprocess
import threading
import time
from collections import defaultdict, deque

import paramiko
from flask import Flask, g, jsonify, redirect, request, session, url_for
from flask_sock import Sock
from werkzeug.middleware.proxy_fix import ProxyFix

# core/* — общая инфраструктура (задача 34, docs/structure-plan.md): плоские
# модули, выполняются при импорте, как и сам app.py. Старые приватные имена
# app.py (`_client_ip`, `_device_check`, ...) наведены через `as`, чтобы не
# трогать все места, где они уже вызываются, — публичные имена без
# подчёркивания (`client_ip`, `device_check`, ...) предназначены для
# blueprints, которые импортируют их напрямую, без веретена фабрики.
from core.auth import (
    DEVICE_COOKIE,
    DEVICE_TTL_DAYS,
    client_ip as _client_ip,
    devices_lock,
    log_login as _log_login,
    login_required,
    password_matches,
    rate_blocked as _rate_blocked,
    rate_clear as _rate_clear,
    rate_hit as _rate_hit,
    trusted_devices,
)
from core.storage import DATA_DIR
from core.templates import template as _template

from blueprints.ai import create_ai_blueprint
from blueprints.apps import create_apps_blueprint
from blueprints.backup_sebastian import (
    SEBASTIAN_HOST,
    create_backup_sebastian_blueprint,
)
from blueprints.debts import create_debts_blueprint, debt_find_user_by_password as _debt_find_user_by_password
from blueprints.devices import create_devices_blueprint
from blueprints.desktop import create_desktop_blueprint
from blueprints.diy import (
    create_diy_blueprint,
    diy_items,
)
from blueprints.drop import (
    DROP_DIR,
    DROP_DOWNLOAD_ID,
    DROP_MAX_SIZE,
    DROP_MUSIK_ID,
    DROP_QUOTA,
    create_drop_blueprint,
    drop_items,
    drop_load_index,
    drop_lock,
    drop_musik_tracks,
    drop_path,
    drop_trash_bytes,
    drop_used,
    drop_used_safe,
    drop_write_index,
)
from blueprints.files import create_files_blueprint
from blueprints.home import create_home_blueprint
from blueprints.login_log import create_login_log_blueprint
from blueprints.music import (
    create_music_blueprint,
    music_folders,
    music_items,
    music_used as _music_used,
)
from blueprints.notebook import (
    create_notebook_blueprint,
    notebook_data,
)
from blueprints.phone import create_phone_blueprint
from blueprints.pwa import ICON_LINKS, create_pwa_blueprint
from blueprints.remote import CLAUDE_DIR, create_remote_blueprint

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

# Пароль кабинета (_password_secret/PASSWORD_SALT/PASSWORD_HASH/
# PASSWORD_ITERATIONS/password_matches) — в core/auth.py (задача 36):
# нужен и здесь (/api/login), и blueprints/debts.py. SystemExit при
# отсутствующей .env-переменной срабатывает там же, при импорте core.auth
# наверху этого файла — раньше падало здесь же, разницы нет.
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
login_attempts = defaultdict(deque)
login_attempts_lock = threading.Lock()

# sftp_enabled — на машине есть SSH-сервер, значит работает и SFTP (это его
# подсистема, тот же порт 22). У linux-машин он подразумевается флагом
# ssh_enabled; отдельный флаг нужен виндовым, куда SSH поставлен ради
# выключения по кнопке, но консоль им не заводили.
NETBIRD_DEVICES = [
    {"ip": "100.104.18.182", "name": "VitazNout", "rdp_enabled": True, "sftp_enabled": True},
    {"ip": "100.104.122.94", "name": "VitazComp", "rdp_enabled": True, "sftp_enabled": True,
     "wol_mac": "d8:bb:c1:a6:d4:81"},
    {"ip": "100.104.1.172", "name": "windows10proxmox", "rdp_enabled": True, "sftp_enabled": True},
    {"ip": "100.104.67.89", "name": "orangepizero3", "ssh_enabled": True},
    {"ip": "100.104.221.91", "name": "ubuntu-server", "ssh_enabled": True},
    {"ip": "100.104.208.57", "name": "proxmox_vps", "ssh_enabled": True},
    {"ip": "100.104.160.121", "name": "windows10V", "rdp_enabled": True, "sftp_enabled": True},
    {"ip": "100.104.111.39", "name": "ubuntuvitaz1", "ssh_enabled": True},
    # Сам VPS, на котором живёт сайт. Показываем только показания (IP, имя,
    # пинг, «был в сети»): ни консоли, ни файлов сюда намеренно не заводим —
    # обе колонки на /netbird остаются пустыми (files_hidden), чтобы там не
    # висело обещающее «СКОРО». Значок задан явно (kind): угадывать его не по
    # чему — у машины нет ни одного разрешённого протокола.
    {"ip": "100.104.94.83", "name": "VPS-Server", "kind": "server", "files_hidden": True},
    # Телефон: VNC снят намеренно — туда он не работает и работать не может
    # (нет сервера на той стороне, и пинг до телефона тоже не дойдёт).
    # Вместо этого телефон сам приходит вебсокетом, см. blueprints/phone.py.
    {"ip": "100.104.86.103", "name": "MOBILA", "agent_enabled": True},
]
# Телефон из круга пинга исключён: у оператора CGNAT, ICMP до него не дойдёт
# никогда, и «офлайн» от пинга затирал бы честный статус из реестра агентов
# (blueprints/phone.py пишет его сам через _phone_publish_status).
PHONE_AGENT_IP = "100.104.86.103"
PING_SKIP_IPS = {PHONE_AGENT_IP}
PING_INTERVAL_SECONDS = 10
PING_TIMEOUT_SECONDS = 1
PING_LATENCY_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)

netbird_status = {device["ip"]: {"online": False, "latency_ms": None, "last_seen": None} for device in NETBIRD_DEVICES}
netbird_status_lock = threading.Lock()
ssh_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("ssh_enabled")}
# Кому на /netbird показывать файлы. Телефон сюда попадает не через SSH
# (его там нет), а своим транспортом — командами агенту в тот же сокет.
sftp_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES
                    if device.get("ssh_enabled") or device.get("sftp_enabled")
                    or device.get("agent_enabled")}

# SSH_GATE_PASSWORD_PREFIX/суточный пароль консоли — в core/auth.py.
# Пароль телефонного агента: одна строка в .env, её же вбивают в приложении.
# Не задан — вебсокет /ws/agent никого не пускает, страница просто показывает
# MOBILA офлайн. В репозиторий токен не попадает: репозиторий публичный.
PHONE_AGENT_TOKEN = os.environ.get("PHONE_AGENT_TOKEN")
# Репозиторий со сборками приложения: оттуда /api/app/pull тянет свежий APK.
PHONE_APK_REPO = os.environ.get("PHONE_APK_REPO", "VITAZGIO/vitazgio.ru")
# PHONE_FILES_USER/PHONE_FILES_PASSWORD (логин/пароль перед файлами
# телефона на /files) теперь читает сама blueprints/files.py (задача 39)
# — были нужны только там.
# Свой пароль вкладки «Долги», не связан с ежедневным паролем консоли —
# задаётся один раз в .env и не меняется день ото дня.
DEBTS_PASSWORD = os.environ.get("DEBTS_PASSWORD")
# SERVERS_PASSWORD — теперь читает сама blueprints/home.py (задача 36),
# больше нигде не нужен.

# guacd (RDP/VNC-хендшейк) — задача 38, теперь в blueprints/remote.py:
# нужен только там, /ws/rdp и /ws/vnc — единственные потребители.
# CONSOLE_LOGIN_*/console_login_attempts(_lock) — в core/auth.py.

# login_log/login_log_lock и константы урезки — в core/auth.py.

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

# Личный дроп (DROP_*, drop_items/drop_lock и вся логика) — теперь целиком
# в blueprints/drop.py (задача 39): самый большой разрез, файл был
# полностью самодостаточен в app.py, кроме музыки (см. ниже) и того, что
# ещё несколько blueprint'ов читают его состояние обратно.

# Доверенные устройства, журнал входов и login_required — в core/auth.py
# (DATA_DIR, DEVICE_COOKIE, trusted_devices, devices_lock — импортированы
# наверху файла; то, что нужно только внутри core/auth.py, туда не тянем).

# Сборки телефонного приложения. Лежат в данных, а не в образе: собирает их
# облачный раннер и кладёт в релиз, а раздаёт сайт из Амстердама — общего
# диска у них нет, поэтому APK приезжает сюда отдельно (/api/app/pull) и
# переживает пересборку контейнера, как дроп и фонотека.
PHONE_APK_DIR = os.path.join(DATA_DIR, "apk")
os.makedirs(PHONE_APK_DIR, exist_ok=True)
# Личные токены устройств (ступень 2): на диске только хэши, как у пароля
# корзины дропа. Файл обязан пережить деплой — телефон держит свой токен у
# себя, и после пересборки сервер должен его узнать.
PHONE_TOKENS_PATH = os.path.join(DATA_DIR, "phone_tokens.json")

# Фонотека (MUSIC_*, music_items/music_folders/music_lock и вся логика)
# — теперь целиком в blueprints/music.py (задача 36). music_items/
# music_folders/music_lock и часть хелперов (music_used, music_used_safe,
# music_write_index, music_scan, music_load, music_unlink, music_safe_name,
# music_split, music_folder_depth, MUSIC_DIR, MUSIC_EXTS, MUSIC_MIMES,
# MUSIC_MAX_DEPTH) app.py читает обратно — их напрямую трогает ещё не
# переехавший drop.py (папка MUSIK показывает саму фонотеку).


# _rate_blocked/_rate_hit/_rate_clear, console_password_today, device_check
# и вся остальная работа с доверенными устройствами — в core/auth.py.
# device_check самому app.py больше не нужен: последний форвард (в
# create_backup_sebastian_blueprint) убран в задаче 37 — теперь тот файл
# читает device_check/DEVICE_COOKIE из core.auth напрямую. Остальные
# device_*/devices_* app.py тоже не нужны — их взяли blueprints/devices.py
# (задача 35), blueprints/diy.py и blueprints/debts.py (задача 36) напрямую.


# Долги (DEBTS_PATH/DEBT_USER_COLORS, debts_data/debts_lock и вся
# логика, guard'ы debts_owner_required/debtor_required) — теперь целиком
# в blueprints/debts.py (задача 36). debt_find_user_by_password читает
# обратно /api/login (перебор паролей должников после пароля кабинета).

# Уведомления (notifications_data/notifications_lock и вся логика) —
# теперь целиком в blueprints/remote.py (задача 38): все их маршруты
# (/notifications, /api/notifications/*) и там же. notification_add
# нужен и blueprints/debts.py — читает его оттуда напрямую.


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
            if device["ip"] in PING_SKIP_IPS:
                continue
            online, latency_ms = ping_once(device["ip"])
            with netbird_status_lock:
                # last_seen — момент последнего успешного пинга; пока устройство
                # офлайн, старое значение остаётся (иначе показывать было бы нечего).
                prev_seen = netbird_status.get(device["ip"], {}).get("last_seen")
                netbird_status[device["ip"]] = {
                    "online": online,
                    "latency_ms": latency_ms,
                    "last_seen": time.time() if online else prev_seen,
                }
        time.sleep(PING_INTERVAL_SECONDS)


threading.Thread(target=netbird_ping_loop, daemon=True).start()


def _phone_publish_status(online, last_seen):
    """Статус MOBILA пишет не пинг, а реестр агентов из blueprints/phone.py.

    Формат тот же, что у остальных машин, — страница /netbird и её
    `/api/netbird/status` ничего про телефон знать не обязаны. Задержки нет:
    у вебсокета её никто не мерит, и строка покажет просто «онлайн»."""
    with netbird_status_lock:
        previous = netbird_status.get(PHONE_AGENT_IP, {})
        netbird_status[PHONE_AGENT_IP] = {
            "online": bool(online),
            "latency_ms": None,
            # Пока телефон офлайн, показываем момент последней связи —
            # ровно как у машин, до которых не дошёл пинг.
            "last_seen": last_seen or previous.get("last_seen"),
        }


# Рекорды аркады (ARCADE_*, arcade_scores/arcade_lock и вся логика) — теперь
# целиком в blueprints/home.py (задача 36): использовались только там же.


# Журнал входов (login_log/login_log_lock/трим/сохранение) и
# login_required — в core/auth.py (`_log_login`, `login_required`
# импортированы наверху файла; сами login_log/login_log_lock app.py
# больше не нужны — их читает только blueprints/login_log.py напрямую).


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
    probe("дроп: занято", lambda: drop_used())
    probe("дроп: корзина", lambda: drop_trash_bytes())
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
        # Именно "remote.cabinet", а не "cabinet": страница кабинета живёт
        # в blueprints/remote.py, а у видов внутри blueprint'а имя эндпоинта
        # всегда с приставкой. Без неё url_for роняет BuildError, и успешный
        # вход отдаёт 500 вместо адреса перехода — так и было после переезда
        # кабинета в blueprint, пока не поймали тестом.
        return jsonify(redirect=url_for("remote.cabinet"))

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
# CLAUDE_DIR/CLAUDE_BIN/CLAUDE_TABS_MAX/CLAUDE_PREFIX/CLAUDE_NAME_RE и
# claude_run/claude_tabs/claude_free_name — теперь в blueprints/remote.py
# (задача 38): нужны только там, /ws/claude — единственный потребитель.
# CLAUDE_HOST и claude_ready()/claude_host_name() остались здесь: им нужен
# ssh_enabled_ips, который живёт тут же. blueprints/ai.py по-прежнему
# получает все три через фабрику app.py (claude_dir теперь берём из
# blueprints.remote, а не объявляем сами).


def _claude_ready():
    """Настроена ли вкладка. Хост должен быть из списка своих машин."""
    return bool(CLAUDE_HOST) and CLAUDE_HOST in ssh_enabled_ips


def _claude_host_name():
    for device in NETBIRD_DEVICES:
        if device["ip"] == CLAUDE_HOST:
            return device["name"]
    return CLAUDE_HOST


rdp_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("rdp_enabled")}
vnc_enabled_ips = {device["ip"] for device in NETBIRD_DEVICES if device.get("vnc_enabled")}


# _guac_encode/_guac_recv_instr/RDP_QUALITY/_guac_handshake/
# _guac_handshake_vnc — теперь в blueprints/remote.py (задача 38): нужны
# только там, /ws/rdp и /ws/vnc — единственные потребители.


@app.get("/api/metrics")
@login_required
def metrics_api():
    with metrics_lock:
        result = []
        for t in METRICS_TARGETS:
            d = metrics_data.get(t["ip"])
            result.append({"ip": t["ip"], "name": t["name"], "data": d})
    return jsonify(result)


# WOL_RELAY_HOST/USER/PASS/WOL_BROADCASTS/_wol_relay — теперь в
# blueprints/remote.py (задача 38): нужны только там, /api/wol —
# единственный потребитель.


@app.get("/api/uptime")
@login_required
def uptime_api():
    try:
        with open("/proc/uptime") as f:
            seconds = int(float(f.read().split()[0]))
        return jsonify(seconds=seconds)
    except Exception:
        return jsonify(seconds=None)


# music_editor_required и music_unlink (как _music_unlink) — тоже в
# blueprints/music.py, импортированы наверху файла.


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
# Страна DIY (DIY_*, diy_items/diy_lock и вся логика) — теперь целиком
# в blueprints/diy.py (задача 36): использовался только там же, кроме
# diy_items, который app.py читает обратно для /api/metrics (импортирован
# наверху файла). diy_lock/diy_load резервным копиям тоже были нужны, но
# это переехало в blueprints/backup_sebastian.py (задача 37) — оно теперь
# читает их из blueprints.diy напрямую, а не через app.py.


# Блокнот (notebook_data/notebook_lock и вся его логика) — теперь целиком
# в blueprints/notebook.py (задача 35): фича владеет своим состоянием сама,
# а не раздаёт его отсюда пачкой аргументов. notebook_data импортирован
# наверху файла — ещё нужен здесь для /api/metrics. notebook_lock резервным
# копиям тоже был нужен, но это переехало в blueprints/backup_sebastian.py
# (задача 37) — оно теперь читает его из blueprints.notebook напрямую.

# ---- Резервные копии и Себастьян переехали в blueprints/backup_sebastian.py
# (задача 37): не связанные друг с другом разделы, но оба были самодостаточны
# в app.py и не тянули за собой ничего, кроме DROP_DIR/drop_lock/drop_items/
# drop_load_index (задача 39 — теперь эти четыре имени читаются из
# blueprints.drop, а не объявляются здесь) и общего game_icons (см.
# пояснение в blueprints/home.py, задача 36).

app.register_blueprint(create_home_blueprint(
    game_icons=_GAME_ICONS,
    netbird_devices=NETBIRD_DEVICES,
))

app.register_blueprint(create_debts_blueprint())

app.register_blueprint(create_devices_blueprint())

app.register_blueprint(create_login_log_blueprint())

app.register_blueprint(create_notebook_blueprint())

app.register_blueprint(create_diy_blueprint())

app.register_blueprint(create_music_blueprint(
    drop_used_safe=drop_used_safe,
    drop_quota=DROP_QUOTA,
    drop_lock=drop_lock,
    drop_musik_tracks=drop_musik_tracks,
))

app.register_blueprint(create_drop_blueprint())

app.register_blueprint(create_backup_sebastian_blueprint(
    game_icons=_GAME_ICONS,
    drop_dir=DROP_DIR,
    drop_lock=drop_lock,
    drop_items=drop_items,
    drop_load_index=drop_load_index,
))

app.register_blueprint(create_ai_blueprint(
    claude_ready=_claude_ready,
    claude_host_name=_claude_host_name,
    claude_dir=CLAUDE_DIR,
))

# Телефонный blueprint регистрируется раньше файлового: файловому нужен его
# транспорт (команды агенту), а не наоборот.
phone_bp = create_phone_blueprint(
    sock=sock,
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    agent_token=PHONE_AGENT_TOKEN,
    agent_ip=PHONE_AGENT_IP,
    publish_status=_phone_publish_status,
    apk_dir=PHONE_APK_DIR,
    apk_repo=PHONE_APK_REPO,
    tokens_path=PHONE_TOKENS_PATH,
)
app.register_blueprint(phone_bp)

app.register_blueprint(create_files_blueprint(
    netbird_devices=NETBIRD_DEVICES,
    sftp_enabled_ips=sftp_enabled_ips,
    phone_fs=phone_bp.fs,
    phone_ip=PHONE_AGENT_IP,
))

app.register_blueprint(create_remote_blueprint(
    sock=sock,
    netbird_devices=NETBIRD_DEVICES,
    netbird_status=netbird_status,
    netbird_status_lock=netbird_status_lock,
    ssh_enabled_ips=ssh_enabled_ips,
    sftp_enabled_ips=sftp_enabled_ips,
    rdp_enabled_ips=rdp_enabled_ips,
    vnc_enabled_ips=vnc_enabled_ips,
    claude_ready=_claude_ready,
    claude_host=CLAUDE_HOST,
    claude_host_name=_claude_host_name,
))

app.register_blueprint(create_apps_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
))

app.register_blueprint(create_desktop_blueprint(
    template=_template,
    icon_links=ICON_LINKS,
    login_required=login_required,
    data_dir=DATA_DIR,
    repo=PHONE_APK_REPO,
))

app.register_blueprint(create_pwa_blueprint(
    template=_template,
    login_required=login_required,
    drop_lock=drop_lock,
    drop_items=drop_items,
    drop_max_size=DROP_MAX_SIZE,
    drop_quota=DROP_QUOTA,
    drop_path=drop_path,
    drop_used=drop_used,
    drop_write_index=drop_write_index,
    drop_download_id=DROP_DOWNLOAD_ID,
))


if __name__ == "__main__":
    # На домашнем сервере (за NAT) слушаем все интерфейсы. На VPS реверс-прокси
    # (nginx-proxy-manager) сидит на bridge-сети докера, а не на network_mode:
    # host — до хоста он достаёт через docker0-шлюз, а не через loopback.
    # Поэтому там в .env стоит BIND_HOST=172.17.0.1 (см. CLAUDE.md), а не
    # 127.0.0.1 — с loopback'ом bridge-контейнер достучаться бы не смог.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=5000, threaded=True)
