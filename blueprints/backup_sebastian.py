"""blueprints/backup_sebastian.py — резервные копии /backup и дворецкий
/sebastian (задача 37, docs/structure-plan.md).

Два не связанных друг с другом раздела в одном файле — так было и в
app.py (соседние секции «Резервные копии» и «Себастьян»), разносить по
двум blueprint'ам не стали: это меньше 250 строк на двоих, отдельный
файл на каждый был бы overkill.

`backup_targets`/`backup_measure`/`backup_build` — не на модульном
уровне, а внутри фабрики: им нужен `drop_dir`, который пока (до задачи
39, разреза `drop.py`) остаётся значением из `app.py` — там ещё живут
`DROP_DIR`/`drop_lock`/`drop_items`/`drop_load_index`, blueprint'а своего
у дропа ещё нет. `game_icons` — по той же причине, что и в `home.py`
(задача 36): общий словарь пиксель-арта, 350+ строк литералов в app.py,
не фича этого файла, переезжать ему некуда конкретно сюда.

`diy_lock`/`diy_items`/`diy_load`, `notebook_lock`/`notebook_data`/
`notebook_load`, `music_lock`/`music_items`/`music_folders`/`music_load`
— уже переехали в свои blueprint'ы (задачи 35-36), этот файл читает их
оттуда напрямую, а не через фабрику app.py.

`SEBASTIAN_HOST` нужен и `app.py` (диагностика `/api/diag`, проверка
«дворецкий: настроен ли») — импортирован оттуда, как `notebook_data` в
`blueprints/ai.py`.
"""

import hmac
import json
import os
import re
import shutil
import tempfile
import threading
import time

from flask import Blueprint, g, jsonify, request, send_file, session

from blueprints.diy import diy_items, diy_lock, diy_load
from blueprints.music import music_folders, music_items, music_load, music_lock
from blueprints.notebook import notebook_data, notebook_lock, notebook_load
from blueprints.pwa import ICON_LINKS
from core.auth import DEVICE_COOKIE, client_ip, device_check, login_required
from core.storage import DATA_DIR
from core.templates import template

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


def backup_skip(path):
    """Мусор и временное в копию не берём."""
    name = os.path.basename(path)
    return (name.endswith(".tmp") or name.endswith(".part")
            or os.sep + "tmp" + os.sep in path)


# ---- Себастьян: разговор с дворецким через сайт ---------------------------
# Отвечает та же модель, что уже висит в памяти видеокарты дома, — новую не
# поднимаем, иначе домашнему Себастьяну не хватит места. Поэтому здесь только
# разговор: никаких инструментов и никакого управления домом, кто бы ни писал.
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


def sebastian_allow(owner):
    """Не даём одному гостю занимать видеокарту весь день."""
    limit = SEBASTIAN_OWNER_HOUR if owner else SEBASTIAN_GUEST_HOUR
    who = "owner" if owner else client_ip()
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


def create_backup_sebastian_blueprint(*, game_icons, drop_dir, drop_lock, drop_items,
                                      drop_load_index):
    bp = Blueprint("backup_sebastian", __name__)

    def backup_targets(full):
        """Какие папки кладём в архив. Возвращает [(корень, имя в архиве)]."""
        roots = [(DATA_DIR, "data")]
        if full:
            roots.append((drop_dir, "drop_data"))
        return [(root, alias) for root, alias in roots if os.path.isdir(root)]

    def backup_measure(full):
        """Сколько весит будущий архив — до того, как его собирать."""
        total, count = 0, 0
        for root, _ in backup_targets(full):
            for base, _dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(base, name)
                    if backup_skip(path):
                        continue
                    try:
                        total += os.path.getsize(path)
                    except OSError:
                        continue
                    count += 1
        return total, count

    def backup_build(full):
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
            for root, alias in backup_targets(full):
                for base, _dirs, files in os.walk(root):
                    for name in files:
                        path = os.path.join(base, name)
                        if backup_skip(path):
                            continue
                        inside = os.path.join(alias, os.path.relpath(path, root))
                        try:
                            zf.write(path, inside)
                        except OSError:
                            continue          # файл увели прямо во время сборки
        return tmp

    @bp.get("/backup")
    @login_required
    def backup_page():
        return template("backup.html").replace("__ICONLINKS__", ICON_LINKS)

    @bp.get("/api/backup/state")
    @login_required
    def backup_state_api():
        """Что и сколько весит — кабинет показывает это до нажатия кнопки."""
        light_size, light_count = backup_measure(False)
        full_size, full_count = backup_measure(True)
        return jsonify(light={"size": light_size, "files": light_count},
                       full={"size": full_size, "files": full_count},
                       robot=bool(BACKUP_TOKEN))

    @bp.get("/api/backup/export")
    def backup_export_api():
        """Отдаёт архив. Пускаем хозяина из кабинета или программу с ключом."""
        token = (request.args.get("token") or "").strip()
        by_token = bool(BACKUP_TOKEN) and token and hmac.compare_digest(token, BACKUP_TOKEN)
        if not by_token and not session.get("authenticated"):
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh

        full = (request.args.get("kind") or "light") == "full"
        try:
            path = backup_build(full)
        except OSError as e:
            return jsonify(error=f"Не удалось собрать копию: {e}"), 500

        stamp = time.strftime("%Y-%m-%d-%H%M")
        name = f"vitazgio-{'full' if full else 'light'}-{stamp}.zip"

        handle = open(path, "rb")
        try:
            os.remove(path)
        except OSError:
            pass
        response = send_file(handle, mimetype="application/zip",
                             as_attachment=True, download_name=name)
        response.headers["Cache-Control"] = "no-store"
        return response

    @bp.post("/api/backup/import")
    @login_required
    def backup_import_api():
        """Разворачивает копию обратно. Файлы кладём поверх, ничего не удаляя."""
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
                roots = {"data": DATA_DIR, "drop_data": drop_dir}
                written = 0
                for inside in names:
                    if inside.endswith("/") or inside == "backup.json":
                        continue
                    head, _, rest = inside.partition("/")
                    target_root = roots.get(head)
                    if not target_root or not rest:
                        continue
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

        with drop_lock:
            drop_items.clear()
        drop_load_index()
        with diy_lock:
            diy_items.clear()
        diy_load()
        with notebook_lock:
            notebook_data["pages"] = []
            notebook_data["entries"] = {}
        notebook_load()
        with music_lock:
            music_items.clear()
            music_folders.clear()
        music_load()
        return jsonify(ok=True, files=written)

    @bp.get("/api/sebastian/state")
    def sebastian_state_api():
        """Готов ли дворецкий отвечать — страница спрашивает при открытии."""
        ready = bool(SEBASTIAN_HOST) and SEBASTIAN_PUBLIC
        return jsonify(ready=ready, model=SEBASTIAN_MODEL if ready else "",
                       owner=bool(session.get("authenticated")))

    @bp.post("/api/sebastian/ask")
    def sebastian_ask_api():
        if not SEBASTIAN_PUBLIC:
            return jsonify(error="Дворецкий сейчас не принимает."), 503
        host = SEBASTIAN_HOST
        if not host:
            return jsonify(error="Дворецкий не на связи: сервер с моделью не указан."), 503

        payload = request.get_json(silent=True) or {}
        text = (payload.get("text") or "").strip()[:SEBASTIAN_MSG_MAX]
        if not text:
            return jsonify(error="Пустой вопрос."), 400

        owner = bool(session.get("authenticated"))
        if not sebastian_allow(owner):
            return jsonify(error="На сегодня довольно вопросов — приходите позже."), 429

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
            req = urlrequest.Request(host + "/api/chat", data=body,
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
        said = re.sub(r"<think>.*?</think>", "", said, flags=re.S).strip()
        if not said:
            return jsonify(error="Дворецкий промолчал."), 502
        return jsonify(text=said[:4000])

    @bp.get("/sebastian")
    def sebastian_page():
        """Разговор с дворецким. Открыт всем: управлять домом отсюда нельзя."""
        html = template("sebastian.html")
        return (html.replace("__ICONLINKS__", ICON_LINKS)
                    .replace("__ICON_BUTLER__", game_icons.get("butler", "")))

    return bp
