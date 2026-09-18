"""blueprints/music.py — фонотека /music, плеер (задача 36,
docs/structure-plan.md).

Данные и вся логика — на модульном уровне здесь же, а не в `app.py`: файл
владеет своим состоянием сам, как блокнот/DIY (задачи 35-36). Дроп и
фонотека делят ОДНО хранилище на 30 ГБ (`DROP_QUOTA`) — правило то же, что
было в app.py: **сначала `music_lock`, потом `drop_lock`** (или каждый
отдельно), никогда наоборот, иначе взаимоблокировка.

`music_items`/`music_folders`/`music_lock` и часть хелперов (`music_used`,
`music_used_safe`, `music_write_index`, `music_scan`, `music_load`,
`music_unlink`, `music_safe_name`, `music_split`, `music_folder_depth`,
`MUSIC_DIR`, `MUSIC_EXTS`, `MUSIC_MIMES`, `MUSIC_MAX_DEPTH`) читает и
пишет напрямую ещё не переехавший `drop.py` (папка MUSIK показывает саму
фонотеку — см. `_drop_music_take`/`_drop_music_view`/`_drop_music_send` в
app.py) — импортированы в `app.py` из `blueprints.music` для форварда, как
notebook_data/diy_items в задачах 35-36. `drop_used_safe`/`drop_quota`/
`drop_lock`/`drop_musik_tracks` остались фабричными аргументами — это уже
DROP-овские вещи, переедут вместе с ним (задача 39).
"""

import hashlib
import json
import os
import re
import threading
import time
import uuid
from functools import wraps

from flask import Blueprint, Response, g, jsonify, request, send_file, session

from blueprints.pwa import ICON_LINKS
from core.auth import DEVICE_COOKIE, device_check, log_login, login_required
from core.storage import DATA_DIR, atomic_write_json
from core.templates import template

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


def music_safe_name(name):
    """Имя файла без путей и запрещённых символов. secure_filename не годится —
    он выбрасывает кириллицу, а треки как раз названы по-русски."""
    name = os.path.basename(name or "")
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name).strip(" .")
    return name[:120] or "track"


def music_split(stem):
    """«Исполнитель - Название» → пара. Разделителем может быть дефис или тире."""
    for sep in (" — ", " – ", " - ", " -", "- "):
        if sep in stem:
            left, _, right = stem.partition(sep)
            if left.strip() and right.strip():
                return left.strip()[:80], right.strip()[:120]
    return "", stem.strip()[:120]


def music_write_index():
    """Вызывать под music_lock."""
    try:
        atomic_write_json(MUSIC_INDEX_PATH, {"items": music_items, "folders": music_folders})
    except OSError:
        pass


def music_digest(fname):
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


def music_twin(size, digest):
    """Имя уже лежащего файла с тем же содержимым, иначе пусто.

    Считать отпечатки всей фонотеки при каждой загрузке было бы расточительно,
    поэтому сначала отсеиваем по размеру: совпал размер — только тогда читаем
    байты, и посчитанное запоминаем в записи. Вызывать под music_lock."""
    for track in music_items.values():
        if track.get("size") != size:
            continue
        if not track.get("hash"):
            track["hash"] = music_digest(track["file"])
        if track["hash"] and track["hash"] == digest:
            return track["file"]
    return ""


def music_used():
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
def music_used_safe():
    with music_lock:
        return music_used()


def music_drop_file(fname):
    """Убрать файл с диска, если на него больше никто не ссылается.
    Вызывать под music_lock."""
    if any(t["file"] == fname for t in music_items.values()):
        return
    try:
        os.remove(os.path.join(MUSIC_DIR, fname))
    except OSError:
        pass


def music_folder_depth(folder_id):
    """Сколько папок над этой. Заодно страхует от закольцованного дерева:
    длиннее MUSIC_MAX_DEPTH подниматься не станем. Вызывать под music_lock."""
    depth, seen = 0, set()
    while folder_id and folder_id in music_folders and folder_id not in seen:
        seen.add(folder_id)
        folder_id = music_folders[folder_id].get("parent", "")
        depth += 1
    return depth


def music_subtree(folder_id):
    """Папка и всё, что под ней. Вызывать под music_lock."""
    found = {folder_id}
    while True:
        grown = {k for k, v in music_folders.items() if v.get("parent") in found}
        if grown <= found:
            return found
        found |= grown


def music_scan():
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
        artist, title = music_split(os.path.splitext(fname)[0])
        try:
            size = os.path.getsize(os.path.join(MUSIC_DIR, fname))
        except OSError:
            continue
        music_items[str(uuid.uuid4())] = {
            "file": fname, "artist": artist, "title": title,
            "size": size, "added": time.time(), "folder": "", "hash": "",
        }


def music_load():
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
    music_scan()
    music_write_index()


music_load()


def music_editor_required(view):
    """Фонотека целиком под паролем кабинета — и слушать, и менять.

    Изначально слушать мог кто угодно, но выкладывать в открытый доступ
    скачанную музыку — это раздача чужого, и претензии тут прилетают
    именно за раздачу, а не за личную копию. Поэтому закрыто всё.

    Отвечаем кодом, а не переадресацией: это разбирает скрипт страницы."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен расширенный режим."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")
        return view(*args, **kwargs)

    return wrapped


def music_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass


def create_music_blueprint(
    *,
    drop_used_safe,
    drop_quota,
    drop_lock,
    drop_musik_tracks,
):
    music_bp = Blueprint("music", __name__)

    @music_bp.get("/api/music")
    @music_editor_required
    def music_list_api():
        with music_lock:
            music_scan()
            music_write_index()
            used = music_used()
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
        drop_used = drop_used_safe()
        return jsonify(tracks=tracks, folders=folders,
                       used=drop_used + used, music=used, quota=drop_quota,
                       limit=MUSIC_MAX_SIZE, fav_folder=fav_folder,
                       can_edit=bool(session.get("authenticated")))

    @music_bp.post("/api/music")
    @music_editor_required
    def music_upload_api():
        f = request.files.get("file")
        if not f:
            return jsonify(error="Файл не выбран."), 400
        name = music_safe_name(f.filename)
        ext = os.path.splitext(name)[1].lower()
        if ext not in MUSIC_EXTS:
            return jsonify(error="Это не музыка."), 415
        if request.content_length and request.content_length > MUSIC_MAX_SIZE + 8192:
            return jsonify(error="Трек больше 40 МБ."), 413

        folder = (request.form.get("folder") or "").strip()
        drop_used = drop_used_safe()          # место общее с дропом (30 ГБ)
        with music_lock:
            music_scan()
            if drop_used + music_used() > drop_quota:
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
            music_unlink(temp)
            return jsonify(error="Трек больше 40 МБ."), 413
        except OSError as e:
            music_unlink(temp)
            return jsonify(error=f"Не удалось сохранить: {e}"), 500

        artist, title = music_split(os.path.splitext(candidate)[0])
        track_id = str(uuid.uuid4())
        with music_lock:
            twin = music_twin(size, digest.hexdigest())
            if twin:
                music_unlink(temp)
                candidate = twin
            else:
                try:
                    os.replace(temp, os.path.join(MUSIC_DIR, candidate))
                except OSError as e:
                    music_unlink(temp)
                    return jsonify(error=f"Не удалось сохранить: {e}"), 500
            music_items[track_id] = {"file": candidate, "artist": artist, "title": title,
                                     "size": size, "added": time.time(),
                                     "folder": folder, "hash": digest.hexdigest()}
            music_write_index()
        return jsonify(id=track_id, artist=artist, title=title, folder=folder, twin=bool(twin))

    @music_bp.patch("/api/music/<track_id>")
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
            music_write_index()
            return jsonify(ok=True, artist=track["artist"], title=track["title"],
                           folder=track.get("folder", ""))

    @music_bp.delete("/api/music/<track_id>")
    @music_editor_required
    def music_delete_api(track_id):
        with music_lock:
            track = music_items.pop(track_id, None)
            if track:
                music_drop_file(track["file"])
                music_write_index()
        return jsonify(ok=True)

    @music_bp.post("/api/music/folder")
    @music_editor_required
    def music_folder_create_api():
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:60] or "Новая папка"
        parent = (payload.get("parent") or "").strip()
        with music_lock:
            if parent and parent not in music_folders:
                parent = ""
            if music_folder_depth(parent) >= MUSIC_MAX_DEPTH:
                return jsonify(error="Глубже вкладывать некуда."), 400
            folder_id = str(uuid.uuid4())
            music_folders[folder_id] = {"name": name, "parent": parent, "added": time.time()}
            music_write_index()
        return jsonify(id=folder_id, name=name, parent=parent)

    @music_bp.patch("/api/music/folder/<folder_id>")
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
                if parent in music_subtree(folder_id):
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
            music_write_index()
            return jsonify(ok=True, name=folder["name"], parent=folder.get("parent", ""),
                           fav=bool(folder.get("fav")))

    @music_bp.delete("/api/music/folder/<folder_id>")
    @music_editor_required
    def music_folder_delete_api(folder_id):
        with music_lock:
            if folder_id not in music_folders:
                return jsonify(error="Папка не найдена."), 404
            doomed = music_subtree(folder_id)
            gone = [k for k, v in music_items.items() if v.get("folder") in doomed]
            files = {music_items[k]["file"] for k in gone}
            for k in gone:
                music_items.pop(k, None)
            for k in doomed:
                music_folders.pop(k, None)
            for fname in files:
                music_drop_file(fname)
            music_write_index()
        return jsonify(ok=True, tracks=len(gone), folders=len(doomed))

    @music_bp.post("/api/music/op")
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
                    music_drop_file(track["file"])
                done += 1
            music_write_index()
        return jsonify(ok=True, done=done)

    @music_bp.get("/api/music/file/<track_id>")
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

    @music_bp.get("/api/player/tracks")
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
            music_scan()
            folder_name = {k: v["name"] for k, v in music_folders.items()}
            folders = [{"id": k, "name": v["name"], "parent": v.get("parent", "")}
                       for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower())]
            fav_id = next((k for k, v in music_folders.items() if v.get("fav")), "")
            if pick and pick in music_folders:
                allowed = music_subtree(pick)          # выбрали конкретную папку
            elif pick == "__all__":
                allowed = None                          # вся музыка
            elif fav_id:
                allowed = music_subtree(fav_id)        # избранная по умолчанию
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
                tracks.extend(drop_musik_tracks())
        return jsonify(tracks=tracks, folders=folders, fav=fav_id, pick=pick)

    @music_bp.get("/vg-player.js")
    def vg_player_js():
        """Единый плеер сайта: один звук, одно состояние, красивый виджет."""
        js = template("vg_player.js.tpl")
        response = Response(js, mimetype="application/javascript; charset=utf-8")
        response.set_etag(hashlib.md5(js.encode("utf-8")).hexdigest())
        response.headers["Cache-Control"] = "private, no-cache"
        return response.make_conditional(request)

    @music_bp.get("/player/pop")
    @login_required
    def player_pop_page():
        """Плеер в настоящем отдельном окне браузера — «вынести» из виджета."""
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

    @music_bp.get("/music")
    @login_required
    def music_page():
        """Фонотека. Вся под паролем кабинета — и слушать, и менять."""
        html = template("music.html")
        return html.replace("__ICONLINKS__", ICON_LINKS)

    return music_bp
