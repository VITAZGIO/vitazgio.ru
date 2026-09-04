import hashlib
import os
import time
import uuid

from flask import Blueprint, Response, jsonify, request, send_file, session


def create_music_blueprint(
    *,
    template,
    icon_links,
    login_required,
    music_editor_required,
    music_items,
    music_folders,
    music_lock,
    music_scan,
    music_write_index,
    music_used,
    drop_used_safe,
    drop_quota,
    music_max_size,
    music_safe_name,
    music_exts,
    music_dir,
    music_chunk,
    music_unlink,
    music_twin,
    music_split,
    music_folder_depth,
    music_max_depth,
    music_subtree,
    music_drop_file,
    music_mimes,
    drop_lock,
    drop_musik_tracks,
):
    music_bp = Blueprint("music", __name__)

    def current_music_dir():
        return music_dir() if callable(music_dir) else music_dir

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
                       limit=music_max_size, fav_folder=fav_folder,
                       can_edit=bool(session.get("authenticated")))

    @music_bp.post("/api/music")
    @music_editor_required
    def music_upload_api():
        f = request.files.get("file")
        if not f:
            return jsonify(error="Файл не выбран."), 400
        name = music_safe_name(f.filename)
        ext = os.path.splitext(name)[1].lower()
        if ext not in music_exts:
            return jsonify(error="Это не музыка."), 415
        if request.content_length and request.content_length > music_max_size + 8192:
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
        while candidate in taken or os.path.exists(os.path.join(current_music_dir(), candidate)):
            candidate = f"{stem} ({counter}){suffix}"
            counter += 1

        # Пишем во временный файл и считаем отпечаток на лету: если такой трек уже
        # лежит, лишние байты на диск не попадут вовсе.
        temp = os.path.join(current_music_dir(), f".upload-{uuid.uuid4().hex}")
        digest = hashlib.sha256()
        size = 0
        try:
            with open(temp, "wb") as out:
                while True:
                    chunk = f.stream.read(music_chunk)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > music_max_size:
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
                    os.replace(temp, os.path.join(current_music_dir(), candidate))
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
            if music_folder_depth(parent) >= music_max_depth:
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
        path = os.path.join(current_music_dir(), track["file"])
        if not os.path.exists(path):
            return "", 404
        ext = os.path.splitext(track["file"])[1].lower()
        return send_file(path, mimetype=music_mimes.get(ext, "audio/mpeg"), conditional=True)

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
        return html.replace("__ICONLINKS__", icon_links)

    return music_bp
