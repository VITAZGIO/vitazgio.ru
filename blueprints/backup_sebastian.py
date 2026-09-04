import hmac
import json
import os
import re
import shutil
import tempfile
import time

from flask import Blueprint, g, jsonify, request, send_file, session


def create_backup_sebastian_blueprint(
    *,
    template,
    icon_links,
    login_required,
    device_check,
    device_cookie,
    backup_token,
    backup_measure,
    backup_build,
    data_dir,
    drop_dir,
    drop_lock,
    drop_items,
    drop_load_index,
    diy_lock,
    diy_items,
    diy_load,
    notebook_lock,
    notebook_data,
    notebook_load,
    music_lock,
    music_items,
    music_folders,
    music_load,
    sebastian_host,
    sebastian_model,
    sebastian_public,
    sebastian_msg_max,
    sebastian_reply_tokens,
    sebastian_timeout,
    sebastian_prompt,
    sebastian_gate,
    sebastian_allow,
    sebastian_icon_svg,
):
    bp = Blueprint("backup_sebastian", __name__)

    def current_backup_token():
        return backup_token() if callable(backup_token) else backup_token

    def current_sebastian_host():
        return sebastian_host() if callable(sebastian_host) else sebastian_host

    def current_sebastian_model():
        return sebastian_model() if callable(sebastian_model) else sebastian_model

    def current_sebastian_public():
        return sebastian_public() if callable(sebastian_public) else sebastian_public

    def current_sebastian_icon_svg():
        return sebastian_icon_svg() if callable(sebastian_icon_svg) else sebastian_icon_svg

    def current_data_dir():
        return data_dir() if callable(data_dir) else data_dir

    def current_drop_dir():
        return drop_dir() if callable(drop_dir) else drop_dir

    @bp.get("/api/backup/state")
    @login_required
    def backup_state_api():
        """Что и сколько весит — кабинет показывает это до нажатия кнопки."""
        light_size, light_count = backup_measure(False)
        full_size, full_count = backup_measure(True)
        return jsonify(light={"size": light_size, "files": light_count},
                       full={"size": full_size, "files": full_count},
                       robot=bool(current_backup_token()))

    @bp.get("/api/backup/export")
    def backup_export_api():
        """Отдаёт архив. Пускаем хозяина из кабинета или программу с ключом."""
        token = (request.args.get("token") or "").strip()
        configured_token = current_backup_token()
        by_token = bool(configured_token) and token and hmac.compare_digest(token, configured_token)
        if not by_token and not session.get("authenticated"):
            fresh = device_check(request.cookies.get(device_cookie))
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
                roots = {"data": current_data_dir(), "drop_data": current_drop_dir()}
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
        ready = bool(current_sebastian_host()) and current_sebastian_public()
        return jsonify(ready=ready, model=current_sebastian_model() if ready else "",
                       owner=bool(session.get("authenticated")))

    @bp.post("/api/sebastian/ask")
    def sebastian_ask_api():
        if not current_sebastian_public():
            return jsonify(error="Дворецкий сейчас не принимает."), 503
        host = current_sebastian_host()
        if not host:
            return jsonify(error="Дворецкий не на связи: сервер с моделью не указан."), 503

        payload = request.get_json(silent=True) or {}
        text = (payload.get("text") or "").strip()[:sebastian_msg_max]
        if not text:
            return jsonify(error="Пустой вопрос."), 400

        owner = bool(session.get("authenticated"))
        if not sebastian_allow(owner):
            return jsonify(error="На сегодня довольно вопросов — приходите позже."), 429

        history = []
        for row in (payload.get("history") or [])[-6:]:
            role = "assistant" if row.get("role") == "bot" else "user"
            body = (row.get("text") or "").strip()[:sebastian_msg_max]
            if body:
                history.append({"role": role, "content": body})

        body = json.dumps({
            "model": current_sebastian_model(),
            "messages": ([{"role": "system", "content": sebastian_prompt}]
                         + history + [{"role": "user", "content": text}]),
            "stream": False,
            "think": False,
            "options": {"num_predict": sebastian_reply_tokens, "temperature": 0.7},
        }).encode("utf-8")

        if not sebastian_gate.acquire(timeout=20):
            return jsonify(error="Дворецкий занят домашними делами. Минуту."), 503
        try:
            from urllib import request as urlrequest, error as urlerror
            req = urlrequest.Request(host + "/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
            try:
                with urlrequest.urlopen(req, timeout=sebastian_timeout) as resp:
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
        return (html.replace("__ICONLINKS__", icon_links)
                    .replace("__ICON_BUTLER__", current_sebastian_icon_svg()))

    return bp
