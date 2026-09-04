import io
import os
import secrets
import threading
import time
import urllib.parse
import uuid
import zipfile

from flask import Blueprint, Response, jsonify, request, send_file, session, url_for


def create_drop_blueprint(
    *,
    template,
    icon_links,
    escape,
    login_required,
    logger,
    drop_items,
    drop_uploads,
    drop_lock,
    drop_jobs,
    drop_jobs_lock,
    drop_folder_icons,
    drop_max_size,
    drop_quota,
    drop_text_preview,
    drop_musik_id,
    drop_zip_chunk,
    drop_ops,
    drop_path,
    drop_tmp_path,
    drop_write_index,
    drop_used,
    drop_children,
    drop_folder_stats,
    drop_trash,
    drop_trash_ok,
    drop_path_to_root,
    drop_is_descendant,
    drop_share_lookup,
    drop_sweep_uploads,
    drop_sweep_trash,
    drop_trash_roots,
    drop_trash_bytes,
    drop_trash_subtree_bytes,
    drop_discard,
    drop_thumb_path,
    drop_can_thumb,
    drop_make_thumb,
    drop_human_size,
    drop_view_kind,
    drop_share_mode,
    drop_send,
    drop_text_name,
    drop_music_take,
    drop_music_view,
    drop_music_send,
    drop_music_delete,
    drop_zip_name,
    drop_zip_plan,
    drop_zip_length,
    drop_zip_time,
    drop_job_set,
    drop_jobs_sweep,
    drop_unique_name,
    music_used_safe,
    music_lock,
    music_items,
    music_folders,
    music_folder_depth,
    music_max_depth,
    music_write_index,
    music_used_raw,
):
    drop_bp = Blueprint("drop", __name__)

    @drop_bp.get("/api/drop/thumb/<item_id>")
    @login_required
    def drop_thumb(item_id):
        with drop_lock:
            item = drop_items.get(item_id)
        if not item or not drop_can_thumb(item):
            return "", 404
        thumb_path = drop_make_thumb(item_id)
        if not thumb_path:
            return "", 404
        response = send_file(thumb_path, mimetype="image/jpeg", conditional=True)
        response.headers["Cache-Control"] = "private, max-age=86400"
        return response

    @drop_bp.post("/api/drop/text")
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
            if drop_used() + len(data) > drop_quota:
                return jsonify(error="Нет места: квота исчерпана."), 507
            try:
                with open(drop_path(item_id), "wb") as fh:
                    fh.write(data)
            except OSError as e:
                return jsonify(error=f"Не удалось сохранить: {e}"), 500
            # Имя лепим из первой строки, но обязательно с .txt на конце. Без
            # него любая точка в тексте («1. Убрать датчики») выглядела как
            # расширение, и переименование правило текст до этой точки.
            first = text.strip().splitlines()[0][:60] if text.strip() else "Текст"
            drop_items[item_id] = {
                "kind": "text", "name": drop_text_name(first), "parent": parent,
                "content_type": "text/plain; charset=utf-8", "size": len(data),
                "created": time.time(), "preview": text[:drop_text_preview],
                "truncated": len(text) > drop_text_preview, "share": None,
            }
            drop_write_index()
        return jsonify(id=item_id)

    @drop_bp.get("/api/drop/text/<item_id>")
    @login_required
    def drop_text_full(item_id):
        with drop_lock:
            item = drop_items.get(item_id)
        if not item or item["kind"] != "text":
            return jsonify(error="Не найдено."), 404
        try:
            with open(drop_path(item_id), encoding="utf-8") as fh:
                return jsonify(text=fh.read())
        except OSError:
            return jsonify(error="Файл потерян."), 404

    @drop_bp.put("/api/drop/text/<item_id>")
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
            if drop_used() - item["size"] + len(data) > drop_quota:
                return jsonify(error="Нет места: квота исчерпана."), 507
            try:
                with open(drop_path(item_id), "wb") as fh:
                    fh.write(data)
            except OSError as e:
                return jsonify(error=f"Не удалось сохранить: {e}"), 500
            item["size"] = len(data)
            item["preview"] = text[:drop_text_preview]
            item["truncated"] = len(text) > drop_text_preview
            item["edited"] = time.time()
            drop_write_index()
        return jsonify(ok=True, size=len(data))

    @drop_bp.post("/api/drop/folder")
    @login_required
    def drop_folder_create():
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:60]
        parent = payload.get("parent") or None
        icon = payload.get("icon") if payload.get("icon") in drop_folder_icons else "folder"
        if not name:
            return jsonify(error="Имя пустое."), 400
        # Папка внутри MUSIK — это папка ФОНОТЕКИ, а не склад дропа. MUSIK
        # показывает не свои вложения, а папки фонотеки (id с «mf_»), поэтому
        # обычная папка дропа тут просто не показалась бы — «создал, а её нет».
        # Заводим настоящую папку фонотеки, туда же потом лягут загруженные треки.
        if parent == drop_musik_id or (parent or "").startswith("mf_"):
            inside = "" if parent == drop_musik_id else parent[3:]
            with music_lock:
                if inside and inside not in music_folders:
                    inside = ""
                if music_folder_depth(inside) >= music_max_depth:
                    return jsonify(error="Глубже вкладывать некуда."), 400
                fid = str(uuid.uuid4())
                music_folders[fid] = {"name": name, "parent": inside, "added": time.time()}
                music_write_index()
            return jsonify(id="mf_" + fid, name=name)
        item_id = str(uuid.uuid4())
        with drop_lock:
            if parent and drop_items.get(parent, {}).get("kind") != "folder":
                parent = None
            drop_items[item_id] = {
                "kind": "folder", "name": name, "parent": parent, "icon": icon,
                "size": 0, "created": time.time(), "share": None,
            }
            drop_write_index()
        return jsonify(id=item_id, name=name)

    @drop_bp.post("/api/drop/upload/init")
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
        if size > drop_max_size:
            return jsonify(error="Файл больше 2 ГБ."), 413

        upload_id = str(uuid.uuid4())
        music_target = parent == drop_musik_id or (parent or "").startswith("mf_")
        music_used = music_used_safe()        # музыка тоже в общем лимите 30 ГБ
        with drop_lock:
            drop_sweep_uploads()
            # MUSIK и папки внутри неё — приёмник фонотеки, а не склад дропа
            if not music_target and parent and drop_items.get(parent, {}).get("kind") != "folder":
                parent = None
            reserved = sum(u["size"] for u in drop_uploads.values())
            if drop_used() + music_used + reserved + size > drop_quota:
                return jsonify(error="Нет места: квота исчерпана."), 507
            drop_uploads[upload_id] = {
                "name": name, "size": size, "parent": parent,
                "received": 0, "started": time.time(),
                "content_type": payload.get("content_type") or "application/octet-stream",
            }
        try:
            open(drop_tmp_path(upload_id), "wb").close()
        except OSError as e:
            return jsonify(error=f"Не удалось начать загрузку: {e}"), 500
        return jsonify(upload_id=upload_id)

    @drop_bp.post("/api/drop/upload/chunk/<upload_id>")
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
            with open(drop_tmp_path(upload_id), "ab") as fh:
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

    @drop_bp.post("/api/drop/upload/finish/<upload_id>")
    @login_required
    def drop_upload_finish(upload_id):
        with drop_lock:
            upload = drop_uploads.pop(upload_id, None)
        if not upload:
            return jsonify(error="Загрузка не найдена."), 404

        tmp_path = drop_tmp_path(upload_id)
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
        if parent_in == drop_musik_id or parent_in.startswith("mf_"):
            return drop_music_take(tmp_path, upload["name"], actual,
                                   "" if parent_in == drop_musik_id else parent_in[3:])

        item_id = str(uuid.uuid4())
        music_used = music_used_safe()        # музыка тоже в общем лимите 30 ГБ
        with drop_lock:
            if drop_used() + music_used + actual > drop_quota:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                return jsonify(error="Нет места: квота исчерпана."), 507
            try:
                os.replace(tmp_path, drop_path(item_id))
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
            drop_write_index()
        return jsonify(id=item_id)

    @drop_bp.get("/api/drop/list")
    @login_required
    def drop_list_api():
        parent = request.args.get("parent") or None
        # Папка MUSIK и всё внутри неё — это фонотека, а не склад дропа
        if parent == drop_musik_id or (parent or "").startswith("mf_"):
            try:
                return drop_music_view(parent)
            except Exception:                                   # noqa: BLE001
                logger.exception("MUSIK: не собрал список фонотеки")
                return jsonify(items=[], breadcrumbs=[{"id": drop_musik_id, "name": "MUSIK"}],
                               used=0, quota=drop_quota, trash=0, music_view=True,
                               warn="Фонотека сейчас не читается.")
        music_used = music_used_safe()        # музыка делит хранилище с дропом
        with drop_lock:
            drop_sweep_trash()
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
                    "thumb": drop_can_thumb(v),
                    "share": bool(v.get("share")),
                    "share_expires": (v.get("share") or {}).get("expires"),
                    "share_mode": drop_share_mode(v["share"]) if v.get("share") else None,
                    # Ссылку отдаём готовой: страница должна уметь показать её
                    # ещё раз, а не только выдать один раз при создании.
                    "share_url": (url_for("drop.drop_public", token=v["share"]["token"], _external=True)
                                  if v.get("share") else None),
                    # По этой отметке страница сортирует. У файла это его время,
                    # у папки — время самого свежего файла внутри.
                    "touched": v["created"],
                }
                if v["kind"] == "folder":
                    size, touched, count = drop_folder_stats(k, memo)
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
                                row["size"] = music_used_raw()
                                row["count"] = len(music_items)
                        except Exception:                       # noqa: BLE001
                            logger.exception("MUSIK: не посчитал фонотеку")
                items.append(row)
            # Сначала новые, но особая папка (MUSIK) всегда падает в самый низ.
            # Сортировка устойчивая: сперва по свежести, затем особые — вниз.
            items.sort(key=lambda x: -x["touched"])
            items.sort(key=lambda x: bool(x.get("special")))
            return jsonify(
                items=items,
                breadcrumbs=drop_path_to_root(parent),
                used=drop_used() + music_used,
                music=music_used,
                quota=drop_quota,
                trash=drop_trash_bytes(memo),
            )

    @drop_bp.get("/api/drop/download/<item_id>")
    @login_required
    def drop_download(item_id):
        tune = drop_music_send(item_id)
        if tune is not None:
            return tune
        with drop_lock:
            item = drop_items.get(item_id)
        if not item or item["kind"] == "folder":
            return "Не найдено", 404
        return drop_send(item_id, item)

    @drop_bp.get("/api/drop/zip/<item_id>")
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
            plan = drop_zip_plan(item_id)
            folder = item["name"]

        def pour():
            sink = _ZipSink()
            with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
                for arcname, file_id, _, made in plan:
                    info = zipfile.ZipInfo(arcname, drop_zip_time(made))
                    info.compress_type = zipfile.ZIP_STORED
                    if file_id is None:
                        zf.writestr(info, b"")          # пустая папка
                        yield sink.drain()
                        continue
                    path = drop_path(file_id)
                    if not os.path.exists(path):
                        continue
                    with zf.open(info, "w") as dst, open(path, "rb") as src:
                        while True:
                            chunk = src.read(drop_zip_chunk)
                            if not chunk:
                                break
                            dst.write(chunk)
                            if sink.held >= drop_zip_chunk:
                                yield sink.drain()
                    if sink.held:
                        yield sink.drain()
            yield sink.drain()

        safe = (drop_zip_name(folder, set()) or "папка") + ".zip"
        quoted = urllib.parse.quote(safe)
        response = Response(pour(), mimetype="application/zip")
        # Имя даём дважды. Русское — только в filename* и только процентами:
        # заголовки уходят в latin-1, и сырая кириллица роняет отдачу на месте.
        # Простое filename оставляем латинским, для совсем старых клиентов.
        response.headers["Content-Disposition"] = (
            "attachment; filename=\"archive.zip\"; filename*=UTF-8''" + quoted)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        length = drop_zip_length(plan)
        if length is not None:
            response.headers["Content-Length"] = str(length)
        return response

    class _ZipSink:
        """Приёмник для zipfile: копит записанное и отдаёт порциями наружу."""

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

    @drop_bp.get("/api/drop/view/<item_id>")
    @login_required
    def drop_view(item_id):
        """То же содержимое, но с настоящим типом — для просмотра внутри дропа."""
        tune = drop_music_send(item_id, inline=True)
        if tune is not None:
            return tune
        with drop_lock:
            item = drop_items.get(item_id)
        if not item or item["kind"] == "folder":
            return "Не найдено", 404
        response = drop_send(item_id, item, inline=True)
        return response

    @drop_bp.patch("/api/drop/<item_id>")
    @login_required
    def drop_update(item_id):
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:120]
        parent = payload.get("parent") if "parent" in payload else None
        icon = payload.get("icon") if payload.get("icon") in drop_folder_icons else None
        with drop_lock:
            item = drop_items.get(item_id)
            if not item:
                return jsonify(error="Не найдено."), 404
            if name:
                item["name"] = name
            if icon and item["kind"] == "folder" and not item.get("special"):
                item["icon"] = icon
            if "parent" in payload:
                target = parent or None
                if item.get("special"):
                    return jsonify(error="Особую папку нельзя переносить."), 400
                if target and drop_items.get(target, {}).get("kind") != "folder":
                    return jsonify(error="Такой папки нет."), 404
                if target and drop_is_descendant(item_id, target):
                    return jsonify(error="Нельзя переложить папку внутрь себя."), 400
                item["parent"] = target
            drop_write_index()
        return jsonify(ok=True)

    @drop_bp.post("/api/drop/op")
    @login_required
    def drop_op_start():
        payload = request.get_json(silent=True) or {}
        op = payload.get("op")
        ids = [str(i) for i in (payload.get("ids") or [])][:2000]
        target = payload.get("parent") or None
        if op not in drop_ops:
            return jsonify(error="Неизвестное действие."), 400
        if not ids:
            return jsonify(error="Ничего не выбрано."), 400

        job_id = str(uuid.uuid4())
        with drop_jobs_lock:
            drop_jobs_sweep()
            drop_jobs[job_id] = {"state": "run", "op": op, "done": 0, "total": len(ids),
                                 "bytes": 0, "bytes_total": 0, "error": "", "ended": 0.0}

        def work():
            try:
                drop_ops[op](job_id, ids, target)
                drop_job_set(job_id, state="done", ended=time.time())
            except Exception as e:                      # noqa: BLE001 — причину показываем как есть
                drop_job_set(job_id, state="fail", error=str(e), ended=time.time())

        threading.Thread(target=work, daemon=True).start()
        return jsonify(job=job_id)

    @drop_bp.get("/api/drop/op/<job_id>")
    @login_required
    def drop_op_status(job_id):
        with drop_jobs_lock:
            job = drop_jobs.get(job_id)
            if not job:
                return jsonify(error="Задача не найдена."), 404
            return jsonify(**{k: v for k, v in job.items() if k != "ended"})

    @drop_bp.post("/api/drop/share/<item_id>")
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
            drop_write_index()
        return jsonify(url=url_for("drop.drop_public", token=token, _external=True),
                       hours=0 if forever else hours, forever=forever, mode=mode)

    @drop_bp.delete("/api/drop/share/<item_id>")
    @login_required
    def drop_share_revoke(item_id):
        with drop_lock:
            item = drop_items.get(item_id)
            if item:
                item["share"] = None
                drop_write_index()
        return jsonify(ok=True)

    def drop_public_item(token):
        """Файл по токену ссылки, либо пусто. Из-под замка выходим сразу:
        держать его на время отдачи файла незачем."""
        with drop_lock:
            item_id = drop_share_lookup(token)
            item = drop_items.get(item_id) if item_id else None
        return (item_id, item) if item else (None, None)

    @drop_bp.get("/d/<token>")
    def drop_public(token):
        """Публичная ссылка — единственный вход в дроп без авторизации."""
        item_id, item = drop_public_item(token)
        if not item:
            return "Ссылка недействительна или истекла", 404
        if drop_share_mode(item.get("share")) != "view":
            return drop_send(item_id, item)
        kind = drop_view_kind(item["name"])
        if not kind:
            return drop_send(item_id, item)
        return drop_view_page(token, item, kind)

    @drop_bp.get("/d/<token>/raw")
    def drop_public_raw(token):
        """Байты для тега на странице просмотра."""
        item_id, item = drop_public_item(token)
        if not item or drop_share_mode(item.get("share")) != "view":
            return "", 404
        return drop_send(item_id, item, inline=True)

    @drop_bp.get("/d/<token>/save")
    def drop_public_save(token):
        """Кнопка «скачать» со страницы просмотра."""
        item_id, item = drop_public_item(token)
        if not item:
            return "", 404
        return drop_send(item_id, item)

    def drop_view_page(token, item, kind):
        """Страница просмотра: сам файл, его имя, вес и кнопка скачивания.

        Ничего не читаем в память — теги ссылаются на /raw, а его отдаёт
        send_file прямо с диска."""
        raw = url_for("drop.drop_public_raw", token=token)
        save = url_for("drop.drop_public_save", token=token)
        name = escape(item["name"])
        size = drop_human_size(item.get("size") or 0)
        if kind == "image":
            body = f'<img src="{raw}" alt="{name}">'
        elif kind == "video":
            body = f'<video src="{raw}" controls playsinline preload="metadata"></video>'
        elif kind == "audio":
            body = f'<audio src="{raw}" controls preload="metadata"></audio>'
        else:
            body = f'<iframe src="{raw}" title="{name}"></iframe>'
        html = template("drop_view.html")
        return (html.replace("__ICONLINKS__", icon_links)
                    .replace("__NAME__", name)
                    .replace("__SIZE__", size)
                    .replace("__SAVE__", save)
                    .replace("__BODY__", body))

    @drop_bp.get("/api/drop/qr")
    @login_required
    def drop_qr():
        """Ссылка картинкой: показать телефону, а не диктовать вслух."""
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

    @drop_bp.delete("/api/drop/<item_id>")
    @login_required
    def drop_delete(item_id):
        # Трек или папку фонотеки удаляем прямо в ней: в дропе они только видны.
        if item_id.startswith("mt_") or item_id.startswith("mf_"):
            return drop_music_delete(item_id)
        with drop_lock:
            if item_id in drop_items:
                drop_trash(item_id)             # в корзину, не насовсем
                drop_write_index()
        return jsonify(ok=True)

    @drop_bp.post("/api/drop/trash/unlock")
    @login_required
    def drop_trash_unlock():
        """Открывает корзину по паролю. Дальше действия с ней разрешены до конца
        сессии — как в проводнике, где второй раз пароль не спрашивают."""
        payload = request.get_json(silent=True) or {}
        if not drop_trash_ok(payload.get("password")):
            return jsonify(error="Неверный пароль."), 403
        session["drop_trash"] = True
        return jsonify(ok=True)

    @drop_bp.get("/api/drop/trash")
    @login_required
    def drop_trash_list():
        if not session.get("drop_trash"):
            return jsonify(error="Корзина закрыта."), 403
        with drop_lock:
            drop_sweep_trash()
            rows = []
            for root in drop_trash_roots():
                v = drop_items[root]
                row = {"id": root, "kind": v["kind"], "name": v["name"],
                       "deleted": v.get("deleted"), "size": v.get("size", 0)}
                if v["kind"] == "folder":
                    row["size"] = drop_trash_subtree_bytes(root)
                rows.append(row)
            rows.sort(key=lambda x: -(x["deleted"] or 0))
            return jsonify(items=rows, trash=drop_trash_bytes(),
                           used=drop_used(), quota=drop_quota, ttl_days=30)

    @drop_bp.post("/api/drop/<item_id>/restore")
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
            item["name"] = drop_unique_name(item["name"], parent)
            item["deleted"] = None
            drop_write_index()
        return jsonify(ok=True)

    @drop_bp.delete("/api/drop/trash/<item_id>")
    @login_required
    def drop_trash_purge(item_id):
        if not session.get("drop_trash"):
            return jsonify(error="Корзина закрыта."), 403
        with drop_lock:
            item = drop_items.get(item_id)
            if not item or not item.get("deleted"):
                return jsonify(error="Не найдено в корзине."), 404
            drop_discard(item_id)               # теперь насовсем
            drop_write_index()
        return jsonify(ok=True)

    @drop_bp.delete("/api/drop/trash")
    @login_required
    def drop_trash_empty():
        """Выкинуть всю корзину разом."""
        if not session.get("drop_trash"):
            return jsonify(error="Корзина закрыта."), 403
        with drop_lock:
            drop_sweep_trash()
            roots = list(drop_trash_roots())
            for item_id in roots:
                drop_discard(item_id)
            if roots:
                drop_write_index()
            return jsonify(ok=True, gone=len(roots), trash=drop_trash_bytes(),
                           used=drop_used(), quota=drop_quota)

    @drop_bp.get("/drop")
    @login_required
    def drop_page():
        html = template("drop.html")
        return html.replace("__ICONLINKS__", icon_links)

    return drop_bp
