import base64
import os
import re
import time
import uuid

from flask import Blueprint, Response, g, jsonify, request, send_file


def create_ai_blueprint(
    *,
    template,
    icon_links,
    login_required,
    claude_ready,
    claude_host_name,
    claude_dir,
    ssh_gate_password_prefix,
    ai_data,
    ai_lock,
    ai_active_lock,
    ai_active_model,
    ai_ready,
    openrouter_model,
    openrouter_vision_model,
    ai_folders_max,
    ai_chats_max,
    ai_msgs_max,
    ai_ctx_msgs,
    ai_text_max,
    ai_img_count_max,
    ai_pdf_max,
    ai_card,
    ai_find,
    ai_find_folder,
    ai_write,
    ai_drop_images,
    ai_msg_imgs,
    ai_img_path,
    ai_store_image,
    ai_pdf_extract,
    ai_smart_title,
    ai_run_stream,
    sse,
):
    ai_bp = Blueprint("ai", __name__)

    def current_openrouter_model():
        return openrouter_model() if callable(openrouter_model) else openrouter_model

    def current_openrouter_vision_model():
        return (openrouter_vision_model()
                if callable(openrouter_vision_model) else openrouter_vision_model)

    @ai_bp.get("/api/claude/state")
    @login_required
    def claude_state_api():
        """Что показывать до подключения: настроена ли вкладка и на какой машине."""
        return jsonify(ready=claude_ready(),
                       host=claude_host_name() if claude_ready() else "",
                       gate=bool(ssh_gate_password_prefix),
                       dir=claude_dir)

    @ai_bp.get("/claude")
    @login_required
    def claude_page():
        """Разговор с Claude Code через сайт."""
        g.frameable = True
        html = template("claude.html")
        return html.replace("__ICONLINKS__", icon_links)

    @ai_bp.get("/api/ai/state")
    @login_required
    def ai_state_api():
        """Готовность, список прошлых чатов и папок — страница спрашивает при открытии."""
        with ai_lock:
            cards = [ai_card(c) for c in ai_data["chats"]]
            folders = [{"id": f["id"], "name": f.get("name", ""), "created": f.get("created", 0)}
                       for f in ai_data["folders"]]
        cards.sort(key=lambda x: x["updated"], reverse=True)
        folders.sort(key=lambda x: x["created"])
        with ai_active_lock:
            active = ai_active_model()
        return jsonify(ready=ai_ready(), model=active,
                       vision=bool(current_openrouter_vision_model()),
                       chats=cards, folders=folders)

    @ai_bp.get("/api/ai/chat/<chat_id>")
    @login_required
    def ai_chat_get(chat_id):
        with ai_lock:
            c = ai_find(chat_id)
            if not c:
                return jsonify(error="Чат не найден."), 404
            msgs = [{"role": m.get("role"), "text": m.get("text", ""),
                     "imgs": ai_msg_imgs(m), "model": m.get("model") or "",
                     "pdf_name": m.get("pdf_name") or "", "ts": m.get("ts", 0),
                     "reasoning": m.get("reasoning") or "",
                     "reasoning_secs": m.get("reasoning_secs") or 0}
                    for m in c.get("messages", [])]
            title = c.get("title") or "Новый чат"
        return jsonify(id=chat_id, title=title, messages=msgs)

    @ai_bp.post("/api/ai/chat")
    @login_required
    def ai_chat_new():
        cid = uuid.uuid4().hex[:12]
        now = time.time()
        chat = {"id": cid, "title": "", "model": current_openrouter_model(), "folder": "",
                "pinned": False, "created": now, "updated": now, "messages": []}
        with ai_lock:
            ai_data["chats"].insert(0, chat)
            if len(ai_data["chats"]) > ai_chats_max:
                for old in ai_data["chats"][ai_chats_max:]:
                    ai_drop_images(old)
                del ai_data["chats"][ai_chats_max:]
            ai_write()
        return jsonify(id=cid, title="Новый чат")

    @ai_bp.patch("/api/ai/chat/<chat_id>")
    @login_required
    def ai_chat_rename(chat_id):
        """Переименовать чат и/или переложить его в другую папку (folder="" — вон из папки)."""
        payload = request.get_json(silent=True) or {}
        with ai_lock:
            c = ai_find(chat_id)
            if not c:
                return jsonify(error="Чат не найден."), 404
            if "title" in payload:
                c["title"] = (payload.get("title") or "").strip()[:80]
            if "folder" in payload:
                fid = (payload.get("folder") or "").strip()
                if fid and not ai_find_folder(fid):
                    return jsonify(error="Папка не найдена."), 404
                c["folder"] = fid
            if "pinned" in payload:
                c["pinned"] = bool(payload.get("pinned"))
            ai_write()
        return jsonify(ok=True, title=c.get("title") or "Новый чат",
                       folder=c.get("folder", ""), pinned=bool(c.get("pinned")))

    @ai_bp.get("/api/ai/folder")
    @login_required
    def ai_folder_list():
        with ai_lock:
            folders = [{"id": f["id"], "name": f.get("name", "")} for f in ai_data["folders"]]
        return jsonify(folders=folders)

    @ai_bp.post("/api/ai/folder")
    @login_required
    def ai_folder_new():
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:40]
        if not name:
            return jsonify(error="Название папки не может быть пустым."), 400
        fid = uuid.uuid4().hex[:10]
        with ai_lock:
            if len(ai_data["folders"]) >= ai_folders_max:
                return jsonify(error="Слишком много папок."), 400
            ai_data["folders"].append({"id": fid, "name": name, "created": time.time()})
            ai_write()
        return jsonify(id=fid, name=name)

    @ai_bp.patch("/api/ai/folder/<fid>")
    @login_required
    def ai_folder_rename(fid):
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:40]
        if not name:
            return jsonify(error="Название папки не может быть пустым."), 400
        with ai_lock:
            f = ai_find_folder(fid)
            if not f:
                return jsonify(error="Папка не найдена."), 404
            f["name"] = name
            ai_write()
        return jsonify(ok=True, name=name)

    @ai_bp.delete("/api/ai/folder/<fid>")
    @login_required
    def ai_folder_delete(fid):
        """Удаляет папку. Чаты внутри не трогаем — просто выкладываем их обратно."""
        with ai_lock:
            f = ai_find_folder(fid)
            if not f:
                return jsonify(error="Папка не найдена."), 404
            ai_data["folders"] = [x for x in ai_data["folders"] if x is not f]
            for c in ai_data["chats"]:
                if c.get("folder") == fid:
                    c["folder"] = ""
            ai_write()
        return jsonify(ok=True)

    @ai_bp.delete("/api/ai/chat/<chat_id>")
    @login_required
    def ai_chat_delete(chat_id):
        with ai_lock:
            c = ai_find(chat_id)
            if not c:
                return jsonify(error="Чат не найден."), 404
            ai_drop_images(c)
            ai_data["chats"] = [x for x in ai_data["chats"] if x is not c]
            ai_write()
        return jsonify(ok=True)

    @ai_bp.get("/api/ai/img/<img_id>")
    @login_required
    def ai_img_api(img_id):
        if not re.match(r"^[0-9a-f]{8,40}\.jpg$", img_id):
            return jsonify(error="нет"), 404
        path = ai_img_path(img_id)
        if not os.path.isfile(path):
            return jsonify(error="нет"), 404
        return send_file(path, mimetype="image/jpeg")

    @ai_bp.post("/api/ai/chat/<chat_id>/send")
    @login_required
    def ai_chat_send(chat_id):
        """Принимает реплику, шлёт разговор в OpenRouter и отдаёт ответ потоком."""
        if not ai_ready():
            return jsonify(error="Ключ OpenRouter на сервере не задан."), 503

        payload = request.get_json(silent=True) or {}
        text = (payload.get("text") or "").strip()[:ai_text_max]
        images_in = payload.get("images")
        if not isinstance(images_in, list):
            images_in = [payload.get("image")] if payload.get("image") else []
        images_in = [x for x in images_in if x][:ai_img_count_max]
        pdf_data = payload.get("pdf") or ""
        pdf_name = (payload.get("pdf_name") or "").strip()[:120]
        if not text and not images_in and not pdf_data:
            return jsonify(error="Пустое сообщение."), 400

        img_ids, imgs_b64 = [], []
        for data_url in images_in:
            iid, b64 = ai_store_image(data_url)
            if iid:
                img_ids.append(iid)
                imgs_b64.append(b64)
        use_vision = bool(imgs_b64) and bool(current_openrouter_vision_model())

        pdf_text = ""
        if pdf_data:
            m = re.match(r"^data:application/pdf;base64,(.+)$", pdf_data, re.I)
            if m:
                try:
                    raw = base64.b64decode(m.group(1), validate=True)
                except Exception:
                    raw = b""
                if raw and len(raw) <= ai_pdf_max:
                    pdf_text = ai_pdf_extract(raw)
            if not pdf_text:
                return jsonify(error="Не удалось прочитать текст из PDF."), 400

        with ai_lock:
            c = ai_find(chat_id)
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
                c["title"] = (ai_smart_title(text)
                              or (("PDF: " + pdf_name) if pdf_name else "")
                              or "Фото")
            c["updated"] = time.time()
            if len(c["messages"]) > ai_msgs_max:
                for old in c["messages"][:-ai_msgs_max]:
                    for iid in ai_msg_imgs(old):
                        try:
                            os.remove(ai_img_path(iid))
                        except OSError:
                            pass
                c["messages"] = c["messages"][-ai_msgs_max:]
            ai_write()
            ctx = list(c["messages"][-ai_ctx_msgs:])
            chat_title = c.get("title") or "Новый чат"

        requested_model = (payload.get("model") or "").strip()
        model = current_openrouter_vision_model() if use_vision else (
            requested_model or current_openrouter_model())
        gen = ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model)

        def with_title():
            yield sse({"title": chat_title})
            yield from gen()

        return Response(with_title(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-store",
                                 "X-Accel-Buffering": "no"})

    @ai_bp.post("/api/ai/chat/<chat_id>/regenerate")
    @login_required
    def ai_chat_regenerate(chat_id):
        """Стирает последний ответ нейронки и просит его заново."""
        if not ai_ready():
            return jsonify(error="Ключ OpenRouter на сервере не задан."), 503
        payload = request.get_json(silent=True) or {}
        requested_model = (payload.get("model") or "").strip()

        with ai_lock:
            c = ai_find(chat_id)
            if not c:
                return jsonify(error="Чат не найден."), 404
            msgs = c.get("messages", [])
            if msgs and msgs[-1].get("role") == "assistant":
                msgs.pop()
                c["updated"] = time.time()
                ai_write()
            if not msgs or msgs[-1].get("role") != "user":
                return jsonify(error="Нечего перегенерировать — нет вопроса."), 400
            ctx = list(msgs[-ai_ctx_msgs:])
            last_imgs = ai_msg_imgs(ctx[-1]) if ctx else []

        imgs_b64 = []
        if last_imgs and current_openrouter_vision_model():
            for iid in last_imgs:
                try:
                    with open(ai_img_path(iid), "rb") as fh:
                        imgs_b64.append(base64.b64encode(fh.read()).decode("ascii"))
                except OSError:
                    pass
        use_vision = bool(imgs_b64)

        model = current_openrouter_vision_model() if use_vision else (
            requested_model or current_openrouter_model())
        gen = ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model)
        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-store",
                                 "X-Accel-Buffering": "no"})

    @ai_bp.get("/neuro")
    @login_required
    def neuro_page():
        """«Нейронки» — одна страница с двумя вкладками."""
        html = template("neuro.html")
        return html.replace("__ICONLINKS__", icon_links)

    @ai_bp.get("/ai")
    @login_required
    def ai_page():
        _preset = (request.args.get("m") or "").strip()
        _low = _preset.lower()
        _net = ("minimax" if "minimax" in _low else
                "nvidia" if ("nvidia" in _low or "nemotron" in _low) else
                "deepseek" if "deepseek" in _low else "")
        g.frameable = True
        html = template("ai.html")
        return (html.replace("__ICONLINKS__", icon_links)
                    .replace("%%PRESET%%", _preset.replace("\"", "\\\""))
                    .replace("%%NET%%", _net))

    return ai_bp
