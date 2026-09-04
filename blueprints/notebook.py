import os
import time
import uuid

from flask import Blueprint, g, jsonify, request, send_file


def create_notebook_blueprint(
    *,
    template,
    icon_links,
    login_required,
    notebook_data,
    notebook_lock,
    notebook_borders,
    notebook_types,
    notebook_entry_limit,
    notebook_pdf_max,
    notebook_pdf_path,
    notebook_write,
    notebook_entry_public,
    notebook_apply,
    diy_safe_name,
):
    notebook_bp = Blueprint("notebook", __name__)

    @notebook_bp.get("/api/notebook")
    @login_required
    def notebook_get_api():
        with notebook_lock:
            pages = list(notebook_data["pages"])
            entries = [notebook_entry_public(k, v)
                       for k, v in notebook_data["entries"].items()]
        entries.sort(key=lambda x: x["order"])
        return jsonify(pages=pages, entries=entries, borders=list(notebook_borders))

    @notebook_bp.post("/api/notebook/page")
    @login_required
    def notebook_page_add():
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:40] or "Без имени"
        pid = str(uuid.uuid4())
        with notebook_lock:
            notebook_data["pages"].append({"id": pid, "name": name})
            notebook_write()
        return jsonify(id=pid, name=name)

    @notebook_bp.patch("/api/notebook/page/<pid>")
    @login_required
    def notebook_page_rename(pid):
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:40]
        if not name:
            return jsonify(error="Пустое имя."), 400
        with notebook_lock:
            page = next((p for p in notebook_data["pages"] if p["id"] == pid), None)
            if not page:
                return jsonify(error="Страница не найдена."), 404
            page["name"] = name
            notebook_write()
        return jsonify(ok=True)

    @notebook_bp.delete("/api/notebook/page/<pid>")
    @login_required
    def notebook_page_delete(pid):
        with notebook_lock:
            pages = notebook_data["pages"]
            if len(pages) <= 1:
                return jsonify(error="Нельзя удалить единственную страницу."), 400
            notebook_data["pages"] = [p for p in pages if p["id"] != pid]
            gone = [k for k, v in notebook_data["entries"].items() if v.get("page") == pid]
            for k in gone:
                notebook_data["entries"].pop(k, None)
            notebook_write()
        for k in gone:
            try:
                os.remove(notebook_pdf_path(k))
            except OSError:
                pass
        return jsonify(ok=True)

    @notebook_bp.post("/api/notebook/entry")
    @login_required
    def notebook_entry_add():
        payload = request.get_json(silent=True) or {}
        etype = payload.get("type")
        if etype not in notebook_types:
            return jsonify(error="Неизвестный тип записи."), 400
        with notebook_lock:
            if len(notebook_data["entries"]) >= notebook_entry_limit:
                return jsonify(error="Слишком много записей."), 400
            pages = notebook_data["pages"]
            page = payload.get("page")
            if not any(p["id"] == page for p in pages):
                page = pages[0]["id"] if pages else None
            eid = str(uuid.uuid4())
            order = 1 + max([v.get("order", 0) for v in notebook_data["entries"].values()],
                            default=0)
            e = {"page": page, "type": etype, "title": "", "note": "",
                 "width": "half", "border": "solid", "accent": "#2de2ff",
                 "order": order, "created": time.time()}
            if etype == "link":
                e["url"] = ""
            elif etype == "text":
                e["text"] = ""
            elif etype == "pdf":
                e["pdf"] = False
                e["filename"] = ""
            notebook_apply(e, payload)
            if not e["title"]:
                e["title"] = {"link": "Ссылка", "text": "Заметка", "pdf": "PDF"}[etype]
            notebook_data["entries"][eid] = e
            notebook_write()
        return jsonify(id=eid)

    @notebook_bp.patch("/api/notebook/entry/<eid>")
    @login_required
    def notebook_entry_edit(eid):
        payload = request.get_json(silent=True) or {}
        with notebook_lock:
            e = notebook_data["entries"].get(eid)
            if not e:
                return jsonify(error="Запись не найдена."), 404
            notebook_apply(e, payload)
            if payload.get("page") and any(p["id"] == payload["page"] for p in notebook_data["pages"]):
                e["page"] = payload["page"]
            notebook_write()
        return jsonify(ok=True)

    @notebook_bp.delete("/api/notebook/entry/<eid>")
    @login_required
    def notebook_entry_delete(eid):
        with notebook_lock:
            gone = notebook_data["entries"].pop(eid, None)
            if gone:
                notebook_write()
        if gone:
            try:
                os.remove(notebook_pdf_path(eid))
            except OSError:
                pass
        return jsonify(ok=True)

    @notebook_bp.post("/api/notebook/entry/<eid>/pdf")
    @login_required
    def notebook_entry_pdf(eid):
        with notebook_lock:
            e = notebook_data["entries"].get(eid)
            if not e or e.get("type") != "pdf":
                return jsonify(error="Запись не найдена."), 404
        upload = request.files.get("file")
        if not upload:
            return jsonify(error="Файл не выбран."), 400
        if request.content_length and request.content_length > notebook_pdf_max + 8192:
            return jsonify(error="PDF больше 25 МБ."), 413
        if os.path.splitext(upload.filename or "")[1].lower() != ".pdf":
            return jsonify(error="Нужен файл PDF."), 415
        dest = notebook_pdf_path(eid)
        upload.save(dest)
        if os.path.getsize(dest) > notebook_pdf_max:
            os.remove(dest)
            return jsonify(error="PDF больше 25 МБ."), 413
        fname = diy_safe_name(upload.filename) or "файл.pdf"
        with notebook_lock:
            e = notebook_data["entries"].get(eid)
            if e:
                e["pdf"] = True
                e["filename"] = fname
                notebook_write()
        return jsonify(ok=True, filename=fname)

    @notebook_bp.get("/notebook/pdf/<eid>")
    @login_required
    def notebook_pdf_view(eid):
        with notebook_lock:
            e = notebook_data["entries"].get(eid)
        if not e or e.get("type") != "pdf" or not e.get("pdf"):
            return "", 404
        path = notebook_pdf_path(eid)
        if not os.path.exists(path):
            return "", 404
        response = send_file(path, mimetype="application/pdf", conditional=True)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; object-src 'self'; img-src 'self' blob:; "
            "style-src 'unsafe-inline'; frame-ancestors 'self'")
        g.frameable = True
        return response

    @notebook_bp.get("/notebook")
    @login_required
    def notebook_page():
        """Блокнот: страницы-вкладки как в браузере, записи трёх видов. Оформлен
        в едином тёмном стиле сайта — бирюзовый акцент, шрифт Cascadia."""
        html = template("notebook.html")
        return html.replace("__ICONLINKS__", icon_links)

    return notebook_bp
