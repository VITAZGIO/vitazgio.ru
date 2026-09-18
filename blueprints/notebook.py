"""blueprints/notebook.py — «Блокнот» /notebook (задача 35, docs/structure-plan.md).

Хозяйская записная книжка: страницы-вкладки, записи трёх видов (ссылка,
текст, PDF). Данные — модульного уровня, здесь же, а не в `app.py`: файл
владеет своим состоянием целиком, как и задумано блоком Б плана. Данные
всё равно лежат в `DATA_DIR`/переживают деплой — только путь к нему теперь
берётся из `core.storage`, а не из фабричного аргумента.

`notebook_data`/`notebook_lock` читает не только этот blueprint — кнопка
«В блокнот» на `/ai` (`blueprints/ai.py`) пишет сюда напрямую, а
`/api/metrics` в `app.py` считает число страниц для диагностики. Оба
по-прежнему получают эти объекты через `app.py`, который сам берёт их
отсюда (`from blueprints.notebook import notebook_data, notebook_lock`)
— перевести и их на прямой импорт можно будет вместе с задачами 37/40.
"""

import json
import os
import re
import threading
import time
import uuid

from flask import Blueprint, g, jsonify, request, send_file

from blueprints.pwa import ICON_LINKS
from core.auth import login_required
from core.storage import DATA_DIR, atomic_write_json, clean_url, safe_filename
from core.templates import template

NOTEBOOK_DIR = os.path.join(DATA_DIR, "notebook")
NOTEBOOK_PATH = os.path.join(DATA_DIR, "notebook.json")
NOTEBOOK_TEXT_MAX = 20000
NOTEBOOK_ENTRY_LIMIT = 1000
NOTEBOOK_PDF_MAX = 25 * 1024 * 1024
NOTEBOOK_TYPES = ("link", "text", "pdf")
NOTEBOOK_BORDERS = ("solid", "dashed", "dotted", "double", "none")
NOTEBOOK_WIDTHS = ("half", "full")

notebook_data: dict = {"pages": [], "entries": {}}
notebook_lock = threading.Lock()
os.makedirs(NOTEBOOK_DIR, exist_ok=True)


def notebook_pdf_path(entry_id):
    return os.path.join(NOTEBOOK_DIR, f"{entry_id}.pdf")


def notebook_write():
    """Вызывать под notebook_lock."""
    try:
        atomic_write_json(NOTEBOOK_PATH, notebook_data)
    except OSError:
        pass


def notebook_load():
    try:
        with open(NOTEBOOK_PATH, encoding="utf-8") as fh:
            saved = json.load(fh) or {}
        notebook_data["pages"] = saved.get("pages", [])
        notebook_data["entries"] = saved.get("entries", {})
    except (OSError, ValueError):
        pass
    if not notebook_data["pages"]:
        notebook_data["pages"] = [{"id": str(uuid.uuid4()), "name": "Заметки"}]
    for e in notebook_data["entries"].values():
        e.setdefault("note", "")
        e.setdefault("width", "half")
        e.setdefault("border", "solid")
        e.setdefault("accent", "#2de2ff")
        e.setdefault("order", 0)


notebook_load()


def notebook_entry_public(eid, e):
    row = {
        "id": eid, "page": e.get("page"), "type": e.get("type"),
        "title": e.get("title", ""), "width": e.get("width", "half"),
        "border": e.get("border", "solid"), "accent": e.get("accent", "#2de2ff"),
        "note": e.get("note", ""), "order": e.get("order", 0),
    }
    if e.get("type") == "link":
        row["url"] = e.get("url", "")
    elif e.get("type") == "text":
        row["text"] = e.get("text", "")
    elif e.get("type") == "pdf":
        row["pdf"] = bool(e.get("pdf"))
        row["filename"] = e.get("filename", "")
    return row


def notebook_apply(e, payload):
    """Переносит присланные поля в запись, каждое — по своим правилам."""
    if "title" in payload:
        e["title"] = (payload.get("title") or "").strip()[:160]
    if "note" in payload:
        e["note"] = (payload.get("note") or "").strip()[:4000]
    if "url" in payload and e["type"] == "link":
        e["url"] = clean_url(payload.get("url"))
    if "text" in payload and e["type"] == "text":
        e["text"] = (payload.get("text") or "")[:NOTEBOOK_TEXT_MAX]
    if payload.get("width") in NOTEBOOK_WIDTHS:
        e["width"] = payload["width"]
    if payload.get("border") in NOTEBOOK_BORDERS:
        e["border"] = payload["border"]
    ac = (payload.get("accent") or "").strip()
    if re.match(r"^#[0-9a-fA-F]{6}$", ac):
        e["accent"] = ac


def create_notebook_blueprint():
    notebook_bp = Blueprint("notebook", __name__)

    @notebook_bp.get("/api/notebook")
    @login_required
    def notebook_get_api():
        with notebook_lock:
            pages = list(notebook_data["pages"])
            entries = [notebook_entry_public(k, v)
                       for k, v in notebook_data["entries"].items()]
        entries.sort(key=lambda x: x["order"])
        return jsonify(pages=pages, entries=entries, borders=list(NOTEBOOK_BORDERS))

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
        if etype not in NOTEBOOK_TYPES:
            return jsonify(error="Неизвестный тип записи."), 400
        with notebook_lock:
            if len(notebook_data["entries"]) >= NOTEBOOK_ENTRY_LIMIT:
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
        if request.content_length and request.content_length > NOTEBOOK_PDF_MAX + 8192:
            return jsonify(error="PDF больше 25 МБ."), 413
        if os.path.splitext(upload.filename or "")[1].lower() != ".pdf":
            return jsonify(error="Нужен файл PDF."), 415
        dest = notebook_pdf_path(eid)
        upload.save(dest)
        if os.path.getsize(dest) > NOTEBOOK_PDF_MAX:
            os.remove(dest)
            return jsonify(error="PDF больше 25 МБ."), 413
        fname = safe_filename(upload.filename) or "файл.pdf"
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
        return html.replace("__ICONLINKS__", ICON_LINKS)

    return notebook_bp
