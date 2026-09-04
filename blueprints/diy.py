import os
import re
import shutil
import time
import uuid
from urllib.parse import quote

from flask import Blueprint, jsonify, request, send_file


def create_diy_blueprint(
    *,
    template,
    icon_links,
    escape,
    diy_editor_required,
    diy_items,
    diy_lock,
    diy_kinds,
    diy_themes,
    diy_body_max,
    diy_asset_limit,
    diy_asset_max,
    diy_asset_side,
    diy_image_ext,
    diy_max_image,
    diy_cover_side,
    diy_can_edit,
    diy_public,
    diy_sorted,
    diy_clean_links,
    diy_write_index,
    diy_cover_path,
    diy_asset_dir,
    diy_asset_path,
    diy_safe_name,
    diy_card,
    diy_head,
):
    diy_bp = Blueprint("diy", __name__)

    def diy_render_body(item_id, body):
        """Подставляет в код статьи адреса вложений: {{имя.jpg}} превращается в
        ссылку на /diy/asset/<id>/имя.jpg. Больше ничего не трогаем — остальное
        хозяин пишет как обычный HTML."""
        def swap(match):
            name = diy_safe_name(match.group(1))
            if not name:
                return match.group(0)
            return "/diy/asset/" + item_id + "/" + quote(name)

        return re.sub(r"\{\{\s*([^{}]+?)\s*\}\}", swap, body or "")

    @diy_bp.get("/api/diy")
    def diy_list_api():
        can_edit = diy_can_edit()
        with diy_lock:
            works = [diy_public(k, v, can_edit) for k, v in diy_sorted(can_edit)]
        return jsonify(works=works, can_edit=can_edit, kinds=list(diy_kinds),
                       themes=[dict(t) for t in diy_themes])

    @diy_bp.post("/api/diy")
    @diy_editor_required
    def diy_create_api():
        payload = request.get_json(silent=True) or {}
        title = (payload.get("title") or "").strip()[:80]
        if not title:
            return jsonify(error="Без названия не сохранить."), 400
        kind = payload.get("kind") if payload.get("kind") in diy_kinds else "разное"
        item_id = str(uuid.uuid4())
        now = time.time()
        with diy_lock:
            diy_items[item_id] = {
                "title": title,
                "summary": (payload.get("summary") or "").strip()[:600],
                "kind": kind,
                "links": diy_clean_links(payload.get("links")),
                "body": (payload.get("body") or "")[:diy_body_max],
                "assets": [],
                "cover": False,
                "hidden": bool(payload.get("hidden")),
                "pinned": bool(payload.get("pinned")),
                "created": now,
                "updated": now,
            }
            diy_write_index()
        return jsonify(id=item_id)

    @diy_bp.patch("/api/diy/<item_id>")
    @diy_editor_required
    def diy_update_api(item_id):
        payload = request.get_json(silent=True) or {}
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            if "title" in payload:
                title = (payload.get("title") or "").strip()[:80]
                if not title:
                    return jsonify(error="Без названия не сохранить."), 400
                work["title"] = title
            if "summary" in payload:
                work["summary"] = (payload.get("summary") or "").strip()[:600]
            if "body" in payload:
                work["body"] = (payload.get("body") or "")[:diy_body_max]
            if "kind" in payload and payload["kind"] in diy_kinds:
                work["kind"] = payload["kind"]
            if "links" in payload:
                work["links"] = diy_clean_links(payload.get("links"))
            for flag in ("hidden", "pinned"):
                if flag in payload:
                    work[flag] = bool(payload[flag])
            work["updated"] = time.time()
            diy_write_index()
        return jsonify(ok=True)

    @diy_bp.delete("/api/diy/<item_id>")
    @diy_editor_required
    def diy_delete_api(item_id):
        with diy_lock:
            work = diy_items.pop(item_id, None)
            if work:
                diy_write_index()
        if work:
            try:
                os.remove(diy_cover_path(item_id))
            except OSError:
                pass
            shutil.rmtree(diy_asset_dir(item_id), ignore_errors=True)
        return jsonify(ok=True)

    @diy_bp.post("/api/diy/<item_id>/asset")
    @diy_editor_required
    def diy_asset_upload_api(item_id):
        """Фото или файл к статье. Картинки ужимаем, прочее кладём как есть.
        Имя сохраняем узнаваемым — по нему хозяин ссылается в коде статьи."""
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            if len(work.get("assets", [])) >= diy_asset_limit:
                return jsonify(error=f"Больше {diy_asset_limit} вложений на запись нельзя."), 400
        upload = request.files.get("file")
        if not upload:
            return jsonify(error="Файл не выбран."), 400
        if request.content_length and request.content_length > diy_asset_max + 8192:
            return jsonify(error="Вложение больше 25 МБ."), 413
        name = diy_safe_name(upload.filename)
        if not name:
            return jsonify(error="Не разобрать имя файла."), 400
        os.makedirs(diy_asset_dir(item_id), exist_ok=True)
        dest = diy_asset_path(item_id, name)
        ext = os.path.splitext(name)[1].lower()
        is_image = ext in diy_image_ext
        try:
            if is_image and ext != ".gif":
                # GIF мог бы быть анимацией — её не трогаем; остальное ужимаем.
                from PIL import Image

                Image.MAX_IMAGE_PIXELS = 80_000_000
                with Image.open(upload.stream) as image:
                    keep_alpha = ext in (".png", ".webp")
                    image = image.convert("RGBA" if keep_alpha else "RGB")
                    image.thumbnail((diy_asset_side, diy_asset_side))
                    if ext == ".png":
                        image.save(dest, "PNG", optimize=True)
                    elif ext == ".webp":
                        image.save(dest, "WEBP", quality=85, method=4)
                    else:
                        image.save(dest, "JPEG", quality=84, optimize=True)
            else:
                upload.save(dest)
                if os.path.getsize(dest) > diy_asset_max:
                    os.remove(dest)
                    return jsonify(error="Вложение больше 25 МБ."), 413
        except Exception:
            try:
                os.remove(dest)
            except OSError:
                pass
            return jsonify(error="Не вышло сохранить вложение."), 415
        size = os.path.getsize(dest)
        kind = "image" if is_image else "file"
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                os.remove(dest)
                return jsonify(error="Запись не найдена."), 404
            assets = [a for a in work.get("assets", []) if a.get("name") != name]
            assets.append({"name": name, "kind": kind, "size": size})
            work["assets"] = assets
            work["updated"] = time.time()
            diy_write_index()
        return jsonify(ok=True, name=name, kind=kind, size=size)

    @diy_bp.delete("/api/diy/<item_id>/asset/<path:name>")
    @diy_editor_required
    def diy_asset_delete_api(item_id, name):
        safe = diy_safe_name(name)
        with diy_lock:
            work = diy_items.get(item_id)
            if not work:
                return jsonify(error="Запись не найдена."), 404
            work["assets"] = [a for a in work.get("assets", []) if a.get("name") != safe]
            work["updated"] = time.time()
            diy_write_index()
        path = diy_asset_path(item_id, safe)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
        return jsonify(ok=True)

    @diy_bp.get("/diy/asset/<item_id>/<path:name>")
    def diy_asset_api(item_id, name):
        """Вложение статьи. Открыто всем, как и обложка — статью смотрит любой.
        У скрытой записи вложения видит только хозяин."""
        with diy_lock:
            work = diy_items.get(item_id)
            hidden = bool(work and work.get("hidden"))
            known = {a.get("name") for a in (work.get("assets", []) if work else [])}
        if not work:
            return "", 404
        if hidden and not diy_can_edit():
            return "", 404
        safe = diy_safe_name(name)
        if safe not in known:
            return "", 404
        path = diy_asset_path(item_id, safe)
        if not path or not os.path.exists(path):
            return "", 404
        response = send_file(path, conditional=True)
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    @diy_bp.post("/api/diy/<item_id>/cover")
    @diy_editor_required
    def diy_cover_upload_api(item_id):
        with diy_lock:
            if item_id not in diy_items:
                return jsonify(error="Запись не найдена."), 404
        picture = request.files.get("file")
        if not picture:
            return jsonify(error="Файл не выбран."), 400
        if request.content_length and request.content_length > diy_max_image + 8192:
            return jsonify(error="Картинка больше 12 МБ."), 413
        try:
            from PIL import Image

            Image.MAX_IMAGE_PIXELS = 80_000_000   # защита от «бомб» с диким разрешением
            with Image.open(picture.stream) as image:
                image.draft("RGB", (diy_cover_side, diy_cover_side))
                image = image.convert("RGB")
                image.thumbnail((diy_cover_side, diy_cover_side))
                image.save(diy_cover_path(item_id), "JPEG", quality=82, optimize=True)
        except Exception:
            return jsonify(error="Это не похоже на картинку."), 415
        with diy_lock:
            work = diy_items.get(item_id)
            if work:
                work["cover"] = True
                work["updated"] = time.time()
                diy_write_index()
        return jsonify(ok=True, size=os.path.getsize(diy_cover_path(item_id)))

    @diy_bp.delete("/api/diy/<item_id>/cover")
    @diy_editor_required
    def diy_cover_delete_api(item_id):
        with diy_lock:
            work = diy_items.get(item_id)
            if work:
                work["cover"] = False
                work["updated"] = time.time()
                diy_write_index()
        try:
            os.remove(diy_cover_path(item_id))
        except OSError:
            pass
        return jsonify(ok=True)

    @diy_bp.get("/diy/cover/<item_id>")
    def diy_cover_api(item_id):
        """Обложка. Открыта всем: страница со списком тоже открыта."""
        with diy_lock:
            work = diy_items.get(item_id)
            hidden = bool(work and work.get("hidden"))
        if not work or not work.get("cover"):
            return "", 404
        if hidden and not diy_can_edit():
            return "", 404
        path = diy_cover_path(item_id)
        if not os.path.exists(path):
            return "", 404
        response = send_file(path, mimetype="image/jpeg", conditional=True)
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    @diy_bp.get("/diy/a/<item_id>")
    def diy_article_page(item_id):
        """Отдельная страница одного творения: полная статья, что открывается из
        короткой карточки в новом окне. Содержимое — код, написанный хозяином;
        вложения он подставляет по имени через {{…}}."""
        with diy_lock:
            work = diy_items.get(item_id)
            if not work or (work.get("hidden") and not diy_can_edit()):
                snapshot = None
            else:
                card = diy_card(work)
                _, text = diy_head(work.get("body", ""))     # шапку в текст не пускаем
                snapshot = {
                    "title": work.get("title", ""),
                    "summary": card["summary"],
                    "tags": card["tags"],
                    "accent": card["accent"] or "#2de2ff",
                    "link": card["link"],
                    "kind": work.get("kind", ""),
                    "body": text,
                    "links": list(work.get("links", [])),
                    "cover": bool(work.get("cover")),
                    "hidden": bool(work.get("hidden")),
                }
        if snapshot is None:
            return "Творение не найдено", 404

        body_html = diy_render_body(item_id, snapshot["body"])
        if not body_html.strip():
            # Кода статьи ещё нет — показываем хотя бы название и описание,
            # чтобы страница не выглядела сломанной.
            body_html = ("<p class=\"lead\">" + str(escape(snapshot["summary"])) + "</p>"
                         if snapshot["summary"] else
                         "<p class=\"lead\">Статья ещё пишется.</p>")
        links_html = ""
        if snapshot["links"]:
            chips = "".join(
                f'<a href="{escape(l["url"])}" target="_blank" rel="noopener">{escape(l["label"])}</a>'
                for l in snapshot["links"])
            links_html = f'<div class="links">{chips}</div>'
        draft = ('<span class="draft">черновик</span>' if snapshot["hidden"] else "")

        html = template("diy_article.html")
        summary_html = (f'<p class="summary">{escape(snapshot["summary"])}</p>'
                        if snapshot["summary"] else "")
        tags = "".join([
            f'<span class="kind">{escape(snapshot["kind"])}</span>' if snapshot["kind"] else "",
            "".join(f'<span class="tag">{escape(t)}</span>' for t in snapshot["tags"]),
            draft,
        ])
        src_html = ""
        if snapshot["link"]:
            src_html = (
                '<div class="srcline"><a href="' + str(escape(snapshot["link"])) + '" target="_blank" rel="noopener">'
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M21 3l-9 9"/>'
                '<path d="M10 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/></svg>'
                'Исходники и сборки</a></div>')
        return (html.replace("__ICONLINKS__", icon_links)
                    .replace("__ACCENT__", snapshot["accent"])
                    .replace("__DESC__", str(escape(snapshot["summary"] or snapshot["title"])))
                    .replace("__TAGS__", tags)
                    .replace("__SUMMARY__", summary_html)
                    .replace("__SRC__", src_html)
                    .replace("__LINKS__", links_html)
                    .replace("__TITLE__", str(escape(snapshot["title"])))
                    .replace("__BODY__", body_html))

    @diy_bp.get("/diy")
    def diy_page():
        """Страна DIY: витрина своих творений.

        Смотреть может кто угодно, добавлять — хозяин. Отдельного входа не просим:
        если сайт уже помнит устройство по кабинету, режим правки включается сам."""
        html = template("diy.html")
        return html.replace("__ICONLINKS__", icon_links)

    return diy_bp
