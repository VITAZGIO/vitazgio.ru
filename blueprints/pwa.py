import json
import os
import time
import uuid
from pathlib import Path

from flask import Blueprint, Response, redirect, request, send_file, url_for


# ---- Иконка приложения ------------------------------------------------------
# Знак VG вычерчен хозяином в КОМПАСе и залит мелким процедурным зерном.
# Исходник лежит в static/icons/vg.svg, рядом с ним готовые png на все
# ходовые размеры: рисовать монограмму кодом больше не нужно.
#
# Маскируемый вариант отдельным файлом: Android режет значок в круг, и знак
# в нём ужат до 62% поля, иначе углы обкусывает.
_ROOT_DIR = Path(__file__).resolve().parent.parent
ICON_DIR = os.path.join(_ROOT_DIR, "static", "icons")
ICON_SIZES = (16, 32, 48, 64, 96, 128, 152, 180, 192, 256, 384, 512)
ICON_MASKABLE_SIZES = (192, 512)

# Поднимать при смене рисунка: версия попадает в адреса в манифесте и в
# разметке, иначе браузер продолжит показывать иконку из кэша.
ICON_VERSION = "vg7"

# Одни и те же ссылки в head всех страниц. Версия в адресе обязательна:
# браузер держит иконку в кэше и на смену картинки не смотрит.
ICON_LINKS = (
    f'<link rel="icon" href="/icon-32.png?v={ICON_VERSION}" sizes="32x32" type="image/png">'
    f'<link rel="icon" href="/icon-192.png?v={ICON_VERSION}" sizes="192x192" type="image/png">'
    f'<link rel="apple-touch-icon" href="/icon-180.png?v={ICON_VERSION}">'
    # Айфон манифест не читает и подписывает ярлык по этой метке, а без неё
    # берёт <title> страницы — вышло бы «Личный кабинет · vitazgio.ru».
    '<meta name="apple-mobile-web-app-title" content="Vitaz Gio">'
)


def _icon_response(name):
    path = os.path.join(ICON_DIR, name)
    if not os.path.exists(path):
        return "", 404
    response = send_file(path, conditional=True)
    # Сутки — достаточно, чтобы не дёргать сервер, и мало, чтобы не залипло
    # навсегда, если версию поднять забудут.
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


def create_pwa_blueprint(
    *,
    template,
    login_required,
    drop_lock,
    drop_items,
    drop_max_size,
    drop_quota,
    drop_path,
    drop_used,
    drop_write_index,
):
    pwa = Blueprint("pwa", __name__)

    @pwa.get("/manifest.webmanifest")
    def manifest():
        """Делает сайт устанавливаемым и, главное, объявляет приём «Поделиться»:
        после установки дроп появляется в системном меню отправки любого файла."""
        return Response(
            json.dumps({
                # Под ярлыком на телефоне подписывается short_name, и места там
                # мало: длинное имя оболочка обрежет многоточием.
                "name": "Vitaz Gio",
                "short_name": "Vitaz Gio",
                "start_url": "/",
                "scope": "/",
                "display": "standalone",
                "background_color": "#0d1321",
                "theme_color": "#0d1321",
                # Версия в адресе обязательна. Браузер кэширует иконки манифеста по
                # ссылке и на смену самой картинки не смотрит: пока адрес прежний,
                # при установке он рисует старую, даже если сервер отдаёт новую.
                "icons": [
                    {"src": f"/icon-192.png?v={ICON_VERSION}", "sizes": "192x192", "type": "image/png"},
                    {"src": f"/icon-512.png?v={ICON_VERSION}", "sizes": "512x512", "type": "image/png"},
                    # Маскируемый — отдельным рисунком с запасом по краям, а не
                    # тем же файлом: круглая обрезка съедала бы углы знака.
                    {"src": f"/icon-maskable-512.png?v={ICON_VERSION}", "sizes": "512x512",
                     "type": "image/png", "purpose": "maskable"},
                    {"src": f"/icon-maskable-192.png?v={ICON_VERSION}", "sizes": "192x192",
                     "type": "image/png", "purpose": "maskable"},
                ],
                "share_target": {
                    "action": "/share-target",
                    "method": "POST",
                    "enctype": "multipart/form-data",
                    "params": {
                        "title": "title",
                        "text": "text",
                        "url": "url",
                        # Только "*/*" мало: на такой шаблон Android часто не
                        # показывает приложение при отправке документов и архивов.
                        "files": [{"name": "files", "accept": [
                            "*/*", "image/*", "video/*", "audio/*", "text/*",
                            "application/pdf", "application/zip", "application/octet-stream",
                            "application/msword", "application/vnd.ms-excel",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            "application/x-7z-compressed", "application/x-rar-compressed",
                            "application/gzip", "application/x-tar", "application/json",
                        ]}],
                    },
                },
            }, ensure_ascii=False),
            mimetype="application/manifest+json",
        )

    @pwa.get("/sw.js")
    def service_worker():
        """Делает три вещи: принимает «Поделиться», держит офлайн-страницу с игрой
        и следит, чтобы установленное приложение показывало свежий сайт.

        Стратегия намеренно «сначала сеть»: страницы никогда не берутся из кэша,
        пока сеть жива, поэтому любая правка на сервере видна в приложении сразу,
        без переустановки. Из кэша достаётся только запасная страница — и только
        когда сети нет вовсе."""
        js = template("service_worker.js.tpl")
        return Response(js, mimetype="application/javascript")

    @pwa.get("/favicon.ico")
    def favicon():
        """Браузеры просят его сами, без всяких ссылок в разметке. Внутри три
        размера — 16, 32 и 48, — иначе на разных экранах видно лесенку."""
        return _icon_response("favicon.ico")

    @pwa.get("/icon-<int:size>.png")
    def app_icon(size):
        if size not in ICON_SIZES:
            return "", 404
        return _icon_response(f"icon-{size}.png")

    @pwa.get("/icon-maskable-<int:size>.png")
    def app_icon_maskable(size):
        if size not in ICON_MASKABLE_SIZES:
            return "", 404
        return _icon_response(f"maskable-{size}.png")

    @pwa.post("/share-target")
    @login_required
    def share_target_fallback():
        """Сюда попадаем, только если обработчик в браузере ещё не встал."""
        saved = 0
        for storage in request.files.getlist("files"):
            if not storage or not storage.filename:
                continue
            item_id = str(uuid.uuid4())
            path = drop_path(item_id)
            try:
                storage.save(path)
                size = os.path.getsize(path)
            except OSError:
                continue
            with drop_lock:
                if size > drop_max_size or drop_used() + size > drop_quota:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    continue
                drop_items[item_id] = {
                    "kind": "file", "name": storage.filename[:120], "parent": None,
                    "content_type": storage.content_type or "application/octet-stream",
                    "size": size, "created": time.time(), "share": None,
                }
                drop_write_index()
            saved += 1
        return redirect(url_for("drop.drop_page") + ("?saved=%d" % saved if saved else ""))

    return pwa
