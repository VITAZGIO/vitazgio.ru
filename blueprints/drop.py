"""blueprints/drop.py — личный дроп /drop, публичные ссылки /d/<token>
(задача 39, docs/structure-plan.md). Самый большой разрез: 61 зависимость
фабрики → 0.

Владеет своим состоянием сам, как остальные фичи блока Б (задачи 35-38).
Почти все 61 фабричных аргумента были либо приватными хелперами app.py
(переехали на модульный уровень без изменений в поведении — только снята
подчёркивающая приставка у тех имён, которые уже были факт­ическими
"публичными" именами фабрики), либо инфраструктурой, давно доступной
напрямую (`template`, `login_required`, `escape`, `icon_links`).

`logger` был `app.logger` — внутри Flask-запроса то же самое даёт
`current_app.logger`, без завязки на объект `app` из app.py.

`DROP_DIR` считался как `os.path.dirname(os.path.abspath(__file__))` —
это работало, пока код жил в `app.py` (`__file__` = путь к app.py, корень
репозитория). Дословный перенос в `blueprints/drop.py` тихо сломал бы путь
(`__file__` стал бы путём к этому файлу, `DROP_DIR` съехал бы в
`blueprints/drop_data` вместо корневого `drop_data/`) — считаем от
`core.storage.REPO_ROOT` вместо этого, тот же самый абсолютный путь.

Дроп и фонотека делят одно хранилище на 30 ГБ и папку MUSIK (виртуальные
id вида «mt_»/«mf_» — фонотека, показанная глазами дропа): этот файл
импортирует `MUSIC_*`/`music_*` из `blueprints.music` напрямую — обычный
однонаправленный импорт (drop → music), без риска цикла. Обратное
направление (music.py читает `drop_lock`/`drop_used_safe`/`DROP_QUOTA`/
`drop_musik_tracks`) устроить прямым импортом уже нельзя: это был бы
настоящий взаимный цикл (drop ⇄ music), который Python не разрешает.
Поэтому мостом по-прежнему служит app.py — как и раньше, просто теперь
берёт эти четыре имени из `blueprints.drop`, а не объявляет их сам. По
той же причине
`blueprints/backup_sebastian.py` (задача 37), `blueprints/files.py`
(следующий коммит этой же задачи) и `blueprints/pwa.py` продолжают
получать `drop_lock`/`drop_items`/`drop_path`/`drop_write_index`/
`drop_used`/`DROP_QUOTA`/`DROP_MAX_SIZE`/`DROP_DOWNLOAD_ID`/
`drop_load_index`/`DROP_DIR` через фабрику app.py — app.py импортирует их
отсюда и форвардит дальше, как `notebook_data` в задаче 35.

Убраны два мёртвых дубликата, найденные при переносе (в app.py лежали
рядом с рабочим кодом, но не вызывались ниоткуда — настоящие версии уже
жили вложенными функциями внутри `create_drop_blueprint`, добавленные
при первом вынесении маршрутов в blueprint): класс `_ZipSink` (уже есть
свой такой же внутри `drop_zip()`) и функция `_drop_public_item` (уже
есть `drop_public_item()` внутри фабрики, с тем же телом).
"""

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import threading
import time
import urllib.parse
import uuid
import zipfile
from datetime import datetime

from flask import Blueprint, Response, current_app, jsonify, request, send_file, session, url_for
from markupsafe import escape

from blueprints.music import (
    MUSIC_DIR,
    MUSIC_EXTS,
    MUSIC_MAX_DEPTH,
    MUSIC_MIMES,
    music_folder_depth,
    music_folders,
    music_items,
    music_lock,
    music_safe_name,
    music_scan,
    music_split,
    music_unlink,
    music_used,
    music_used_safe,
    music_write_index,
)
from blueprints.pwa import ICON_LINKS
from core.auth import login_required
from core.storage import REPO_ROOT
from core.templates import template

# ---- Личный дроп ------------------------------------------------------------
# Содержимое лежит на диске под именами-uuid, настоящие имена только в индексе.
# Пользовательский текст никогда не попадает в путь, поэтому выйти за пределы
# каталога принципиально нечем. Удаления по времени нет — только вручную,
# ограничителем служит квота.
DROP_DIR = os.path.join(str(REPO_ROOT), "drop_data")

DROP_TMP_DIR = os.path.join(DROP_DIR, "tmp")

DROP_INDEX_PATH = os.path.join(DROP_DIR, "index.json")

DROP_QUOTA = 30 * 1024 * 1024 * 1024      # 30 ГБ на весь дроп

DROP_MAX_SIZE = 2 * 1024 * 1024 * 1024    # 2 ГБ на один файл

DROP_CHUNK_TTL = 6 * 3600                 # брошенные недокачки убираем через 6 ч

DROP_TEXT_PREVIEW = 400

# Особая папка «MUSIK»: всегда внизу списка, удалить нельзя. Что кинешь в
# неё (треки или папки с треками) — попадает в плеер. Живёт под своим
# постоянным id, чтобы переживать перезапуски.
DROP_MUSIK_ID = "musik"

DROP_AUDIO_EXTS = {".mp3", ".ogg", ".wav", ".m4a", ".opus", ".flac", ".aac"}

# Особая папка «Download»: тоже нельзя переименовать/удалить, тоже всегда на
# месте. В отличие от MUSIK ничего не подменяет — обычная папка дропа, просто
# защищённая и с фиксированным назначением: сюда по умолчанию (без явного
# выбора папки) падает то, что прислали «Поделиться» с телефона и кнопка VG
# со страницы файлов SFTP.
DROP_DOWNLOAD_ID = "download"

drop_items: dict = {}

drop_uploads: dict = {}

drop_lock = threading.Lock()
os.makedirs(DROP_TMP_DIR, exist_ok=True)

def drop_path(item_id):
    return os.path.join(DROP_DIR, f"{item_id}.bin")

def drop_tmp_path(upload_id):
    return os.path.join(DROP_TMP_DIR, f"{upload_id}.part")

def drop_write_index():
    """Вызывать под drop_lock."""
    tmp = DROP_INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(drop_items, fh, ensure_ascii=False)
    os.replace(tmp, DROP_INDEX_PATH)

def drop_used():
    """Занято байт. Вызывать под drop_lock."""
    return sum(item.get("size", 0) for item in drop_items.values())

def drop_children(parent):
    """Прямые потомки папки. Вызывать под drop_lock."""
    return [k for k, v in drop_items.items() if v.get("parent") == parent]

# Значки папок. Имя из этого списка сохраняется в индексе, а рисует его
# уже страница — так на сервере не лежит ни байта разметки.
DROP_FOLDER_ICONS = (
    "folder", "warn", "clock", "tree", "monitor", "phone",
    "claude", "vitaz", "star", "lock", "music", "photo",
    "video", "work", "trash", "game",
    # Вторая строка добавлена 2026-09-11 для папки Download: стрелка загрузки
    # (её же икона), «поделиться», настройки (шестерёнка) и профиль —
    # присланы вторым и третьим заходом, первые версии шестерёнки/профиля
    # оказались той же стрелкой загрузки по ошибке.
    "download", "share", "settings", "profile",
)

def drop_folder_stats(item_id, memo=None):
    """Сколько папка весит, сколько в ней всего и когда её трогали в последний
    раз — считая по всему содержимому вглубь. Вызывать под drop_lock.

    Свежесть папки берём по самому свежему файлу внутри: на Windows папка
    считается изменённой, когда правишь её содержимое, и сортировка «сначала
    новые» без этого выглядит враньём."""
    memo = {} if memo is None else memo
    if item_id in memo:
        return memo[item_id]
    memo[item_id] = (0, 0.0, 0)                       # заглушка от петли в индексе
    size = 0
    touched = drop_items.get(item_id, {}).get("created", 0.0)
    count = 0
    for child in drop_children(item_id):
        node = drop_items[child]
        # Удалённое (в корзине) в счёт живой папки не идёт — оно считается
        # отдельно, как содержимое корзины.
        if node.get("deleted"):
            continue
        count += 1
        if node["kind"] == "folder":
            sub_size, sub_touched, sub_count = drop_folder_stats(child, memo)
            size += sub_size
            count += sub_count
            touched = max(touched, sub_touched)
        else:
            size += node.get("size", 0)
            touched = max(touched, node.get("created", 0.0))
    memo[item_id] = (size, touched, count)
    return memo[item_id]

def drop_discard(item_id):
    """Удаляет элемент, для папки — вместе со всем содержимым. Под drop_lock."""
    item = drop_items.get(item_id)
    if not item:
        return
    if item["kind"] == "folder":
        for child in drop_children(item_id):
            drop_discard(child)
    drop_items.pop(item_id, None)
    for path in (drop_path(item_id), os.path.join(DROP_DIR, f"{item_id}.thumb")):
        try:
            os.remove(path)
        except OSError:
            pass

# ---- Корзина -------------------------------------------------------------
# Удалённое не стирается сразу, а уезжает в корзину: метка `deleted` со
# временем. Место оно продолжает занимать (входит в «Занято»), само чистится
# через месяц, а до того его можно вернуть или снести вручную по паролю.
DROP_TRASH_TTL = 30 * 24 * 3600

# Пароль корзины хранится хешем — plaintext в исходник не кладём.
# sha256("1224"); пароль простой, это защёлка «как в Windows», не броня.
DROP_TRASH_PASS_HASH = "0d866ba9f9fd0f2cbb2134daf52356d2021a3686352d5c19d967305bf9e4bbdc"

def drop_trash(item_id, when=None):
    """Отправляет элемент в корзину. Для папки метку ставим только на неё —
    содержимое уезжает вместе, но своих меток не получает. Особую папку MUSIK
    не трогаем. Под drop_lock."""
    if item_id == DROP_MUSIK_ID:
        return
    item = drop_items.get(item_id)
    if item and item.get("special"):
        return
    if item and not item.get("deleted"):
        item["deleted"] = when or time.time()

def _drop_has_deleted_ancestor(item_id):
    """Лежит ли элемент внутри уже удалённой папки. Под drop_lock."""
    seen = set()
    parent = drop_items.get(item_id, {}).get("parent")
    while parent and parent in drop_items and parent not in seen:
        seen.add(parent)
        if drop_items[parent].get("deleted"):
            return True
        parent = drop_items[parent].get("parent")
    return False

def drop_trash_roots():
    """Корни удалённых поддеревьев — то, что показываем в корзине списком.
    Вложенное в удалённую папку отдельной строкой не выводим. Под drop_lock."""
    return [k for k, v in drop_items.items()
            if v.get("deleted") and not _drop_has_deleted_ancestor(k)]

def drop_trash_bytes(memo=None):
    """Сколько всего занимает корзина. Под drop_lock."""
    memo = {} if memo is None else memo
    total = 0
    for root in drop_trash_roots():
        item = drop_items[root]
        if item["kind"] == "folder":
            total += drop_trash_subtree_bytes(root)
        else:
            total += item.get("size", 0)
    return total

def drop_trash_subtree_bytes(item_id):
    """Вес удалённой папки со всем, что внутри (живое обычным подсчётом уже
    пропускает удалённое, поэтому считаем отдельно). Под drop_lock."""
    total = 0
    for child in drop_children(item_id):
        node = drop_items[child]
        if node["kind"] == "folder":
            total += drop_trash_subtree_bytes(child)
        else:
            total += node.get("size", 0)
    return total

def drop_sweep_trash():
    """Выносит из корзины то, что пролежало дольше месяца. Под drop_lock."""
    now = time.time()
    for root in drop_trash_roots():
        if now - (drop_items[root].get("deleted") or 0) > DROP_TRASH_TTL:
            drop_discard(root)

def drop_trash_ok(password):
    got = hashlib.sha256((password or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(got, DROP_TRASH_PASS_HASH)

def drop_path_to_root(item_id):
    """Цепочка папок от корня до item_id включительно. Под drop_lock."""
    chain, seen = [], set()
    while item_id and item_id in drop_items and item_id not in seen:
        seen.add(item_id)
        chain.append({"id": item_id, "name": drop_items[item_id]["name"]})
        item_id = drop_items[item_id].get("parent")
    return list(reversed(chain))

def drop_is_descendant(item_id, maybe_parent):
    """Не пытаются ли переместить папку внутрь самой себя. Под drop_lock."""
    seen = set()
    while maybe_parent and maybe_parent not in seen:
        if maybe_parent == item_id:
            return True
        seen.add(maybe_parent)
        maybe_parent = drop_items.get(maybe_parent, {}).get("parent")
    return False

def drop_share_lookup(token):
    """Ищет элемент по токену ссылки. Под drop_lock."""
    now = time.time()
    for item_id, item in drop_items.items():
        share = item.get("share")
        # Сравниваем байты: compare_digest падает на строках с не-ASCII,
        # а токен приходит из адресной строки и может быть каким угодно.
        if share and hmac.compare_digest(share["token"].encode(), token.encode()):
            if share["expires"] and share["expires"] < now:
                return None
            return item_id
    return None

def drop_sweep_uploads():
    """Подчищает брошенные недокачки. Под drop_lock."""
    now = time.time()
    for upload_id in [k for k, v in drop_uploads.items() if now - v["started"] > DROP_CHUNK_TTL]:
        drop_uploads.pop(upload_id, None)
        try:
            os.remove(drop_tmp_path(upload_id))
        except OSError:
            pass

def drop_load_index():
    try:
        with open(DROP_INDEX_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        saved = {}

    for item_id, meta in saved.items():
        # Записи старого формата: плоский список файлов без папок и ссылок.
        meta.setdefault("kind", "text" if meta.pop("is_text", False) else "file")
        meta.setdefault("parent", None)
        meta.setdefault("share", None)
        meta.setdefault("size", 0)
        meta.setdefault("deleted", None)
        if meta["kind"] == "folder" or os.path.exists(drop_path(item_id)):
            drop_items[item_id] = meta

    known = set(drop_items)
    for fname in os.listdir(DROP_DIR):
        for suffix in (".bin", ".thumb"):
            if fname.endswith(suffix) and fname[: -len(suffix)] not in known:
                try:
                    os.remove(os.path.join(DROP_DIR, fname))
                except OSError:
                    pass
    for fname in os.listdir(DROP_TMP_DIR):
        try:
            os.remove(os.path.join(DROP_TMP_DIR, fname))
        except OSError:
            pass

    # Потерянные родители: папку могли удалить в обход рекурсии.
    for item in drop_items.values():
        if item["parent"] and item["parent"] not in drop_items:
            item["parent"] = None
    _drop_ensure_musik()         # особая папка MUSIK всегда на месте
    _drop_ensure_download()      # особая папка Download тоже
    drop_sweep_trash()          # что пролежало в корзине дольше месяца — вон
    drop_write_index()


def _drop_ensure_download():
    """Заводит (или чинит) особую папку Download в корне. Под drop_lock либо
    на старте до потоков. Сюда по умолчанию падает то, что «Поделиться» с
    телефона и кнопка VG со страницы файлов (SFTP) кладут без явного выбора
    папки — сам дроп при обычной загрузке от этого не меняется, там папку
    выбирают, зайдя в неё заранее."""
    d = drop_items.get(DROP_DOWNLOAD_ID)
    if not d or d.get("kind") != "folder":
        drop_items[DROP_DOWNLOAD_ID] = {
            "kind": "folder", "name": "Download", "parent": None, "share": None,
            "size": 0, "deleted": None, "icon": "download", "special": True,
            "created": time.time(),
        }
    else:
        d["parent"] = None            # всегда в корне
        d["deleted"] = None           # в корзину не уходит
        d["special"] = True
        d.setdefault("icon", "download")

def _drop_ensure_musik():
    """Заводит (или чинит) особую папку MUSIK в корне. Под drop_lock либо на
    старте до потоков."""
    m = drop_items.get(DROP_MUSIK_ID)
    if not m or m.get("kind") != "folder":
        drop_items[DROP_MUSIK_ID] = {
            "kind": "folder", "name": "MUSIK", "parent": None, "share": None,
            "size": 0, "deleted": None, "icon": "music", "special": True,
            "created": time.time(),
        }
    else:
        m["parent"] = None            # всегда в корне
        m["deleted"] = None           # в корзину не уходит
        m["special"] = True
        m.setdefault("icon", "music")

def drop_musik_tracks():
    """Аудиофайлы внутри папки MUSIK (вглубь по подпапкам) — для плеера.
    Каждый со своим адресом потока. Под drop_lock."""
    out = []

    def walk(parent, label):
        kids = [(k, v) for k, v in drop_items.items()
                if v.get("parent") == parent and not v.get("deleted")]
        kids.sort(key=lambda kv: kv[1]["name"].lower())
        for k, v in kids:
            if v["kind"] == "folder":
                walk(k, (label + " / " if label else "") + v["name"])
            elif v["kind"] == "file":
                if os.path.splitext(v["name"])[1].lower() in DROP_AUDIO_EXTS:
                    out.append({
                        "id": "d_" + k,
                        "title": os.path.splitext(v["name"])[0],
                        "artist": "", "folder": label,
                        "url": "/api/drop/view/" + k,
                    })

    walk(DROP_MUSIK_ID, "")
    return out


drop_load_index()

# Дроп и фонотека делят ОДНО хранилище на 30 ГБ (DROP_QUOTA) — правило:
# сначала music_lock, потом drop_lock (или каждый отдельно), никогда
# наоборот, иначе взаимоблокировка (music_used_safe — в blueprints/music.py).
def drop_used_safe():
    with drop_lock:
        return drop_used()

def drop_thumb_path(item_id):
    return os.path.join(DROP_DIR, f"{item_id}.thumb")

def drop_can_thumb(item):
    """Миниатюры делаем только для растровых картинок. SVG сюда не пускаем:
    это документ со скриптами, а не картинка."""
    if item.get("kind") != "file":
        return False
    name = item.get("name", "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in {"jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff"}

def drop_make_thumb(item_id):
    """Рисует миниатюру рядом с файлом. Возвращает путь или None."""
    thumb_path = drop_thumb_path(item_id)
    if os.path.exists(thumb_path):
        return thumb_path
    try:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = 80_000_000  # защита от «бомб» с гигантским разрешением
        with Image.open(drop_path(item_id)) as image:
            image.draft("RGB", (256, 256))  # для JPEG декодируем сразу уменьшенным
            image = image.convert("RGB")
            image.thumbnail((200, 200))
            image.save(thumb_path, "JPEG", quality=62, optimize=True)
        return thumb_path
    except Exception:
        return None

# Растровые картинки, которые можно безопасно отдать в строку: они не умеют
# выполнять скрипты. SVG сюда не входит намеренно — внутри него живёт
# полноценный JS, и на домене сайта он дотянулся бы до сессии.
# Что можно безопасно показать прямо в браузере. Ни один из этих типов не
# умеет выполнять скрипты. SVG и HTML сюда не входят намеренно: внутри них
# живёт полноценный JS, и на домене сайта он дотянулся бы до сессии.
DROP_INLINE_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".ico": "image/x-icon", ".avif": "image/avif",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8", ".csv": "text/plain; charset=utf-8",
    ".mp4": "video/mp4", ".webm": "video/webm", ".m4v": "video/mp4",
    ".mov": "video/quicktime", ".ogv": "video/ogg",
    ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav",
    ".m4a": "audio/mp4", ".opus": "audio/ogg", ".flac": "audio/flac",
    ".aac": "audio/aac",
}

# Чем показывать файл на странице ссылки. Всё, чего тут нет, ссылка просто
# отдаёт файлом — выдумывать просмотр для архива или экзешника незачем.
DROP_VIEW_KINDS = (
    ("image", {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".avif", ".ico"}),
    ("video", {".mp4", ".webm", ".m4v", ".mov", ".ogv"}),
    ("audio", {".mp3", ".ogg", ".wav", ".m4a", ".opus", ".flac", ".aac"}),
    ("page", {".pdf", ".txt", ".log", ".md", ".csv"}),
)

def drop_human_size(bytes_count):
    """Вес файла по-человечески — для шапки страницы просмотра."""
    if bytes_count >= 1073741824:
        return f"{bytes_count / 1073741824:.2f} ГБ"
    if bytes_count >= 1048576:
        return f"{bytes_count / 1048576:.1f} МБ"
    if bytes_count >= 1024:
        return f"{round(bytes_count / 1024)} КБ"
    return f"{bytes_count} Б"

def drop_view_kind(name):
    """Каким тегом показывать файл, либо пусто — если показывать нечем."""
    ext = os.path.splitext(name or "")[1].lower()
    for kind, exts in DROP_VIEW_KINDS:
        if ext in exts:
            return kind
    return ""

def drop_share_mode(share):
    """Что делает ссылка: «view» — открывает страницу, «dl» — отдаёт файл.

    У ссылок, выданных до появления тумблера, поля нет. Раньше правило было
    негласным: бессрочная открывалась в браузере, а срочная скачивалась —
    его и повторяем, чтобы старые ссылки вели себя как вели."""
    mode = (share or {}).get("mode")
    if mode in ("view", "dl"):
        return mode
    return "dl" if (share or {}).get("expires") else "view"

def drop_send(item_id, item, inline=False):
    """По умолчанию отдаём вложением: иначе загруженный .html или .svg со
    скриптом выполнился бы на домене сайта и добрался до сессии и токена
    устройства. Открываем в браузере только по бессрочной ссылке и только
    те типы, которые заведомо ничего не выполняют."""
    ext = os.path.splitext(item["name"])[1].lower()
    mime = DROP_INLINE_TYPES.get(ext) if inline else None
    response = send_file(
        drop_path(item_id),
        mimetype=mime or "application/octet-stream",
        as_attachment=not mime,
        download_name=item["name"],
        conditional=True,
    )
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    # Без этого браузер может «донюхать» тип сам и решить, что перед ним HTML
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

def drop_text_name(first_line):
    """Имя текстовой заметки: первая строка плюс .txt, если его ещё нет."""
    name = (first_line or "").strip()[:60] or "Текст"
    return name if name.lower().endswith(".txt") else name + ".txt"

def drop_music_take(tmp_path, name, size, folder):
    """Принимает файл, брошенный в папку MUSIK, прямо в фонотеку — тогда он
    сразу оказывается и в плеере, и на странице музыки."""
    ext = os.path.splitext(name)[1].lower()
    if ext not in MUSIC_EXTS:
        music_unlink(tmp_path)
        return jsonify(error="В MUSIK кладём только музыку."), 415
    # Место общее с дропом: дроп занят + вся музыка + новый файл против 30 ГБ.
    drop_used = drop_used_safe()
    with music_lock:
        if drop_used + music_used() + size > DROP_QUOTA:
            music_unlink(tmp_path)
            return jsonify(error="В хранилище кончилось место."), 507
        if folder and folder not in music_folders:
            folder = ""
        # подбираем свободное имя, как это делает загрузка на странице музыки
        safe = music_safe_name(name)
        taken = {t["file"] for t in music_items.values()}
        stem, suffix = os.path.splitext(safe)
        candidate, counter = safe, 2
        while candidate in taken or os.path.exists(os.path.join(MUSIC_DIR, candidate)):
            candidate = f"{stem} ({counter}){suffix}"
            counter += 1
        try:
            os.replace(tmp_path, os.path.join(MUSIC_DIR, candidate))
        except OSError as e:
            music_unlink(tmp_path)
            return jsonify(error=f"Не удалось сохранить: {e}"), 500
        artist, title = music_split(os.path.splitext(candidate)[0])
        track_id = str(uuid.uuid4())
        music_items[track_id] = {"file": candidate, "artist": artist, "title": title,
                                 "size": size, "added": time.time(), "folder": folder}
        music_write_index()
    return jsonify(id="mt_" + track_id, music=True)

def drop_music_view(parent):
    """Содержимое папки MUSIK — это сама фонотека, показанная глазами дропа.

    Раньше дроп и фонотека были двумя разными складами: трек, загруженный на
    странице музыки, в дропе не появлялся, и наоборот. Теперь MUSIK не хранит
    ничего своего, а показывает папки и треки фонотеки — то же самое, что
    играет плеер. Значки виртуальные: id папки начинается с «mf_», трека — с
    «mt_», по ним и разбираем запросы дальше."""
    inside = "" if parent == DROP_MUSIK_ID else parent[3:]
    items, chain = [], []
    with music_lock:
        music_scan()
        music_bytes = music_used()
        for k, v in sorted(music_folders.items(), key=lambda x: x[1]["name"].lower()):
            if v.get("parent", "") != inside:
                continue
            kids = sum(1 for t in music_items.values() if t.get("folder", "") == k)
            size = sum(t.get("size", 0) for t in music_items.values()
                       if t.get("folder", "") == k)
            items.append({"id": "mf_" + k, "kind": "folder", "name": v["name"],
                          "size": size, "count": kids, "icon": "music",
                          "created": v.get("added", 0), "touched": v.get("added", 0),
                          "share": False, "share_expires": None, "share_mode": None,
                          "share_url": None, "thumb": False, "preview": None,
                          "truncated": False, "music": True})
        for k, v in sorted(music_items.items(),
                           key=lambda x: (str(x[1].get("artist", "")).lower(),
                                          str(x[1].get("title", "")).lower())):
            if v.get("folder", "") != inside:
                continue
            name = " — ".join([p for p in (v.get("artist"), v.get("title")) if p]) or v["file"]
            items.append({"id": "mt_" + k, "kind": "file", "name": name,
                          "size": v.get("size", 0), "created": v.get("added", 0),
                          "touched": v.get("added", 0), "preview": None, "truncated": False,
                          "thumb": False, "share": False, "share_expires": None,
                          "share_mode": None, "share_url": None, "music": True})
        # путь наверх: MUSIK, а дальше вложенные папки фонотеки
        node = inside
        seen = set()
        while node and node in music_folders and node not in seen:
            seen.add(node)
            chain.append({"id": "mf_" + node, "name": music_folders[node]["name"]})
            node = music_folders[node].get("parent", "")
        chain.reverse()
    with drop_lock:
        used, trash = drop_used() + music_bytes, drop_trash_bytes()
    return jsonify(items=items,
                   breadcrumbs=[{"id": DROP_MUSIK_ID, "name": "MUSIK"}] + chain,
                   used=used, music=music_bytes, quota=DROP_QUOTA, trash=trash,
                   music_view=True)

def drop_music_send(item_id, inline=False):
    """Трек фонотеки, отданный через дроп: id вида «mt_<id>». Возвращает
    ответ или None, если это обычный элемент дропа."""
    if not item_id.startswith("mt_"):
        return None
    with music_lock:
        track = music_items.get(item_id[3:])
    if not track:
        return "Не найдено", 404
    path = os.path.join(MUSIC_DIR, track["file"])
    if not os.path.exists(path):
        return "Не найдено", 404
    ext = os.path.splitext(track["file"])[1].lower()
    name = " — ".join([p for p in (track.get("artist"), track.get("title")) if p]) or track["file"]
    return send_file(path, mimetype=MUSIC_MIMES.get(ext, "audio/mpeg"),
                     as_attachment=not inline, download_name=name + ext, conditional=True)

# Архив папки собираем на лету и сразу отдаём: складывать его в памяти
# нельзя — папка с фотографиями легко весит больше, чем есть оперативки.
DROP_ZIP_CHUNK = 1024 * 1024

def drop_zip_name(name, taken):
    """Имя внутри архива: без разделителей пути и без повторов в одной папке.

    Разделители убираем не для красоты — имя вида «../ключи» распаковалось бы
    мимо выбранной папки."""
    clean = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name or "").strip(" .") or "файл"
    stem, dot, ext = clean.rpartition(".")
    if not dot:
        stem, ext = clean, ""
    candidate, counter = clean, 2
    while candidate.lower() in taken:
        candidate = f"{stem} ({counter})" + (f".{ext}" if dot else "")
        counter += 1
    taken.add(candidate.lower())
    return candidate

def drop_zip_plan(folder_id):
    """Что кладём в архив: путь внутри архива, файл на диске, размер, время.
    Пустые папки тоже попадают — иначе они пропадут при распаковке.
    Вызывать под drop_lock."""
    plan = []

    def walk(node_id, prefix, seen):
        if node_id in seen:
            return
        seen = seen | {node_id}
        taken = set()
        for child in sorted(drop_children(node_id),
                            key=lambda k: drop_items[k]["name"].lower()):
            item = drop_items[child]
            name = drop_zip_name(item["name"], taken)
            if item["kind"] == "folder":
                plan.append((prefix + name + "/", None, 0, item.get("created", 0)))
                walk(child, prefix + name + "/", seen)
            else:
                plan.append((prefix + name, child, item.get("size", 0),
                             item.get("created", 0)))

    walk(folder_id, "", set())
    return plan

def drop_zip_length(plan):
    """Точный размер будущего архива, чтобы браузер показал полосу загрузки.

    Считается только для несжатого архива без ZIP64: заголовок файла 30 байт
    плюс имя, затем данные, затем метка на 16 байт; в конце по 46 байт плюс
    имя на каждую запись и 22 байта хвоста. Если выходит за четыре гигабайта,
    формат переключится на ZIP64 и эта арифметика перестанет быть верной —
    тогда длину не обещаем вовсе."""
    total = 22
    for arcname, file_id, size, _ in plan:
        name_len = len(arcname.encode("utf-8"))
        # 30 — заголовок файла, 16 — метка с размерами после данных,
        # 46 — запись в оглавлении. Метка пишется и для папок: zipfile
        # ставит её всем записям, раз поток непрокручиваемый.
        total += 30 + name_len + 16 + 46 + name_len
        if file_id:
            total += size
    limit = 0xFFFFFFFF
    if total > limit or any(size > limit for _, _, size, _ in plan):
        return None
    return total

def drop_zip_time(stamp):
    """Время файла для архива. До 1980 года формат не умеет, ниже не опускаем."""
    try:
        # Время в архиве пишется без пояса — берём местное, как и делают
        # все архиваторы.
        moment = datetime.fromtimestamp(stamp or 0)
    except (OSError, OverflowError, ValueError):
        moment = datetime.now()
    if moment.year < 1980:
        return (1980, 1, 1, 0, 0, 0)
    return (moment.year, moment.month, moment.day,
            moment.hour, moment.minute, moment.second - moment.second % 2)

# ---- Пакетные действия: копирование, перенос, удаление -----------------------
# Копирование гигабайтной папки занимает секунды, а то и минуты, поэтому работа
# уходит в отдельный поток, а страница спрашивает о ходе дела по номеру задачи.
# Диск трогаем вне drop_lock: под ним весь дроп встал бы на всё время копии.
drop_jobs: dict = {}

drop_jobs_lock = threading.Lock()

DROP_JOB_TTL = 900              # доделанную задачу держим ещё четверть часа

DROP_COPY_CHUNK = 4 * 1024 * 1024

def drop_job_set(job_id, **fields):
    with drop_jobs_lock:
        job = drop_jobs.get(job_id)
        if job:
            job.update(fields)

def drop_jobs_sweep():
    """Выкидываем задачи, о которых уже не спросят. Под drop_jobs_lock."""
    edge = time.time() - DROP_JOB_TTL
    for key in [k for k, v in drop_jobs.items()
                if v["state"] != "run" and v["ended"] < edge]:
        drop_jobs.pop(key, None)

def drop_unique_name(name, parent, extra=()):
    """«файл.txt» рядом с таким же становится «файл (2).txt». Под drop_lock.

    extra — имена, которых в папке ещё нет, но они там вот-вот появятся:
    при копировании план строится целиком заранее, и без этого списка две
    одинаковые копии в одной пачке получили бы одно и то же имя."""
    taken = {drop_items[k]["name"] for k in drop_children(parent)} | set(extra)
    if name not in taken:
        return name
    stem, ext = os.path.splitext(name)
    for n in range(2, 1000):
        candidate = f"{stem} ({n}){ext}"
        if candidate not in taken:
            return candidate
    return f"{stem} ({uuid.uuid4().hex[:6]}){ext}"

def _drop_copy_plan(ids, target):
    """Разворачивает выделенное в плоский список работ. Под drop_lock.

    Порядок обхода такой, что папка всегда идёт раньше своего содержимого —
    значит к моменту создания ребёнка его новый родитель уже существует."""
    plan, total, claimed = [], 0, set()

    def walk(item_id, parent, rename):
        nonlocal total
        item = drop_items.get(item_id)
        if not item:
            return
        new_id = str(uuid.uuid4())
        if rename:
            name = drop_unique_name(item["name"], parent, claimed)
            claimed.add(name)
        else:
            name = item["name"]
        plan.append({"src": item_id, "new": new_id, "parent": parent,
                     "name": name, "kind": item["kind"],
                     "size": item.get("size", 0)})
        total += item.get("size", 0)
        if item["kind"] == "folder":
            for child in drop_children(item_id):
                walk(child, new_id, False)

    for item_id in ids:
        walk(item_id, target, True)
    return plan, total

def _drop_copy_file(src_id, new_id, job_id):
    """Копирует тело файла кусками, отмечая пройденные байты."""
    src, dst = drop_path(src_id), drop_path(new_id)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(DROP_COPY_CHUNK)
            if not chunk:
                break
            fout.write(chunk)
            with drop_jobs_lock:
                job = drop_jobs.get(job_id)
                if not job:
                    raise RuntimeError("задача отменена")
                job["bytes"] += len(chunk)
    thumb = drop_thumb_path(src_id)
    if os.path.exists(thumb):
        try:
            shutil.copyfile(thumb, drop_thumb_path(new_id))
        except OSError:
            pass

def _drop_run_copy(job_id, ids, target):
    with drop_lock:
        plan, total_bytes = _drop_copy_plan(ids, target)
        free = DROP_QUOTA - drop_used()
    if total_bytes > free:
        raise RuntimeError("Не хватает места: нужно "
                           f"{total_bytes // 1048576} МБ, свободно {max(free, 0) // 1048576} МБ.")
    drop_job_set(job_id, total=len(plan), bytes_total=total_bytes)
    for step in plan:
        if step["kind"] != "folder":
            _drop_copy_file(step["src"], step["new"], job_id)
        with drop_lock:
            src = drop_items.get(step["src"])
            if not src:                       # исчез, пока копировали
                continue
            copy = dict(src)
            copy.update({"name": step["name"], "parent": step["parent"],
                         "created": time.time(), "share": None})
            drop_items[step["new"]] = copy
            drop_write_index()
        with drop_jobs_lock:
            job = drop_jobs.get(job_id)
            if job:
                job["done"] += 1

def _drop_run_move(job_id, ids, target):
    with drop_lock:
        if target and drop_items.get(target, {}).get("kind") != "folder":
            raise RuntimeError("Такой папки нет.")
        for item_id in ids:
            if target and drop_is_descendant(item_id, target):
                raise RuntimeError("Нельзя переложить папку внутрь себя.")
        drop_job_set(job_id, total=len(ids))
        for item_id in ids:
            item = drop_items.get(item_id)
            if not item or item.get("parent") == target:
                with drop_jobs_lock:
                    drop_jobs[job_id]["done"] += 1
                continue
            # Имя подбираем до перекладывания: после него элемент уже лежит
            # в приёмнике и считает тёзкой сам себя — папка «Склад» так
            # переезжала и становилась «Склад (2)».
            item["name"] = drop_unique_name(item["name"], target)
            item["parent"] = target
            with drop_jobs_lock:
                drop_jobs[job_id]["done"] += 1
        drop_write_index()

def _drop_run_delete(job_id, ids, _target):
    with drop_lock:
        drop_job_set(job_id, total=len(ids))
        for item_id in ids:
            drop_trash(item_id)             # пакетное удаление — тоже в корзину
            with drop_jobs_lock:
                drop_jobs[job_id]["done"] += 1
        drop_write_index()

DROP_OPS = {"copy": _drop_run_copy, "move": _drop_run_move, "delete": _drop_run_delete}

def drop_music_delete(item_id):
    """Удаление из фонотеки по запросу из дропа. Корзины у фонотеки нет —
    предупреждение об этом висит на самой кнопке."""
    with music_lock:
        if item_id.startswith("mt_"):
            track = music_items.pop(item_id[3:], None)
            if track:
                still = any(t["file"] == track["file"] for t in music_items.values())
                if not still:
                    music_unlink(os.path.join(MUSIC_DIR, track["file"]))
                music_write_index()
            return jsonify(ok=True)
        fid = item_id[3:]
        if fid not in music_folders:
            return jsonify(error="Папка не найдена."), 404
        # вместе с папкой уносим её подпапки и треки
        doomed, queue = {fid}, [fid]
        while queue:
            cur = queue.pop()
            for k, v in music_folders.items():
                if v.get("parent", "") == cur and k not in doomed:
                    doomed.add(k)
                    queue.append(k)
        for k in [k for k, v in music_items.items() if v.get("folder", "") in doomed]:
            track = music_items.pop(k)
            still = any(t["file"] == track["file"] for t in music_items.values())
            if not still:
                music_unlink(os.path.join(MUSIC_DIR, track["file"]))
        for k in doomed:
            music_folders.pop(k, None)
        music_write_index()
    return jsonify(ok=True)


def create_drop_blueprint():
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
            if drop_used() + len(data) > DROP_QUOTA:
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
                "created": time.time(), "preview": text[:DROP_TEXT_PREVIEW],
                "truncated": len(text) > DROP_TEXT_PREVIEW, "share": None,
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
            if drop_used() - item["size"] + len(data) > DROP_QUOTA:
                return jsonify(error="Нет места: квота исчерпана."), 507
            try:
                with open(drop_path(item_id), "wb") as fh:
                    fh.write(data)
            except OSError as e:
                return jsonify(error=f"Не удалось сохранить: {e}"), 500
            item["size"] = len(data)
            item["preview"] = text[:DROP_TEXT_PREVIEW]
            item["truncated"] = len(text) > DROP_TEXT_PREVIEW
            item["edited"] = time.time()
            drop_write_index()
        return jsonify(ok=True, size=len(data))

    @drop_bp.post("/api/drop/folder")
    @login_required
    def drop_folder_create():
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()[:60]
        parent = payload.get("parent") or None
        icon = payload.get("icon") if payload.get("icon") in DROP_FOLDER_ICONS else "folder"
        if not name:
            return jsonify(error="Имя пустое."), 400
        # Папка внутри MUSIK — это папка ФОНОТЕКИ, а не склад дропа. MUSIK
        # показывает не свои вложения, а папки фонотеки (id с «mf_»), поэтому
        # обычная папка дропа тут просто не показалась бы — «создал, а её нет».
        # Заводим настоящую папку фонотеки, туда же потом лягут загруженные треки.
        if parent == DROP_MUSIK_ID or (parent or "").startswith("mf_"):
            inside = "" if parent == DROP_MUSIK_ID else parent[3:]
            with music_lock:
                if inside and inside not in music_folders:
                    inside = ""
                if music_folder_depth(inside) >= MUSIC_MAX_DEPTH:
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
        if size > DROP_MAX_SIZE:
            return jsonify(error="Файл больше 2 ГБ."), 413

        upload_id = str(uuid.uuid4())
        music_target = parent == DROP_MUSIK_ID or (parent or "").startswith("mf_")
        music_used = music_used_safe()        # музыка тоже в общем лимите 30 ГБ
        with drop_lock:
            drop_sweep_uploads()
            # MUSIK и папки внутри неё — приёмник фонотеки, а не склад дропа
            if not music_target and parent and drop_items.get(parent, {}).get("kind") != "folder":
                parent = None
            reserved = sum(u["size"] for u in drop_uploads.values())
            if drop_used() + music_used + reserved + size > DROP_QUOTA:
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
        if parent_in == DROP_MUSIK_ID or parent_in.startswith("mf_"):
            return drop_music_take(tmp_path, upload["name"], actual,
                                   "" if parent_in == DROP_MUSIK_ID else parent_in[3:])

        item_id = str(uuid.uuid4())
        music_used = music_used_safe()        # музыка тоже в общем лимите 30 ГБ
        with drop_lock:
            if drop_used() + music_used + actual > DROP_QUOTA:
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
        if parent == DROP_MUSIK_ID or (parent or "").startswith("mf_"):
            try:
                return drop_music_view(parent)
            except Exception:                                   # noqa: BLE001
                current_app.logger.exception("MUSIK: не собрал список фонотеки")
                return jsonify(items=[], breadcrumbs=[{"id": DROP_MUSIK_ID, "name": "MUSIK"}],
                               used=0, quota=DROP_QUOTA, trash=0, music_view=True,
                               warn="Фонотека сейчас не читается.")
        music_bytes = music_used_safe()        # музыка делит хранилище с дропом
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
                        # Подмена веса — только для MUSIK: она показывает фонотеку,
                        # а не свои файлы (внутри неё вообще нет настоящих drop_items,
                        # _drop_folder_stats насчитал бы 0). Другие особые папки
                        # (Download) — обычные папки дропа, их вес уже посчитан
                        # выше как у всех, трогать не нужно. Если фонотека вдруг
                        # не читается — не повод ронять весь список файлов, просто
                        # оставляем прежние цифры.
                        if k == DROP_MUSIK_ID:
                            try:
                                with music_lock:
                                    row["size"] = music_used()
                                    row["count"] = len(music_items)
                            except Exception:                       # noqa: BLE001
                                current_app.logger.exception("MUSIK: не посчитал фонотеку")
                items.append(row)
            # Сначала новые, но особая папка (MUSIK) всегда падает в самый низ.
            # Сортировка устойчивая: сперва по свежести, затем особые — вниз.
            items.sort(key=lambda x: -x["touched"])
            items.sort(key=lambda x: bool(x.get("special")))
            return jsonify(
                items=items,
                breadcrumbs=drop_path_to_root(parent),
                used=drop_used() + music_bytes,
                music=music_bytes,
                quota=DROP_QUOTA,
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
                            chunk = src.read(DROP_ZIP_CHUNK)
                            if not chunk:
                                break
                            dst.write(chunk)
                            if sink.held >= DROP_ZIP_CHUNK:
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
        icon = payload.get("icon") if payload.get("icon") in DROP_FOLDER_ICONS else None
        with drop_lock:
            item = drop_items.get(item_id)
            if not item:
                return jsonify(error="Не найдено."), 404
            if name:
                if item.get("special") and name != item["name"]:
                    return jsonify(error="Особую папку нельзя переименовать."), 400
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
        if op not in DROP_OPS:
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
                DROP_OPS[op](job_id, ids, target)
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
        return (html.replace("__ICONLINKS__", ICON_LINKS)
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
                           used=drop_used(), quota=DROP_QUOTA, ttl_days=30)

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
                           used=drop_used(), quota=DROP_QUOTA)

    @drop_bp.get("/drop")
    @login_required
    def drop_page():
        html = template("drop.html")
        return html.replace("__ICONLINKS__", ICON_LINKS)

    return drop_bp
