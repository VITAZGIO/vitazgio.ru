"""blueprints/ai.py — «Нейронки» /neuro + /ai (чаты через OpenRouter),
страница /claude (задача 37, docs/structure-plan.md).

Как и debts.py/notebook.py: данные (`ai_data`, `ai_lock`) и вся логика
(SSE-стриминг, хранение картинок/PDF, подбор рабочей бесплатной модели)
переехали на модульный уровень сюда же — блок был полностью
самодостаточен в app.py, ничего из него не читал никто другой.

`claude_ready`/`claude_host_name`/`claude_dir` остаются параметрами
фабрики: это часть `/ws/claude` (SSH/tmux через paramiko), которая живёт
в `blueprints/remote.py` и пока не переехала (задача 38) — трогать
раньше времени рискованно, откладываем.

Самое хрупкое место: `ai_run_stream()` — SSE-генератор, который при
обрыве соединения кнопкой «Стоп» получает `GeneratorExit` прямо на
текущем `yield`; `finally` внутри `gen()` всё равно досохраняет частичный
ответ через `save_once()`, иначе история чата разъедется с тем, что
человек увидел на экране. Перенесено дословно — не трогать эту часть без
теста `test_ai.py::test_stop_saves_partial_reply`.
"""

import base64
import io
import json
import os
import re
import threading
import time
import uuid

from flask import Blueprint, Response, g, jsonify, request, send_file

from core.auth import SSH_GATE_PASSWORD_PREFIX, login_required
from core.storage import DATA_DIR
from core.templates import template
from blueprints.pwa import ICON_LINKS

# ---- Нейросеть: чат с DeepSeek через OpenRouter ---------------------------
# Отдельная страница-чат в кабинете. В отличие от Себастьяна (тот крутится
# дома на видеокарте и потому один на всех), эта модель живёт в облаке
# OpenRouter — дома ничего не грузит, видеопамять свободна. OpenRouter говорит
# на языке OpenAI, так что запрос простой. Историю держит сам сайт: рядом с
# блокнотом, под паролем кабинета. Между запросами ни OpenRouter, ни DeepSeek
# ничего не помнят — весь разговор шлём заново каждый раз.
OPENROUTER_KEY = os.environ.get("OPENROUTER_KEY", "").strip()
OPENROUTER_URL = os.environ.get(
    "OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions").strip()
OPENROUTER_MODEL = os.environ.get(
    "OPENROUTER_MODEL", "deepseek/deepseek-chat-v3.1:free").strip()
# OpenRouter время от времени переименовывает и снимает с раздачи бесплатные
# модели DeepSeek. Держим короткий список запасных: если основная вернула
# 404, сервер сам пойдёт по списку и запомнит рабочую до перезапуска.
# Известные рабочие бесплатные модели на разных провайдерах: держим их как
# первый эшелон, если из .env ничего не задано. Список пополняется живым
# ответом от /api/v1/models — тем моделям, у которых prompt/completion == 0.
OPENROUTER_FALLBACKS = [
    "minimax/minimax-m3:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "openrouter/auto",                    # роутер сам выберет живую бесплатную
    "qwen/qwen3-coder:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "google/gemma-3-27b-it:free",
    "google/gemma-2-9b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "openai/gpt-oss-120b:free",
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-chat-v3.1:free",   # вдруг вернутся
    "deepseek/deepseek-r1:free",
]
_ai_active_model = OPENROUTER_MODEL
ai_active_lock = threading.Lock()
_ai_discovered = []            # что вернул /models на прошлом запросе
_ai_discovered_at = 0
_AI_DISCOVER_TTL = 900          # секунд между обращениями к каталогу


def _ai_discover():
    """Смотрит каталог OpenRouter и запоминает id всех бесплатных моделей."""
    global _ai_discovered, _ai_discovered_at
    if not OPENROUTER_KEY:
        return []
    if time.time() - _ai_discovered_at < _AI_DISCOVER_TTL and _ai_discovered:
        return _ai_discovered
    from urllib import request as urlrequest, error as urlerror
    base = OPENROUTER_URL.rsplit("/chat/completions", 1)[0]
    req = urlrequest.Request(base + "/models",
                             headers={"Authorization": "Bearer " + OPENROUTER_KEY})
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urlerror.URLError, ValueError, OSError):
        return _ai_discovered
    free = []
    for m in data.get("data", []):
        pr = m.get("pricing") or {}
        try:
            if float(pr.get("prompt", 0)) == 0 and float(pr.get("completion", 0)) == 0:
                mid = m.get("id")
                if mid:
                    free.append(mid)
        except (TypeError, ValueError):
            continue
    if free:
        _ai_discovered = free
        _ai_discovered_at = time.time()
    return _ai_discovered


def _ai_models_to_try(primary):
    """Порядок: сначала указанная (из .env или прошлая удачная), затем
    живой каталог бесплатных, потом наши запасные, без повторов."""
    seen, order = set(), []
    def add(m):
        if m and m not in seen:
            seen.add(m); order.append(m)
    add(primary)
    for m in _ai_discover():
        add(m)
    for m in OPENROUTER_FALLBACKS:
        add(m)
    return order
# Vision-модель отдельно: у бесплатного DeepSeek картинок нет, поэтому фото
# уходит той модели, что назвал хозяин здесь. Пусто — кнопка фото прячется.
OPENROUTER_VISION_MODEL = os.environ.get("OPENROUTER_VISION_MODEL", "").strip()

AI_CHAT_PATH = os.path.join(DATA_DIR, "aichat.json")
AI_IMG_DIR = os.path.join(DATA_DIR, "aichat_img")
AI_TEXT_MAX = 8000
AI_CTX_MSGS = 16            # сколько последних реплик отдаём модели
AI_CHATS_MAX = 200         # столько чатов храним, старше — выкидываем
AI_MSGS_MAX = 600          # столько реплик на чат
AI_REPLY_TOKENS = 1400
AI_TIMEOUT = 120
AI_IMG_MAX = 4 * 1024 * 1024
AI_IMG_COUNT_MAX = 6                # столько фото за одну реплику
AI_PDF_MAX = 8 * 1024 * 1024        # исходный файл
AI_PDF_TEXT_MAX = 6000              # столько текста из PDF отдаём модели
AI_SYS_PROMPT = ("Ты дружелюбный и толковый собеседник на личном сайте. "
                 "Отвечай по-русски, живо и по делу. Просят код — давай рабочий "
                 "и с коротким пояснением.")

os.makedirs(AI_IMG_DIR, exist_ok=True)
ai_data: dict = {"chats": [], "folders": []}
ai_lock = threading.Lock()
AI_FOLDERS_MAX = 40


def _ai_load():
    try:
        with open(AI_CHAT_PATH, encoding="utf-8") as fh:
            saved = json.load(fh) or {}
        ai_data["chats"] = saved.get("chats", [])
        ai_data["folders"] = saved.get("folders", [])
    except (OSError, ValueError):
        pass
    for c in ai_data["chats"]:
        c.setdefault("folder", "")


def ai_write():
    """Вызывать под ai_lock."""
    try:
        tmp = AI_CHAT_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ai_data, fh, ensure_ascii=False)
        os.replace(tmp, AI_CHAT_PATH)
    except OSError:
        pass


_ai_load()


def ai_ready():
    return bool(OPENROUTER_KEY)


def ai_find(chat_id):
    for c in ai_data["chats"]:
        if c.get("id") == chat_id:
            return c
    return None


def ai_card(c):
    return {"id": c["id"], "title": c.get("title") or "Новый чат",
            "updated": c.get("updated", 0), "count": len(c.get("messages", [])),
            "model": c.get("model", OPENROUTER_MODEL), "folder": c.get("folder", ""),
            "pinned": bool(c.get("pinned"))}


def _ai_wants_reasoning(model_id):
    """Показ размышлений просим только у моделей, которые их реально умеют
    (MiniMax, NVIDIA/Nemotron) — остальным лишний параметр может не
    понравиться, а откатной список моделей общий для всех сетей."""
    return bool(re.search(r"minimax|nemotron|nvidia", model_id or "", re.I))


def ai_smart_title(text):
    """Короткий заголовок из первой реплики: без markdown-мусора, обрезан по
    границе слова, а не насрединеслова."""
    t = re.sub(r"[`*_#>\[\]]", "", (text or "")).strip()
    t = re.sub(r"\s+", " ", t)
    if not t:
        return ""
    if len(t) <= 60:
        return t
    cut = t[:60]
    sp = cut.rfind(" ")
    if sp > 30:
        cut = cut[:sp]
    return cut.strip() + "…"


def ai_pdf_extract(raw):
    """Вытаскивает текст из PDF для моделей без своего PDF-чтения. Ограничено
    по длине — иначе один документ съест весь контекст разговора."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        parts, total = [], 0
        for page in reader.pages:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            if t:
                parts.append(t)
                total += len(t)
            if total >= AI_PDF_TEXT_MAX:
                break
        text = "\n".join(parts).strip()
        if len(text) > AI_PDF_TEXT_MAX:
            text = text[:AI_PDF_TEXT_MAX].rstrip() + "…[обрезано]"
        return text
    except Exception:
        return ""


def ai_find_folder(fid):
    for f in ai_data["folders"]:
        if f.get("id") == fid:
            return f
    return None


def ai_img_path(img_id):
    return os.path.join(AI_IMG_DIR, img_id)


def ai_store_image(data_url):
    """Разбирает data:image-URL, сохраняет файл на диск, возвращает
    (id, base64) или (None, None), если картинка кривая/слишком большая."""
    m = re.match(r"^data:image/(?:png|jpe?g|webp);base64,(.+)$", data_url or "", re.I)
    if not m:
        return None, None
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:                                        # noqa: BLE001
        return None, None
    if not raw or len(raw) > AI_IMG_MAX:
        return None, None
    img_id = uuid.uuid4().hex[:16] + ".jpg"
    try:
        with open(ai_img_path(img_id), "wb") as fh:
            fh.write(raw)
    except OSError:
        return None, None
    return img_id, base64.b64encode(raw).decode("ascii")


def ai_msg_imgs(m):
    """Все id картинок сообщения — новый список imgs плюс старое одиночное img."""
    ids = list(m.get("imgs") or [])
    if m.get("img") and m["img"] not in ids:
        ids.append(m["img"])
    return ids


def ai_drop_images(chat):
    for m in chat.get("messages", []):
        for iid in ai_msg_imgs(m):
            try:
                os.remove(ai_img_path(iid))
            except OSError:
                pass


def sse(obj):
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


def _ai_http_error(code):
    if code == 429:
        return ("Дневной лимит бесплатных запросов исчерпан. "
                "Приходите позже или смените модель в .env.")
    if code == 401:
        return "OpenRouter не принял ключ — проверьте OPENROUTER_KEY."
    if code == 402:
        return "На счету OpenRouter не хватает средств для этой модели."
    return f"OpenRouter вернул ошибку {code}."


def ai_run_stream(chat_id, ctx, use_vision, imgs_b64, requested_model, model):
    """Строит сообщения для OpenRouter и возвращает функцию-генератор SSE.
    Общий код для отправки нового сообщения и для «Перегенерировать».

    Если клиент оборвал соединение (кнопка «Стоп»), генератор получает
    GeneratorExit прямо на текущем yield — ловим это в finally и всё равно
    сохраняем то, что успели получить: иначе после «Стоп» история чата
    разъезжалась бы с тем, что человек реально увидел на экране."""
    api_msgs = [{"role": "system", "content": AI_SYS_PROMPT}]
    last = ctx[-1] if ctx else None
    for msg in ctx:
        if msg is last and use_vision and imgs_b64:
            content = []
            if msg.get("text"):
                content.append({"type": "text", "text": msg["text"]})
            for b64 in imgs_b64:
                content.append({"type": "image_url", "image_url": {
                    "url": "data:image/jpeg;base64," + b64}})
            api_msgs.append({"role": "user", "content": content})
        else:
            body = msg.get("text", "")
            if msg.get("pdf_text"):
                # PDF когда-то приложили к этой реплике — модель без своего
                # чтения PDF получает вытащенный текст прямо в сообщении,
                # так разговор про документ продолжается и на следующих ходах.
                body = (f"[Файл: {msg.get('pdf_name') or 'документ.pdf'}]\n"
                        f"{msg['pdf_text']}\n\n{body}").strip()
            if not body and ai_msg_imgs(msg):
                body = "[фото]"
            api_msgs.append({"role": msg.get("role", "user"), "content": body})

    def _body_for(candidate):
        body = {"model": candidate, "messages": api_msgs, "stream": True,
                "max_tokens": AI_REPLY_TOKENS}
        # Показ размышлений просим только у моделей, которые их реально
        # умеют (MiniMax, NVIDIA/Nemotron) — остальным лишний параметр
        # может не понравиться, а откатной список моделей общий.
        if _ai_wants_reasoning(candidate):
            body["reasoning"] = {"enabled": True}
        return json.dumps(body).encode("utf-8")

    req_body = _body_for(model)

    def save_reply(full, used_model, reasoning="", reasoning_secs=0):
        with ai_lock:
            cc = ai_find(chat_id)
            if cc is not None:
                msg = {"role": "assistant", "text": full, "model": used_model, "ts": time.time()}
                if reasoning:
                    msg["reasoning"] = reasoning
                    msg["reasoning_secs"] = reasoning_secs
                cc.setdefault("messages", []).append(msg)
                cc["updated"] = time.time()
                ai_write()

    def gen():
        global _ai_active_model
        from urllib import request as urlrequest, error as urlerror
        headers = {"Authorization": "Bearer " + OPENROUTER_KEY,
                   "Content-Type": "application/json",
                   "HTTP-Referer": "https://vitazgio.ru",
                   "X-Title": "vitazgio.ru"}
        # Vision-запрос идёт на свою модель без замены. У обычного —
        # пробуем список: если основная 404, следующая; удачную запомним.
        with ai_active_lock:
            primary = _ai_active_model if not use_vision else model
        if requested_model:
            # Вкладка назвала свою модель. Ставим её первой, но если она
            # молчит — дальше по общему списку, чтобы чат не встал колом.
            candidates = _ai_models_to_try(requested_model)
        elif use_vision:
            candidates = [model]
        else:
            candidates = _ai_models_to_try(primary)
        resp = None
        chosen = candidates[0]
        for candidate in candidates:
            body_try = req_body if candidate == model else _body_for(candidate)
            req = urlrequest.Request(OPENROUTER_URL, data=body_try, headers=headers)
            try:
                resp = urlrequest.urlopen(req, timeout=AI_TIMEOUT)
                chosen = candidate
                break
            except urlerror.HTTPError as e:
                detail = ""
                try:
                    body = json.loads(e.read().decode("utf-8", "replace"))
                    detail = ((body.get("error") or {}).get("message") or "").strip()
                except Exception:
                    pass
                # 400/402/404/429 — модель переименовали, сняли или упёрлись
                # в лимит: пробуем следующую из списка, пока они есть.
                if e.code in (400, 402, 404, 429) and candidate != candidates[-1]:
                    continue
                msg_txt = _ai_http_error(e.code) + f" (модель {candidate})"
                if detail:
                    msg_txt += " — " + detail[:200]
                yield sse({"error": msg_txt})
                return
            except urlerror.URLError:
                yield sse({"error": "OpenRouter не отвечает. Попробуйте позже."})
                return
        if resp is None:
            yield sse({"error": "Ни одна из известных бесплатных моделей не ответила."})
            return
        if not use_vision and chosen != (requested_model or _ai_active_model):
            if not requested_model:
                with ai_active_lock:
                    _ai_active_model = chosen
            yield sse({"model": chosen})

        acc = []
        racc = []                      # текст размышлений (если модель умеет)
        think_start = time.time()
        think_secs = {"v": 0}
        content_started = {"v": False}
        saved = {"done": False}

        def save_once():
            if saved["done"]:
                return
            full = "".join(acc).strip()
            if full:
                saved["done"] = True
                save_reply(full, chosen, "".join(racc).strip(), think_secs["v"])

        try:
            for rawline in resp:
                line = rawline.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    obj = json.loads(chunk)
                except ValueError:
                    continue
                choices = obj.get("choices") or [{}]
                delta = choices[0].get("delta") or {}
                rtext = delta.get("reasoning") or delta.get("reasoning_content")
                if rtext:
                    racc.append(rtext)
                    yield sse({"reasoning": rtext})
                ctext = delta.get("content")
                if ctext:
                    if not content_started["v"]:
                        content_started["v"] = True
                        think_secs["v"] = round(time.time() - think_start, 1)
                    acc.append(ctext)
                    yield sse({"delta": ctext})
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass
            save_once()   # доходит и через «Стоп» (GeneratorExit), и штатно

        full = "".join(acc).strip()
        if full:
            yield sse({"done": True, "text": full})
        else:
            yield sse({"error": "Модель промолчала — попробуйте ещё раз."})

    return gen


def create_ai_blueprint(*, claude_ready, claude_host_name, claude_dir):
    ai_bp = Blueprint("ai", __name__)

    def current_openrouter_model():
        return OPENROUTER_MODEL

    def current_openrouter_vision_model():
        return OPENROUTER_VISION_MODEL

    @ai_bp.get("/api/claude/state")
    @login_required
    def claude_state_api():
        """Что показывать до подключения: настроена ли вкладка и на какой машине."""
        return jsonify(ready=claude_ready(),
                       host=claude_host_name() if claude_ready() else "",
                       gate=bool(SSH_GATE_PASSWORD_PREFIX),
                       dir=claude_dir)

    @ai_bp.get("/claude")
    @login_required
    def claude_page():
        """Разговор с Claude Code через сайт."""
        g.frameable = True
        html = template("claude.html")
        return html.replace("__ICONLINKS__", ICON_LINKS)

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
            active = _ai_active_model
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
            if len(ai_data["chats"]) > AI_CHATS_MAX:
                for old in ai_data["chats"][AI_CHATS_MAX:]:
                    ai_drop_images(old)
                del ai_data["chats"][AI_CHATS_MAX:]
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
            if len(ai_data["folders"]) >= AI_FOLDERS_MAX:
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
        text = (payload.get("text") or "").strip()[:AI_TEXT_MAX]
        images_in = payload.get("images")
        if not isinstance(images_in, list):
            images_in = [payload.get("image")] if payload.get("image") else []
        images_in = [x for x in images_in if x][:AI_IMG_COUNT_MAX]
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
                if raw and len(raw) <= AI_PDF_MAX:
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
            if len(c["messages"]) > AI_MSGS_MAX:
                for old in c["messages"][:-AI_MSGS_MAX]:
                    for iid in ai_msg_imgs(old):
                        try:
                            os.remove(ai_img_path(iid))
                        except OSError:
                            pass
                c["messages"] = c["messages"][-AI_MSGS_MAX:]
            ai_write()
            ctx = list(c["messages"][-AI_CTX_MSGS:])
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
            ctx = list(msgs[-AI_CTX_MSGS:])
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
        return html.replace("__ICONLINKS__", ICON_LINKS)

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
        return (html.replace("__ICONLINKS__", ICON_LINKS)
                    .replace("%%PRESET%%", _preset.replace("\"", "\\\""))
                    .replace("%%NET%%", _net))

    return ai_bp
