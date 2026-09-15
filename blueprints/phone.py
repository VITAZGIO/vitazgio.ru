"""Ретранслятор телефона — ступень 1: только «жив или нет».

Телефон не может принимать входящие: у оператора CGNAT, своего адреса в
интернете у него нет (подробно — `docs/phone-access-plan.md`, разделы 2-3).
Поэтому соединение всегда исходящее: телефон сам приходит сюда вебсокетом
и держит его открытым, а сайт только отмечает, что он жив.

Больше здесь пока ничего нет и быть не должно: ни экрана, ни файлов. Смысл
ступени — выяснить одну вещь, не убьёт ли оболочка HiOS это соединение за
ночь. Если убьёт, всё, что легло бы сверху, пришлось бы разбирать обратно.

Реестр живых агентов — обычный словарь в памяти процесса. Это законно:
сайт однопроцессный (`app.run(threaded=True)`), ровно так же живут
`netbird_status` в `app.py` и пул SFTP-соединений в `blueprints/files.py`.

Ступень 2 добавила сюда **токены устройств**: приложение больше не просит
вбить общий пароль руками — хозяин заходит в кабинет внутри оболочки, и
страница сама выдаёт устройству личный токен (`/api/phone/token`), а JS-мост
кладёт его в `EncryptedSharedPreferences`. Отозвать такой токен можно с
сайта поштучно, не меняя общий пароль всем сразу. На диске лежат только
хэши (sha256) — как у пароля корзины дропа: утечка файла доступа не даёт.
Общий `PHONE_AGENT_TOKEN` из `.env` при этом никуда не делся: он запасной
путь на случай, если войти в кабинет с телефона почему-то не выходит.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from flask import Blueprint, jsonify, request, send_file, session

AGENT_HELLO_TIMEOUT = 15     # столько ждём первое сообщение с токеном
AGENT_PING_SECONDS = 25      # молчит столько — сами шлём ping
AGENT_STALE_SECONDS = 60     # молчит дольше — считаем офлайн и выкидываем
AGENT_SWEEP_SECONDS = 10     # как часто дворник проверяет протухших
AGENT_EVENTS_MAX = 60        # хвост журнала: кто когда пришёл и когда отвалился
DEVICE_TOKEN_BYTES = 32      # длина личного токена устройства
DEVICE_LABEL_MAX = 64

# Версия сборки — число в имени файла (`vg-agent-7.apk` → 7). Так же его
# видит приложение при самообновлении: больше номер — есть что ставить.
APK_VERSION_RE = re.compile(r"(\d+)")
APK_PULL_MAX = 200 * 1024 * 1024   # потолок на скачивание релиза, чтобы не залить диск


def create_phone_blueprint(
    *,
    sock,
    login_required,
    agent_token,
    agent_ip,
    publish_status,
    apk_dir,
    apk_repo,
    tokens_path,
):
    phone_bp = Blueprint("phone", __name__)

    # conn_id -> {"name", "version", "peer", "connected", "last_seen"}
    agents = {}
    agents_lock = threading.Lock()
    events = []                  # хвост событий для отладки ночного теста

    def _log(text):
        with agents_lock:
            events.append({"at": time.time(), "text": text})
            del events[:-AGENT_EVENTS_MAX]

    def _snapshot_locked():
        deadline = time.time() - AGENT_STALE_SECONDS
        alive = [a for a in agents.values() if a["last_seen"] > deadline]
        last_seen = max((a["last_seen"] for a in agents.values()), default=None)
        return {
            "online": bool(alive),
            "last_seen": last_seen,
            "agents": sorted(alive, key=lambda a: a["connected"]),
            "events": list(reversed(events)),
        }

    def _snapshot():
        with agents_lock:
            return _snapshot_locked()

    def _publish():
        """Отдать состояние наружу — в `netbird_status`, откуда его берёт
        `/api/netbird/status` и красит строку MOBILA на `/netbird`."""
        snapshot = _snapshot()
        publish_status(snapshot["online"], snapshot["last_seen"])

    def _sweeper():
        """Агент мог не попрощаться: телефон уехал в тоннель, оболочка убила
        процесс. Молчащую запись выкидываем сами, иначе MOBILA висела бы
        «онлайн» до перезапуска сайта."""
        while True:
            time.sleep(AGENT_SWEEP_SECONDS)
            deadline = time.time() - AGENT_STALE_SECONDS
            with agents_lock:
                stale = [cid for cid, a in agents.items() if a["last_seen"] <= deadline]
                for cid in stale:
                    agents.pop(cid, None)
            for cid in stale:
                _log("агент молчал дольше минуты — офлайн")
            if stale:
                _publish()

    threading.Thread(target=_sweeper, daemon=True).start()

    # ---- Токены устройств ------------------------------------------------
    # Файл переживает перезапуск сайта: телефон держит свой токен у себя, и
    # после деплоя сервер обязан его узнать. На диске — только хэши.

    devices = {}                 # token_id -> {"label", "hash", "created", "last_used"}
    devices_lock = threading.Lock()

    def _devices_load():
        try:
            with open(tokens_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            for token_id, row in data.items():
                if isinstance(row, dict) and row.get("hash"):
                    devices[str(token_id)] = {
                        "label": str(row.get("label") or "телефон")[:DEVICE_LABEL_MAX],
                        "hash": str(row["hash"]),
                        "created": float(row.get("created") or 0),
                        "last_used": float(row.get("last_used") or 0) or None,
                    }

    def _devices_write_locked():
        os.makedirs(os.path.dirname(tokens_path), exist_ok=True)
        tmp = tokens_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(devices, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, tokens_path)

    _devices_load()

    def _hash(raw):
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _device_match(candidate):
        """id устройства, чей это токен, или None. Сравнение — по хэшам и
        через compare_digest: обычное `==` на строках выходит из сравнения на
        первом же несовпавшем символе и тем выдаёт длину общего начала."""
        if not isinstance(candidate, str) or not candidate:
            return None
        digest = _hash(candidate)
        with devices_lock:
            for token_id, row in devices.items():
                if hmac.compare_digest(digest, row["hash"]):
                    return token_id
        return None

    def _token_ok(candidate):
        """Пускаем и по общему паролю из .env, и по личному токену устройства."""
        if not isinstance(candidate, str) or not candidate:
            return False
        if agent_token:
            # Сравниваем байтами: compare_digest на строках с кириллицей (а
            # токен мог быть набран каким угодно) падает TypeError, а не
            # отвечает «нет».
            if hmac.compare_digest(candidate.encode("utf-8"), str(agent_token).encode("utf-8")):
                return True
        return _device_match(candidate) is not None

    def handle_agent(ws, peer=""):
        """Весь разговор с телефоном. Вынесено из роута отдельной функцией:
        так её зовёт тест с фальшивым сокетом, не поднимая сети."""
        try:
            raw = ws.receive(timeout=AGENT_HELLO_TIMEOUT)
        except Exception:
            return
        try:
            hello = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            hello = {}
        if not isinstance(hello, dict) or hello.get("type") != "hello" or not _token_ok(hello.get("token")):
            _log(f"отказ в подключении ({peer or 'адрес неизвестен'})")
            try:
                ws.close()
            except Exception:
                pass
            return

        # Пришёл по личному токену — отмечаем, что устройство на связи. По
        # этой отметке на сайте видно, какой из выданных токенов живой, а
        # какой можно отзывать.
        device_id = _device_match(hello.get("token"))
        if device_id:
            with devices_lock:
                row = devices.get(device_id)
                if row:
                    row["last_used"] = time.time()
                    _devices_write_locked()

        conn_id = secrets.token_hex(8)
        now = time.time()
        entry = {
            "name": str(hello.get("agent") or "агент")[:64],
            "version": hello.get("version") if isinstance(hello.get("version"), int) else None,
            "peer": peer,
            "connected": now,
            "last_seen": now,
        }
        with agents_lock:
            agents[conn_id] = entry
        _log(f"агент на связи: {entry['name']}")
        _publish()

        try:
            ws.send(json.dumps({
                "type": "hello-ok",
                "ping": AGENT_PING_SECONDS,
                "stale": AGENT_STALE_SECONDS,
            }))
        except Exception:
            pass

        try:
            while True:
                try:
                    message = ws.receive(timeout=AGENT_PING_SECONDS)
                except Exception:
                    break
                now = time.time()
                if message is None:
                    # Тишина в канале сама по себе ничего не значит: телефон
                    # мог просто молчать. Дёргаем ping — вот его молчание в
                    # ответ уже и есть смерть соединения.
                    if now - entry["last_seen"] > AGENT_STALE_SECONDS:
                        break
                    try:
                        ws.send(json.dumps({"type": "ping", "t": int(now)}))
                    except Exception:
                        break
                    continue
                entry["last_seen"] = now
                with agents_lock:
                    if conn_id not in agents:     # дворник успел выкинуть — возвращаем
                        agents[conn_id] = entry
                try:
                    payload = json.loads(message)
                except (TypeError, ValueError):
                    continue
                if isinstance(payload, dict) and payload.get("type") == "ping":
                    try:
                        ws.send(json.dumps({"type": "pong", "t": payload.get("t")}))
                    except Exception:
                        break
        finally:
            with agents_lock:
                agents.pop(conn_id, None)
            _log(f"агент отключился: {entry['name']}")
            _publish()
            try:
                ws.close()
            except Exception:
                pass

    @sock.route("/ws/agent", bp=phone_bp)
    def agent_ws(ws):
        handle_agent(ws, peer=request.headers.get("X-Forwarded-For", "") or (request.remote_addr or ""))

    @phone_bp.get("/api/phone/agent")
    @login_required
    def phone_agent_api():
        snapshot = _snapshot()
        snapshot["ip"] = agent_ip
        snapshot["configured"] = bool(agent_token)
        return jsonify(snapshot)

    @phone_bp.get("/api/phone/token")
    @login_required
    def phone_token_issue():
        """Выдать этому устройству личный токен.

        Зовёт JS-мост оболочки, когда хозяин уже вошёл в кабинет внутри
        приложения, — потому руками токен больше не вбивают. Секрет уходит
        в ответе один-единственный раз: на диске остаётся только хэш, и
        показать его заново неоткуда."""
        raw = secrets.token_urlsafe(DEVICE_TOKEN_BYTES)
        payload = request.get_json(silent=True) or {}
        label = str(payload.get("label") or request.args.get("label") or "телефон")
        token_id = secrets.token_hex(8)
        with devices_lock:
            devices[token_id] = {
                "label": label[:DEVICE_LABEL_MAX],
                "hash": _hash(raw),
                "created": time.time(),
                "last_used": None,
            }
            _devices_write_locked()
        _log(f"выдан токен устройству: {label[:DEVICE_LABEL_MAX]}")
        return jsonify(id=token_id, token=raw)

    @phone_bp.get("/api/phone/tokens")
    @login_required
    def phone_tokens_api():
        with devices_lock:
            rows = [
                {"id": token_id, "label": row["label"],
                 "created": row["created"], "last_used": row["last_used"]}
                for token_id, row in devices.items()
            ]
        rows.sort(key=lambda r: r["created"], reverse=True)
        return jsonify(tokens=rows)

    @phone_bp.delete("/api/phone/token/<token_id>")
    @login_required
    def phone_token_revoke(token_id):
        """Отзыв поштучный и с сайта — в этом весь смысл личных токенов.
        Общий пароль из .env менять ради одного потерянного телефона не
        придётся."""
        with devices_lock:
            row = devices.pop(token_id, None)
            if row:
                _devices_write_locked()
        if not row:
            return jsonify(error="Такого токена нет."), 404
        _log(f"токен отозван: {row['label']}")
        return jsonify(ok=True)

    # ---- Раздача сборки --------------------------------------------------
    # APK лежит не в образе, а в `data/apk` рядом с остальными данными: тот
    # же примонтированный каталог, что у дропа и фонотеки, — переживает
    # пересборку контейнера. Собирает его отдельный workflow и кладёт в
    # релиз; на VPS сборка приезжает кнопкой «подтянуть» (ниже).

    def _apk_pick():
        """Самая свежая сборка: (путь, номер версии) или (None, 0)."""
        try:
            names = [n for n in os.listdir(apk_dir) if n.lower().endswith(".apk")]
        except OSError:
            return None, 0
        best, best_version, best_mtime = None, 0, 0.0
        for name in names:
            path = os.path.join(apk_dir, name)
            digits = APK_VERSION_RE.findall(name)
            version = int(digits[-1]) if digits else 0
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if (version, mtime) > (best_version, best_mtime):
                best, best_version, best_mtime = path, version, mtime
        return best, best_version

    def _version_payload():
        path, version = _apk_pick()
        if not path:
            return {"version": 0, "url": None, "name": None, "size": 0, "updated": None}
        return {
            "version": version,
            "url": "/app",
            "name": os.path.basename(path),
            "size": os.path.getsize(path),
            "updated": os.path.getmtime(path),
        }

    @phone_bp.get("/app")
    @login_required
    def app_apk():
        path, _version = _apk_pick()
        if not path:
            return jsonify(error="Сборки ещё нет — собери её workflow'ом android.yml "
                                 "и нажми «подтянуть» на /api/app/pull."), 404
        return send_file(path, as_attachment=True,
                         download_name=os.path.basename(path),
                         mimetype="application/vnd.android.package-archive")

    @phone_bp.get("/api/app/version")
    def app_version_api():
        # Пускаем и хозяина из браузера, и сам телефон по токену агента:
        # самообновлению неоткуда взять куку сессии.
        header_token = request.headers.get("X-Agent-Token")
        if not session.get("authenticated") and not _token_ok(header_token):
            return jsonify(error="Нужен вход или токен агента."), 403
        return jsonify(_version_payload())

    @phone_bp.post("/api/app/pull")
    @login_required
    def app_pull_api():
        """Забрать свежий APK из последнего релиза репозитория.

        Иначе сборку пришлось бы каждый раз руками копировать на VPS: собирает
        её облачный раннер, а раздаёт сайт из Амстердама, и общего диска у них
        нет. Репозиторий публичный, поэтому токен не нужен."""
        api = f"https://api.github.com/repos/{apk_repo}/releases/latest"
        try:
            request_obj = urllib.request.Request(api, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "vitazgio.ru",
            })
            with urllib.request.urlopen(request_obj, timeout=15) as resp:
                release = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            return jsonify(error=f"Не удалось спросить GitHub: {exc}"), 502

        asset = next((a for a in release.get("assets", [])
                      if str(a.get("name", "")).lower().endswith(".apk")), None)
        if not asset:
            return jsonify(error="В последнем релизе нет ни одного .apk."), 404
        if int(asset.get("size") or 0) > APK_PULL_MAX:
            return jsonify(error="Сборка подозрительно большая — не качаю."), 413

        os.makedirs(apk_dir, exist_ok=True)
        name = os.path.basename(str(asset["name"]))
        target = os.path.join(apk_dir, name)
        tmp = target + ".part"
        try:
            asset_req = urllib.request.Request(asset["browser_download_url"],
                                               headers={"User-Agent": "vitazgio.ru"})
            with urllib.request.urlopen(asset_req, timeout=60) as resp, open(tmp, "wb") as out:
                written = 0
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > APK_PULL_MAX:
                        raise OSError("сборка больше разрешённого")
                    out.write(chunk)
            os.replace(tmp, target)
        except (urllib.error.URLError, OSError) as exc:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return jsonify(error=f"Не удалось скачать сборку: {exc}"), 502

        payload = _version_payload()
        payload["pulled"] = name
        return jsonify(payload)

    # Тестам нужен разговор с агентом без сети, а странице отладки — реестр.
    phone_bp.handle_agent = handle_agent
    phone_bp.agent_snapshot = _snapshot
    return phone_bp
