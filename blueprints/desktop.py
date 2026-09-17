"""Windows agents: device pairing, bounded WebRTC signalling, release discovery.

Video/audio/input never traverse this blueprint. A viewer must pass the same
cabinet + console gate as RDP. An agent token only controls its own sessions.
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
from functools import wraps

from flask import Blueprint, jsonify, request, session


def create_desktop_blueprint(*, template, icon_links, login_required, data_dir, repo):
    bp = Blueprint("desktop", __name__)
    lock = threading.RLock()
    path = os.path.join(data_dir, "desktop_devices.json")
    try:
        with open(path, encoding="utf-8") as f:
            devices = json.load(f)
    except (OSError, ValueError):
        devices = {}
    live, calls = {}, {}
    release_cache = {"at": 0, "value": None}
    ice_servers = json.loads(os.environ.get("DESKTOP_ICE_SERVERS", '[{"urls":"stun:stun.l.google.com:19302"}]'))

    @bp.before_request
    def limit_body():
        if request.content_length and request.content_length > 70000:
            return jsonify(error="Слишком большой запрос."), 413
        # The browser viewer sends Content-Type: application/json uniformly,
        # including on GET requests without a body.  A GET has no JSON payload
        # to validate, otherwise listing devices is rejected before its route.
        if request.method in {"POST", "PUT", "PATCH"} and request.is_json and not isinstance(request.get_json(silent=True), dict):
            return jsonify(error="Ожидается JSON-объект."), 400

    def save():
        os.makedirs(data_dir, exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(devices, f, ensure_ascii=False)
        os.replace(path + ".tmp", path)

    def agent_id():
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token or len(token) > 512:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with lock:
            return next((did for did, row in devices.items() if hmac.compare_digest(row["hash"], digest)), None)

    def viewer_required(fn):
        @login_required
        @wraps(fn)
        def inner(*args, **kwargs):
            if not session.get("console_authenticated"):
                return jsonify(error="Нужен суточный пароль консоли.", console_required=True), 403
            return fn(*args, **kwargs)
        return inner

    def expire():
        now = time.time()
        for cid, row in list(calls.items()):
            if now - row["seen"] > 25 or now - live.get(row["device"], {}).get("seen", 0) > 25:
                calls.pop(cid, None)

    @bp.get("/desktop")
    @login_required
    def desktop_page():
        return template("desktop.html").replace("__ICONLINKS__", icon_links)

    @bp.post("/api/desktop/register")
    @login_required
    def register():
        payload = request.get_json(silent=True) or {}
        token, did = secrets.token_urlsafe(32), secrets.token_hex(16)
        with lock:
            if len(devices) >= 32:
                return jsonify(error="Удалите неиспользуемые устройства (лимит 32)."), 409
            devices[did] = {"name": str(payload.get("name") or "Windows")[:80],
                            "hash": hashlib.sha256(token.encode()).hexdigest(), "created": time.time()}
            save()
        return jsonify(id=did, token=token)

    @bp.get("/api/desktop/devices")
    @login_required
    def device_list():
        with lock:
            expire()
            rows = [{"id": did, "name": row["name"], **live.get(did, {}),
                     "online": time.time() - live.get(did, {}).get("seen", 0) < 20}
                    for did, row in devices.items()]
        return jsonify(devices=rows)

    @bp.delete("/api/desktop/devices/<did>")
    @login_required
    def revoke(did):
        with lock:
            if devices.pop(did, None) is None:
                return jsonify(error="Устройство не найдено."), 404
            live.pop(did, None)
            for cid, row in list(calls.items()):
                if row["device"] == did:
                    calls.pop(cid, None)
            save()
        return jsonify(ok=True)

    @bp.post("/api/desktop/host")
    def host():
        did = agent_id()
        if not did:
            return jsonify(error="Токен устройства отозван. Войдите в кабинет заново."), 401
        payload = request.get_json(silent=True) or {}
        with lock:
            live[did] = {"seen": time.time(), "enabled": payload.get("enabled") is True,
                         "control": payload.get("control") is True,
                         "version": str(payload.get("version", ""))[:24]}
            expire()
            if not live[did]["enabled"]:
                for cid, row in list(calls.items()):
                    if row["device"] == did:
                        calls.pop(cid, None)
            active = [{"id": cid, "offer": row["offer"], "control": row["control"] and live[did]["control"]}
                      for cid, row in calls.items() if row["device"] == did]
        return jsonify(sessions=active, iceServers=ice_servers)

    @bp.post("/api/desktop/sessions")
    @viewer_required
    def create_session():
        payload = request.get_json(silent=True) or {}
        did, offer = payload.get("device"), payload.get("offer")
        if not isinstance(did, str) or not isinstance(offer, str) or not offer.startswith("v=0") or len(offer) > 65536:
            return jsonify(error="Некорректное предложение соединения."), 400
        with lock:
            expire()
            status = live.get(did, {})
            if did not in devices or not status.get("enabled") or time.time() - status.get("seen", 0) > 20:
                return jsonify(error="ПК не на связи или доступ выключен в приложении."), 409
            if any(row["device"] == did for row in calls.values()):
                return jsonify(error="К этому ПК уже подключён зритель."), 409
            owner = session.setdefault("desktop_viewer", secrets.token_hex(24))
            cid = secrets.token_hex(16)
            calls[cid] = {"device": did, "owner": owner, "offer": offer, "answer": None,
                          "control": payload.get("control") is True and status.get("control") is True,
                          "seen": time.time(), "error": None}
            return jsonify(id=cid, control=calls[cid]["control"])

    @bp.get("/api/desktop/config")
    @viewer_required
    def config():
        return jsonify(iceServers=ice_servers)

    def get_call(cid):
        # Call under lock; do not trust the caller's device id or a supplied role.
        expire()
        row = calls.get(cid)
        if not row:
            return None, False
        did = agent_id()
        is_host = bool(did and did == row["device"])
        is_viewer = (session.get("authenticated") and session.get("console_authenticated")
                     and session.get("desktop_viewer") == row["owner"])
        return (row if is_host or is_viewer else None), is_host

    @bp.get("/api/desktop/sessions/<cid>")
    def read_session(cid):
        with lock:
            row, is_host = get_call(cid)
            if not row:
                return jsonify(error="Соединение закрыто или нет доступа."), 404
            if not is_host:
                row["seen"] = time.time()
            return jsonify(answer=row["answer"], error=row["error"], control=row["control"])

    @bp.post("/api/desktop/sessions/<cid>")
    def answer_session(cid):
        if request.content_length and request.content_length > 70000:
            return jsonify(error="Слишком большой ответ."), 413
        payload = request.get_json(silent=True) or {}
        with lock:
            row, is_host = get_call(cid)
            if not row or not is_host:
                return jsonify(error="Соединение не найдено."), 404
            answer = payload.get("answer")
            if answer is not None and (not isinstance(answer, str) or not answer.startswith("v=0") or len(answer) > 65536):
                return jsonify(error="Некорректный ответ."), 400
            row["answer"] = answer
            row["error"] = str(payload["error"])[:250] if payload.get("error") else None
        return jsonify(ok=True)

    @bp.delete("/api/desktop/sessions/<cid>")
    def close_session(cid):
        with lock:
            row, _ = get_call(cid)
            if not row:
                return jsonify(error="Соединение не найдено."), 404
            calls.pop(cid, None)
        return jsonify(ok=True)

    @bp.get("/api/desktop/version")
    @login_required
    def version():
        if time.time() - release_cache["at"] < 60:
            return jsonify(release_cache["value"])
        url = f"https://api.github.com/repos/{repo}/releases?per_page=100"
        req = urllib.request.Request(url, headers={"User-Agent": "vitazgio.ru", "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                releases = json.load(response)
            found = []
            for release in releases:
                match = re.fullmatch(r"windows-v(\d+\.\d+\.\d+)", release.get("tag_name", ""))
                if not match or release.get("draft") or release.get("prerelease"):
                    continue
                ver = match[1]
                name = f"vitazgio-windows-{ver}-x64.exe"
                download = f"https://github.com/{repo}/releases/download/windows-v{ver}/{name}"
                asset = next((a for a in release.get("assets", []) if a.get("name") == name and a.get("browser_download_url") == download), None)
                if asset:
                    found.append({"version": ver, "url": download, "name": name})
            value = max(found, key=lambda row: tuple(map(int, row["version"].split("."))), default={"version": None, "url": None})
            release_cache.update(at=time.time(), value=value)
            return jsonify(value)
        except (urllib.error.URLError, OSError, ValueError, TypeError) as exc:
            return jsonify(error=f"Не удалось проверить сборку: {exc}"), 502

    return bp
