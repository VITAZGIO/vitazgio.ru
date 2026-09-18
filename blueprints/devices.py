"""blueprints/devices.py — вкладка кабинета «Запомнить устройства» (/devices).

Переведён на прямые импорты из core/ (задача 35, docs/structure-plan.md,
по образцу задачи 34/login_log.py). Все нужные примитивы — доверенные
устройства, суточный пароль консоли, ограничение частоты попыток, журнал
входов — уже в `core/auth.py` (перевезены сюда тем же разрезом: раньше
`login_required` тянул их за собой, и раз они всё равно там — блюпринт
берёт напрямую, а не через `app.py`).
"""

import hmac

from flask import Blueprint, g, jsonify, request

from blueprints.pwa import ICON_LINKS
from core.auth import (
    CONSOLE_LOGIN_MAX_ATTEMPTS,
    CONSOLE_LOGIN_WINDOW_SECONDS,
    DEVICE_COOKIE,
    SSH_GATE_PASSWORD_PREFIX,
    client_ip,
    console_login_attempts,
    console_login_attempts_lock,
    console_password_today,
    device_forget,
    device_issue,
    device_label,
    devices_lock,
    devices_prune_expired,
    devices_write,
    log_login,
    login_required,
    rate_blocked,
    rate_clear,
    rate_hit,
    trusted_devices,
    unique_label,
)
from core.templates import template


def create_devices_blueprint():
    devices_bp = Blueprint("devices", __name__)

    @devices_bp.get("/devices")
    @login_required
    def devices_page():
        return template("devices.html").replace("__ICONLINKS__", ICON_LINKS)

    @devices_bp.post("/api/devices/trust")
    @login_required
    def device_trust():
        if not SSH_GATE_PASSWORD_PREFIX:
            return jsonify(error="Суточный пароль не настроен на сервере."), 503

        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        password = (request.get_json(silent=True) or {}).get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), console_password_today().encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            log_login("неверный суточный пароль (доверие устройству)", kind="fail")
            return jsonify(error="Неверный суточный пароль."), 401

        rate_clear(console_login_attempts, console_login_attempts_lock, client)

        ua = request.headers.get("User-Agent", "")
        raw = request.cookies.get(DEVICE_COOKIE) or ""
        selector = raw.split(".", 1)[0] if "." in raw else None
        with devices_lock:
            devices_prune_expired()
            if selector not in trusted_devices:
                selector = None
            label = trusted_devices[selector]["label"] if selector else unique_label(device_label(ua))
            g.new_device_cookie = device_issue(label, ua, client_ip(), selector)
        return jsonify(ok=True, label=label)

    @devices_bp.get("/api/devices")
    @login_required
    def devices_list_api():
        current = (request.cookies.get(DEVICE_COOKIE) or "").split(".", 1)[0]
        with devices_lock:
            if devices_prune_expired():
                devices_write()
            items = [
                {"id": selector, "label": d["label"], "last_used": d["last_used"],
                 "last_ip": d.get("last_ip", ""), "created": d["created"],
                 "current": selector == current}
                for selector, d in sorted(trusted_devices.items(), key=lambda x: -x[1]["last_used"])
            ]
        return jsonify(items)

    @devices_bp.patch("/api/devices/<selector>")
    @login_required
    def device_rename_api(selector):
        label = ((request.get_json(silent=True) or {}).get("label") or "").strip()[:40]
        if not label:
            return jsonify(error="Пустое имя."), 400
        with devices_lock:
            if selector not in trusted_devices:
                return jsonify(error="Устройство не найдено."), 404
            trusted_devices[selector]["label"] = label
            devices_write()
        return jsonify(ok=True, label=label)

    @devices_bp.delete("/api/devices/<selector>")
    @login_required
    def device_forget_api(selector):
        removed = device_forget(selector)
        if removed and (request.cookies.get(DEVICE_COOKIE) or "").split(".", 1)[0] == selector:
            g.clear_device_cookie = True
        return jsonify(ok=True)

    return devices_bp
