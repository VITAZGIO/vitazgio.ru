import hmac

from flask import Blueprint, g, jsonify, request


def create_devices_blueprint(
    *,
    template,
    icon_links,
    login_required,
    device_cookie,
    devices_lock,
    trusted_devices,
    devices_prune_expired,
    devices_write,
    unique_label,
    device_label,
    device_issue,
    device_forget,
    ssh_gate_password_prefix,
    console_password_today,
    client_ip,
    rate_blocked,
    rate_hit,
    rate_clear,
    console_login_attempts,
    console_login_attempts_lock,
    console_login_window_seconds,
    console_login_max_attempts,
    log_login,
):
    devices_bp = Blueprint("devices", __name__)

    @devices_bp.get("/devices")
    @login_required
    def devices_page():
        return template("devices.html").replace("__ICONLINKS__", icon_links)

    @devices_bp.post("/api/devices/trust")
    @login_required
    def device_trust():
        if not ssh_gate_password_prefix:
            return jsonify(error="Суточный пароль не настроен на сервере."), 503

        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        console_login_window_seconds, console_login_max_attempts):
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
        raw = request.cookies.get(device_cookie) or ""
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
        current = (request.cookies.get(device_cookie) or "").split(".", 1)[0]
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
        if removed and (request.cookies.get(device_cookie) or "").split(".", 1)[0] == selector:
            g.clear_device_cookie = True
        return jsonify(ok=True)

    return devices_bp
