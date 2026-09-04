import hmac
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Blueprint, g, jsonify, request, session


def create_debts_blueprint(
    *,
    template,
    login_required,
    debts_owner_required,
    debtor_required,
    debts_lock,
    debts_data,
    debts_owner_unlocked,
    debts_snapshot_locked,
    debts_write_locked,
    debt_hash_password,
    debt_password_matches,
    debt_user_public_locked,
    debt_amount_cents,
    debt_clean_date,
    today_iso,
    password_matches,
    device_check,
    device_cookie,
    client_ip,
    rate_blocked,
    rate_hit,
    rate_clear,
    console_login_attempts,
    console_login_attempts_lock,
    console_login_window_seconds,
    console_login_max_attempts,
    console_password_today,
    log_login,
):
    debts_bp = Blueprint("debts", __name__)

    def data():
        return debts_data() if callable(debts_data) else debts_data

    @debts_bp.post("/api/debts/unlock")
    def debts_unlock_api():
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(device_cookie))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")

        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        console_login_window_seconds, console_login_max_attempts):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), console_password_today().encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            return jsonify(error="Неверный ежедневный пароль."), 401

        rate_clear(console_login_attempts, console_login_attempts_lock, client)
        session["debts_owner_authenticated"] = True
        session["debts_owner_day"] = today_iso()
        return jsonify(ok=True)

    @debts_bp.get("/api/debts")
    @debts_owner_required
    def debts_api():
        with debts_lock:
            return jsonify(debts_snapshot_locked())

    @debts_bp.post("/api/debts/users")
    @debts_owner_required
    def debts_user_create_api():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip()
        password = payload.get("password", "")
        if not name:
            return jsonify(error="Введите имя."), 400
        if len(name) > 60:
            return jsonify(error="Имя слишком длинное."), 400
        if not isinstance(password, str) or len(password.strip()) < 3:
            return jsonify(error="Пароль должен быть хотя бы 3 символа."), 400
        password = password.strip()
        if password_matches(password):
            return jsonify(error="Не используй пароль владельца для должника."), 400

        salt, password_hash = debt_hash_password(password)
        now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")
        user_id = uuid.uuid4().hex
        with debts_lock:
            store = data()
            if any(u.get("name", "").lower() == name.lower() for u in store["users"]):
                return jsonify(error="Такой человек уже есть."), 400
            if any(debt_password_matches(u, password) for u in store["users"]):
                return jsonify(error="Такой пароль уже занят."), 400
            store["users"].append({
                "id": user_id,
                "name": name,
                "password_plain": password,
                "salt": salt,
                "password_hash": password_hash,
                "created": now,
            })
            debts_write_locked()
            snapshot = debts_snapshot_locked()
            snapshot["selected_id"] = user_id
            return jsonify(snapshot)

    @debts_bp.post("/api/debts/entries")
    @debts_owner_required
    def debts_entry_create_api():
        payload = request.get_json(silent=True) or {}
        user_id = str(payload.get("user_id") or "")
        kind = str(payload.get("kind") or "debt")
        if kind not in ("debt", "return"):
            return jsonify(error="Неверный тип записи."), 400
        try:
            amount_cents = debt_amount_cents(payload.get("amount"))
            entry_date = debt_clean_date(payload.get("date"))
        except ValueError as err:
            return jsonify(error=str(err)), 400
        comment = str(payload.get("comment") or "").strip()[:220] or "—"
        now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")

        with debts_lock:
            store = data()
            if not any(u.get("id") == user_id for u in store["users"]):
                return jsonify(error="Выберите человека."), 400
            store["entries"].append({
                "id": uuid.uuid4().hex,
                "user_id": user_id,
                "kind": kind,
                "date": entry_date,
                "amount_cents": amount_cents,
                "comment": comment,
                "created": now,
            })
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.delete("/api/debts/entries/<entry_id>")
    @debts_owner_required
    def debts_entry_delete_api(entry_id):
        with debts_lock:
            store = data()
            before = len(store["entries"])
            store["entries"] = [e for e in store["entries"] if e.get("id") != entry_id]
            if len(store["entries"]) == before:
                return jsonify(error="Запись не найдена."), 404
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.get("/api/debts/me")
    def debts_me_api():
        user_id = session.get("debtor_id")
        if not user_id:
            return jsonify(error="Нужен вход."), 403
        with debts_lock:
            store = data()
            user = next((u for u in store["users"] if u.get("id") == user_id), None)
            if not user:
                session.pop("debtor_id", None)
                return jsonify(error="Пользователь не найден."), 404
            snapshot = debts_snapshot_locked(user_id)
            snapshot["me"] = debt_user_public_locked(user)
            return jsonify(snapshot)

    @debts_bp.delete("/api/debts/users/<user_id>")
    @debts_owner_required
    def debts_user_delete_api(user_id):
        with debts_lock:
            store = data()
            before = len(store["users"])
            store["users"] = [u for u in store["users"] if u.get("id") != user_id]
            if len(store["users"]) == before:
                return jsonify(error="Пользователь не найден."), 404
            store["entries"] = [e for e in store["entries"] if e.get("user_id") != user_id]
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.post("/api/debts/users/<user_id>/password")
    @debts_owner_required
    def debts_user_password_api(user_id):
        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not isinstance(password, str) or len(password.strip()) < 3:
            return jsonify(error="Пароль должен быть хотя бы 3 символа."), 400
        password = password.strip()
        if password_matches(password):
            return jsonify(error="Не используй пароль владельца для должника."), 400
        salt, password_hash = debt_hash_password(password)
        with debts_lock:
            store = data()
            user = next((u for u in store["users"] if u.get("id") == user_id), None)
            if not user:
                return jsonify(error="Пользователь не найден."), 404
            if any(u.get("id") != user_id and debt_password_matches(u, password) for u in store["users"]):
                return jsonify(error="Такой пароль уже занят."), 400
            user["password_plain"] = password
            user["salt"] = salt
            user["password_hash"] = password_hash
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.get("/debts/me")
    @debtor_required
    def debts_me_page():
        return debts_page_html(owner=False)

    @debts_bp.get("/debts")
    @login_required
    def debts_page():
        return debts_page_html(owner=True)

    def debts_page_html(owner=True):
        mode = "owner" if owner else "debtor"
        title = "Долги" if owner else "Мои долги"
        back_href = "/cabinet" if owner else "/"
        owner_unlocked = owner and debts_owner_unlocked()
        html = template("debts.html")
        return (html.replace("**MODE**", mode)
                    .replace("**TITLE**", title)
                    .replace("**TITLE_FIRST**", title.split()[0])
                    .replace("**TITLE_REST**", " ".join(title.split()[1:]))
                    .replace("**BACK_HREF**", back_href)
                    .replace("**UNLOCK_HIDDEN**", "hidden" if not owner or owner_unlocked else "")
                    .replace("**OWNER_APP_HIDDEN**", "hidden" if not owner or not owner_unlocked else "")
                    .replace("**DEBTOR_APP_HIDDEN**", "hidden" if owner else ""))

    return debts_bp
