import hmac
import time
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
    debts_snapshot_locked,
    debts_write_locked,
    debt_hash_password,
    debt_password_matches,
    debt_user_public_locked,
    debt_amount_cents,
    debt_clean_date,
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
    debts_password,
    debt_user_colors,
    log_login,
):
    debts_bp = Blueprint("debts", __name__)
    payment_banks = ("ОЗОН", "Т-Банк")

    def data():
        return debts_data() if callable(debts_data) else debts_data

    def _verify_debts_password(payload):
        """Пароль долгов + троттлинг попыток. Используется и для входа в
        раздел, и для подтверждения удаления — случайный тычок не тот
        пункт списка не должен сносить запись без повторного ввода пароля."""
        if not debts_password:
            return jsonify(error="Пароль долгов не настроен на сервере."), 503
        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        console_login_window_seconds, console_login_max_attempts):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429
        password = payload.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), debts_password.encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            return jsonify(error="Неверный пароль."), 401
        rate_clear(console_login_attempts, console_login_attempts_lock, client)
        return None

    @debts_bp.post("/api/debts/unlock")
    def debts_unlock_api():
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(device_cookie))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")

        err = _verify_debts_password(request.get_json(silent=True) or {})
        if err:
            return err

        session["debts_owner_authenticated"] = True
        session["debts_owner_unlocked_at"] = time.time()
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
        color = str(payload.get("color") or "")
        if color not in debt_user_colors:
            color = debt_user_colors[0]
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
                "color": color,
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

    @debts_bp.post("/api/debts/payment-requests")
    def debts_payment_request_create_api():
        user_id = session.get("debtor_id")
        if not user_id:
            return jsonify(error="Нужен вход."), 403
        payload = request.get_json(silent=True) or {}
        bank = str(payload.get("bank") or "").strip()
        if bank not in payment_banks:
            return jsonify(error="Выберите банк из списка."), 400
        try:
            amount_cents = debt_amount_cents(payload.get("amount"))
            entry_date = debt_clean_date(payload.get("date"))
        except ValueError as err:
            return jsonify(error=str(err)), 400
        now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")

        with debts_lock:
            store = data()
            store.setdefault("payment_requests", [])
            if not any(u.get("id") == user_id for u in store["users"]):
                session.pop("debtor_id", None)
                return jsonify(error="Пользователь не найден."), 404
            store["payment_requests"].append({
                "id": uuid.uuid4().hex,
                "user_id": user_id,
                "date": entry_date,
                "amount_cents": amount_cents,
                "bank": bank,
                "status": "pending",
                "created": now,
            })
            debts_write_locked()
            snapshot = debts_snapshot_locked(user_id)
            user = next(u for u in store["users"] if u.get("id") == user_id)
            snapshot["me"] = debt_user_public_locked(user)
            return jsonify(snapshot)

    @debts_bp.post("/api/debts/payment-requests/<request_id>/approve")
    @debts_owner_required
    def debts_payment_request_approve_api(request_id):
        now = datetime.now(ZoneInfo("Europe/Moscow")).isoformat(timespec="seconds")
        with debts_lock:
            store = data()
            requests = store.setdefault("payment_requests", [])
            payment = next((r for r in requests if r.get("id") == request_id), None)
            if not payment:
                return jsonify(error="Заявка не найдена."), 404
            if not any(u.get("id") == payment.get("user_id") for u in store["users"]):
                return jsonify(error="Должник не найден."), 404
            store["entries"].append({
                "id": uuid.uuid4().hex,
                "user_id": payment.get("user_id"),
                "kind": "return",
                "date": payment.get("date") or debt_clean_date(None),
                "amount_cents": int(payment.get("amount_cents") or 0),
                "comment": f"Взнос: {payment.get('bank') or 'банк'}",
                "created": now,
            })
            store["payment_requests"] = [r for r in requests if r.get("id") != request_id]
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.delete("/api/debts/payment-requests/<request_id>")
    @debts_owner_required
    def debts_payment_request_cancel_api(request_id):
        with debts_lock:
            store = data()
            requests = store.setdefault("payment_requests", [])
            before = len(requests)
            store["payment_requests"] = [r for r in requests if r.get("id") != request_id]
            if len(store["payment_requests"]) == before:
                return jsonify(error="Заявка не найдена."), 404
            debts_write_locked()
            return jsonify(debts_snapshot_locked())

    @debts_bp.delete("/api/debts/entries/<entry_id>")
    @debts_owner_required
    def debts_entry_delete_api(entry_id):
        err = _verify_debts_password(request.get_json(silent=True) or {})
        if err:
            return err
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
        err = _verify_debts_password(request.get_json(silent=True) or {})
        if err:
            return err
        with debts_lock:
            store = data()
            before = len(store["users"])
            store["users"] = [u for u in store["users"] if u.get("id") != user_id]
            if len(store["users"]) == before:
                return jsonify(error="Пользователь не найден."), 404
            store["entries"] = [e for e in store["entries"] if e.get("user_id") != user_id]
            store["payment_requests"] = [
                r for r in store.setdefault("payment_requests", []) if r.get("user_id") != user_id
            ]
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

    @debts_bp.post("/api/debts/users/<user_id>/color")
    @debts_owner_required
    def debts_user_color_api(user_id):
        payload = request.get_json(silent=True) or {}
        color = str(payload.get("color") or "")
        if color not in debt_user_colors:
            return jsonify(error="Неверный цвет."), 400
        with debts_lock:
            store = data()
            user = next((u for u in store["users"] if u.get("id") == user_id), None)
            if not user:
                return jsonify(error="Пользователь не найден."), 404
            user["color"] = color
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
        # Сейф, а не сессия: каждое открытие страницы владельцем — заново
        # спрашиваем пароль, даже если недавно уже вводили его в другой
        # вкладке (owner_unlocked() тут нарочно не смотрим — он только
        # для API-запросов уже открытой страницы, см. debts_owner_required).
        html = template("debts.html")
        return (html.replace("**MODE**", mode)
                    .replace("**TITLE**", title)
                    .replace("**TITLE_FIRST**", title.split()[0])
                    .replace("**TITLE_REST**", " ".join(title.split()[1:]))
                    .replace("**BACK_HREF**", back_href)
                    .replace("**UNLOCK_HIDDEN**", "hidden" if not owner else "")
                    .replace("**OWNER_APP_HIDDEN**", "hidden")
                    .replace("**DEBTOR_APP_HIDDEN**", "hidden" if owner else ""))

    return debts_bp
