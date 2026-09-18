"""blueprints/debts.py — вкладка кабинета «Долги» /debts (задача 36,
docs/structure-plan.md).

Данные и вся логика — на модульном уровне здесь же, а не в `app.py`: файл
владеет своим состоянием сам, как остальные фичи блока Б. `debts_data`
(в отличие от notebook_data/diy_items/music_items) не мутируется на
месте, а ПЕРЕСОЗДАЁТСЯ целиком в `debts_load()` (`global debts_data`) —
так было и в app.py; ни один другой файл её не читает, поэтому опасности
устаревшей ссылки нет (раньше индирекция через `lambda: debts_data` была
нужна именно из-за границы модуля app.py↔blueprint, сейчас всё в одном
файле).

`debt_find_user_by_password` читает и `app.py`: страница входа сначала
проверяет пароль кабинета, а если не подошёл — перебирает пароли
должников (`/api/login`, тот же вход, что и в кабинет) — импортирован в
app.py из `blueprints.debts` для этого единственного вызова.
`password_matches` (проверка «не совпадает ли с паролем кабинета») теперь
в `core/auth.py`: нужна и `app.py` (свой `/api/login`), и этому файлу —
классический признак того, что место — в core, а не в одном из двух.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from zoneinfo import ZoneInfo

from flask import Blueprint, g, jsonify, redirect, request, session, url_for

from core.auth import (
    CONSOLE_LOGIN_MAX_ATTEMPTS,
    CONSOLE_LOGIN_WINDOW_SECONDS,
    DEVICE_COOKIE,
    PASSWORD_ITERATIONS,
    client_ip,
    console_login_attempts,
    console_login_attempts_lock,
    device_check,
    log_login,
    login_required,
    password_matches,
    rate_blocked,
    rate_clear,
    rate_hit,
)
from core.storage import DATA_DIR, atomic_write_json
from core.templates import template

# Свой пароль вкладки «Долги», не связан с ежедневным паролем консоли —
# задаётся один раз в .env и не меняется день ото дня.
DEBTS_PASSWORD = os.environ.get("DEBTS_PASSWORD")

DEBTS_PATH = os.path.join(DATA_DIR, "debts.json")
debts_lock = threading.Lock()
debts_data = {
    "users": [],
    "entries": [],
    "payment_requests": [],
    "payment_request_attempts": [],
}
# Палитра для кружка-аватарки должника на /debts — фиксированный набор,
# не произвольный CSS/hex с фронта (тот же принцип, что и цвета сайта
# через переменные, а не хардкод: тут просто ключи вместо hex).
DEBT_USER_COLORS = ("cyan", "green", "pink", "yellow", "violet", "orange")


def _today_iso():
    return datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y-%m-%d")


def debts_load():
    global debts_data
    try:
        with open(DEBTS_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    debts_data = {
        "users": raw.get("users") if isinstance(raw.get("users"), list) else [],
        "entries": raw.get("entries") if isinstance(raw.get("entries"), list) else [],
        "payment_requests": (
            raw.get("payment_requests")
            if isinstance(raw.get("payment_requests"), list)
            else []
        ),
        "payment_request_attempts": (
            raw.get("payment_request_attempts")
            if isinstance(raw.get("payment_request_attempts"), list)
            else []
        ),
    }


def debts_write_locked():
    os.makedirs(DATA_DIR, exist_ok=True)
    atomic_write_json(DEBTS_PATH, debts_data, indent=2)


def debt_hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def debt_password_matches(user, password):
    visible = user.get("password_plain")
    if isinstance(visible, str) and visible:
        return hmac.compare_digest(visible, password)
    try:
        salt = base64.b64decode(user.get("salt", ""))
        expected = base64.b64decode(user.get("password_hash", ""))
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def debt_find_user_by_password(password):
    if not isinstance(password, str) or not password:
        return None
    with debts_lock:
        for user in debts_data["users"]:
            if debt_password_matches(user, password):
                return {"id": user["id"], "name": user.get("name", "Должник")}
    return None


def debt_amount_cents(raw):
    text = str(raw or "").strip().replace(" ", "").replace(",", ".")
    if not re.fullmatch(r"\d+(?:\.\d{1,2})?", text):
        raise ValueError("Введите сумму числом, максимум 2 знака после точки.")
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ValueError("Введите сумму числом.")
    if value <= 0 or value > Decimal("10000000"):
        raise ValueError("Сумма должна быть больше нуля и меньше 10 000 000.")
    return int((value * Decimal("100")).quantize(Decimal("1")))


def debt_clean_date(raw):
    text = (str(raw or "").strip() or _today_iso())
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Дата должна быть в формате ГГГГ-ММ-ДД.")
    return text


def _debt_user_total_locked(user_id):
    total = 0
    for entry in debts_data["entries"]:
        if entry.get("user_id") != user_id:
            continue
        amount = int(entry.get("amount_cents") or 0)
        total += amount if entry.get("kind") == "debt" else -amount
    return total


def _debt_pending_return_total_locked(user_id):
    total = 0
    for row in debts_data.get("payment_requests", []):
        if row.get("user_id") != user_id or row.get("status", "pending") != "pending":
            continue
        total += int(row.get("amount_cents") or 0)
    return total


def _debt_entry_public_locked(entry):
    user = next((u for u in debts_data["users"] if u.get("id") == entry.get("user_id")), None)
    return {
        "id": entry.get("id"),
        "user_id": entry.get("user_id"),
        "user_name": user.get("name", "Должник") if user else "Должник",
        "date": entry.get("date") or _today_iso(),
        "kind": entry.get("kind") if entry.get("kind") in ("debt", "return") else "debt",
        "amount_cents": int(entry.get("amount_cents") or 0),
        "comment": entry.get("comment") or "—",
        "created": entry.get("created") or "",
    }


def _debt_payment_request_public_locked(row):
    user = next((u for u in debts_data["users"] if u.get("id") == row.get("user_id")), None)
    return {
        "id": row.get("id"),
        "user_id": row.get("user_id"),
        "user_name": user.get("name", "Должник") if user else "Должник",
        "date": row.get("date") or _today_iso(),
        "amount_cents": int(row.get("amount_cents") or 0),
        "bank": row.get("bank") or "Банк",
        "status": row.get("status") or "pending",
        "created": row.get("created") or "",
    }


def debt_user_public_locked(user):
    user_id = user.get("id")
    entries = [e for e in debts_data["entries"] if e.get("user_id") == user_id]
    pending_return_cents = _debt_pending_return_total_locked(user_id)
    total_cents = _debt_user_total_locked(user_id)
    color = user.get("color")
    return {
        "id": user_id,
        "name": user.get("name", "Должник"),
        "password": user.get("password_plain") or "",
        "total_cents": total_cents,
        "pending_return_cents": pending_return_cents,
        "projected_total_cents": total_cents - pending_return_cents,
        "entry_count": len(entries),
        "created": user.get("created") or "",
        "color": color if color in DEBT_USER_COLORS else DEBT_USER_COLORS[0],
    }


def debts_snapshot_locked(user_id=None):
    users = [debt_user_public_locked(u) for u in debts_data["users"]]
    users.sort(key=lambda u: u["name"].lower())
    entries = [_debt_entry_public_locked(e) for e in debts_data["entries"] if user_id is None or e.get("user_id") == user_id]
    entries.sort(key=lambda e: (e["date"], e["created"]), reverse=True)
    payment_requests = [
        _debt_payment_request_public_locked(r)
        for r in debts_data.get("payment_requests", [])
        if user_id is None or r.get("user_id") == user_id
    ]
    payment_requests.sort(key=lambda r: (r["date"], r["created"]), reverse=True)
    total = sum(u["total_cents"] for u in users if user_id is None or u["id"] == user_id)
    pending_total = sum(
        u["pending_return_cents"] for u in users if user_id is None or u["id"] == user_id
    )
    return {
        "users": users,
        "entries": entries,
        "payment_requests": payment_requests,
        "total_cents": total,
        "pending_return_cents": pending_total,
        "projected_total_cents": total - pending_total,
        "today": _today_iso(),
    }


# «Долги» — как сейф: страница СВЕЖИМ открытием (GET /debts) спрашивает
# пароль всегда, не важно, разблокировали её недавно или нет (см.
# debts_page_html в blueprints/debts.py — там owner_unlocked() не
# вызывается вообще). А чтобы во время самой работы со страницей не
# спрашивать пароль на каждый клик, разблокировка живёт ещё
# DEBTS_OWNER_IDLE_SECONDS от последнего запроса (скользящее окно) — если
# всё это время просто не трогать страницу (отошли, забыли), она сама
# «запрётся» и следующий клик потребует пароль снова.
DEBTS_OWNER_IDLE_SECONDS = 600


def _debts_owner_unlocked():
    return bool(
        session.get("debts_owner_authenticated")
        and time.time() - session.get("debts_owner_unlocked_at", 0) < DEBTS_OWNER_IDLE_SECONDS
    )


def debts_owner_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
            if not fresh:
                return jsonify(error="Нужен вход в кабинет."), 403
            session["authenticated"] = True
            g.new_device_cookie = fresh
            log_login("доверенное устройство")
        if not _debts_owner_unlocked():
            return jsonify(error="Нужен пароль."), 403
        session["debts_owner_unlocked_at"] = time.time()
        return view(*args, **kwargs)
    return wrapped


def debtor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("debtor_id"):
            return redirect(url_for("home.home"))
        return view(*args, **kwargs)
    return wrapped


debts_load()


def create_debts_blueprint(*, notification_add):
    debts_bp = Blueprint("debts", __name__)
    payment_banks = ("ОЗОН", "Т-Банк")
    payment_request_limit = 5
    payment_request_window = timedelta(minutes=5)
    moscow_tz = ZoneInfo("Europe/Moscow")

    def data():
        return debts_data() if callable(debts_data) else debts_data

    def payment_request_created_at(row):
        try:
            created = datetime.fromisoformat(str(row.get("created") or ""))
        except ValueError:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=moscow_tz)
        return created.astimezone(moscow_tz)

    def _verify_debts_password(payload):
        """Пароль долгов + троттлинг попыток. Используется и для входа в
        раздел, и для подтверждения удаления — случайный тычок не тот
        пункт списка не должен сносить запись без повторного ввода пароля."""
        if not DEBTS_PASSWORD:
            return jsonify(error="Пароль долгов не настроен на сервере."), 503
        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        CONSOLE_LOGIN_WINDOW_SECONDS, CONSOLE_LOGIN_MAX_ATTEMPTS):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429
        password = payload.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), DEBTS_PASSWORD.encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            return jsonify(error="Неверный пароль."), 401
        rate_clear(console_login_attempts, console_login_attempts_lock, client)
        return None

    @debts_bp.post("/api/debts/unlock")
    def debts_unlock_api():
        if not session.get("authenticated"):
            fresh = device_check(request.cookies.get(DEVICE_COOKIE))
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
        if color not in DEBT_USER_COLORS:
            color = DEBT_USER_COLORS[0]
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
        now = datetime.now(moscow_tz)

        with debts_lock:
            store = data()
            requests = store.setdefault("payment_requests", [])
            user = next((u for u in store["users"] if u.get("id") == user_id), None)
            if not user:
                session.pop("debtor_id", None)
                return jsonify(error="Пользователь не найден."), 404

            pending_count = sum(
                row.get("user_id") == user_id and row.get("status", "pending") == "pending"
                for row in requests
            )
            if pending_count >= payment_request_limit:
                return jsonify(error="Можно одновременно держать не больше 5 заявок в обработке."), 429

            cutoff = now - payment_request_window
            recent_attempts = [
                row for row in store.setdefault("payment_request_attempts", [])
                if (created := payment_request_created_at(row)) and created >= cutoff
            ]
            store["payment_request_attempts"] = recent_attempts
            recent_count = sum(row.get("user_id") == user_id for row in recent_attempts)
            if recent_count >= payment_request_limit:
                return jsonify(error="Можно отправить не больше 5 заявок за 5 минут."), 429

            created = now.isoformat(timespec="seconds")
            store["payment_request_attempts"].append({
                "user_id": user_id,
                "created": created,
            })
            requests.append({
                "id": uuid.uuid4().hex,
                "user_id": user_id,
                "date": entry_date,
                "amount_cents": amount_cents,
                "bank": bank,
                "status": "pending",
                "created": created,
            })
            amount = f"{amount_cents / 100:.2f}".rstrip("0").rstrip(".").replace(".", ",")
            notification_add(
                "Заявка на пополнение",
                f"{user.get('name') or 'Должник'}: {amount} ₽ · {bank}",
                href="/debts",
                kind="payment-request",
            )
            debts_write_locked()
            snapshot = debts_snapshot_locked(user_id)
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

    @debts_bp.delete("/api/debts/me/payment-requests/<request_id>")
    @debtor_required
    def debts_own_payment_request_cancel_api(request_id):
        debtor_id = session.get("debtor_id")
        with debts_lock:
            store = data()
            requests = store.setdefault("payment_requests", [])
            payment = next((r for r in requests if r.get("id") == request_id), None)
            if not payment:
                return jsonify(error="Заявка не найдена."), 404
            if payment.get("user_id") != debtor_id:
                return jsonify(error="Нельзя удалить чужую заявку."), 403
            store["payment_requests"] = [r for r in requests if r.get("id") != request_id]
            debts_write_locked()
            snapshot = debts_snapshot_locked(debtor_id)
            user = next((u for u in store["users"] if u.get("id") == debtor_id), None)
            if not user:
                session.pop("debtor_id", None)
                return jsonify(error="Пользователь не найден."), 404
            snapshot["me"] = debt_user_public_locked(user)
            return jsonify(snapshot)

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
        if color not in DEBT_USER_COLORS:
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
                    .replace("**OWNER_LOCKED**", "true" if owner else "false")
                    .replace("**TITLE**", title)
                    .replace("**TITLE_FIRST**", title.split()[0])
                    .replace("**TITLE_REST**", " ".join(title.split()[1:]))
                    .replace("**BACK_HREF**", back_href)
                    .replace("**UNLOCK_HIDDEN**", "hidden" if not owner else "")
                    .replace("**OWNER_APP_HIDDEN**", "hidden")
                    .replace("**DEBTOR_APP_HIDDEN**", "hidden" if owner else ""))

    return debts_bp
