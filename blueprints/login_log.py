"""blueprints/login_log.py — вкладка кабинета «Журнал входов» (/login-log).

Первый blueprint, переведённый на прямые импорты из core/ (задача 34,
docs/structure-plan.md) — образец для остальных: вместо фабрики,
принимающей все зависимости аргументами, файл сам берёт то, что ему
нужно. Данные журнала (`login_log`/`login_log_lock`) и их урезка живут в
core/auth.py — их пишет `login_required` и вход в кабинет при каждой
попытке, эта страница только читает.
"""

from flask import Blueprint, jsonify

from blueprints.pwa import ICON_LINKS
from core.auth import login_log, login_log_lock, login_log_trim, login_required
from core.templates import template


def create_login_log_blueprint():
    login_log_bp = Blueprint("login_log", __name__)

    @login_log_bp.get("/login-log")
    @login_required
    def login_log_page():
        return template("login_log.html").replace("__ICONLINKS__", ICON_LINKS)

    @login_log_bp.get("/api/login-log")
    @login_required
    def login_log_api():
        with login_log_lock:
            login_log_trim()
            return jsonify(list(reversed(login_log)))

    return login_log_bp
