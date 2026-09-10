from flask import Blueprint, jsonify


def create_login_log_blueprint(
    *,
    template,
    icon_links,
    login_required,
    login_log,
    login_log_lock,
    login_log_trim,
):
    login_log_bp = Blueprint("login_log", __name__)

    @login_log_bp.get("/login-log")
    @login_required
    def login_log_page():
        return template("login_log.html").replace("__ICONLINKS__", icon_links)

    @login_log_bp.get("/api/login-log")
    @login_required
    def login_log_api():
        with login_log_lock:
            login_log_trim()
            return jsonify(list(reversed(login_log)))

    return login_log_bp
