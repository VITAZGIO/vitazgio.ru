import hmac
import secrets
import time

from flask import Blueprint, jsonify, request


def create_home_blueprint(
    *,
    template,
    icon_links,
    game_icons,
    login_required,
    netbird_devices,
    arcade_games,
    arcade_top,
    arcade_keep,
    arcade_value_max,
    arcade_submit_window,
    arcade_submit_max,
    arcade_scores,
    arcade_lock,
    arcade_submit_attempts,
    arcade_submit_lock,
    arcade_clean_name,
    arcade_sort,
    arcade_save,
    arcade_public,
    client_ip,
    rate_blocked,
    rate_hit,
    rate_clear,
    console_login_attempts,
    console_login_attempts_lock,
    console_login_window_seconds,
    console_login_max_attempts,
    log_login,
    ssh_gate_password_prefix,
    console_password_today,
):
    home_bp = Blueprint("home", __name__)

    # ---- Рекорды аркады: без пароля, аркада ведь тоже открыта ---------------
    @home_bp.get("/api/arcade/scores")
    def arcade_scores_api():
        with arcade_lock:
            return jsonify(
                scores=arcade_public(),
                games={g: {"title": m["title"], "order": m["order"], "unit": m["unit"]}
                       for g, m in arcade_games.items()},
            )

    @home_bp.post("/api/arcade/scores")
    def arcade_score_add():
        client = client_ip()
        if rate_blocked(arcade_submit_attempts, arcade_submit_lock, client,
                        arcade_submit_window, arcade_submit_max):
            return jsonify(error="Слишком часто. Попробуйте позже."), 429
        rate_hit(arcade_submit_attempts, arcade_submit_lock, client)

        payload = request.get_json(silent=True) or {}
        game = payload.get("game")
        if game not in arcade_games:
            return jsonify(error="Неизвестная игра."), 400
        try:
            value = int(payload.get("value"))
        except (TypeError, ValueError):
            return jsonify(error="Плохой результат."), 400
        meta = arcade_games[game]
        if not meta.get("lo", 0) <= value <= min(meta.get("hi", arcade_value_max),
                                                 arcade_value_max):
            return jsonify(error="Результат вне правдоподобных границ."), 400

        row = {
            "id": secrets.token_urlsafe(6),
            "name": arcade_clean_name(payload.get("name")),
            "value": value,
            "at": time.time(),
            "epoch": meta["epoch"],
        }
        with arcade_lock:
            rows = arcade_sort(game, arcade_scores.get(game, []) + [row])[:arcade_keep]
            arcade_scores[game] = rows
            arcade_save()
            place = next((i for i, r in enumerate(rows) if r["id"] == row["id"]), None)
            return jsonify(
                # place — место в таблице (0 — первое) или null, если не пролез
                place=place if place is not None and place < arcade_top else None,
                scores=arcade_public(),
            )

    @home_bp.post("/api/arcade/scores/delete")
    def arcade_score_delete():
        """Чистка таблицы от неприличных ников. Пускаем по тому же суточному
        паролю, что и в консоль, — заводить ради этого отдельный секрет незачем."""
        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        console_login_window_seconds, console_login_max_attempts):
            log_login("лимит попыток (рекорды)", kind="block")
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not ssh_gate_password_prefix or not isinstance(password, str) or \
                not hmac.compare_digest(password.encode(), console_password_today().encode()):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            log_login("неверный суточный пароль (рекорды)", kind="fail")
            return jsonify(error="Неверный суточный пароль."), 401
        rate_clear(console_login_attempts, console_login_attempts_lock, client)

        game = payload.get("game")
        if game not in arcade_games:
            return jsonify(error="Неизвестная игра."), 400
        target = str(payload.get("id", ""))
        with arcade_lock:
            rows = arcade_scores.get(game, [])
            kept = [r for r in rows if r["id"] != target]
            if len(kept) != len(rows):
                arcade_scores[game] = kept
                arcade_save()
            return jsonify(scores=arcade_public())

    @home_bp.get("/themes")
    @login_required
    def themes_page():
        """Витрина оформления: разделы кабинета как органы и импланты киборга.
        Своего бэкенда нет — данные берутся из уже существующих эндпоинтов."""
        organs = ["ЛОБНАЯ ДОЛЯ", "ТЕМЕННАЯ ДОЛЯ", "ЗАТЫЛОЧНАЯ ДОЛЯ", "ВИСОЧНАЯ ДОЛЯ",
                  "МОЗЖЕЧОК", "СТВОЛ МОЗГА", "ТАЛАМУС", "ГИПОФИЗ"]
        cols, rows = [60, 330, 600, 870], [250, 420]
        cards = []
        for i, device in enumerate(netbird_devices[:8]):
            left, top = cols[i % 4], rows[i // 4]
            kind = ("SSH" if device.get("ssh_enabled") else
                    "RDP" if device.get("rdp_enabled") else
                    "VNC" if device.get("vnc_enabled") else "\u2014")
            cards.append(
                f'<g class="ncard" style="--i:{i}">'
                f'<path class="ncard-plate" d="M{left} {top + 12} L{left + 12} {top} L{left + 246} {top} '
                f'L{left + 246} {top + 68} L{left + 234} {top + 80} L{left} {top + 80} Z"/>'
                f'<text class="ncard-organ" x="{left + 84}" y="{top + 20}">{organs[i]}</text>'
                f'<text class="ncard-name" x="{left + 84}" y="{top + 38}">{device["name"]}</text>'
                f'<text class="ncard-ip" x="{left + 84}" y="{top + 54}">{device["ip"]}</text>'
                f'<text class="ncard-ping" x="{left + 236}" y="{top + 22}" text-anchor="end" '
                f'data-ping="{device["ip"]}">\u2014 \u2014 \u2014</text>'
                f'<g class="ncard-btn"><rect x="{left + 84}" y="{top + 60}" width="100" height="16" rx="1"/>'
                f'<text x="{left + 134}" y="{top + 72}" text-anchor="middle">ПОДКЛЮЧИТЬСЯ</text></g>'
                f'<text class="ncard-ip" x="{left + 236}" y="{top + 72}" text-anchor="end">{kind}</text>'
                f'</g>'
            )

        html = template("themes.html")
        return html.replace("__NODES__", "".join(cards)) \
                   .replace("__ICONLINKS__", icon_links)

    @home_bp.get("/servers")
    def servers_page():
        """Хозяйство: три машины, их роли и что на них крутится.

        Страница открыта всем, поэтому наружу не выносим ни публичный адрес VPS,
        ни адреса mesh-сети — только домашние 192.168.x, которые одинаковы у
        половины страны и ничего не выдают."""
        html = template("servers.html")
        return html.replace("__ICONLINKS__", icon_links)

    @home_bp.route("/")
    def home():
        html = template("home.html")
        for name, svg in game_icons.items():
            html = html.replace("__ICON_%s__" % name.upper(), svg)
        html = html.replace("__ICONLINKS__", icon_links)
        return html

    return home_bp
