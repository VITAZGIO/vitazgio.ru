"""Вкладка кабинета «Приложения» — программы на других устройствах.

Своя страница, не аккордеон, как «Запомнить устройства» или «Журнал
входов». Сейчас на ней ровно один жилец — телефонный агент (вместо
служебного экрана внутри самого приложения, который отсюда и убрали: все
показания и кнопки переехали на сайт, где их видно и с телефона, и с ПК).
Раздел «Windows» — задел на будущее, программ пока нет.

Страница сама ничего не считает — данные и так уже отдаёт `blueprints/phone.py`
(`/api/phone/agent`, `/api/phone/tokens`, `/api/app/version`, `/api/app/pull`).
Этот файл только показывает их в общем дизайне сайта.
"""

from flask import Blueprint


def create_apps_blueprint(*, template, icon_links, login_required):
    apps_bp = Blueprint("apps", __name__)

    @apps_bp.get("/apps")
    @login_required
    def apps_page():
        return template("apps.html").replace("__ICONLINKS__", icon_links)

    return apps_bp
