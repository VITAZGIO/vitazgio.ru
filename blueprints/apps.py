"""Вкладка кабинета «Приложения» — программы на других устройствах.

Своя страница, не аккордеон, как «Запомнить устройства» или «Журнал
входов». На ней телефонный агент (вместо
служебного экрана внутри самого приложения, который отсюда и убрали: все
показания и кнопки переехали на сайт, где их видно и с телефона, и с ПК).
Раздел «Windows» показывает сборку оболочки и компьютеры с их доступом.

Страница сама ничего не считает — данные и так уже отдаёт `blueprints/phone.py`
(`/api/phone/agent`, `/api/phone/tokens`, `/api/app/version`, `/api/app/pull`).
Windows-данные отдаёт `blueprints/desktop.py`. Этот файл только показывает
общую страницу, без дублирования логики агентов.
"""

from flask import Blueprint


def create_apps_blueprint(*, template, icon_links, login_required):
    apps_bp = Blueprint("apps", __name__)

    @apps_bp.get("/apps")
    @login_required
    def apps_page():
        return template("apps.html").replace("__ICONLINKS__", icon_links)

    return apps_bp
