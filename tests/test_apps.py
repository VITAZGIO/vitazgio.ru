"""Вкладка кабинета «Приложения» (blueprints/apps.py) — заняла место бывшего
«Резерва 1». Сама страница ничего не считает, поэтому проверяем главное:
гейт и то, что она действительно ссылается на уже существующие API, а не
завела свои дублирующие.
"""


def test_apps_page_is_behind_the_door(client, auth_client):
    assert client.get("/apps").status_code in (302, 401, 403)
    resp = auth_client.get("/apps")
    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    assert "Приложения" in page
    # Свои показания и кнопки — переехали с самого телефона сюда: страница
    # обязана говорить с уже существующими ручками, не заводить новые.
    assert "/api/phone/agent" in page
    assert "/api/phone/tokens" in page
    assert "/api/app/version" in page
    assert "/api/app/pull" in page
    assert 'href="/app"' in page


def test_reserve_tile_became_a_real_link_on_cabinet(auth_client):
    page = auth_client.get("/cabinet").get_data(as_text=True)
    assert 'href="/apps"' in page
    assert "Приложения" in page
    assert "Резерв 1" not in page


def test_phone_tokens_panel_moved_off_netbird(auth_client):
    """Токены телефона теперь живут на /apps — не дублируем их на /netbird."""
    page = auth_client.get("/netbird").get_data(as_text=True)
    assert "Токены телефона" not in page
