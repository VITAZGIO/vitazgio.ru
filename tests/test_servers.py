def test_servers_page_requires_its_own_password(client):
    response = client.get("/servers")

    assert response.status_code == 200
    assert "Введите пароль для просмотра." in response.get_data(as_text=True)
    assert "Orange Pi Zero 3" not in response.get_data(as_text=True)


def test_servers_page_opens_after_correct_password(client):
    response = client.post("/servers/unlock", data={"password": "1224"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/servers")
    page = client.get("/servers")
    assert page.status_code == 200
    assert "Orange Pi Zero 3" in page.get_data(as_text=True)


def test_servers_page_rejects_wrong_password(client):
    response = client.post("/servers/unlock", data={"password": "0000"})

    assert response.status_code == 401
    assert "Неверный пароль." in response.get_data(as_text=True)
