"""Вход в кабинет. Ломается незаметно — а за ним весь сайт."""

import pytest

from conftest import TEST_PASSWORD


@pytest.mark.xfail(
    strict=True,
    reason="Найдено этими же тестами: /api/login зовёт url_for('cabinet'), но "
           "после разреза на blueprints эндпоинт называется 'remote.cabinet'. "
           "Успешный вход отдаёт 500 вместо адреса перехода. Сессия при этом "
           "ОТКРЫВАЕТСЯ (см. test_login_opens_session_despite_500), поэтому "
           "снаружи выглядит как «пароль верный, но сайт ругается». "
           "Правка — одно слово в app.py, но задача была «только тесты», "
           "поэтому здесь она лишь зафиксирована. Когда починят — снять "
           "маркер, тест уже написан правильно (strict: пройдёт — CI скажет).",
)
def test_login_success(client):
    resp = client.post("/api/login", json={"password": TEST_PASSWORD})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "error" not in body
    # Именно этот адрес страница входа использует для перехода в кабинет.
    assert body.get("redirect") == "/cabinet"


def test_login_opens_session_despite_500(client):
    """Что происходит на самом деле сегодня.

    Пароль принимается и кука сессии выставляется (это успевает произойти
    до падения), но ответ — 500. Тест закрепляет ровно ту половину, что
    работает: пароль действительно открывает доступ. Когда 500 починят,
    он останется верным и переписывать его не придётся.
    """
    resp = client.post("/api/login", json={"password": TEST_PASSWORD})
    assert resp.status_code in (200, 500)
    assert client.get("/cabinet").status_code == 200
    assert client.get("/drop").status_code == 200


def test_login_wrong_password(client):
    resp = client.post("/api/login", json={"password": "не тот пароль"})
    assert resp.status_code == 401
    assert resp.get_json().get("error")
    # Главное: неудачная попытка не открывает сессию.
    assert client.get("/drop").status_code == 302


def test_login_empty_password(client):
    """Пустое тело не должно случайно совпасть с хэшем и пустить внутрь."""
    resp = client.post("/api/login", json={})
    assert resp.status_code == 401
    assert client.get("/drop").status_code == 302


def test_logout_closes_session(auth_client):
    assert auth_client.get("/drop").status_code == 200
    auth_client.post("/logout")
    assert auth_client.get("/drop").status_code == 302
