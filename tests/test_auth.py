"""Вход в кабинет. Ломается незаметно — а за ним весь сайт."""

import pathlib
import re

import pytest

from conftest import TEST_PASSWORD


def test_login_success(client):
    """Верный пароль обязан вернуть 200 и адрес перехода.

    Тест написан, когда здесь был 500: после переезда кабинета в
    blueprint в /api/login остался url_for("cabinet") вместо
    url_for("remote.cabinet"). Пароль принимался, сессия открывалась, но
    ответ падал с BuildError — и все три формы входа (главная, DIY,
    фонотека) показывали ошибку вместо перехода.
    """
    resp = client.post("/api/login", json={"password": TEST_PASSWORD})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "error" not in body
    assert body.get("redirect") == "/cabinet"


def test_login_opens_session(client):
    """Пароль действительно открывает доступ, а не только отвечает 200."""
    client.post("/api/login", json={"password": TEST_PASSWORD})
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


REPO = pathlib.Path(__file__).resolve().parent.parent
URL_FOR = re.compile(r"""url_for\(\s*['"]([^'"]+)['"]""")


@pytest.mark.parametrize("source", sorted(
    [p.relative_to(REPO) for p in REPO.glob("*.py")]
    + [p.relative_to(REPO) for p in (REPO / "blueprints").glob("*.py")],
), ids=str)
def test_every_url_for_target_exists(app_module, source):
    """Каждый url_for обязан ссылаться на живой эндпоинт.

    Общая страховка от той самой поломки: при переносе вида в blueprint
    его имя получает приставку (`cabinet` → `remote.cabinet`), а вызовы
    url_for в других файлах об этом не знают. Ошибка вылезает только в
    момент вызова, поэтому ни py_compile, ни чтение кода её не ловят —
    зато здесь она видна сразу и для всех роутов, а не только для входа.
    """
    known = {rule.endpoint for rule in app_module.app.url_map.iter_rules()}
    text = (REPO / source).read_text(encoding="utf-8")
    missing = sorted({e for e in URL_FOR.findall(text) if e not in known})
    assert not missing, f"{source}: url_for на несуществующие эндпоинты: {missing}"
