"""Вкладка кабинета «Запомнить устройства» (/devices).

Переведён на прямые импорты из core/ (задача 35) — раньше не был покрыт
отдельным тестом вовсе, только косвенно через `test_every_url_for_target_exists`.
"""

import pytest

from conftest import console_password_today


@pytest.fixture(autouse=True)
def reset_trusted_devices(app_module):
    """`trusted_devices` — модульное состояние `core.auth`, живёт весь
    сеанс тестов (`app_module` — session-scoped); без сброса устройства,
    выданные одним тестом, путались бы со следующим."""
    with app_module.devices_lock:
        app_module.trusted_devices.clear()


def test_devices_requires_login(client):
    assert client.get("/devices").status_code == 302
    assert client.get("/api/devices").status_code == 302


def test_devices_page_opens_for_owner(auth_client):
    assert auth_client.get("/devices").status_code == 200


def test_devices_list_empty_initially(auth_client):
    resp = auth_client.get("/api/devices")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_trust_rejects_wrong_console_password(auth_client):
    resp = auth_client.post("/api/devices/trust", json={"password": "не тот"})
    assert resp.status_code == 401


def test_trust_issues_device_and_lists_it(auth_client, app_module):
    resp = auth_client.post(
        "/api/devices/trust",
        json={"password": console_password_today()},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["label"]

    items = auth_client.get("/api/devices").get_json()
    assert len(items) == 1
    assert items[0]["label"] == body["label"]


def test_rename_and_forget_device(auth_client, app_module):
    auth_client.post("/api/devices/trust",
                      json={"password": console_password_today()})
    selector = auth_client.get("/api/devices").get_json()[0]["id"]

    resp = auth_client.patch(f"/api/devices/{selector}", json={"label": "Мой ноутбук"})
    assert resp.status_code == 200
    items = auth_client.get("/api/devices").get_json()
    assert items[0]["label"] == "Мой ноутбук"

    resp = auth_client.delete(f"/api/devices/{selector}")
    assert resp.status_code == 200
    assert auth_client.get("/api/devices").get_json() == []
