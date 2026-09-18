"""Главная `/`, рекорды аркады (задача 36).

Аркада раньше не была покрыта отдельным тестом вовсе — только косвенно
через `test_every_url_for_target_exists`. Теперь она ещё и владеет своим
состоянием сама (`blueprints/home.py`, не `app.py`), поэтому сброс между
тестами обязателен: `arcade_scores` — модульный словарь, живущий весь
сеанс (`app_module` — session-scoped).
"""

import sys

import pytest


@pytest.fixture(autouse=True)
def reset_arcade(app_module):
    """`arcade_scores`/`arcade_submit_attempts` — модульное состояние
    `blueprints.home` (задача 36, файл владеет своими рекордами сам), не
    `app.py` — доступ через sys.modules, как и в tests/test_files.py."""
    home_module = sys.modules["blueprints.home"]
    with home_module.arcade_lock:
        home_module.arcade_scores.clear()
    with home_module.arcade_submit_lock:
        home_module.arcade_submit_attempts.clear()


def test_home_page_loads_for_guest(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_arcade_scores_empty_initially(client):
    body = client.get("/api/arcade/scores").get_json()
    assert body["scores"] == {}
    assert "snake" in body["games"]


def test_arcade_submit_and_read_back(client):
    resp = client.post("/api/arcade/scores", json={"game": "snake", "value": 500, "name": "Витя"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["place"] == 0

    scores = client.get("/api/arcade/scores").get_json()["scores"]
    assert scores["snake"][0]["name"] == "Витя"
    assert scores["snake"][0]["value"] == 500


def test_arcade_submit_rejects_unknown_game(client):
    resp = client.post("/api/arcade/scores", json={"game": "не игра", "value": 1})
    assert resp.status_code == 400


def test_arcade_submit_rejects_implausible_value(client):
    resp = client.post("/api/arcade/scores", json={"game": "snake", "value": 999_999_999})
    assert resp.status_code == 400


def test_arcade_delete_requires_console_password(client):
    client.post("/api/arcade/scores", json={"game": "snake", "value": 100})
    entry_id = client.get("/api/arcade/scores").get_json()["scores"]["snake"][0]["id"]

    resp = client.post("/api/arcade/scores/delete",
                        json={"game": "snake", "id": entry_id, "password": "не тот"})
    assert resp.status_code == 401
    scores = client.get("/api/arcade/scores").get_json()["scores"]
    assert len(scores["snake"]) == 1


def test_arcade_delete_with_correct_password(client, app_module):
    client.post("/api/arcade/scores", json={"game": "snake", "value": 100})
    entry_id = client.get("/api/arcade/scores").get_json()["scores"]["snake"][0]["id"]

    resp = client.post("/api/arcade/scores/delete", json={
        "game": "snake", "id": entry_id,
        "password": app_module.console_password_today(),
    })
    assert resp.status_code == 200
    scores = client.get("/api/arcade/scores").get_json()["scores"]
    assert scores.get("snake", []) == []
