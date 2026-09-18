"""«Страна DIY» /diy (задача 36).

Первая фича настолько большая, что раньше не имела ни одного pytest'а
вовсе (только `scratchpad/diy.js` для раскладки). После задачи 36 владеет
своим состоянием сама (`blueprints/diy.py`, не `app.py`), поэтому и тесты
обращаются к нему через `sys.modules["blueprints.diy"]`, как в
tests/test_home.py.
"""

import io
import sys

import pytest


@pytest.fixture(autouse=True)
def reset_diy(app_module):
    """`diy_items` — модульное состояние `blueprints.diy`, живёт весь сеанс
    (заготовки `_diy_seed()` тоже сидят там же) — сбрасываем перед каждым
    тестом, чтобы записи одного теста не путались с заготовками или
    другими тестами."""
    diy_module = sys.modules["blueprints.diy"]
    with diy_module.diy_lock:
        diy_module.diy_items.clear()


def test_diy_page_opens_for_guest(client):
    assert client.get("/diy").status_code == 200


def test_list_starts_empty_after_reset(client):
    body = client.get("/api/diy").get_json()
    assert body["works"] == []
    assert body["can_edit"] is False
    assert "программы" in body["kinds"]


def test_create_requires_login(client):
    resp = client.post("/api/diy", json={"title": "Тест"})
    assert resp.status_code == 403


def test_create_requires_title(auth_client):
    resp = auth_client.post("/api/diy", json={"title": "  "})
    assert resp.status_code == 400


def test_create_update_delete_roundtrip(auth_client):
    resp = auth_client.post("/api/diy", json={
        "title": "ssh-туннель", "kind": "программы", "body": "код статьи",
    })
    assert resp.status_code == 200
    item_id = resp.get_json()["id"]

    works = auth_client.get("/api/diy").get_json()["works"]
    assert works[0]["title"] == "ssh-туннель"
    assert works[0]["has_body"] is True

    resp = auth_client.patch(f"/api/diy/{item_id}", json={"title": "Переименовано"})
    assert resp.status_code == 200
    works = auth_client.get("/api/diy").get_json()["works"]
    assert works[0]["title"] == "Переименовано"

    resp = auth_client.delete(f"/api/diy/{item_id}")
    assert resp.status_code == 200
    assert auth_client.get("/api/diy").get_json()["works"] == []


def test_hidden_work_invisible_to_guest(auth_client, client):
    item_id = auth_client.post("/api/diy", json={
        "title": "Черновик", "hidden": True,
    }).get_json()["id"]

    guest_works = client.get("/api/diy").get_json()["works"]
    assert guest_works == []

    owner_works = auth_client.get("/api/diy").get_json()["works"]
    assert owner_works[0]["id"] == item_id

    assert client.get(f"/diy/a/{item_id}").status_code == 404
    assert auth_client.get(f"/diy/a/{item_id}").status_code == 200


def test_asset_upload_download_and_delete(auth_client, client):
    item_id = auth_client.post("/api/diy", json={"title": "С вложением"}).get_json()["id"]

    resp = auth_client.post(
        f"/api/diy/{item_id}/asset",
        data={"file": (io.BytesIO("привет".encode()), "note.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "note.txt"

    # вложение открыто всем, как и сама статья
    resp = client.get(f"/diy/asset/{item_id}/note.txt")
    assert resp.status_code == 200
    assert resp.data == "привет".encode()

    resp = auth_client.delete(f"/api/diy/{item_id}/asset/note.txt")
    assert resp.status_code == 200
    assert client.get(f"/diy/asset/{item_id}/note.txt").status_code == 404


def test_link_in_article_header_gets_https_prefix(auth_client):
    """Проверяет заодно core.storage.clean_url — общий с notebook.py хелпер,
    здесь вызывается из _diy_card напрямую (не через notebook.py)."""
    body = "---\nссылка: example.com\n---\nтекст статьи"
    item_id = auth_client.post("/api/diy", json={"title": "Со ссылкой", "body": body}).get_json()["id"]
    work = auth_client.get("/api/diy").get_json()["works"][0]
    assert work["id"] == item_id
    assert work["link"] == "https://example.com"


def test_editor_required_for_asset_and_cover(client, auth_client):
    item_id = auth_client.post("/api/diy", json={"title": "Чужая правка"}).get_json()["id"]
    resp = client.post(
        f"/api/diy/{item_id}/asset",
        data={"file": (io.BytesIO(b"x"), "x.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 403
