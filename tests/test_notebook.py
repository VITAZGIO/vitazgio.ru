"""«Блокнот» /notebook.

Первая фича, которая после задачи 35 владеет своим состоянием сама
(`notebook_data`/`notebook_lock` теперь в `blueprints/notebook.py`, не в
`app.py`) — раньше страница не была покрыта отдельным тестом вовсе.
"""

import io

import pytest


@pytest.fixture(autouse=True)
def reset_notebook(app_module):
    """`notebook_data` — модульное состояние `blueprints.notebook`, живёт
    весь сеанс тестов; без сброса записи одного теста мешали бы другому."""
    with app_module.notebook_lock:
        app_module.notebook_data["pages"] = [{"id": "p1", "name": "Заметки"}]
        app_module.notebook_data["entries"] = {}


def test_notebook_requires_login(client):
    assert client.get("/notebook").status_code == 302
    assert client.get("/api/notebook").status_code == 302


def test_notebook_page_opens_for_owner(auth_client):
    assert auth_client.get("/notebook").status_code == 200


def test_notebook_starts_with_one_page(auth_client):
    body = auth_client.get("/api/notebook").get_json()
    assert len(body["pages"]) == 1
    assert body["entries"] == []


def test_add_rename_and_delete_page(auth_client):
    pid = auth_client.post("/api/notebook/page", json={"name": "Вторая"}).get_json()["id"]
    pages = {p["id"]: p["name"] for p in auth_client.get("/api/notebook").get_json()["pages"]}
    assert pages[pid] == "Вторая"

    auth_client.patch(f"/api/notebook/page/{pid}", json={"name": "Переименовано"})
    pages = {p["id"]: p["name"] for p in auth_client.get("/api/notebook").get_json()["pages"]}
    assert pages[pid] == "Переименовано"

    resp = auth_client.delete(f"/api/notebook/page/{pid}")
    assert resp.status_code == 200
    ids = [p["id"] for p in auth_client.get("/api/notebook").get_json()["pages"]]
    assert pid not in ids


def test_cannot_delete_last_page(auth_client):
    resp = auth_client.delete("/api/notebook/page/p1")
    assert resp.status_code == 400


def test_link_entry_gets_https_prefix(auth_client):
    """Проверяет заодно и core.storage.clean_url — общий с _diy_card в app.py."""
    resp = auth_client.post("/api/notebook/entry", json={
        "type": "link", "page": "p1", "url": "example.com",
    })
    assert resp.status_code == 200
    eid = resp.get_json()["id"]
    entry = next(e for e in auth_client.get("/api/notebook").get_json()["entries"]
                 if e["id"] == eid)
    assert entry["url"] == "https://example.com"


def test_text_entry_roundtrip(auth_client):
    eid = auth_client.post("/api/notebook/entry",
                            json={"type": "text", "page": "p1"}).get_json()["id"]
    auth_client.patch(f"/api/notebook/entry/{eid}", json={"text": "заметка"})
    entry = next(e for e in auth_client.get("/api/notebook").get_json()["entries"]
                 if e["id"] == eid)
    assert entry["text"] == "заметка"

    resp = auth_client.delete(f"/api/notebook/entry/{eid}")
    assert resp.status_code == 200
    ids = [e["id"] for e in auth_client.get("/api/notebook").get_json()["entries"]]
    assert eid not in ids


def test_pdf_entry_upload_and_view(auth_client):
    eid = auth_client.post("/api/notebook/entry",
                            json={"type": "pdf", "page": "p1"}).get_json()["id"]
    resp = auth_client.post(
        f"/api/notebook/entry/{eid}/pdf",
        data={"file": (io.BytesIO(b"%PDF-1.4 fake"), "report.pdf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["filename"] == "report.pdf"

    view = auth_client.get(f"/notebook/pdf/{eid}")
    assert view.status_code == 200
    assert view.data == b"%PDF-1.4 fake"


def test_pdf_entry_rejects_non_pdf(auth_client):
    eid = auth_client.post("/api/notebook/entry",
                            json={"type": "pdf", "page": "p1"}).get_json()["id"]
    resp = auth_client.post(
        f"/api/notebook/entry/{eid}/pdf",
        data={"file": (io.BytesIO(b"not a pdf"), "report.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 415
