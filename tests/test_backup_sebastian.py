"""/backup (резервные копии) и /sebastian (дворецкий) — задача 37,
docs/structure-plan.md: первая проверка для этих двух разделов вообще,
раньше не были покрыты ни одним тестом.

Настоящий Ollama (SEBASTIAN_OLLAMA) в тестовом окружении не настроен —
проверяем только то, что сервер честно отвечает «не готов», не пытаясь
никуда стучаться.
"""

import io
import sys
import zipfile

import pytest


@pytest.fixture(autouse=True)
def reset_notebook(app_module):
    notebook_module = sys.modules["blueprints.notebook"]
    with notebook_module.notebook_lock:
        notebook_module.notebook_data["pages"] = [{"id": "p1", "name": "Заметки"}]
        notebook_module.notebook_data["entries"] = {}


def test_backup_page_requires_login(client):
    assert client.get("/backup").status_code == 302
    assert client.post("/api/backup/import").status_code == 302


def test_backup_page_opens_for_owner(auth_client):
    assert auth_client.get("/backup").status_code == 200


def test_backup_state_reports_sizes(auth_client):
    body = auth_client.get("/api/backup/state").get_json()
    assert "size" in body["light"] and "files" in body["light"]
    assert "size" in body["full"] and "files" in body["full"]
    assert body["robot"] is False           # BACKUP_TOKEN не задан в тестах


def test_backup_export_without_login_is_refused(client):
    assert client.get("/api/backup/export").status_code == 403


def test_backup_export_produces_valid_zip(auth_client):
    """`backup_skip()` отбраковывает всё, что лежит под путём с сегментом
    `tmp` (в проде — только служебные `*_tmp` папки, а pytest сам кладёт
    песочницу под /tmp — поэтому тут не проверяем содержимое, только что
    получился настоящий архив с manifest'ом)."""
    resp = auth_client.get("/api/backup/export")
    assert resp.status_code == 200
    assert resp.mimetype == "application/zip"
    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        assert "backup.json" in zf.namelist()


def test_backup_export_import_roundtrip_restores_notebook(auth_client):
    """Собираем архив вручную (реальный `/api/backup/export` в песочнице
    `pytest` сам ничего не кладёт — см. `test_backup_export_produces_valid_zip`)
    и разворачиваем через `/api/backup/import`: проверяем именно то, что
    касается задачи 37 — restore зовёт `notebook_load()`, `diy_load()`,
    `music_load()` из уже переехавших blueprint'ов, а не из app.py, и блокнот
    после импорта отражает содержимое архива."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("backup.json", "{}")
        zf.writestr("data/notebook.json", '{"pages": [{"id": "p9", "name": "Из копии"}], '
                                          '"entries": {}}')
    archive.seek(0)

    resp = auth_client.post(
        "/api/backup/import",
        data={"file": (archive, "backup.zip")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["files"] == 1

    pages = {p["id"]: p["name"] for p in auth_client.get("/api/notebook").get_json()["pages"]}
    assert pages == {"p9": "Из копии"}


def test_backup_import_rejects_non_backup_zip(auth_client):
    fake = io.BytesIO()
    with zipfile.ZipFile(fake, "w") as zf:
        zf.writestr("hello.txt", "не копия сайта")
    fake.seek(0)
    resp = auth_client.post(
        "/api/backup/import",
        data={"file": (fake, "not-a-backup.zip")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_sebastian_page_opens_for_guest(client):
    assert client.get("/sebastian").status_code == 200


def test_sebastian_state_not_ready_without_ollama(client):
    body = client.get("/api/sebastian/state").get_json()
    assert body["ready"] is False


def test_sebastian_ask_fails_gracefully_without_ollama(client):
    resp = client.post("/api/sebastian/ask", json={"text": "Привет!"})
    assert resp.status_code == 503
    assert resp.get_json().get("error")
