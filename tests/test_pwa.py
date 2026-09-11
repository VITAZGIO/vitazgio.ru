"""Манифест и service worker.

Их почти никто не открывает руками, поэтому поломка тут — самая тихая:
установленное приложение просто перестаёт обновляться или ставиться, а
сайт в браузере выглядит целым.
"""

import json


def test_manifest_served(client):
    resp = client.get("/manifest.webmanifest")
    assert resp.status_code == 200
    # Тип обязателен: с другим браузер манифест молча проигнорирует и
    # предложение «установить приложение» не появится.
    assert resp.mimetype == "application/manifest+json"
    assert resp.data

    manifest = json.loads(resp.data.decode("utf-8"))
    # Без этих полей приложение не устанавливается вовсе.
    assert manifest["name"]
    assert manifest["start_url"]
    assert manifest["icons"]


def test_service_worker_served(client):
    resp = client.get("/sw.js")
    assert resp.status_code == 200
    assert resp.mimetype == "application/javascript"
    assert resp.data
    # Пустой или обрезанный файл браузер принял бы молча, а офлайн-режим
    # и приём «Поделиться» отвалились бы.
    assert b"addEventListener" in resp.data


def test_manifest_and_sw_are_public(client):
    """Оба должны отдаваться гостю: браузер просит их без куки сессии."""
    assert client.get("/manifest.webmanifest").status_code == 200
    assert client.get("/sw.js").status_code == 200


def test_share_target_fallback_lands_in_download_folder(auth_client):
    """Резервный (без сервис-воркера) путь приёма «Поделиться» — тоже в
    Download по умолчанию, тем же местом, что и обычный JS-путь."""
    from io import BytesIO

    resp = auth_client.post("/share-target", data={
        "files": (BytesIO(b"hello from android"), "снимок.jpg"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    assert "saved=1" in resp.headers["Location"]

    rows = {row["name"]: row for row in auth_client.get("/api/drop/list?parent=download").get_json()["items"]}
    assert "снимок.jpg" in rows
    assert rows["снимок.jpg"]["size"] == len(b"hello from android")
