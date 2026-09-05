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
