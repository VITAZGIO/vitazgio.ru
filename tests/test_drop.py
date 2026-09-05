"""Дроп: доступ и целостность файла.

Дроп — это хранилище чужих и своих файлов. Две вещи, которые дорого
сломать незаметно: он не должен открываться без пароля, и то, что из
него скачали, обязано побайтово совпасть с тем, что загрузили.
"""

from pathlib import Path


def test_drop_page_requires_login(client):
    """Гостя разворачивает на главную, а не показывает содержимое."""
    resp = client.get("/drop")
    assert resp.status_code == 302
    assert "/drop" not in resp.headers["Location"]


def test_drop_api_requires_login(client):
    resp = client.get("/api/drop/list")
    assert resp.status_code == 302


def test_drop_page_opens_for_owner(auth_client):
    resp = auth_client.get("/drop")
    assert resp.status_code == 200
    assert resp.data


def test_upload_then_download_roundtrip(auth_client):
    """Загрузка одним куском и скачивание: содержимое обязано совпасть.

    Байты нарочно не текстовые — так ловится порча из-за кодировок и
    случайного перевода в текстовый режим где-нибудь по дороге.
    """
    payload = bytes(range(256)) * 4 + b"\r\n\x00 \xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2"
    name = "проверка.bin"

    init = auth_client.post("/api/drop/upload/init",
                            json={"name": name, "size": len(payload)})
    assert init.status_code == 200, init.data
    upload_id = init.get_json()["upload_id"]

    chunk = auth_client.post(f"/api/drop/upload/chunk/{upload_id}?offset=0",
                             data=payload,
                             content_type="application/octet-stream")
    assert chunk.status_code == 200, chunk.data
    assert chunk.get_json()["received"] == len(payload)

    finish = auth_client.post(f"/api/drop/upload/finish/{upload_id}")
    assert finish.status_code == 200, finish.data
    item_id = finish.get_json()["id"]

    got = auth_client.get(f"/api/drop/download/{item_id}")
    assert got.status_code == 200
    assert got.data == payload, "скачанное не совпало с загруженным"

    # Файл виден в списке под своим именем и с верным размером: имя живёт
    # только в индексе (на диске он лежит под uuid), и рассинхрон индекса
    # с диском — как раз та поломка, которую снаружи не видно.
    listing = auth_client.get("/api/drop/list").get_json()
    mine = [x for x in listing["items"] if x["id"] == item_id]
    assert len(mine) == 1
    assert mine[0]["name"] == name
    assert mine[0]["size"] == len(payload)


def test_upload_rejects_size_mismatch(auth_client):
    """Заявили один размер, прислали другой — файл не должен сохраниться
    обрезанным: лучше явная ошибка, чем битый файл в хранилище."""
    init = auth_client.post("/api/drop/upload/init",
                            json={"name": "битый.bin", "size": 100})
    upload_id = init.get_json()["upload_id"]

    auth_client.post(f"/api/drop/upload/chunk/{upload_id}?offset=0",
                     data=b"x" * 10, content_type="application/octet-stream")
    finish = auth_client.post(f"/api/drop/upload/finish/{upload_id}")
    assert finish.status_code == 400
    assert finish.get_json().get("error")


def test_download_unknown_id(auth_client):
    resp = auth_client.get("/api/drop/download/нет-такого")
    assert resp.status_code == 404


def test_storage_is_isolated_from_the_repo(app_module):
    """Страховка самой обвязки: тесты обязаны писать во временную папку, а
    не в настоящий дроп и фонотеку. Если изоляция когда-нибудь сломается,
    узнать об этом лучше здесь, чем по пропавшим файлам хозяина."""
    repo = Path(__file__).resolve().parent.parent
    for path in (app_module.DROP_DIR, app_module.DATA_DIR):
        assert repo not in Path(path).resolve().parents, f"{path} внутри репозитория"
