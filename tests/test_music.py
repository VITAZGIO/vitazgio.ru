"""Фонотека и движок плеера.

Про ETag на `/vg-player.js` в CLAUDE.md есть отдельная заметка: без
перепроверки версии свежая страница зовёт метод, которого ещё нет в
закэшированном у браузера старом движке, и кнопки молча перестают
работать. Поэтому заголовки тут проверяются построчно.
"""

import hashlib
import io
import sys
from pathlib import Path

import pytest

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "vg_player.js.tpl"


@pytest.fixture(autouse=True)
def reset_music(app_module):
    """`music_items`/`music_folders` — модульное состояние `blueprints.music`
    (задача 36: файл владеет своим состоянием сам, не `app.py`), живёт весь
    сеанс — сбрасываем перед каждым тестом, как в tests/test_home.py."""
    music_module = sys.modules["blueprints.music"]
    with music_module.music_lock:
        music_module.music_items.clear()
        music_module.music_folders.clear()


def test_music_api_closed_for_guest(client):
    """Фонотека закрыта целиком — и менять, и слушать.

    Отвечает кодом, а не переадресацией, намеренно: ответ разбирает
    скрипт страницы, редирект он принял бы за успешный ответ.
    """
    resp = client.get("/api/music")
    assert resp.status_code == 403
    assert resp.get_json().get("error")


def test_music_page_closed_for_guest(client):
    assert client.get("/music").status_code == 302


def test_music_api_opens_for_owner(auth_client):
    resp = auth_client.get("/api/music")
    assert resp.status_code == 200
    body = resp.get_json()
    for field in ("tracks", "folders", "used", "quota"):
        assert field in body


def test_player_js_etag_matches_template(client):
    """ETag обязан быть md5 от самого шаблона движка.

    Считаем хэш здесь заново, из файла в репозитории, — тогда правка
    шаблона без смены ETag (или наоборот) сразу видна.
    """
    resp = client.get("/vg-player.js")
    assert resp.status_code == 200
    assert resp.data

    expected = hashlib.md5(TEMPLATE.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    assert resp.headers["ETag"] == f'"{expected}"'
    # Без no-cache браузер не переспросит и останется на старом движке.
    assert "no-cache" in resp.headers["Cache-Control"]


def test_player_js_revalidates(client):
    """С тем же ETag сервер обязан ответить 304, а не отдать тело заново."""
    first = client.get("/vg-player.js")
    etag = first.headers["ETag"]

    again = client.get("/vg-player.js", headers={"If-None-Match": etag})
    assert again.status_code == 304
    assert not again.data

    # А на чужой ETag — полное тело: значит, версия действительно сверяется.
    stale = client.get("/vg-player.js", headers={"If-None-Match": '"устаревший"'})
    assert stale.status_code == 200
    assert stale.data == first.data


def test_player_js_is_public(client):
    """Движок отдаётся без пароля: его тянет и окно `/player/pop`, и
    страницы, которые сами по себе гостю доступны."""
    assert client.get("/vg-player.js").status_code == 200


def test_upload_rename_and_delete_track(auth_client):
    resp = auth_client.post(
        "/api/music",
        data={"file": (io.BytesIO(b"fake mp3 bytes"), "Artist - Song.mp3")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["artist"] == "Artist"
    assert body["title"] == "Song"
    track_id = body["id"] if "id" in body else None

    tracks = auth_client.get("/api/music").get_json()["tracks"]
    assert len(tracks) == 1
    track_id = track_id or tracks[0]["id"]

    resp = auth_client.patch(f"/api/music/{track_id}", json={"title": "Переименовано"})
    assert resp.status_code == 200
    tracks = auth_client.get("/api/music").get_json()["tracks"]
    assert tracks[0]["title"] == "Переименовано"

    resp = auth_client.delete(f"/api/music/{track_id}")
    assert resp.status_code == 200
    assert auth_client.get("/api/music").get_json()["tracks"] == []


def test_upload_rejects_non_music_extension(auth_client):
    resp = auth_client.post(
        "/api/music",
        data={"file": (io.BytesIO(b"not music"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 415


def test_folder_create_and_fav_toggle(auth_client):
    resp = auth_client.post("/api/music/folder", json={"name": "Рок"})
    assert resp.status_code == 200
    folder_id = resp.get_json()["id"]

    folders = auth_client.get("/api/music").get_json()["folders"]
    assert folders[0]["fav"] is False

    resp = auth_client.patch(f"/api/music/folder/{folder_id}", json={"fav": True})
    assert resp.status_code == 200
    assert resp.get_json()["fav"] is True

    folders = auth_client.get("/api/music").get_json()["folders"]
    assert folders[0]["fav"] is True

    resp = auth_client.delete(f"/api/music/folder/{folder_id}")
    assert resp.status_code == 200
    assert auth_client.get("/api/music").get_json()["folders"] == []


def test_player_tracks_uses_favorite_folder_by_default(auth_client):
    """`/api/player/tracks` без параметра играет избранную папку — задача
    датируется до задачи 36, но теперь и данные, и хендлер в одном файле."""
    folder_id = auth_client.post("/api/music/folder",
                                  json={"name": "Избранное"}).get_json()["id"]
    auth_client.patch(f"/api/music/folder/{folder_id}", json={"fav": True})

    auth_client.post("/api/music", data={
        "file": (io.BytesIO(b"in favorite"), "In - Favorite.mp3"),
    }, content_type="multipart/form-data")
    track_id = auth_client.get("/api/music").get_json()["tracks"][0]["id"]
    auth_client.patch(f"/api/music/{track_id}", json={"folder": folder_id})

    auth_client.post("/api/music", data={
        "file": (io.BytesIO(b"outside"), "Out - Side.mp3"),
    }, content_type="multipart/form-data")

    body = auth_client.get("/api/player/tracks").get_json()
    assert body["fav"] == folder_id
    titles = {t["title"] for t in body["tracks"]}
    assert titles == {"Favorite"}
