"""Фонотека и движок плеера.

Про ETag на `/vg-player.js` в CLAUDE.md есть отдельная заметка: без
перепроверки версии свежая страница зовёт метод, которого ещё нет в
закэшированном у браузера старом движке, и кнопки молча перестают
работать. Поэтому заголовки тут проверяются построчно.
"""

import hashlib
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "vg_player.js.tpl"


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
