"""Телефонный агент — приём вебсокета, реестр живых и статус на /netbird.

Настоящего вебсокета тут нет: сокет подменён фальшивкой, как paramiko в
`tests/test_files.py`. Разговор с агентом живёт отдельной функцией
(`handle_agent` на blueprint'е), поэтому его можно позвать напрямую — без
сети, без сервера и без ожиданий на настоящих таймаутах.
"""

import json
import os
import queue
import threading
import time

import pytest

AGENT_TOKEN = "test-agent-token"       # тот же, что conftest кладёт в окружение
MOBILA_IP = "100.104.86.103"


class FakeWs:
    """Сокет из двух очередей: что прислал «телефон» и что ушло ему."""

    def __init__(self, incoming=()):
        self.inbox = queue.Queue()
        self.sent = []
        self.closed = False
        for message in incoming:
            self.inbox.put(message)

    def push(self, payload):
        self.inbox.put(payload if isinstance(payload, str) else json.dumps(payload))

    def receive(self, timeout=None):
        if self.closed:
            raise ConnectionError("сокет закрыт")
        try:
            # Ждём не весь запрошенный таймаут (он у сервера 15-25 секунд),
            # а чуть-чуть: тест не должен стоять там, где стоит телефон.
            return self.inbox.get(timeout=0.25 if timeout else None)
        except queue.Empty:
            return None

    def send(self, message):
        if self.closed:
            raise ConnectionError("сокет закрыт")
        self.sent.append(message)

    def close(self):
        self.closed = True

    def types(self):
        out = []
        for raw in self.sent:
            try:
                out.append(json.loads(raw).get("type"))
            except ValueError:
                pass
        return out


@pytest.fixture
def phone_bp(app_module):
    return app_module.app.blueprints["phone"]


def _run(phone_bp, ws):
    """Разговор в отдельном потоке — как он и живёт в настоящем сервере."""
    thread = threading.Thread(target=phone_bp.handle_agent, args=(ws,), kwargs={"peer": "1.2.3.4"})
    thread.daemon = True
    thread.start()
    return thread


def _wait(check, limit=3.0):
    deadline = time.time() + limit
    while time.time() < deadline:
        if check():
            return True
        time.sleep(0.02)
    return False


def _hello(token=AGENT_TOKEN, **extra):
    return json.dumps({"type": "hello", "token": token, "agent": "тест", **extra})


def test_wrong_token_is_shown_the_door(phone_bp):
    ws = FakeWs([_hello(token="не тот токен")])
    _run(phone_bp, ws).join(3)
    assert ws.closed, "чужой токен обязан закрывать сокет"
    assert phone_bp.agent_snapshot()["online"] is False
    assert ws.types() == [], "до hello-ok дело доходить не должно"


def test_message_that_is_not_hello_is_shown_the_door(phone_bp):
    ws = FakeWs(['{"type": "ping"}'])
    _run(phone_bp, ws).join(3)
    assert ws.closed
    assert phone_bp.agent_snapshot()["online"] is False


def test_garbage_instead_of_hello_is_shown_the_door(phone_bp):
    ws = FakeWs(["это не json"])
    _run(phone_bp, ws).join(3)
    assert ws.closed
    assert phone_bp.agent_snapshot()["online"] is False


def test_agent_appears_in_registry_and_leaves_it(phone_bp, auth_client):
    ws = FakeWs([_hello(version=4)])
    thread = _run(phone_bp, ws)

    assert _wait(lambda: phone_bp.agent_snapshot()["online"]), "агент не попал в реестр"
    snapshot = phone_bp.agent_snapshot()
    assert snapshot["agents"][0]["name"] == "тест"
    assert snapshot["agents"][0]["version"] == 4
    assert "hello-ok" in ws.types()

    # Страница /netbird берёт статус отсюда же — телефон должен быть онлайн.
    status = auth_client.get("/api/netbird/status").get_json()
    assert status[MOBILA_IP]["online"] is True
    assert status[MOBILA_IP]["latency_ms"] is None, "у вебсокета задержку никто не мерит"

    ws.close()                         # телефон уехал в тоннель
    thread.join(3)
    assert not thread.is_alive()
    assert phone_bp.agent_snapshot()["online"] is False
    status = auth_client.get("/api/netbird/status").get_json()
    assert status[MOBILA_IP]["online"] is False
    assert status[MOBILA_IP]["last_seen"], "момент последней связи должен остаться"


def test_silence_earns_a_ping_and_a_pong_is_answered(phone_bp):
    ws = FakeWs([_hello()])
    thread = _run(phone_bp, ws)
    assert _wait(lambda: "ping" in ws.types()), "молчащему агенту сервер обязан слать ping"

    ws.push({"type": "ping", "t": 7})
    assert _wait(lambda: "pong" in ws.types()), "на ping агента сервер отвечает pong"
    ws.close()
    thread.join(3)


def test_phone_agent_api_is_behind_the_door(client, auth_client):
    assert client.get("/api/phone/agent").status_code in (302, 401, 403)
    payload = auth_client.get("/api/phone/agent").get_json()
    assert payload["ip"] == MOBILA_IP
    assert payload["configured"] is True


def test_mobila_has_no_vnc_anymore(app_module, auth_client):
    assert MOBILA_IP not in app_module.vnc_enabled_ips
    page = auth_client.get("/netbird").get_data(as_text=True)
    row = page.split(f'data-ip="{MOBILA_IP}"', 1)[1].split("</li>", 1)[0]
    assert 'data-type="vnc"' not in row, "VNC на телефон не работает и работать не может"


def test_phone_is_not_pinged(app_module):
    assert MOBILA_IP in app_module.PING_SKIP_IPS


# ---- Раздача сборки ---------------------------------------------------------

def test_app_download_needs_login(client):
    assert client.get("/app").status_code in (302, 401, 403)


def test_version_is_zero_until_there_is_a_build(auth_client):
    payload = auth_client.get("/api/app/version").get_json()
    assert payload["version"] == 0
    assert payload["url"] is None
    assert auth_client.get("/app").status_code == 404


def test_freshest_build_wins_and_downloads(app_module, auth_client):
    directory = app_module.PHONE_APK_DIR
    builds = {"vg-agent-3.apk": b"old build", "vg-agent-11.apk": b"fresh build"}
    for name, body in builds.items():
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(body)
    try:
        payload = auth_client.get("/api/app/version").get_json()
        assert payload["version"] == 11, "11 новее 3, хотя строкой меньше"
        assert payload["url"] == "/app"
        assert payload["name"] == "vg-agent-11.apk"
        assert payload["size"] == len(builds["vg-agent-11.apk"])

        download = auth_client.get("/app")
        assert download.status_code == 200
        assert download.data == builds["vg-agent-11.apk"]
    finally:
        for name in builds:
            os.remove(os.path.join(directory, name))


def test_agent_token_opens_the_version_check(client):
    """Самообновлению неоткуда взять куку сессии — пускаем по токену."""
    assert client.get("/api/app/version").status_code == 403
    ok = client.get("/api/app/version", headers={"X-Agent-Token": AGENT_TOKEN})
    assert ok.status_code == 200
    bad = client.get("/api/app/version", headers={"X-Agent-Token": "не тот токен"})
    assert bad.status_code == 403


# ---- Токены устройств (ступень 2: оболочка-браузер) -------------------------

def test_token_issue_is_behind_the_door(client):
    assert client.post("/api/phone/token").status_code in (302, 401, 403)
    assert client.get("/api/phone/tokens").status_code in (302, 401, 403)
    assert client.delete("/api/phone/token/whatever").status_code in (302, 401, 403)


def test_issued_token_opens_the_socket_and_revoked_one_does_not(phone_bp, auth_client, app_module):
    issued = auth_client.post("/api/phone/token", json={"label": "Tecno"}).get_json()
    assert issued["token"] and issued["id"]

    # Секрет ушёл ровно один раз: в списке его нет, на диске — только хэш.
    listed = auth_client.get("/api/phone/tokens").get_json()["tokens"]
    row = next(r for r in listed if r["id"] == issued["id"])
    assert row["label"] == "Tecno"
    assert row["last_used"] is None
    assert "token" not in row and "hash" not in row
    with open(app_module.PHONE_TOKENS_PATH, encoding="utf-8") as handle:
        on_disk = handle.read()
    assert issued["token"] not in on_disk, "сырой токен на диск попадать не должен"

    ws = FakeWs([_hello(token=issued["token"], agent="Tecno")])
    thread = _run(phone_bp, ws)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"]), "личный токен обязан пускать"
    ws.close()
    thread.join(3)

    # Подключение отметилось на самом токене — видно, какой из них живой.
    row = next(r for r in auth_client.get("/api/phone/tokens").get_json()["tokens"]
               if r["id"] == issued["id"])
    assert row["last_used"], "после подключения у токена должна быть отметка"

    assert auth_client.delete(f"/api/phone/token/{issued['id']}").status_code == 200
    assert auth_client.delete(f"/api/phone/token/{issued['id']}").status_code == 404

    dead = FakeWs([_hello(token=issued["token"])])
    _run(phone_bp, dead).join(3)
    assert dead.closed, "отозванный токен пускать нельзя"
    assert phone_bp.agent_snapshot()["online"] is False


def test_shared_env_token_still_works_next_to_device_tokens(phone_bp, auth_client):
    auth_client.post("/api/phone/token", json={"label": "лишний"})
    ws = FakeWs([_hello()])                      # тот самый общий из .env
    thread = _run(phone_bp, ws)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"])
    ws.close()
    thread.join(3)


def test_cabinet_asks_the_bridge_for_a_token(auth_client):
    page = auth_client.get("/cabinet").get_data(as_text=True)
    assert "window.VGPhone" in page
    assert "/api/phone/token" in page


# ---- Экран телефона (ступень 3) ---------------------------------------------
# Настоящего H.264 тут нет и не нужно: сайт — мост, он кадры не разбирает.
# Проверяем ровно то, за что он отвечает: гейт, пересылку и поведение, когда
# одна из сторон отвалилась.

def _frame(kind, payload=b"nal", stamp=0):
    """Кадр в том же виде, в каком его шлёт телефон: тип, метка времени
    (8 байт big-endian), дальше Annex-B."""
    return bytes([kind]) + stamp.to_bytes(8, "big") + payload


def _viewer(phone_bp, ws):
    thread = threading.Thread(target=phone_bp.handle_viewer, args=(ws,))
    thread.daemon = True
    thread.start()
    return thread


def _received(ws, kind_byte, limit=3.0):
    """Дождаться двоичного кадра нужного типа среди присланного зрителю."""
    deadline = time.time() + limit
    while time.time() < deadline:
        for item in list(ws.sent):
            if isinstance(item, (bytes, bytearray)) and item[:1] == bytes([kind_byte]):
                return bytes(item)
        time.sleep(0.02)
    return None


def _messages(ws, kind):
    out = []
    for item in ws.sent:
        if not isinstance(item, str):
            continue
        try:
            payload = json.loads(item)
        except ValueError:
            continue
        if payload.get("type") == kind:
            out.append(payload)
    return out


def test_phone_page_is_behind_the_door(client, auth_client):
    assert client.get("/phone").status_code in (302, 401, 403)
    page = auth_client.get("/phone").get_data(as_text=True)
    assert "Экран телефона" in page
    # Суточный пароль ещё не вводили — страница обязана спросить его сама.
    assert '"{{CONSOLE_OK}}"' not in page, "заглушка шаблона должна быть подставлена"
    assert 'const consoleOk = "0"' in page


def test_viewer_socket_needs_console_password(app_module):
    """Гейт как у консоли: одного пароля кабинета мало."""
    c = app_module.app.test_client()
    with c.session_transaction() as session:
        session["authenticated"] = True         # вошёл, но консольного пароля нет
    page = c.get("/phone").get_data(as_text=True)
    assert 'const consoleOk = "0"' in page


def test_frames_travel_from_agent_to_viewer(phone_bp):
    agent = FakeWs([_hello()])
    agent_thread = _run(phone_bp, agent)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"])

    viewer = FakeWs()
    viewer_thread = _viewer(phone_bp, viewer)
    assert _wait(lambda: phone_bp.screen_snapshot()["viewers"] == 1)

    # Зритель просит показать экран — телефон получает команду, а не отказ.
    viewer.push({"type": "start"})
    assert _wait(lambda: any(t == "screen-start" for t in agent.types()))
    assert _messages(viewer, "asked")[0]["ok"] is True

    # Телефон подтвердил захват, прислал параметры кодека и два кадра.
    agent.push({"type": "screen-state", "running": True, "width": 1080, "height": 2400})
    assert _wait(lambda: phone_bp.screen_snapshot()["running"])
    agent.inbox.put(_frame(1, b"sps-pps"))
    agent.inbox.put(_frame(2, b"keyframe", 1000))
    agent.inbox.put(_frame(3, b"delta", 2000))

    assert _received(viewer, 1), "параметры кодека обязаны дойти"
    assert _received(viewer, 2), "опорный кадр обязан дойти"
    assert _received(viewer, 3), "разностный кадр обязан дойти"
    assert _received(viewer, 2).endswith(b"keyframe")

    viewer.close()
    viewer_thread.join(3)
    # Зрителей не осталось — телефону сказано не кодировать в пустоту.
    assert _wait(lambda: "screen-pause" in agent.types())

    agent.close()
    agent_thread.join(3)


def test_late_viewer_gets_config_and_a_fresh_keyframe(phone_bp):
    agent = FakeWs([_hello()])
    agent_thread = _run(phone_bp, agent)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"])
    agent.push({"type": "screen-state", "running": True, "width": 720, "height": 1600})
    assert _wait(lambda: phone_bp.screen_snapshot()["running"])
    agent.inbox.put(_frame(1, b"sps-pps"))
    time.sleep(0.2)

    late = FakeWs()
    late_thread = _viewer(phone_bp, late)
    # Пришёл посреди трансляции: сперва параметры (иначе декодер не заведётся),
    # потом просьба телефону дать опорный кадр — без него была бы каша.
    assert _received(late, 1), "опоздавший зритель обязан получить параметры кодека"
    assert _wait(lambda: "screen-key" in agent.types())

    late.close()
    late_thread.join(3)
    agent.close()
    agent_thread.join(3)


def test_viewer_without_agent_is_told_the_truth(phone_bp):
    assert phone_bp.agent_snapshot()["online"] is False
    viewer = FakeWs()
    thread = _viewer(phone_bp, viewer)
    viewer.push({"type": "start"})
    assert _wait(lambda: _messages(viewer, "asked"))
    asked = _messages(viewer, "asked")[0]
    assert asked["ok"] is False
    assert "не на связи" in asked["error"].lower()
    viewer.close()
    thread.join(3)


def test_agent_leaving_drops_the_screen_state(phone_bp):
    agent = FakeWs([_hello()])
    agent_thread = _run(phone_bp, agent)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"])
    agent.push({"type": "screen-state", "running": True, "width": 720, "height": 1600})
    assert _wait(lambda: phone_bp.screen_snapshot()["running"])

    viewer = FakeWs()
    viewer_thread = _viewer(phone_bp, viewer)
    assert _wait(lambda: phone_bp.screen_snapshot()["viewers"] == 1)

    agent.close()
    agent_thread.join(3)
    # Телефон пропал — зритель обязан узнать об этом, а не смотреть в
    # застывший кадр и гадать.
    assert _wait(lambda: phone_bp.screen_snapshot()["running"] is False)
    assert _wait(lambda: any(m.get("agent") is False for m in _messages(viewer, "state")))
    viewer.close()
    viewer_thread.join(3)


def test_unknown_message_from_agent_does_not_break_the_talk(phone_bp):
    """Неизвестный тип агент и сайт игнорируют, а не падают."""
    agent = FakeWs([_hello()])
    thread = _run(phone_bp, agent)
    assert _wait(lambda: phone_bp.agent_snapshot()["online"])
    agent.push({"type": "нечто-невиданное", "payload": 1})
    agent.push({"type": "ping", "t": 5})
    assert _wait(lambda: "pong" in agent.types()), "разговор должен продолжаться"
    agent.close()
    thread.join(3)
