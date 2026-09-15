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
