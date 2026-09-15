"""Файлы телефона под той же страницей /files.

Приём тот же, что у фальшивого paramiko в `tests/test_files.py`, только
подменяется не SSH, а сам телефон: фальшивый агент держит «телефон» обычной
временной папкой и отвечает на команды по тому же протоколу, что настоящий.
В сеть тесты не ходят.

Смысл этих тестов — не столько проверить операции (их логика на странице та
же), сколько убедиться, что интерфейс двух бэкендов выбран правильно:
страница, её вёрстка и её API остались нетронутыми.
"""

import json
import os
import shutil
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

PHONE_IP = "100.104.86.103"
AGENT_TOKEN = "test-agent-token"

FRAME_FILE = 4


class FakeWs:
    """Тот же фальшивый сокет, что и в tests/test_phone.py."""

    def __init__(self, incoming=()):
        import queue
        self.inbox = queue.Queue()
        self.sent = []
        self.closed = False
        self._lock = threading.Lock()
        for message in incoming:
            self.inbox.put(message)

    def push(self, payload):
        self.inbox.put(payload if isinstance(payload, str) else json.dumps(payload))

    def receive(self, timeout=None):
        import queue
        if self.closed:
            raise ConnectionError("сокет закрыт")
        try:
            return self.inbox.get(timeout=0.2 if timeout else None)
        except queue.Empty:
            return None

    def send(self, message):
        if self.closed:
            raise ConnectionError("сокет закрыт")
        with self._lock:
            self.sent.append(message)

    def close(self):
        self.closed = True


class FakeAgent:
    """«Телефон»: обычная папка плюс разбор команд файловой части протокола."""

    def __init__(self, ws, root):
        self.ws = ws
        self.root = Path(root)
        self.seen = 0
        self.writes = {}          # id -> открытый файл
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            with self.ws._lock:
                fresh = self.ws.sent[self.seen:]
                self.seen = len(self.ws.sent)
            for item in fresh:
                try:
                    self._handle(item)
                except Exception as exc:                     # pragma: no cover
                    print("фальшивый агент споткнулся:", exc)
            time.sleep(0.01)

    def _real(self, path):
        return self.root / str(path).lstrip("/")

    def _handle(self, item):
        if isinstance(item, (bytes, bytearray)):
            if item[:1] != bytes([FRAME_FILE]):
                return                                       # кадр экрана, не наше
            call_id = int.from_bytes(item[1:5], "big")
            handle = self.writes.get(call_id)
            if handle:
                handle.write(item[5:])
            return
        try:
            payload = json.loads(item)
        except ValueError:
            return
        if payload.get("type") != "fs":
            return
        call_id = payload["id"]
        op = payload.get("op")
        path = payload.get("path")
        try:
            if op == "home":
                self._reply(call_id, path=str("/"))
            elif op == "list":
                rows = []
                for child in sorted(self._real(path).iterdir()):
                    info = child.stat()
                    rows.append({"name": child.name, "dir": child.is_dir(),
                                 "size": info.st_size, "mtime": int(info.st_mtime)})
                self._reply(call_id, entries=rows)
            elif op == "stat":
                target = self._real(path)
                info = target.stat()
                self._reply(call_id, dir=target.is_dir(), size=info.st_size,
                            mtime=int(info.st_mtime))
            elif op == "read":
                self._reply(call_id)
                self._pour(call_id, self._real(path), int(payload.get("chunk") or 65536))
            elif op == "write":
                self.writes[call_id] = open(self._real(path), "wb")
                self._reply(call_id)
            elif op == "write-end":
                handle = self.writes.pop(call_id, None)
                if handle:
                    handle.close()
                self._reply(call_id)
            elif op == "cancel":
                pass
            elif op == "mkdir":
                self._real(path).mkdir()
                self._reply(call_id)
            elif op == "rename":
                self._real(path).rename(self._real(payload.get("to")))
                self._reply(call_id)
            elif op == "remove":
                self._real(path).unlink()
                self._reply(call_id)
            elif op == "rmdir":
                target = self._real(path)
                if any(target.iterdir()):
                    self._fail(call_id, "Папка не пуста.", "not-empty")
                    return
                target.rmdir()
                self._reply(call_id)
        except FileNotFoundError:
            self._fail(call_id, "Не найдено.", "not-found")
        except FileExistsError:
            self._fail(call_id, "Уже есть.", "exists")
        except PermissionError:
            self._fail(call_id, "Нет доступа.", "denied")

    def _pour(self, call_id, path, chunk):
        with open(path, "rb") as handle:
            while True:
                piece = handle.read(chunk)
                if not piece:
                    break
                self.ws.push_binary(bytes([FRAME_FILE]) + call_id.to_bytes(4, "big") + piece)
        self.ws.push({"type": "fs-reply", "id": call_id, "ok": True, "eof": True})

    def _reply(self, call_id, **extra):
        self.ws.push({"type": "fs-reply", "id": call_id, "ok": True, **extra})

    def _fail(self, call_id, text, code):
        self.ws.push({"type": "fs-reply", "id": call_id, "ok": False,
                      "error": text, "code": code})

    def shut(self):
        self.stop.set()


def _push_binary(self, data):
    """Двоичное сообщение «от телефона» — тем же путём, что и текстовые."""
    self.inbox.put(data)


FakeWs.push_binary = _push_binary


@pytest.fixture
def phone_files(app_module):
    """Телефон на связи, «его» файлы — во временной папке."""
    phone_bp = app_module.app.blueprints["phone"]
    root = Path(app_module.DATA_DIR) / "fake-phone"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    (root / "DCIM").mkdir()
    (root / "DCIM" / "снимок.jpg").write_bytes(b"photo bytes" * 100)
    (root / "заметка.txt").write_text("привет", encoding="utf-8")

    ws = FakeWs([json.dumps({"type": "hello", "token": AGENT_TOKEN, "agent": "тест"})])
    talk = threading.Thread(target=phone_bp.handle_agent, args=(ws,), daemon=True)
    talk.start()
    deadline = time.time() + 3
    while time.time() < deadline and not phone_bp.agent_snapshot()["online"]:
        time.sleep(0.02)
    agent = FakeAgent(ws, root)
    # Отдаём и папку, и сам сокет: одному тесту нужно оборвать связь на
    # середине работы — ровно так, как это делает уехавший в тоннель телефон.
    yield SimpleNamespace(root=root, ws=ws)
    agent.shut()
    ws.close()
    talk.join(3)
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def phone_client(app_module, phone_files):
    """Хозяин, вошедший и в кабинет, и в консоль: тот же гейт, что у SFTP."""
    from tests.conftest import TEST_PASSWORD
    c = app_module.app.test_client()
    c.post("/api/login", json={"password": TEST_PASSWORD})
    with c.session_transaction() as session:
        session["console_authenticated"] = True
    return c


def test_phone_now_has_a_files_page(phone_client):
    """Кнопка «СКОРО» стала живой: страница у телефона есть."""
    resp = phone_client.get(f"/files/{PHONE_IP}")
    assert resp.status_code == 200
    assert "MOBILA" in resp.get_data(as_text=True)


def test_page_opens_without_asking_for_a_password(phone_client):
    """SSH на телефоне нет — спрашивать логин не у кого, и страница его не
    спросит: соединение поднято сервером, /api/files/session его видит."""
    phone_client.get(f"/files/{PHONE_IP}")
    data = phone_client.get("/api/files/session").get_json()
    assert data["connected"] is True
    assert data["ip"] == PHONE_IP
    assert data["user"] == "агент"


def test_listing_comes_from_the_phone(phone_client):
    phone_client.get(f"/files/{PHONE_IP}")
    rows = phone_client.get("/api/files/list?path=/").get_json()["entries"]
    names = {row["name"]: row for row in rows}
    assert names["DCIM"]["dir"] is True
    assert names["заметка.txt"]["dir"] is False
    assert names["заметка.txt"]["size"] == len("привет".encode("utf-8"))
    # Папки идут первыми — та же сортировка, что и у SFTP-бэкенда.
    assert rows[0]["dir"] is True


def test_download_streams_the_file(phone_client, phone_files):
    phone_client.get(f"/files/{PHONE_IP}")
    resp = phone_client.get("/api/files/download?path=/DCIM/снимок.jpg")
    assert resp.status_code == 200
    assert resp.data == (phone_files.root / "DCIM" / "снимок.jpg").read_bytes()
    # Тип обязан остаться октетами: gzip иначе собрал бы поток в буфер.
    assert resp.headers["Content-Type"].startswith("application/octet-stream")


def test_upload_arrives_in_chunks(phone_client, phone_files):
    """С ПК летит фильм — телефон принимает его кусками, а не целиком."""
    phone_client.get(f"/files/{PHONE_IP}")
    body = os.urandom(700_000)          # больше одного куска, как настоящий фильм
    resp = phone_client.post(
        "/api/files/upload?path=/&name=кино.mp4",
        data=body, content_type="application/octet-stream",
    )
    assert resp.status_code == 200, resp.data
    assert resp.get_json()["size"] == len(body)
    assert (phone_files.root / "кино.mp4").read_bytes() == body


def test_rename_and_delete(phone_client, phone_files):
    phone_client.get(f"/files/{PHONE_IP}")
    resp = phone_client.post("/api/files/op", json={
        "op": "rename", "path": "/заметка.txt", "name": "переименованная.txt",
    })
    assert resp.status_code == 200, resp.data
    assert (phone_files.root / "переименованная.txt").exists()

    resp = phone_client.post("/api/files/op", json={
        "op": "delete", "path": "/переименованная.txt",
    })
    assert resp.status_code == 200, resp.data
    assert not (phone_files.root / "переименованная.txt").exists()


def test_folder_with_files_asks_before_deleting(phone_client):
    """Та же защита, что у SFTP: непустую папку с первого раза не сносим."""
    phone_client.get(f"/files/{PHONE_IP}")
    resp = phone_client.post("/api/files/op", json={"op": "delete", "path": "/DCIM"})
    assert resp.status_code == 409
    assert resp.get_json().get("needs_recursive") is True


def test_mkdir(phone_client, phone_files):
    phone_client.get(f"/files/{PHONE_IP}")
    resp = phone_client.post("/api/files/op", json={"op": "mkdir", "path": "/Новая"})
    assert resp.status_code == 200, resp.data
    assert (phone_files.root / "Новая").is_dir()


def test_phone_gone_mid_work_is_an_honest_error(phone_client, phone_files, app_module):
    """Телефон уехал в тоннель — страница обязана получить ошибку, а не
    висеть до упора."""
    phone_client.get(f"/files/{PHONE_IP}")
    phone_bp = app_module.app.blueprints["phone"]
    assert phone_bp.fs.online is True

    phone_files.ws.close()                      # связь оборвалась
    deadline = time.time() + 5
    while time.time() < deadline and phone_bp.fs.online:
        time.sleep(0.05)
    assert phone_bp.fs.online is False, "сервер обязан заметить уход телефона"

    resp = phone_client.get("/api/files/list?path=/")
    assert resp.status_code >= 400
    assert "телефон" in resp.get_json()["error"].lower()


def test_files_page_still_refuses_without_console_password(app_module, phone_files):
    """Гейт тот же, что у остальных машин: одного входа в кабинет мало."""
    from tests.conftest import TEST_PASSWORD
    c = app_module.app.test_client()
    c.post("/api/login", json={"password": TEST_PASSWORD})
    c.get(f"/files/{PHONE_IP}")
    # Соединение без суточного пароля не поднимается, значит страница
    # спросит его сама, как и всегда.
    assert c.get("/api/files/session").get_json()["connected"] is False
    resp = c.post("/api/files/connect", json={"ip": PHONE_IP, "username": "", "password": ""})
    assert resp.status_code == 403
