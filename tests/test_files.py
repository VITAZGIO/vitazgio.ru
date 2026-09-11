"""Файлы по SFTP — страница /files/<ip> и её API.

Настоящего SSH тут нет и быть не может: вместо paramiko подставляется
фальшивка, у которой «удалённая машина» — обычная временная папка. Так
проверяется весь путь целиком (гейт по паролям, список, загрузка,
скачивание, переименование, удаление), но в сеть тесты не ходят.
"""

import os
import stat as statmod
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest

DEVICE_IP = "100.104.221.91"      # ubuntu-server: ssh_enabled, значит и SFTP
SSH_PASSWORD = "ssh-pass"


class _Attr(SimpleNamespace):
    pass


class FakeSFTP:
    """Пятая часть SFTPClient — ровно те методы, которыми пользуется код."""

    def __init__(self, root):
        self.root = Path(root)
        self.closed = False

    def _real(self, path):
        return self.root / path.lstrip("/")

    def normalize(self, path):
        return "/"

    def listdir_attr(self, path):
        rows = []
        for child in self._real(path).iterdir():
            info = child.stat()
            rows.append(_Attr(filename=child.name, st_mode=info.st_mode,
                              st_size=info.st_size, st_mtime=int(info.st_mtime)))
        return rows

    def stat(self, path):
        info = self._real(path).stat()
        return _Attr(st_mode=info.st_mode, st_size=info.st_size, st_mtime=int(info.st_mtime))

    def open(self, path, mode="rb"):
        handle = open(self._real(path), mode)
        handle.prefetch = lambda *a, **k: None
        handle.set_pipelined = lambda *a, **k: None
        return handle

    def mkdir(self, path):
        self._real(path).mkdir()

    def rename(self, old, new):
        self._real(old).rename(self._real(new))

    def remove(self, path):
        self._real(path).unlink()

    def rmdir(self, path):
        target = self._real(path)
        if any(target.iterdir()):
            raise OSError(39, "Directory not empty")
        target.rmdir()

    def close(self):
        self.closed = True


class FakeSSHClient:
    root = None

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, ip, username=None, password=None, **kwargs):
        if password != SSH_PASSWORD:
            raise paramiko.AuthenticationException("no")

    def open_sftp(self):
        return FakeSFTP(FakeSSHClient.root)

    def get_transport(self):
        return None

    def close(self):
        pass


@pytest.fixture
def remote_root(tmp_path, monkeypatch):
    """«Машина на том конце»: временная папка + подменённый paramiko."""
    root = tmp_path / "remote"
    root.mkdir()
    (root / "заметки.txt").write_text("привет", encoding="utf-8")
    (root / "проекты").mkdir()

    FakeSSHClient.root = root
    files_module = sys.modules["blueprints.files"]
    monkeypatch.setattr(files_module, "paramiko", SimpleNamespace(
        SSHClient=FakeSSHClient,
        AutoAddPolicy=object,
        AuthenticationException=paramiko.AuthenticationException,
        SSHException=paramiko.SSHException,
    ))
    return root


@pytest.fixture
def sftp_client(auth_client, app_module, remote_root):
    """Хозяин, прошедший пароль консоли и подключённый к «машине»."""
    resp = auth_client.post("/api/console/login",
                            json={"password": app_module.console_password_today()})
    assert resp.status_code == 200, resp.data
    resp = auth_client.post("/api/files/connect", json={
        "ip": DEVICE_IP, "username": "vitaz", "password": SSH_PASSWORD,
    })
    assert resp.status_code == 200, resp.data
    return auth_client


def test_page_closed_for_guest(client):
    assert client.get(f"/files/{DEVICE_IP}").status_code == 302


def test_page_unknown_machine(auth_client):
    """Телефон и винды без SSH в список не входят — страницы для них нет."""
    assert auth_client.get("/files/100.104.86.103").status_code == 404


def test_connect_needs_console_password(auth_client, remote_root):
    resp = auth_client.post("/api/files/connect", json={
        "ip": DEVICE_IP, "username": "vitaz", "password": SSH_PASSWORD,
    })
    assert resp.status_code == 403


def test_connect_rejects_wrong_ssh_password(auth_client, app_module, remote_root):
    auth_client.post("/api/console/login", json={"password": app_module.console_password_today()})
    resp = auth_client.post("/api/files/connect", json={
        "ip": DEVICE_IP, "username": "vitaz", "password": "не тот",
    })
    assert resp.status_code == 401


def test_api_without_connection_asks_to_reconnect(auth_client):
    """Соединение живёт в памяти процесса: пока его нет, страница должна
    получить внятный сигнал «переподключись», а не пустой список."""
    resp = auth_client.get("/api/files/list?path=/")
    assert resp.status_code == 409
    assert resp.get_json().get("reconnect") is True


def test_listing_shows_folders_first(sftp_client):
    resp = sftp_client.get("/api/files/list?path=/")
    assert resp.status_code == 200
    entries = resp.get_json()["entries"]
    assert [e["name"] for e in entries] == ["проекты", "заметки.txt"]
    assert entries[0]["dir"] is True and entries[1]["dir"] is False


def test_upload_then_download_roundtrip(sftp_client, remote_root):
    payload = "содержимое файла".encode("utf-8")
    resp = sftp_client.post("/api/files/upload?path=%2F&name=new.txt", data=payload)
    assert resp.status_code == 200
    assert (remote_root / "new.txt").read_bytes() == payload

    resp = sftp_client.get("/api/files/download?path=%2Fnew.txt")
    assert resp.status_code == 200
    assert resp.data == payload
    # Скачивание не должно попасть под gzip из after_request, иначе поток
    # собрался бы в буфер целиком.
    assert "Content-Encoding" not in resp.headers


def test_upload_name_cannot_escape_folder(sftp_client, remote_root):
    """Имя берётся только как имя: «../» в нём не должно уводить выше."""
    sftp_client.post("/api/files/upload?path=%2Fпроекты&name=..%2Fсбежал.txt", data=b"x")
    assert not (remote_root / "сбежал.txt").exists()
    assert (remote_root / "проекты" / "сбежал.txt").exists()


def test_zip_download_of_folder(sftp_client, remote_root):
    """Папка целиком архивом — тот же приём, что уже работает в дропе."""
    import io
    import zipfile

    (remote_root / "проекты" / "вложенная").mkdir()
    (remote_root / "проекты" / "код.py").write_text("print(1)", encoding="utf-8")

    resp = sftp_client.get("/api/files/zip?path=%2Fпроекты")
    assert resp.status_code == 200
    assert resp.mimetype == "application/zip"
    assert "Content-Encoding" not in resp.headers   # поток не должен уйти в gzip-буфер

    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        names = set(zf.namelist())
        assert "код.py" in names
        assert any(n.startswith("вложенная") for n in names)
        assert zf.read("код.py") == b"print(1)"


def test_zip_rejects_a_plain_file(sftp_client):
    resp = sftp_client.get("/api/files/zip?path=%2Fзаметки.txt")
    assert resp.status_code == 400


# ---- Кнопка VG: перенос файла/папки с машины прямо в личный дроп ----------
# Перенос идёт в фоновом потоке, POST отвечает сразу job_id — страница
# опрашивает /api/files/to-drop/<job_id>, чтобы показать полосу загрузки.

def _wait_job(client, job_id, timeout=5):
    """Ждёт, пока фоновый перенос перестанет быть 'run'. В тестах он занимает
    доли секунды (обычная запись в temp-папку), но всё равно другой поток."""
    deadline = time.time() + timeout
    status = None
    while time.time() < deadline:
        resp = client.get(f"/api/files/to-drop/{job_id}")
        assert resp.status_code == 200
        status = resp.get_json()
        if status["state"] != "run":
            return status
        time.sleep(0.02)
    raise AssertionError(f"задача не завершилась за {timeout}с: {status}")


def test_vg_button_reports_progress_and_lands_in_download_folder(sftp_client):
    start = sftp_client.post("/api/files/to-drop", json={"path": "/заметки.txt"})
    assert start.status_code == 200
    body = start.get_json()
    assert body["kind"] == "file"
    assert body["total"] == len("привет".encode("utf-8"))
    job_id = body["job"]

    status = _wait_job(sftp_client, job_id)
    assert status["state"] == "done"
    assert status["done"] == body["total"]

    rows = {row["name"]: row for row in sftp_client.get("/api/drop/list?parent=download").get_json()["items"]}
    assert "заметки.txt" in rows
    assert rows["заметки.txt"]["size"] == len("привет".encode("utf-8"))


def test_to_drop_job_status_unknown_id(sftp_client):
    assert sftp_client.get("/api/files/to-drop/нет-такой-задачи").status_code == 404


def test_vg_button_sends_folder_recursively(sftp_client, remote_root):
    (remote_root / "проекты" / "вложенная").mkdir()
    (remote_root / "проекты" / "код.py").write_text("print(1)", encoding="utf-8")

    start = sftp_client.post("/api/files/to-drop", json={"path": "/проекты"})
    assert start.status_code == 200
    body = start.get_json()
    assert body["kind"] == "folder"

    status = _wait_job(sftp_client, body["job"])
    assert status["state"] == "done"

    top = {row["name"]: row for row in sftp_client.get("/api/drop/list?parent=download").get_json()["items"]}
    assert top["проекты"]["kind"] == "folder"
    folder_id = top["проекты"]["id"]

    inside = {row["name"]: row for row in sftp_client.get(f"/api/drop/list?parent={folder_id}").get_json()["items"]}
    assert inside["код.py"]["kind"] == "file"
    assert inside["вложенная"]["kind"] == "folder"


def test_vg_button_respects_drop_quota(sftp_client, app_module):
    """Квота дропа общая — перенос с машины не должен обходить лимит,
    который соблюдает обычная загрузка через браузер. Забиваем квоту одной
    синтетической записью прямо в drop_items — тот же словарь, на который
    смотрит _drop_used(), так что менять реальные 30 ГБ не нужно.

    app_module общий на весь прогон тестов (сессионная фикстура) — запись
    убираем сами, иначе квота останется «забитой» для тестов после этого."""
    before = {row["id"] for row in sftp_client.get("/api/drop/list?parent=download").get_json()["items"]}
    with app_module.drop_lock:
        app_module.drop_items["huge-for-test"] = {
            "kind": "file", "name": "huge.bin", "parent": None,
            "content_type": "application/octet-stream",
            "size": app_module.DROP_QUOTA, "created": 0, "share": None,
        }
    try:
        start = sftp_client.post("/api/files/to-drop", json={"path": "/заметки.txt"})
        assert start.status_code == 200          # задача стартует всегда — квоту проверяет фон
        status = _wait_job(sftp_client, start.get_json()["job"])
        assert status["state"] == "error"
        assert "квота" in status["error"].lower()

        after = {row["id"] for row in sftp_client.get("/api/drop/list?parent=download").get_json()["items"]}
        assert after == before   # ничего нового не появилось — отказ не наполовину
    finally:
        with app_module.drop_lock:
            app_module.drop_items.pop("huge-for-test", None)


def test_vg_button_requires_connection(auth_client):
    resp = auth_client.post("/api/files/to-drop", json={"path": "/заметки.txt"})
    assert resp.status_code == 409
    assert resp.get_json().get("reconnect") is True


def test_rename_and_delete(sftp_client, remote_root):
    resp = sftp_client.post("/api/files/op", json={
        "op": "rename", "path": "/заметки.txt", "name": "другое.txt",
    })
    assert resp.status_code == 200
    assert (remote_root / "другое.txt").exists()

    resp = sftp_client.post("/api/files/op", json={"op": "delete", "path": "/другое.txt"})
    assert resp.status_code == 200
    assert not (remote_root / "другое.txt").exists()


def test_mkdir(sftp_client, remote_root):
    resp = sftp_client.post("/api/files/op", json={"op": "mkdir", "path": "/новая"})
    assert resp.status_code == 200
    assert (remote_root / "новая").is_dir()


def test_full_folder_asks_before_wiping(sftp_client, remote_root):
    """Непустую папку с первого раза не сносим: сперва вопрос человеку."""
    (remote_root / "проекты" / "файл.txt").write_text("тут что-то есть", encoding="utf-8")

    resp = sftp_client.post("/api/files/op", json={"op": "delete", "path": "/проекты"})
    assert resp.status_code == 409
    assert resp.get_json().get("needs_recursive") is True
    assert (remote_root / "проекты").exists()

    resp = sftp_client.post("/api/files/op",
                            json={"op": "delete", "path": "/проекты", "recursive": True})
    assert resp.status_code == 200
    assert not (remote_root / "проекты").exists()


def test_disconnect_drops_the_session(sftp_client):
    assert sftp_client.post("/api/files/disconnect").status_code == 200
    assert sftp_client.get("/api/files/list?path=/").status_code == 409


def test_session_reports_no_connection_before_connect(auth_client):
    resp = auth_client.get("/api/files/session")
    assert resp.status_code == 200
    assert resp.get_json() == {"connected": False}


def test_session_lets_files_page_skip_the_login_modal(sftp_client):
    """Кнопка «Файлы» в оверлее RDP/консоли подключает SFTP в фоне тем же
    логином-паролем — открыв потом /files той же машины, второй раз пароль
    вводить не должны: /api/files/session должен опознать уже живое
    соединение и назвать домашнюю папку."""
    resp = sftp_client.get("/api/files/session")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"connected": True, "ip": DEVICE_IP, "user": "vitaz", "home": "/"}


def test_session_ip_mismatch_does_not_leak_into_another_machine_page(sftp_client):
    """Если соединение поднято для одной машины, страница другой машины не
    должна принять его за своё."""
    resp = sftp_client.get("/api/files/session")
    assert resp.get_json()["ip"] == DEVICE_IP != "100.104.122.94"
