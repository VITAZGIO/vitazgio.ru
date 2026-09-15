"""Файловый менеджер по SFTP — то же, что умеет Termius с телефона.

SFTP — не отдельная служба, а подсистема внутри SSH: тот же порт 22, тот же
логин и пароль, что у консоли кабинета. Поэтому здесь нет ни новых портов в
mesh-сети, ни второго набора секретов — только `paramiko`, который и так уже
держит консоль.

Пароль SSH на диск не попадает: живое соединение лежит в памяти процесса,
ключом к нему служит случайный токен из сессии (подписанная кука). Простой
дольше SFTP_IDLE_SECONDS закрывается сам.
"""

import mimetypes
import os
import posixpath
import re
import secrets
import stat as statmod
import threading
import time
import urllib.parse
import uuid
import zipfile
from datetime import datetime

import paramiko
from flask import Blueprint, Response, jsonify, request, session
from types import SimpleNamespace

SFTP_IDLE_SECONDS = 15 * 60      # столько живёт соединение без единого запроса
SFTP_CHUNK = 256 * 1024          # кусок чтения/записи: компромисс память/скорость
SFTP_RECURSIVE_MAX = 5000        # потолок на рекурсивное удаление/архивацию, чтобы не уйти в никуда
TO_DROP_JOB_TTL = 5 * 60         # доделанная передача видна ещё столько — успеть долистать список


# Коды отказов от телефона. Страница уже умеет показывать текст карточкой —
# ей нужна человеческая формулировка, а не «code: enospc».
_AGENT_ERRORS = {
    "denied": "Нет доступа. Разреши приложению «доступ ко всем файлам» в настройках телефона.",
    "not-found": "Не найдено.",
    "exists": "Уже существует.",
    "not-empty": "Папка не пуста.",
    "no-space": "На телефоне нет места.",
    "offline": "Телефон не на связи.",
    "timeout": "Телефон не ответил вовремя.",
}


def _error_text(exc):
    """Человеческая формулировка вместо «[Errno 13] Permission denied»."""
    code = getattr(exc, "code", None)
    if code and code in _AGENT_ERRORS:
        return _AGENT_ERRORS[code]
    errno = getattr(exc, "errno", None)
    if errno == 13:
        return "Нет доступа."
    if errno == 2:
        return "Не найдено."
    if errno == 17:
        return "Уже существует."
    if errno == 39 or "not empty" in str(exc).lower():
        return "Папка не пуста."
    return str(exc) or "Ошибка SFTP."


class AgentBackend:
    """Файлы телефона под той же страницей /files, что и файлы по SFTP.

    Страница, её вёрстка и её API не переписаны ни строкой: под ними поменян
    только транспорт. Поэтому бэкенд повторяет ту часть `paramiko.SFTPClient`,
    которой код выше реально пользуется, — и это и есть «общий интерфейс»
    двух бэкендов:

        normalize · listdir_attr · stat · open(read/write) · mkdir ·
        rename · remove · rmdir

    Ниже вместо SSH — команды агенту в его же вебсокет (`blueprints/phone.py`,
    слой `PhoneFs`). Так бесплатно достаётся всё, что странице уже умеет:
    zip папки целиком, перенос в дроп кнопкой VG, прогресс загрузки,
    переиспользование соединения без повторного пароля.
    """

    # Столько байт просим у телефона за раз. Меньше — лишние круги по сети,
    # больше — телефон дольше держит кусок в памяти.
    CHUNK = 256 * 1024

    def __init__(self, fs, home="/sdcard"):
        self.fs = fs
        self.home = home

    # ---- то, что зовёт код страницы ------------------------------------

    def normalize(self, path):
        if path in (".", "", None):
            reply = self.fs.call("home")
            return str(reply.get("path") or self.home)
        return posixpath.normpath(path)

    def listdir_attr(self, path):
        reply = self.fs.call("list", path=path)
        rows = []
        for row in reply.get("entries", []):
            is_dir = bool(row.get("dir"))
            rows.append(SimpleNamespace(
                filename=str(row.get("name") or ""),
                # Режим собираем сами: код выше разбирает его через
                # stat-модуль, как и у настоящего SFTP.
                st_mode=(statmod.S_IFDIR | 0o755) if is_dir else (statmod.S_IFREG | 0o644),
                st_size=int(row.get("size") or 0),
                st_mtime=int(row.get("mtime") or 0),
            ))
        return rows

    def stat(self, path):
        reply = self.fs.call("stat", path=path)
        is_dir = bool(reply.get("dir"))
        return SimpleNamespace(
            st_mode=(statmod.S_IFDIR | 0o755) if is_dir else (statmod.S_IFREG | 0o644),
            st_size=int(reply.get("size") or 0),
            st_mtime=int(reply.get("mtime") or 0),
        )

    def open(self, path, mode="rb"):
        if "w" in mode:
            return _AgentWrite(self.fs, path)
        return _AgentRead(self.fs, path, self.CHUNK)

    def mkdir(self, path):
        self.fs.call("mkdir", path=path)

    def rename(self, old, new):
        self.fs.call("rename", path=old, to=new)

    def remove(self, path):
        self.fs.call("remove", path=path)

    def rmdir(self, path):
        self.fs.call("rmdir", path=path)

    def close(self):
        pass                      # сокет агента живёт сам по себе


class _AgentRead:
    """Чтение файла кусками. Целиком в память не тянем ни на телефоне, ни
    здесь: с той стороны бывают фильмы на несколько гигабайт."""

    def __init__(self, fs, path, chunk):
        self.fs = fs
        self.call_id = fs.begin("read", path=path, chunk=chunk)
        try:
            fs.wait(self.call_id)
        except Exception:
            fs.finish(self.call_id)
            raise
        self.buffer = b""
        self.done = False

    def read(self, size=-1):
        if size is None or size < 0:
            parts = []
            while True:
                piece = self.read(1 << 20)
                if not piece:
                    return b"".join(parts)
                parts.append(piece)
        while not self.done and len(self.buffer) < size:
            chunk = self.fs.chunk(self.call_id)
            if chunk is None:
                self.done = True
                break
            self.buffer += chunk
        out, self.buffer = self.buffer[:size], self.buffer[size:]
        return out

    def prefetch(self, *args, **kwargs):
        pass                      # у paramiko это ускорение, здесь не нужно

    def set_pipelined(self, *args, **kwargs):
        pass

    def close(self):
        if not self.done:
            # Страница закрыла вкладку посреди скачивания — телефону надо
            # сказать, чтобы перестал читать, иначе он дочитает гигабайт в
            # никуда.
            self.fs.tell(self.call_id, "cancel")
        self.fs.finish(self.call_id)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class _AgentWrite:
    """Запись файла кусками — тем же номером запроса, двоичными кадрами."""

    def __init__(self, fs, path):
        self.fs = fs
        self.call_id = fs.begin("write", path=path)
        try:
            fs.wait(self.call_id)
        except Exception:
            fs.finish(self.call_id)
            raise
        self.closed = False

    def write(self, data):
        if not data:
            return
        self.fs.send_chunk(self.call_id, bytes(data))

    def set_pipelined(self, *args, **kwargs):
        pass                      # у paramiko это ускорение записи, здесь не нужно

    def prefetch(self, *args, **kwargs):
        pass

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.fs.tell(self.call_id, "write-end")
            # Ждём подтверждения: без него «загружено» на странице означало
            # бы только «отправлено», а файл на телефоне мог не закрыться.
            self.fs.wait(self.call_id)
        finally:
            self.fs.finish(self.call_id)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def create_files_blueprint(
    *,
    template,
    icon_links,
    login_required,
    netbird_devices,
    sftp_enabled_ips,
    drop_lock,
    drop_items,
    drop_path,
    drop_write_index,
    drop_used,
    drop_quota,
    drop_download_id,
    phone_fs=None,
    phone_ip=None,
):
    files_bp = Blueprint("files", __name__)

    def _is_phone(ip):
        """Телефон ходит не по SSH: под той же страницей у него свой
        транспорт — команды агенту в его же сокет."""
        return bool(phone_ip) and ip == phone_ip and phone_fs is not None

    # token -> {"client", "sftp", "ip", "user", "used", "io_lock"}
    live = {}
    live_lock = threading.Lock()

    # job_id -> {"state", "name", "kind", "total", "done", "error", "finished"}
    # Прогресс кнопки VG (перенос на сайт): паровозик POST запускает фоновый
    # поток и сразу отвечает, страница опрашивает состояние отдельным GET —
    # тот же приём, что у пакетных действий дропа (drop_op_start/status).
    to_drop_jobs = {}
    to_drop_lock = threading.Lock()

    def _shut(entry):
        for name in ("sftp", "client"):
            target = entry.get(name)
            if target is None:
                continue          # у агентского бэкенда ssh-клиента нет вовсе
            try:
                target.close()
            except Exception:
                pass

    def _janitor():
        while True:
            time.sleep(60)
            deadline = time.time() - SFTP_IDLE_SECONDS
            with live_lock:
                stale = [t for t, e in live.items() if e["used"] < deadline]
                dropped = [live.pop(t) for t in stale]
            for entry in dropped:
                _shut(entry)
            job_deadline = time.time() - TO_DROP_JOB_TTL
            with to_drop_lock:
                for job_id in [j for j, v in to_drop_jobs.items()
                              if v["state"] != "run" and v.get("finished", 0) < job_deadline]:
                    to_drop_jobs.pop(job_id, None)

    threading.Thread(target=_janitor, daemon=True).start()

    def _device_name(ip):
        for device in netbird_devices:
            if device["ip"] == ip:
                return device["name"]
        return ip

    def _session():
        """Живое соединение текущего браузера или None."""
        token = session.get("sftp_token")
        if not token:
            return None
        with live_lock:
            entry = live.get(token)
            if entry:
                entry["used"] = time.time()
        return entry

    def _drop_current():
        token = session.pop("sftp_token", None)
        if not token:
            return
        with live_lock:
            entry = live.pop(token, None)
        if entry:
            _shut(entry)

    def _clean(path):
        """Путь всегда абсолютный и нормализованный: «..» схлопываются тут,
        а не уезжают на машину строкой."""
        if not isinstance(path, str) or not path.startswith("/"):
            return None
        return posixpath.normpath(path)

    def _entries(sftp, path):
        rows = []
        for attr in sftp.listdir_attr(path):
            mode = attr.st_mode or 0
            is_dir = statmod.S_ISDIR(mode)
            if statmod.S_ISLNK(mode):
                # Симлинк на папку должен открываться как папка, поэтому
                # спрашиваем, куда он ведёт. Битый — остаётся файлом.
                try:
                    is_dir = statmod.S_ISDIR(sftp.stat(posixpath.join(path, attr.filename)).st_mode or 0)
                except Exception:
                    is_dir = False
            rows.append({
                "name": attr.filename,
                "dir": is_dir,
                "size": attr.st_size or 0,
                "mtime": attr.st_mtime or 0,
            })
        rows.sort(key=lambda r: (not r["dir"], r["name"].lower()))
        return rows

    # ---- Скачивание папки zip-архивом (тот же приём, что у дропа) -----------

    def _zip_name(name, taken):
        """Имя внутри архива: без разделителей пути и без повторов на одном
        уровне. «../» в имени распаковалось бы мимо выбранной папки."""
        clean = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name or "").strip(" .") or "файл"
        stem, dot, ext = clean.rpartition(".")
        if not dot:
            stem, ext = clean, ""
        candidate, counter = clean, 2
        while candidate.lower() in taken:
            candidate = f"{stem} ({counter})" + (f".{ext}" if dot else "")
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _zip_time(stamp):
        try:
            moment = datetime.fromtimestamp(stamp or 0)
        except (OSError, OverflowError, ValueError):
            moment = datetime.now()
        if moment.year < 1980:
            return (1980, 1, 1, 0, 0, 0)
        return (moment.year, moment.month, moment.day,
                moment.hour, moment.minute, moment.second - moment.second % 2)

    def _zip_plan(sftp, root, budget):
        """Путь внутри архива, путь на машине (None — пустая папка), размер,
        время. Рекурсия идёт прямо по SFTP, поэтому и лимит на число записей —
        общий с рекурсивным удалением."""
        plan = []

        def walk(path, prefix):
            taken = set()
            for attr in sftp.listdir_attr(path):
                if budget[0] <= 0:
                    raise OSError("Слишком много файлов — архивируйте по частям.")
                budget[0] -= 1
                mode = attr.st_mode or 0
                is_dir = statmod.S_ISDIR(mode)
                child = posixpath.join(path, attr.filename)
                if statmod.S_ISLNK(mode):
                    try:
                        is_dir = statmod.S_ISDIR(sftp.stat(child).st_mode or 0)
                    except Exception:
                        is_dir = False
                name = _zip_name(attr.filename, taken)
                if is_dir:
                    plan.append((prefix + name + "/", None, 0, attr.st_mtime or 0))
                    walk(child, prefix + name + "/")
                else:
                    plan.append((prefix + name, child, attr.st_size or 0, attr.st_mtime or 0))

        walk(root, "")
        return plan

    def _zip_length(plan):
        """Точный размер архива без сжатия и без ZIP64 — чтобы браузер показал
        полосу загрузки. За гигабайтами формат меняется, тогда длину не обещаем."""
        total = 22
        for arcname, remote_path, size, _ in plan:
            name_len = len(arcname.encode("utf-8"))
            total += 30 + name_len + 16 + 46 + name_len
            if remote_path is not None:
                total += size
        limit = 0xFFFFFFFF
        if total > limit or any(size > limit for _, _, size, _ in plan):
            return None
        return total

    class _ZipSink:
        """Приёмник для zipfile: копит записанное и отдаёт порциями наружу."""

        def __init__(self):
            self._parts = []
            self._pos = 0
            self._held = 0

        def write(self, data):
            data = bytes(data)
            self._parts.append(data)
            self._pos += len(data)
            self._held += len(data)
            return len(data)

        def tell(self):
            return self._pos

        def flush(self):
            pass

        @property
        def held(self):
            return self._held

        def drain(self):
            out = b"".join(self._parts)
            self._parts.clear()
            self._held = 0
            return out

    # ---- Кнопка VG: перенос файла/папки на сайт, в личный дроп ---------------
    # Идёт напрямую с машины в дроп, минуя браузер — тем же соединением SFTP,
    # что и весь остальной /files. По умолчанию всё падает в особую папку
    # Download (см. DROP_DOWNLOAD_ID в app.py) — ровно так же, как «Поделиться»
    # с телефона: выбирать папку тут не из чего, спрашивать некого.

    def _to_drop_file(sftp, remote_path, parent_id, on_chunk=None):
        name = (posixpath.basename(remote_path) or "файл")[:120]
        try:
            expected_size = sftp.stat(remote_path).st_size or 0
        except Exception:
            expected_size = 0
        with drop_lock:
            if drop_used() + expected_size > drop_quota:
                raise OSError("Нет места: квота дропа исчерпана.")

        item_id = str(uuid.uuid4())
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        written = 0
        try:
            with sftp.open(remote_path, "rb") as src:
                src.prefetch()
                with open(drop_path(item_id), "wb") as dst:
                    while True:
                        chunk = src.read(SFTP_CHUNK)
                        if not chunk:
                            break
                        dst.write(chunk)
                        written += len(chunk)
                        if on_chunk:
                            on_chunk(len(chunk))
        except Exception:
            try:
                os.remove(drop_path(item_id))
            except OSError:
                pass
            raise

        with drop_lock:
            # Заявленный размер мог соврать (или файл на той стороне изменился
            # за время передачи) — перепроверяем по факту записанного, прежде
            # чем регистрировать в дропе.
            if drop_used() + written > drop_quota:
                try:
                    os.remove(drop_path(item_id))
                except OSError:
                    pass
                raise OSError("Нет места: квота дропа исчерпана.")
            drop_items[item_id] = {
                "kind": "file", "name": name, "parent": parent_id,
                "content_type": content_type, "size": written,
                "created": time.time(), "share": None,
            }
            drop_write_index()
        return item_id

    def _to_drop_folder(sftp, remote_path, parent_id, budget, on_chunk=None):
        name = (posixpath.basename(remote_path.rstrip("/")) or "папка")[:60]
        folder_id = str(uuid.uuid4())
        with drop_lock:
            drop_items[folder_id] = {
                "kind": "folder", "name": name, "parent": parent_id, "icon": "folder",
                "size": 0, "created": time.time(), "share": None,
            }
            drop_write_index()
        for attr in sftp.listdir_attr(remote_path):
            if budget[0] <= 0:
                raise OSError("Слишком много файлов — переносите по частям.")
            budget[0] -= 1
            child = posixpath.join(remote_path, attr.filename)
            mode = attr.st_mode or 0
            is_dir = statmod.S_ISDIR(mode)
            if statmod.S_ISLNK(mode):
                try:
                    is_dir = statmod.S_ISDIR(sftp.stat(child).st_mode or 0)
                except Exception:
                    is_dir = False
            if is_dir:
                _to_drop_folder(sftp, child, folder_id, budget, on_chunk)
            else:
                _to_drop_file(sftp, child, folder_id, on_chunk)
        return folder_id

    def _to_drop_plan_size(sftp, path, is_dir, budget):
        """Только чтобы прикинуть общий размер для полосы загрузки — тот же
        обход, что и у zip-архива, но нужна лишь сумма размеров файлов."""
        if not is_dir:
            try:
                return sftp.stat(path).st_size or 0
            except Exception:
                return 0
        total = 0
        for attr in sftp.listdir_attr(path):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            child = posixpath.join(path, attr.filename)
            mode = attr.st_mode or 0
            child_is_dir = statmod.S_ISDIR(mode)
            if statmod.S_ISLNK(mode):
                try:
                    child_is_dir = statmod.S_ISDIR(sftp.stat(child).st_mode or 0)
                except Exception:
                    child_is_dir = False
            if child_is_dir:
                total += _to_drop_plan_size(sftp, child, True, budget)
            else:
                total += attr.st_size or 0
        return total

    @files_bp.post("/api/files/to-drop")
    @login_required
    def files_to_drop():
        """Запускает перенос в фоне и сразу отвечает — страница дальше
        опрашивает /api/files/to-drop/<job_id>, чтобы показать полосу."""
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409
        payload = request.get_json(silent=True) or {}
        path = _clean(payload.get("path", ""))
        if not path:
            return jsonify(error="Плохой путь."), 400

        sftp = entry["sftp"]
        name = posixpath.basename(path.rstrip("/")) or path
        try:
            with entry["io_lock"]:
                is_dir = statmod.S_ISDIR(sftp.stat(path).st_mode or 0)
                total = _to_drop_plan_size(sftp, path, is_dir, [SFTP_RECURSIVE_MAX])
        except Exception as e:
            return jsonify(error=_error_text(e)), 400

        job_id = secrets.token_urlsafe(12)
        with to_drop_lock:
            to_drop_jobs[job_id] = {
                "state": "run", "name": name, "kind": "folder" if is_dir else "file",
                "total": total, "done": 0, "error": "", "finished": 0,
            }

        def on_chunk(n):
            with to_drop_lock:
                job = to_drop_jobs.get(job_id)
                if job:
                    job["done"] += n

        def work():
            try:
                with entry["io_lock"]:
                    if is_dir:
                        _to_drop_folder(sftp, path, drop_download_id, [SFTP_RECURSIVE_MAX], on_chunk)
                    else:
                        _to_drop_file(sftp, path, drop_download_id, on_chunk)
                state, error = "done", ""
            except Exception as e:                       # noqa: BLE001 — причину показываем как есть
                state, error = "error", _error_text(e)
            with to_drop_lock:
                job = to_drop_jobs.get(job_id)
                if job:
                    job["state"] = state
                    job["error"] = error
                    job["finished"] = time.time()

        threading.Thread(target=work, daemon=True).start()
        return jsonify(job=job_id, name=name, total=total, kind="folder" if is_dir else "file")

    @files_bp.get("/api/files/to-drop/<job_id>")
    @login_required
    def files_to_drop_status(job_id):
        with to_drop_lock:
            job = to_drop_jobs.get(job_id)
            if not job:
                return jsonify(error="Задача не найдена."), 404
            return jsonify(**{k: v for k, v in job.items() if k != "finished"})

    def _rm_tree(sftp, path, budget):
        """Рекурсивное удаление с потолком: без него кривой путь мог бы
        увести в обход всего диска."""
        for attr in sftp.listdir_attr(path):
            if budget[0] <= 0:
                raise OSError("Слишком много файлов — удалите частями.")
            budget[0] -= 1
            child = posixpath.join(path, attr.filename)
            mode = attr.st_mode or 0
            if statmod.S_ISDIR(mode):
                _rm_tree(sftp, child, budget)
            else:
                sftp.remove(child)
        sftp.rmdir(path)

    # ---- Страница -----------------------------------------------------------

    def _agent_entry():
        """Живое «соединение» с телефоном. Пароля тут нет и быть не может:
        SSH на телефоне нет, а гейт — суточный пароль консоли, как и у
        остальных машин."""
        backend = AgentBackend(phone_fs)
        home = backend.normalize(".")
        _drop_current()
        token = secrets.token_urlsafe(18)
        with live_lock:
            live[token] = {"client": None, "sftp": backend, "ip": phone_ip,
                           "user": "агент", "home": home, "used": time.time(),
                           # Тот же лок, что у SFTP: фоновый перенос кнопкой
                           # VG живёт своим потоком параллельно запросам
                           # страницы, и мешать их в одном канале нельзя.
                           "io_lock": threading.Lock()}
        session["sftp_token"] = token
        return live[token]

    @files_bp.get("/files/<ip>")
    @login_required
    def files_page(ip):
        if ip not in sftp_enabled_ips:
            return "Для этой машины файлы недоступны.", 404
        # Телефону логин спрашивать не у кого, поэтому соединение поднимаем
        # прямо здесь — страница сама увидит его через /api/files/session и
        # пропустит карточку логина (тот же путь, что и у кнопки «Файлы» в
        # оверлее RDP). Суточный пароль при этом обязателен, как и везде.
        if _is_phone(ip) and session.get("console_authenticated") and phone_fs.online:
            try:
                _agent_entry()
            except Exception:
                pass              # не поднялось — страница спросит как обычно
        html = template("files.html")
        return (html.replace("{{IP}}", ip)
                    .replace("{{NAME}}", _device_name(ip))
                    .replace("{{NEED_CONSOLE}}", "" if session.get("console_authenticated") else "1")
                    .replace("__ICONLINKS__", icon_links))

    # ---- Соединение ---------------------------------------------------------

    @files_bp.post("/api/files/connect")
    @login_required
    def files_connect():
        if not session.get("console_authenticated"):
            return jsonify(error="Сначала пароль консоли."), 403

        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip")
        username = payload.get("username")
        password = payload.get("password")
        if ip not in sftp_enabled_ips:
            return jsonify(error="Неизвестная машина."), 400

        if _is_phone(ip):
            # Телефон: ни логина, ни пароля — SSH там нет. Что вбито в поля
            # карточки, значения не имеет, и придумывать туда пароль не надо.
            if not phone_fs.online:
                return jsonify(error="Телефон не на связи."), 502
            try:
                entry = _agent_entry()
                with entry["io_lock"]:
                    rows = _entries(entry["sftp"], entry["home"])
            except Exception as e:
                return jsonify(error=f"Телефон не ответил: {e}"), 502
            return jsonify(path=entry["home"], user=entry["user"], entries=rows)

        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            return jsonify(error="Нужны логин и пароль."), 400

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, username=username, password=password,
                           timeout=8, look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            return jsonify(error="Логин или пароль не подошли."), 401
        except (paramiko.SSHException, OSError) as e:
            return jsonify(error=f"Не удалось подключиться: {e}"), 502

        try:
            sftp = client.open_sftp()
            home = sftp.normalize(".")
            rows = _entries(sftp, home)
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass
            return jsonify(error=f"SFTP не открылся: {e}"), 502

        transport = client.get_transport()
        if transport:
            transport.set_keepalive(20)

        _drop_current()   # второе подключение не оставляет первое висеть
        token = secrets.token_urlsafe(18)
        with live_lock:
            live[token] = {"client": client, "sftp": sftp, "ip": ip,
                           "user": username, "home": home, "used": time.time(),
                           # paramiko не гарантирует потокобезопасность при
                           # одновременной работе с одним SFTP-клиентом из
                           # нескольких потоков — а перенос кнопкой VG теперь
                           # идёт в фоне, параллельно обычным запросам этой же
                           # вкладки. Лок сериализует любое обращение к sftp.
                           "io_lock": threading.Lock()}
        session["sftp_token"] = token
        return jsonify(path=home, user=username, entries=rows)

    @files_bp.post("/api/files/disconnect")
    @login_required
    def files_disconnect():
        _drop_current()
        return jsonify(ok=True)

    @files_bp.get("/api/files/session")
    @login_required
    def files_session():
        """Есть ли уже живое соединение — и на какую машину.

        Даёт странице /files пропустить повторный ввод логина/пароля, если
        подключение уже поднято кнопкой «SFTP» из окна RDP/консоли той же
        машины (тот же браузер — та же кука сессии, значит и то же
        соединение видно в любой вкладке)."""
        entry = _session()
        if not entry:
            return jsonify(connected=False)
        return jsonify(connected=True, ip=entry["ip"], user=entry["user"], home=entry["home"])

    # ---- Работа с файлами ---------------------------------------------------

    @files_bp.get("/api/files/list")
    @login_required
    def files_list():
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409
        path = _clean(request.args.get("path", ""))
        if not path:
            return jsonify(error="Плохой путь."), 400
        try:
            with entry["io_lock"]:
                rows = _entries(entry["sftp"], path)
            return jsonify(path=path, entries=rows)
        except Exception as e:
            return jsonify(error=_error_text(e)), 400

    @files_bp.get("/api/files/download")
    @login_required
    def files_download():
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409
        path = _clean(request.args.get("path", ""))
        if not path:
            return jsonify(error="Плохой путь."), 400

        sftp = entry["sftp"]
        try:
            with entry["io_lock"]:
                size = sftp.stat(path).st_size or 0
                handle = sftp.open(path, "rb")
                handle.prefetch()
        except Exception as e:
            return jsonify(error=_error_text(e)), 400

        def stream():
            # Лок держим на всё чтение — фоновый перенос кнопкой VG работает
            # тем же sftp-клиентом, а paramiko не рассчитан на одновременную
            # работу с ним из разных потоков.
            with entry["io_lock"]:
                try:
                    while True:
                        chunk = handle.read(SFTP_CHUNK)
                        if not chunk:
                            break
                        yield chunk
                finally:
                    try:
                        handle.close()
                    except Exception:
                        pass

        name = posixpath.basename(path) or "file"
        # Заголовки уходят в latin-1, поэтому имя с кириллицей нельзя ставить
        # в них как есть: сервер падает на кодировании, и скачивание рвётся
        # без единого понятного слова (поймано живым прогоном на файле
        # «снимок.jpg»). filename* по RFC 5987 обязан быть percent-encoded,
        # а простой filename оставляем запасным — для старых браузеров.
        plain = name.encode("ascii", "ignore").decode("ascii") or "file"
        quoted = urllib.parse.quote(name, safe="")
        # application/octet-stream не входит в GZIP_TYPES, поэтому after_request
        # его не тронет — поток уедет как есть, без сбора в буфер.
        return Response(stream(), mimetype="application/octet-stream", headers={
            "Content-Length": str(size),
            "Content-Disposition": f"attachment; filename=\"{plain}\"; filename*=UTF-8''{quoted}",
            "Cache-Control": "private, no-store",
        })

    @files_bp.get("/api/files/zip")
    @login_required
    def files_zip():
        """Папка целиком одним архивом — тот же приём, что уже есть в дропе.

        Без сжатия: фото и видео и так уже сжаты, второй проход только грузит
        процессор ради процента-двух, а несжатый архив собирается со скоростью
        сети до машины."""
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409
        path = _clean(request.args.get("path", ""))
        if not path:
            return jsonify(error="Плохой путь."), 400

        sftp = entry["sftp"]
        try:
            with entry["io_lock"]:
                if not statmod.S_ISDIR(sftp.stat(path).st_mode or 0):
                    return jsonify(error="Это не папка."), 400
                plan = _zip_plan(sftp, path, [SFTP_RECURSIVE_MAX])
        except Exception as e:
            return jsonify(error=_error_text(e)), 400

        def pour():
            with entry["io_lock"]:
                sink = _ZipSink()
                with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
                    for arcname, remote_path, _, mtime in plan:
                        info = zipfile.ZipInfo(arcname, _zip_time(mtime))
                        info.compress_type = zipfile.ZIP_STORED
                        if remote_path is None:
                            zf.writestr(info, b"")          # пустая папка
                            yield sink.drain()
                            continue
                        try:
                            handle = sftp.open(remote_path, "rb")
                            handle.prefetch()
                        except Exception:
                            continue   # файл исчез между списком и чтением — пропускаем
                        with zf.open(info, "w") as dst:
                            try:
                                while True:
                                    chunk = handle.read(SFTP_CHUNK)
                                    if not chunk:
                                        break
                                    dst.write(chunk)
                                    if sink.held >= SFTP_CHUNK:
                                        yield sink.drain()
                            finally:
                                handle.close()
                        if sink.held:
                            yield sink.drain()
                yield sink.drain()

        safe = (_zip_name(posixpath.basename(path) or "папка", set())) + ".zip"
        quoted = urllib.parse.quote(safe)
        response = Response(pour(), mimetype="application/zip")
        # Русское имя — только в filename* процентами (заголовки идут в
        # latin-1, сырая кириллица роняет отдачу), простое filename — латиницей.
        response.headers["Content-Disposition"] = (
            "attachment; filename=\"archive.zip\"; filename*=UTF-8''" + quoted)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        length = _zip_length(plan)
        if length is not None:
            response.headers["Content-Length"] = str(length)
        return response

    @files_bp.post("/api/files/upload")
    @login_required
    def files_upload():
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409
        folder = _clean(request.args.get("path", ""))
        name = posixpath.basename(request.args.get("name", "") or "")
        if not folder or not name or name in (".", ".."):
            return jsonify(error="Плохое имя файла."), 400

        target = posixpath.join(folder, name)
        written = 0
        try:
            with entry["io_lock"]:
                with entry["sftp"].open(target, "wb") as remote:
                    remote.set_pipelined(True)
                    while True:
                        chunk = request.stream.read(SFTP_CHUNK)
                        if not chunk:
                            break
                        remote.write(chunk)
                        written += len(chunk)
        except Exception as e:
            return jsonify(error=_error_text(e)), 400
        return jsonify(ok=True, name=name, size=written)

    @files_bp.post("/api/files/op")
    @login_required
    def files_op():
        entry = _session()
        if not entry:
            return jsonify(error="Нет соединения.", reconnect=True), 409

        payload = request.get_json(silent=True) or {}
        op = payload.get("op")
        path = _clean(payload.get("path", ""))
        if not path:
            return jsonify(error="Плохой путь."), 400
        sftp = entry["sftp"]

        try:
            with entry["io_lock"]:
                if op == "mkdir":
                    sftp.mkdir(path)
                elif op == "rename":
                    name = posixpath.basename(payload.get("name", "") or "")
                    if not name or name in (".", ".."):
                        return jsonify(error="Плохое имя."), 400
                    sftp.rename(path, posixpath.join(posixpath.dirname(path), name))
                elif op == "delete":
                    if statmod.S_ISDIR(sftp.stat(path).st_mode or 0):
                        if payload.get("recursive"):
                            _rm_tree(sftp, path, [SFTP_RECURSIVE_MAX])
                        else:
                            try:
                                sftp.rmdir(path)
                            except Exception as e:
                                # Папка с содержимым — не молчим и не сносим втихую,
                                # а спрашиваем у человека отдельной карточкой.
                                # Телефон говорит об этом своим кодом, SSH —
                                # номером ошибки; для страницы это одно и то же.
                                if (getattr(e, "errno", None) in (39, 66)
                                        or getattr(e, "code", "") == "not-empty"
                                        or "not empty" in str(e).lower()):
                                    return jsonify(error="Папка не пуста.", needs_recursive=True), 409
                                raise
                    else:
                        sftp.remove(path)
                else:
                    return jsonify(error="Неизвестная операция."), 400
        except Exception as e:
            return jsonify(error=_error_text(e)), 400
        return jsonify(ok=True)

    return files_bp
