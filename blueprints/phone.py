"""Ретранслятор телефона — ступень 1: только «жив или нет».

Телефон не может принимать входящие: у оператора CGNAT, своего адреса в
интернете у него нет (подробно — `docs/phone-access-plan.md`, разделы 2-3).
Поэтому соединение всегда исходящее: телефон сам приходит сюда вебсокетом
и держит его открытым, а сайт только отмечает, что он жив.

Больше здесь пока ничего нет и быть не должно: ни экрана, ни файлов. Смысл
ступени — выяснить одну вещь, не убьёт ли оболочка HiOS это соединение за
ночь. Если убьёт, всё, что легло бы сверху, пришлось бы разбирать обратно.

Реестр живых агентов — обычный словарь в памяти процесса. Это законно:
сайт однопроцессный (`app.run(threaded=True)`), ровно так же живут
`netbird_status` в `app.py` и пул SFTP-соединений в `blueprints/files.py`.

Ступень 2 добавила сюда **токены устройств**: приложение больше не просит
вбить общий пароль руками — хозяин заходит в кабинет внутри оболочки, и
страница сама выдаёт устройству личный токен (`/api/phone/token`), а JS-мост
кладёт его в `EncryptedSharedPreferences`. Отозвать такой токен можно с
сайта поштучно, не меняя общий пароль всем сразу. На диске лежат только
хэши (sha256) — как у пароля корзины дропа: утечка файла доступа не даёт.
Общий `PHONE_AGENT_TOKEN` из `.env` при этом никуда не делся: он запасной
путь на случай, если войти в кабинет с телефона почему-то не выходит.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import queue
import threading
import time
import urllib.error
import urllib.request

from flask import Blueprint, jsonify, request, send_file, session

AGENT_HELLO_TIMEOUT = 15     # столько ждём первое сообщение с токеном
AGENT_PING_SECONDS = 25      # молчит столько — сами шлём ping
AGENT_STALE_SECONDS = 60     # молчит дольше — считаем офлайн и выкидываем
AGENT_SWEEP_SECONDS = 10     # как часто дворник проверяет протухших
AGENT_EVENTS_MAX = 60        # хвост журнала: кто когда пришёл и когда отвалился
DEVICE_TOKEN_BYTES = 32      # длина личного токена устройства
DEVICE_LABEL_MAX = 64

# ---- Экран телефона (ступень 3) --------------------------------------------
# Кадры ходят двоичными сообщениями с коротким заголовком: тип (1 байт) и
# метка времени в микросекундах (8 байт, big-endian), дальше сам H.264 в
# Annex-B. Заголовок нужен зрителю: WebCodecs обязан знать, опорный это кадр
# или разностный, и с какой меткой его показывать.
FRAME_CONFIG = 1             # SPS/PPS — параметры кодека
FRAME_KEY = 2                # опорный кадр
FRAME_DELTA = 3              # разностный
FRAME_HEADER = 9

# Файлы телефона (ступень 4) ходят тем же двоичным каналом, что и кадры
# экрана, поэтому номеру запроса предшествует байт типа: иначе кусок файла
# было бы не отличить от кадра видео. После него — 4 байта номера запроса
# (big-endian), дальше сами байты файла.
FRAME_FILE = 4
FILE_HEADER = 5
FS_TIMEOUT = 25              # столько ждём ответ телефона на операцию
FS_CHUNK_QUEUE = 64          # кусков файла в памяти сервера на один запрос

# Очередь кадров на зрителя. Медленный зритель не должен тормозить телефон:
# очередь переполнилась — выбрасываем накопленное и просим новый опорный
# кадр, иначе кадры копились бы в памяти сервера, а картинка всё равно
# отставала бы на минуты.
VIEWER_QUEUE_MAX = 90

# Версия сборки — число в имени файла (`vg-agent-7.apk` → 7). Так же его
# видит приложение при самообновлении: больше номер — есть что ставить.
APK_VERSION_RE = re.compile(r"(\d+)")
APK_PULL_MAX = 200 * 1024 * 1024   # потолок на скачивание релиза, чтобы не залить диск


def create_phone_blueprint(
    *,
    sock,
    template,
    icon_links,
    login_required,
    agent_token,
    agent_ip,
    publish_status,
    apk_dir,
    apk_repo,
    tokens_path,
):
    phone_bp = Blueprint("phone", __name__)

    # conn_id -> {"name", "version", "peer", "connected", "last_seen"}
    agents = {}
    agents_lock = threading.Lock()
    events = []                  # хвост событий для отладки ночного теста

    def _log(text):
        with agents_lock:
            events.append({"at": time.time(), "text": text})
            del events[:-AGENT_EVENTS_MAX]

    def _snapshot_locked():
        deadline = time.time() - AGENT_STALE_SECONDS
        alive = [a for a in agents.values() if a["last_seen"] > deadline]
        last_seen = max((a["last_seen"] for a in agents.values()), default=None)
        return {
            "online": bool(alive),
            "last_seen": last_seen,
            "agents": sorted(alive, key=lambda a: a["connected"]),
            "events": list(reversed(events)),
        }

    def _snapshot():
        with agents_lock:
            return _snapshot_locked()

    def _publish():
        """Отдать состояние наружу — в `netbird_status`, откуда его берёт
        `/api/netbird/status` и красит строку MOBILA на `/netbird`."""
        snapshot = _snapshot()
        publish_status(snapshot["online"], snapshot["last_seen"])

    def _sweeper():
        """Агент мог не попрощаться: телефон уехал в тоннель, оболочка убила
        процесс. Молчащую запись выкидываем сами, иначе MOBILA висела бы
        «онлайн» до перезапуска сайта."""
        while True:
            time.sleep(AGENT_SWEEP_SECONDS)
            deadline = time.time() - AGENT_STALE_SECONDS
            with agents_lock:
                stale = [cid for cid, a in agents.items() if a["last_seen"] <= deadline]
                for cid in stale:
                    agents.pop(cid, None)
            for cid in stale:
                _log("агент молчал дольше минуты — офлайн")
            if stale:
                _publish()

    threading.Thread(target=_sweeper, daemon=True).start()

    # ---- Токены устройств ------------------------------------------------
    # Файл переживает перезапуск сайта: телефон держит свой токен у себя, и
    # после деплоя сервер обязан его узнать. На диске — только хэши.

    devices = {}                 # token_id -> {"label", "hash", "created", "last_used"}
    devices_lock = threading.Lock()

    def _devices_load():
        try:
            with open(tokens_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            for token_id, row in data.items():
                if isinstance(row, dict) and row.get("hash"):
                    devices[str(token_id)] = {
                        "label": str(row.get("label") or "телефон")[:DEVICE_LABEL_MAX],
                        "hash": str(row["hash"]),
                        "created": float(row.get("created") or 0),
                        "last_used": float(row.get("last_used") or 0) or None,
                    }

    def _devices_write_locked():
        os.makedirs(os.path.dirname(tokens_path), exist_ok=True)
        tmp = tokens_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(devices, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, tokens_path)

    _devices_load()

    def _hash(raw):
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _device_match(candidate):
        """id устройства, чей это токен, или None. Сравнение — по хэшам и
        через compare_digest: обычное `==` на строках выходит из сравнения на
        первом же несовпавшем символе и тем выдаёт длину общего начала."""
        if not isinstance(candidate, str) or not candidate:
            return None
        digest = _hash(candidate)
        with devices_lock:
            for token_id, row in devices.items():
                if hmac.compare_digest(digest, row["hash"]):
                    return token_id
        return None

    def _token_ok(candidate):
        """Пускаем и по общему паролю из .env, и по личному токену устройства."""
        if not isinstance(candidate, str) or not candidate:
            return False
        if agent_token:
            # Сравниваем байтами: compare_digest на строках с кириллицей (а
            # токен мог быть набран каким угодно) падает TypeError, а не
            # отвечает «нет».
            if hmac.compare_digest(candidate.encode("utf-8"), str(agent_token).encode("utf-8")):
                return True
        return _device_match(candidate) is not None

    # ---- Экран телефона: сайт как мост между двумя исходящими -------------
    # Тот же приём, что уже работает у guacamole (`/ws/rdp`, `/ws/vnc` в
    # blueprints/remote.py): телефон пришёл сам, зритель пришёл сам, сайт
    # перекладывает байты между ними. Ни к телефону, ни к браузеру никто
    # снаружи не стучится — входящих соединений в этой схеме нет вовсе.

    agent_send_lock = threading.Lock()   # в сокет агента пишут и насос, и зрители
    live_agent = {"ws": None}

    screen = {
        "running": False,      # телефон реально отдаёт кадры
        "paused": False,       # захват жив, но зрителей нет и кодировать некуда
        "config": None,        # последние SPS/PPS: без них поздний зритель слеп
        "width": 0,
        "height": 0,
        "error": "",
    }
    screen_lock = threading.Lock()

    viewers = {}               # id -> {"queue", "ws", "alive"}
    viewers_lock = threading.Lock()

    def _agent_send(payload):
        """Команда телефону. Врать о результате нельзя: зритель по ответу
        решает, показывать ли «жду подтверждения на телефоне»."""
        ws = live_agent["ws"]
        if ws is None:
            return False
        try:
            with agent_send_lock:
                ws.send(json.dumps(payload))
            return True
        except Exception:
            return False

    def _screen_snapshot():
        with screen_lock:
            state = dict(screen)
        state.pop("config", None)
        with agents_lock:
            state["agent"] = bool(agents)
        with viewers_lock:
            state["viewers"] = len(viewers)
        return state

    def _viewers_tell(payload):
        message = json.dumps(payload)
        with viewers_lock:
            targets = list(viewers.values())
        for viewer in targets:
            _viewer_put(viewer, message)

    def _viewer_put(viewer, item):
        """Положить кадр (или строку) в очередь зрителя.

        Переполнилась — чистим и просим опорный кадр: показать отставшую на
        минуту картинку хуже, чем на секунду замереть и продолжить со свежей."""
        try:
            viewer["queue"].put_nowait(item)
        except queue.Full:
            drained = 0
            try:
                while True:
                    viewer["queue"].get_nowait()
                    drained += 1
            except queue.Empty:
                pass
            viewer["need_key"] = True
            _agent_send({"type": "screen-key"})
            try:
                viewer["queue"].put_nowait(item)
            except queue.Full:
                pass

    def _screen_frame(data):
        """Кадр от телефона — всем зрителям. Параметры кодека запоминаем:
        зритель, подключившийся посреди трансляции, обязан получить их
        первым сообщением, иначе декодер не заведётся вовсе."""
        if len(data) < FRAME_HEADER:
            return
        kind = data[0]
        if kind == FRAME_CONFIG:
            with screen_lock:
                screen["config"] = bytes(data)
        with viewers_lock:
            targets = list(viewers.values())
        for viewer in targets:
            if viewer.get("need_key") and kind == FRAME_DELTA:
                continue                      # ждём опорный, разностные ему не помогут
            if kind in (FRAME_CONFIG, FRAME_KEY):
                viewer["need_key"] = False
            _viewer_put(viewer, data)

    # ---- Файлы телефона: запрос-ответ поверх того же сокета ---------------
    # Страница /files и её API не переписываются (см. docs/phone-tz/04-files.md):
    # под ними меняется только транспорт. Здесь — низ этого транспорта: номера
    # запросов, ожидание ответов и приём кусков файла. Сам бэкенд, который
    # выглядит для files.py как SFTP-клиент, живёт в blueprints/files.py.

    fs_lock = threading.Lock()
    fs_calls = {}              # id -> {"reply": Event, "data": dict, "chunks": Queue}
    fs_next = {"id": 1}

    class PhoneFsError(Exception):
        """Телефон ответил отказом. Код нужен странице: она уже умеет
        показывать «нет места»/«нет прав»/«не найдено» карточкой."""

        def __init__(self, text, code=""):
            super().__init__(text)
            self.code = code

    class PhoneFs:
        """То немногое, что нужно файловому бэкенду от сокета агента."""

        error = PhoneFsError

        @property
        def online(self):
            with agents_lock:
                return bool(agents) and live_agent["ws"] is not None

        def begin(self, op, **args):
            """Начать операцию. Возвращает номер запроса — по нему придут и
            ответ, и куски файла."""
            if live_agent["ws"] is None:
                raise PhoneFsError("Телефон не на связи.", "offline")
            with fs_lock:
                call_id = fs_next["id"]
                fs_next["id"] = (call_id + 1) % 0x7FFFFFFF or 1
                fs_calls[call_id] = {
                    "reply": threading.Event(),
                    "data": None,
                    "chunks": queue.Queue(maxsize=FS_CHUNK_QUEUE),
                }
            if not _agent_send({"type": "fs", "id": call_id, "op": op, **args}):
                self.finish(call_id)
                raise PhoneFsError("Телефон не на связи.", "offline")
            return call_id

        def wait(self, call_id, timeout=FS_TIMEOUT):
            """Дождаться ответа на операцию."""
            with fs_lock:
                call = fs_calls.get(call_id)
            if call is None:
                raise PhoneFsError("Запрос потерялся.", "lost")
            if not call["reply"].wait(timeout):
                self.finish(call_id)
                raise PhoneFsError("Телефон не ответил вовремя.", "timeout")
            data = call["data"] or {}
            call["reply"].clear()
            if not data.get("ok", False):
                raise PhoneFsError(str(data.get("error") or "Телефон отказал."),
                                   str(data.get("code") or ""))
            return data

        def call(self, op, **args):
            """Операция без потока данных: список, создать, переименовать…"""
            call_id = self.begin(op, **args)
            try:
                return self.wait(call_id)
            finally:
                self.finish(call_id)

        def chunk(self, call_id, timeout=FS_TIMEOUT):
            """Следующий кусок файла или None, когда файл кончился."""
            with fs_lock:
                call = fs_calls.get(call_id)
            if call is None:
                raise PhoneFsError("Передача оборвалась.", "lost")
            try:
                item = call["chunks"].get(timeout=timeout)
            except queue.Empty:
                raise PhoneFsError("Телефон замолчал посреди файла.", "timeout")
            if isinstance(item, PhoneFsError):
                raise item
            return item

        def send_chunk(self, call_id, data):
            """Кусок файла телефону. Двоичным, с тем же номером запроса."""
            ws = live_agent["ws"]
            if ws is None:
                raise PhoneFsError("Телефон не на связи.", "offline")
            head = bytes([FRAME_FILE]) + call_id.to_bytes(4, "big")
            try:
                with agent_send_lock:
                    ws.send(head + data)
            except Exception:
                raise PhoneFsError("Соединение с телефоном оборвалось.", "offline")

        def tell(self, call_id, op, **args):
            """Досказать что-то по уже начатой операции (конец записи, отмена)."""
            _agent_send({"type": "fs", "id": call_id, "op": op, **args})

        def finish(self, call_id):
            with fs_lock:
                fs_calls.pop(call_id, None)

    phone_fs = PhoneFs()

    def _fs_reply(payload):
        call_id = payload.get("id")
        with fs_lock:
            call = fs_calls.get(call_id)
        if call is None:
            return
        if payload.get("eof"):
            # Файл кончился: None в очереди — сигнал читателю остановиться.
            try:
                call["chunks"].put_nowait(None)
            except queue.Full:
                pass
            if payload.get("ok", True):
                return
        call["data"] = payload
        call["reply"].set()
        if not payload.get("ok", True):
            # Отказ посреди чтения: читатель висит на очереди, и ждать ему
            # больше нечего — кладём саму ошибку.
            try:
                call["chunks"].put_nowait(
                    PhoneFsError(str(payload.get("error") or "Телефон отказал."),
                                 str(payload.get("code") or "")))
            except queue.Full:
                pass

    def _fs_frame(data):
        call_id = int.from_bytes(data[1:5], "big")
        with fs_lock:
            call = fs_calls.get(call_id)
        if call is None:
            return
        chunk = data[FILE_HEADER:]
        try:
            call["chunks"].put(chunk, timeout=FS_TIMEOUT)
        except queue.Full:
            pass

    def _fs_drop_all(reason):
        """Агент пропал — все ждущие операции обязаны оборваться, а не висеть
        до таймаута: страница покажет ошибку сразу."""
        with fs_lock:
            calls = list(fs_calls.values())
            fs_calls.clear()
        for call in calls:
            call["data"] = {"ok": False, "error": reason, "code": "offline"}
            call["reply"].set()
            try:
                call["chunks"].put_nowait(PhoneFsError(reason, "offline"))
            except queue.Full:
                pass

    def handle_agent(ws, peer=""):
        """Весь разговор с телефоном. Вынесено из роута отдельной функцией:
        так её зовёт тест с фальшивым сокетом, не поднимая сети."""
        try:
            raw = ws.receive(timeout=AGENT_HELLO_TIMEOUT)
        except Exception:
            return
        try:
            hello = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            hello = {}
        if not isinstance(hello, dict) or hello.get("type") != "hello" or not _token_ok(hello.get("token")):
            _log(f"отказ в подключении ({peer or 'адрес неизвестен'})")
            try:
                ws.close()
            except Exception:
                pass
            return

        # Пришёл по личному токену — отмечаем, что устройство на связи. По
        # этой отметке на сайте видно, какой из выданных токенов живой, а
        # какой можно отзывать.
        device_id = _device_match(hello.get("token"))
        if device_id:
            with devices_lock:
                row = devices.get(device_id)
                if row:
                    row["last_used"] = time.time()
                    _devices_write_locked()

        conn_id = secrets.token_hex(8)
        now = time.time()
        entry = {
            "name": str(hello.get("agent") or "агент")[:64],
            "version": hello.get("version") if isinstance(hello.get("version"), int) else None,
            "peer": peer,
            "connected": now,
            "last_seen": now,
        }
        with agents_lock:
            agents[conn_id] = entry
        live_agent["ws"] = ws
        _log(f"агент на связи: {entry['name']}")
        _publish()

        try:
            ws.send(json.dumps({
                "type": "hello-ok",
                "ping": AGENT_PING_SECONDS,
                "stale": AGENT_STALE_SECONDS,
            }))
        except Exception:
            pass

        try:
            while True:
                try:
                    message = ws.receive(timeout=AGENT_PING_SECONDS)
                except Exception:
                    break
                now = time.time()
                if message is None:
                    # Тишина в канале сама по себе ничего не значит: телефон
                    # мог просто молчать. Дёргаем ping — вот его молчание в
                    # ответ уже и есть смерть соединения.
                    if now - entry["last_seen"] > AGENT_STALE_SECONDS:
                        break
                    try:
                        ws.send(json.dumps({"type": "ping", "t": int(now)}))
                    except Exception:
                        break
                    continue
                entry["last_seen"] = now
                with agents_lock:
                    if conn_id not in agents:     # дворник успел выкинуть — возвращаем
                        agents[conn_id] = entry

                # Двоичное — это кадр экрана. Разбирать его незачем: сайт
                # только мост, картинку собирает браузер зрителя.
                if isinstance(message, (bytes, bytearray, memoryview)):
                    raw = bytes(message)
                    # Первый байт говорит, что это: кадр экрана или кусок
                    # файла. Без него одно от другого не отличить — канал
                    # у них общий.
                    if raw[:1] == bytes([FRAME_FILE]):
                        _fs_frame(raw)
                    else:
                        _screen_frame(raw)
                    continue

                try:
                    payload = json.loads(message)
                except (TypeError, ValueError):
                    continue
                if not isinstance(payload, dict):
                    continue
                kind = payload.get("type")
                if kind == "ping":
                    try:
                        with agent_send_lock:
                            ws.send(json.dumps({"type": "pong", "t": payload.get("t")}))
                    except Exception:
                        break
                elif kind == "touch-reply":
                    _viewers_tell(payload)
                elif kind == "fs-reply":
                    _fs_reply(payload)
                elif kind == "screen-state":
                    with screen_lock:
                        screen["running"] = bool(payload.get("running"))
                        screen["paused"] = bool(payload.get("paused"))
                        screen["width"] = int(payload.get("width") or 0)
                        screen["height"] = int(payload.get("height") or 0)
                        screen["error"] = str(payload.get("error") or "")[:200]
                        if not screen["running"]:
                            # Захват кончился — старые SPS/PPS больше не
                            # описывают ничего, следующий зритель должен
                            # дождаться новых, а не завести декодер зря.
                            screen["config"] = None
                    _viewers_tell({"type": "state", **_screen_snapshot()})
                # Неизвестный тип сообщения не роняет разговор и не толкуется
                # наугад — то же правило, что у агента на той стороне.
        finally:
            with agents_lock:
                agents.pop(conn_id, None)
            if live_agent["ws"] is ws:
                live_agent["ws"] = None
            _fs_drop_all("Телефон отключился.")
            with screen_lock:
                screen.update(running=False, paused=False, config=None, error="")
            _viewers_tell({"type": "state", **_screen_snapshot()})
            _log(f"агент отключился: {entry['name']}")
            _publish()
            try:
                ws.close()
            except Exception:
                pass

    @sock.route("/ws/agent", bp=phone_bp)
    def agent_ws(ws):
        handle_agent(ws, peer=request.headers.get("X-Forwarded-For", "") or (request.remote_addr or ""))

    # ---- Зритель: браузер на ПК -------------------------------------------

    def handle_viewer(ws):
        """Один зритель экрана. Отдельной функцией — как и разговор с
        агентом: тест зовёт её с фальшивым сокетом, без сети."""
        viewer_id = secrets.token_hex(8)
        viewer = {"queue": queue.Queue(maxsize=VIEWER_QUEUE_MAX), "need_key": False}
        with viewers_lock:
            first = not viewers
            viewers[viewer_id] = viewer

        # Кадры уходят своим потоком, а не прямо из насоса агента: медленный
        # зритель иначе тормозил бы телефон, у которого на другом конце
        # копился бы неотправленный поток.
        stop = threading.Event()

        def pump():
            while not stop.is_set():
                try:
                    item = viewer["queue"].get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    ws.send(item)
                except Exception:
                    stop.set()
                    return

        sender = threading.Thread(target=pump, daemon=True)
        sender.start()

        try:
            _viewer_put(viewer, json.dumps({"type": "state", **_screen_snapshot()}))
            with screen_lock:
                config = screen["config"]
                running = screen["running"]
            if running:
                # Пришёл посреди трансляции: сперва параметры кодека, потом
                # просим опорный кадр — без него зритель смотрел бы на кашу,
                # пока телефон не соберётся послать опорный сам.
                if config:
                    _viewer_put(viewer, config)
                viewer["need_key"] = True
                if first:
                    _agent_send({"type": "screen-resume"})
                _agent_send({"type": "screen-key"})
            elif first:
                _agent_send({"type": "screen-resume"})

            while not stop.is_set():
                try:
                    message = ws.receive(timeout=30)
                except Exception:
                    break
                if message is None:
                    continue
                if isinstance(message, (bytes, bytearray, memoryview)):
                    continue                  # зрителю нечего слать двоичным
                try:
                    payload = json.loads(message)
                except (TypeError, ValueError):
                    continue
                if not isinstance(payload, dict):
                    continue
                kind = payload.get("type")
                if kind == "start":
                    # Подтверждение на телефоне спросит сама система Android,
                    # и обойти это нечем — см. docs/phone-tz/03-screen.md.
                    ok = _agent_send({"type": "screen-start"})
                    _viewer_put(viewer, json.dumps({
                        "type": "asked", "ok": ok,
                        "error": "" if ok else "Телефон не на связи.",
                    }))
                elif kind == "stop":
                    _agent_send({"type": "screen-stop"})
                elif kind == "key":
                    viewer["need_key"] = True
                    _agent_send({"type": "screen-key"})
                elif kind == "touch":
                    # Управление пальцем (ступень 5). Сайт ничего тут не
                    # решает — только передаёт: что можно нажимать, решает
                    # служба спец-возможностей на самом телефоне, которую
                    # человек включил руками.
                    ok = _agent_send({
                        "type": "touch",
                        "action": str(payload.get("action") or "")[:16],
                        "x": float(payload.get("x") or 0),
                        "y": float(payload.get("y") or 0),
                        "x2": float(payload.get("x2") or 0),
                        "y2": float(payload.get("y2") or 0),
                        "ms": int(payload.get("ms") or 0),
                        "name": str(payload.get("name") or "")[:16],
                        "text": str(payload.get("text") or "")[:500],
                    })
                    if not ok:
                        _viewer_put(viewer, json.dumps({
                            "type": "touch-reply", "ok": False,
                            "error": "Телефон не на связи.",
                        }))
                elif kind == "ping":
                    _viewer_put(viewer, json.dumps({"type": "pong"}))
        finally:
            stop.set()
            with viewers_lock:
                viewers.pop(viewer_id, None)
                empty = not viewers
            # Зрителей не осталось — телефону незачем кодировать в пустоту:
            # это батарея и мобильный трафик. Захват при этом НЕ выключаем,
            # иначе Android спросил бы подтверждение заново при возврате.
            if empty:
                _agent_send({"type": "screen-pause"})
            try:
                ws.close()
            except Exception:
                pass

    @sock.route("/ws/phone", bp=phone_bp)
    def phone_ws(ws):
        # Гейт как у консоли: пароль кабинета плюс суточный пароль. Правило
        # хозяина «гости не управляют устройствами» действует и здесь.
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        handle_viewer(ws)

    @phone_bp.get("/phone")
    @login_required
    def phone_page():
        # Суточный пароль спрашивает сама страница (карточка в стиле сайта),
        # как это делает /netbird: отдельного экрана-гейта на сайте нет.
        html = template("phone.html")
        return (html.replace("{{CONSOLE_OK}}", "1" if session.get("console_authenticated") else "0")
                    .replace("__ICONLINKS__", icon_links))

    @phone_bp.get("/api/phone/agent")
    @login_required
    def phone_agent_api():
        snapshot = _snapshot()
        snapshot["ip"] = agent_ip
        snapshot["configured"] = bool(agent_token)
        return jsonify(snapshot)

    @phone_bp.post("/api/phone/token")
    @login_required
    def phone_token_issue():
        """Выдать этому устройству личный токен.

        POST, а не GET: ручка заводит новую запись, а меняющие состояние
        адреса на этом сайте всегда POST (как /api/files/connect или
        /api/drop/folder). Заодно из него нельзя выстрелить чужой картинкой
        или ссылкой — кука сессии и так `SameSite=Strict`, но складывать две
        защиты дешевле, чем потом разбираться, какая из них не сработала.

        Зовёт JS-мост оболочки, когда хозяин уже вошёл в кабинет внутри
        приложения, — потому руками токен больше не вбивают. Секрет уходит
        в ответе один-единственный раз: на диске остаётся только хэш, и
        показать его заново неоткуда."""
        raw = secrets.token_urlsafe(DEVICE_TOKEN_BYTES)
        payload = request.get_json(silent=True) or {}
        label = str(payload.get("label") or request.args.get("label") or "телефон")
        token_id = secrets.token_hex(8)
        with devices_lock:
            devices[token_id] = {
                "label": label[:DEVICE_LABEL_MAX],
                "hash": _hash(raw),
                "created": time.time(),
                "last_used": None,
            }
            _devices_write_locked()
        _log(f"выдан токен устройству: {label[:DEVICE_LABEL_MAX]}")
        return jsonify(id=token_id, token=raw)

    @phone_bp.get("/api/phone/tokens")
    @login_required
    def phone_tokens_api():
        with devices_lock:
            rows = [
                {"id": token_id, "label": row["label"],
                 "created": row["created"], "last_used": row["last_used"]}
                for token_id, row in devices.items()
            ]
        rows.sort(key=lambda r: r["created"], reverse=True)
        return jsonify(tokens=rows)

    @phone_bp.delete("/api/phone/token/<token_id>")
    @login_required
    def phone_token_revoke(token_id):
        """Отзыв поштучный и с сайта — в этом весь смысл личных токенов.
        Общий пароль из .env менять ради одного потерянного телефона не
        придётся."""
        with devices_lock:
            row = devices.pop(token_id, None)
            if row:
                _devices_write_locked()
        if not row:
            return jsonify(error="Такого токена нет."), 404
        _log(f"токен отозван: {row['label']}")
        return jsonify(ok=True)

    # ---- Раздача сборки --------------------------------------------------
    # APK лежит не в образе, а в `data/apk` рядом с остальными данными: тот
    # же примонтированный каталог, что у дропа и фонотеки, — переживает
    # пересборку контейнера. Собирает его отдельный workflow и кладёт в
    # релиз; на VPS сборка приезжает кнопкой «подтянуть» (ниже).

    def _apk_pick():
        """Самая свежая сборка: (путь, номер версии) или (None, 0)."""
        try:
            names = [n for n in os.listdir(apk_dir) if n.lower().endswith(".apk")]
        except OSError:
            return None, 0
        best, best_version, best_mtime = None, 0, 0.0
        for name in names:
            path = os.path.join(apk_dir, name)
            digits = APK_VERSION_RE.findall(name)
            version = int(digits[-1]) if digits else 0
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if (version, mtime) > (best_version, best_mtime):
                best, best_version, best_mtime = path, version, mtime
        return best, best_version

    def _version_payload():
        path, version = _apk_pick()
        if not path:
            return {"version": 0, "url": None, "name": None, "size": 0, "updated": None}
        return {
            "version": version,
            "url": "/app",
            "name": os.path.basename(path),
            "size": os.path.getsize(path),
            "updated": os.path.getmtime(path),
        }

    @phone_bp.get("/app")
    @login_required
    def app_apk():
        path, _version = _apk_pick()
        if not path:
            return jsonify(error="Сборки ещё нет — собери её workflow'ом android.yml "
                                 "и нажми «подтянуть» на /api/app/pull."), 404
        return send_file(path, as_attachment=True,
                         download_name=os.path.basename(path),
                         mimetype="application/vnd.android.package-archive")

    @phone_bp.get("/api/app/version")
    def app_version_api():
        # Пускаем и хозяина из браузера, и сам телефон по токену агента:
        # самообновлению неоткуда взять куку сессии.
        header_token = request.headers.get("X-Agent-Token")
        if not session.get("authenticated") and not _token_ok(header_token):
            return jsonify(error="Нужен вход или токен агента."), 403
        return jsonify(_version_payload())

    @phone_bp.post("/api/app/pull")
    @login_required
    def app_pull_api():
        """Забрать свежий APK из последнего релиза репозитория.

        Иначе сборку пришлось бы каждый раз руками копировать на VPS: собирает
        её облачный раннер, а раздаёт сайт из Амстердама, и общего диска у них
        нет. Репозиторий публичный, поэтому токен не нужен."""
        api = f"https://api.github.com/repos/{apk_repo}/releases/latest"
        try:
            request_obj = urllib.request.Request(api, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "vitazgio.ru",
            })
            with urllib.request.urlopen(request_obj, timeout=15) as resp:
                release = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            return jsonify(error=f"Не удалось спросить GitHub: {exc}"), 502

        asset = next((a for a in release.get("assets", [])
                      if str(a.get("name", "")).lower().endswith(".apk")), None)
        if not asset:
            return jsonify(error="В последнем релизе нет ни одного .apk."), 404
        if int(asset.get("size") or 0) > APK_PULL_MAX:
            return jsonify(error="Сборка подозрительно большая — не качаю."), 413

        os.makedirs(apk_dir, exist_ok=True)
        name = os.path.basename(str(asset["name"]))
        target = os.path.join(apk_dir, name)
        tmp = target + ".part"
        try:
            asset_req = urllib.request.Request(asset["browser_download_url"],
                                               headers={"User-Agent": "vitazgio.ru"})
            with urllib.request.urlopen(asset_req, timeout=60) as resp, open(tmp, "wb") as out:
                written = 0
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > APK_PULL_MAX:
                        raise OSError("сборка больше разрешённого")
                    out.write(chunk)
            os.replace(tmp, target)
        except (urllib.error.URLError, OSError) as exc:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return jsonify(error=f"Не удалось скачать сборку: {exc}"), 502

        payload = _version_payload()
        payload["pulled"] = name
        return jsonify(payload)

    # Тестам нужен разговор с агентом без сети, а странице отладки — реестр.
    phone_bp.fs = phone_fs
    phone_bp.handle_agent = handle_agent
    phone_bp.handle_viewer = handle_viewer
    phone_bp.screen_snapshot = _screen_snapshot
    phone_bp.agent_snapshot = _snapshot
    return phone_bp
