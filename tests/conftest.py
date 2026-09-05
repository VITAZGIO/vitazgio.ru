"""Общая обвязка тестов.

Главная сложность здесь одна: `app.py` — не фабрика, а модуль, который
делает всю работу прямо при импорте. Он читает соль и хэш пароля из
окружения (без них — SystemExit), считает пути к данным от собственного
расположения (`DATA_DIR`/`DROP_DIR` рядом с `app.py`) и запоминает адрес
OpenRouter в глобальную переменную.

Отсюда два решения, на которых держатся все тесты:

1. **Импортируем копию проекта во временной папке**, а не сам репозиторий.
   Раз пути к данным считаются от `__file__`, копия автоматически получает
   свои `data/` и `drop_data/` внутри `tmp` — тесты не могут затоптать
   настоящую фонотеку, дроп и историю чатов. Трогать ради этого код
   приложения (добавлять переменные окружения для путей) не пришлось.

2. **Окружение готовим ДО импорта.** Пароль, ключ и адрес OpenRouter
   попадают в глобальные переменные модуля в момент импорта, поменять их
   потом нельзя.

Пароль кабинета для тестов задаём свой: считаем PBKDF2 от `TEST_PASSWORD`
теми же 600 000 итераций и кладём соль с хэшем в окружение. Настоящие
значения лежат только в `.env` на сервере и тестам недоступны.
"""

import base64
import hashlib
import importlib
import json
import os
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Пароль кабинета, под которым ходят тесты. К настоящему отношения не имеет.
TEST_PASSWORD = "test-pass-12345"

# Что фейковый OpenRouter отдаёт по кускам. Тест сверяет, что склеенный
# ответ дошёл до клиента целиком и в том же порядке.
FAKE_AI_CHUNKS = ["Привет", ", ", "это тест."]
FAKE_AI_REPLY = "".join(FAKE_AI_CHUNKS)


# ---- Фейковый OpenRouter ----------------------------------------------------
# В `scratchpad/` у хозяина лежит `fakeor.py` для ручных прогонов, но
# scratchpad в .gitignore — в репозитории его нет, переиспользовать нечего.
# Поэтому здесь свой, маленький: только то, что нужно двум тестам.
#
# Поднимаем настоящий HTTP-сервер, а не подменяем urllib: так проверяется
# весь путь целиком — сборка тела запроса, разбор SSE построчно, накопление
# ответа и сохранение его в историю чата.

class _FakeOpenRouter(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass                      # не засорять вывод pytest логом запросов

    def do_GET(self):
        # Каталог моделей: приложение спрашивает его, чтобы собрать список
        # запасных. Отдаём пусто — тогда пробуется только запрошенная.
        if self.path.endswith("/models"):
            self._send_json({"data": []})
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError:
            body = {}
        self.server.last_request = body

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for piece in FAKE_AI_CHUNKS:
            frame = {"choices": [{"delta": {"content": piece}}]}
            self.wfile.write(
                b"data: " + json.dumps(frame, ensure_ascii=False).encode("utf-8") + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _send_json(self, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture(scope="session")
def fake_openrouter():
    """Адрес фейкового OpenRouter. Поднят до импорта приложения — иначе
    в модуль попал бы настоящий адрес и тест полез бы в интернет."""
    server = HTTPServer(("127.0.0.1", 0), _FakeOpenRouter)
    server.last_request = None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


# ---- Приложение -------------------------------------------------------------

@pytest.fixture(scope="session")
def app_module(tmp_path_factory, fake_openrouter):
    """Импортированная копия `app.py` со своими данными во временной папке."""
    work = tmp_path_factory.mktemp("site")
    for name in ("app.py", "blueprints", "templates", "static"):
        src = REPO_ROOT / name
        dst = work / name
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst)

    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", TEST_PASSWORD.encode("utf-8"), salt, 600_000)
    host, port = fake_openrouter.server_address[0], fake_openrouter.server_address[1]
    os.environ.update({
        "CABINET_PASSWORD_SALT": base64.b64encode(salt).decode(),
        "CABINET_PASSWORD_HASH": base64.b64encode(digest).decode(),
        # Фиксированный ключ сессии: без него модуль берёт случайный, и
        # куки бы протухали между перезагрузками модуля.
        "VITAZGIO_SESSION_SECRET": "test-secret-not-a-real-one",
        "OPENROUTER_KEY": "test-key",
        "OPENROUTER_URL": f"http://{host}:{port}/api/v1/chat/completions",
        "OPENROUTER_MODEL": "test/fake-model",
    })

    # Копия должна выиграть у настоящего репозитория: pytest кладёт корень
    # проекта в sys.path, а имена модулей (`app`, `blueprints`) совпадают.
    sys.path.insert(0, str(work))
    for name in [m for m in sys.modules if m == "app" or m.startswith("blueprints")]:
        del sys.modules[name]
    try:
        module = importlib.import_module("app")
    finally:
        sys.path.remove(str(work))

    module.app.config.update(TESTING=True)
    return module


@pytest.fixture
def client(app_module):
    """Гость: пароль не вводили, доверенного устройства нет."""
    return app_module.app.test_client()


@pytest.fixture
def auth_client(app_module):
    """Хозяин: вошёл настоящим паролем через /api/login, а не подделкой
    сессии — так проверяется в том числе и то, что вход вообще работает."""
    c = app_module.app.test_client()
    resp = c.post("/api/login", json={"password": TEST_PASSWORD})
    assert resp.status_code == 200, f"вход не удался: {resp.data!r}"
    return c
