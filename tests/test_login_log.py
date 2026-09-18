"""Вкладка кабинета «Журнал входов» (/login-log).

Первый blueprint, переехавший на прямые импорты из core/ (задача 34) —
здесь ловим не только «страница открывается», но и то, что запись,
которую при входе пишет `core.auth.log_login`, реально долетает до
API, который читает `blueprints/login_log.py`: до этой задачи обе
стороны были один и тот же модуль `app.py`, теперь это два разных файла,
делящих общее состояние через core/auth.py.
"""


def test_login_log_requires_login(client):
    assert client.get("/login-log").status_code == 302
    assert client.get("/api/login-log").status_code == 302


def test_login_log_page_opens_for_owner(auth_client):
    resp = auth_client.get("/login-log")
    assert resp.status_code == 200


def test_successful_login_is_recorded_and_readable_via_api(auth_client):
    """`auth_client` уже вошёл через POST /api/login — значит core.auth.log_login
    уже дописал(а) запись с kind="ok" в login_log до этого вызова."""
    resp = auth_client.get("/api/login-log")
    assert resp.status_code == 200
    rows = resp.get_json()
    assert rows, "журнал пуст, хотя вход только что состоялся"
    # Список — reversed(login_log), самая новая запись первая.
    assert rows[0]["kind"] == "ok"


def test_failed_login_is_recorded_as_fail(client, auth_client):
    client.post("/api/login", json={"password": "точно не тот пароль"})
    rows = auth_client.get("/api/login-log").get_json()
    kinds = {row["kind"] for row in rows}
    assert "fail" in kinds
