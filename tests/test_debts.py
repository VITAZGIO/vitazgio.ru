import time

import pytest


DEBTOR_ID = "debtor-1"
DEBTOR_PASSWORD = "debtor-pass-123"


@pytest.fixture(autouse=True)
def reset_debts(app_module):
    salt, password_hash = app_module._debt_hash_password(DEBTOR_PASSWORD)
    with app_module.notifications_lock:
        app_module.notifications_data.clear()
    with app_module.debts_lock:
        app_module.debts_data.clear()
        app_module.debts_data.update({
            "users": [{
                "id": DEBTOR_ID,
                "name": "Иван",
                "password_plain": DEBTOR_PASSWORD,
                "salt": salt,
                "password_hash": password_hash,
                "created": "2026-09-10T10:00:00",
                "color": "cyan",
            }],
            "entries": [{
                "id": "debt-1",
                "user_id": DEBTOR_ID,
                "kind": "debt",
                "date": "2026-09-10",
                "amount_cents": 200000,
                "comment": "Долг",
                "created": "2026-09-10T10:01:00",
            }],
            "payment_requests": [],
        })


def _debtor_client(app_module):
    client = app_module.app.test_client()
    resp = client.post("/api/login", json={"password": DEBTOR_PASSWORD})
    assert resp.status_code == 200
    return client


def _owner_client(auth_client):
    with auth_client.session_transaction() as sess:
        sess["debts_owner_authenticated"] = True
        sess["debts_owner_unlocked_at"] = time.time()
    return auth_client


def test_debtor_payment_request_keeps_actual_debt_pending(app_module):
    client = _debtor_client(app_module)

    resp = client.post("/api/debts/payment-requests", json={
        "date": "2026-09-11",
        "amount": "2000",
        "bank": "ОЗОН",
    })

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["me"]["total_cents"] == 200000
    assert body["me"]["pending_return_cents"] == 200000
    assert body["me"]["projected_total_cents"] == 0
    assert body["payment_requests"][0]["bank"] == "ОЗОН"
    assert body["payment_requests"][0]["status"] == "pending"
    assert body["entries"][0]["kind"] == "debt"
    with app_module.notifications_lock:
        notifications = app_module._notifications_snapshot_locked()
    assert notifications["unread_count"] == 1
    assert notifications["items"][0]["title"] == "Заявка на пополнение"
    assert "Иван" in notifications["items"][0]["text"]


def test_owner_approves_payment_request_into_return(app_module, auth_client):
    debtor = _debtor_client(app_module)
    created = debtor.post("/api/debts/payment-requests", json={
        "date": "2026-09-11",
        "amount": "2000",
        "bank": "Т-Банк",
    }).get_json()
    request_id = created["payment_requests"][0]["id"]

    owner = _owner_client(auth_client)
    resp = owner.post(f"/api/debts/payment-requests/{request_id}/approve")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["payment_requests"] == []
    assert body["users"][0]["total_cents"] == 0
    approved = [e for e in body["entries"] if e["kind"] == "return"][0]
    assert approved["amount_cents"] == 200000
    assert approved["comment"] == "Взнос: Т-Банк"


def test_owner_cancels_payment_request_without_changing_debt(app_module, auth_client):
    debtor = _debtor_client(app_module)
    created = debtor.post("/api/debts/payment-requests", json={
        "amount": "500",
        "bank": "ОЗОН",
    }).get_json()
    request_id = created["payment_requests"][0]["id"]

    owner = _owner_client(auth_client)
    resp = owner.delete(f"/api/debts/payment-requests/{request_id}")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["payment_requests"] == []
    assert body["users"][0]["total_cents"] == 200000
    assert all(e["kind"] != "return" for e in body["entries"])


def test_debtor_can_cancel_own_pending_payment_request(app_module):
    client = _debtor_client(app_module)
    created = client.post("/api/debts/payment-requests", json={
        "amount": "500",
        "bank": "ОЗОН",
    }).get_json()
    request_id = created["payment_requests"][0]["id"]

    resp = client.delete(f"/api/debts/me/payment-requests/{request_id}")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["payment_requests"] == []
    assert body["me"]["total_cents"] == 200000


def test_payment_request_requires_known_bank(app_module):
    client = _debtor_client(app_module)

    resp = client.post("/api/debts/payment-requests", json={
        "amount": "100",
        "bank": "Другой банк",
    })

    assert resp.status_code == 400
    assert "банк" in resp.get_json()["error"].lower()
