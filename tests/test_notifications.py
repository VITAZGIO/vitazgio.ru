def _reset_notifications(app_module):
    with app_module.notifications_lock:
        app_module.notifications_data.clear()


def test_notifications_page_and_api_flow(app_module, auth_client):
    _reset_notifications(app_module)
    app_module._notification_add(
        "Заявка на пополнение",
        "Иван: 500 ₽ · ОЗОН",
        href="/debts",
        kind="payment-request",
    )

    page = auth_client.get("/notifications")
    listing = auth_client.get("/api/notifications")

    assert page.status_code == 200
    assert listing.status_code == 200
    body = listing.get_json()
    assert body["unread_count"] == 1
    notification_id = body["items"][0]["id"]

    marked = auth_client.post(f"/api/notifications/{notification_id}/read")
    assert marked.status_code == 200
    assert marked.get_json()["unread_count"] == 0

    cleared = auth_client.delete("/api/notifications")
    assert cleared.status_code == 200
    assert cleared.get_json()["items"] == []


def test_notifications_api_requires_login(client):
    assert client.get("/api/notifications").status_code == 302
