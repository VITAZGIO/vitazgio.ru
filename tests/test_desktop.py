"""Device credentials, viewer isolation and revocation for Windows signalling."""
from functools import wraps
import re
import shutil
import subprocess

import pytest
from flask import Flask, jsonify, session

@pytest.fixture
def desktop(tmp_path, app_module):
    # ``blueprints`` is deliberately imported by app_module from an isolated
    # temporary copy of the site.  Importing it at collection time works on a
    # developer machine by accident (the repository is on sys.path), but not
    # reliably in GitHub Actions.
    create_desktop_blueprint = app_module.create_desktop_blueprint
    app = Flask(__name__)
    app.secret_key = "desktop-test-only"
    app.testing = True

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return jsonify(error="login"), 401
            return fn(*args, **kwargs)
        return wrapped

    app.register_blueprint(create_desktop_blueprint(
        template=lambda name: name, icon_links="", login_required=login_required,
        data_dir=str(tmp_path), repo="VITAZGIO/vitazgio.ru"))
    return app, tmp_path


def owner(app, console=True):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess.update(authenticated=True, console_authenticated=console)
    return client


def pair(client, enabled=True, control=True):
    data = client.post("/api/desktop/register", json={"name": "Test PC"}).get_json()
    headers = {"Authorization": "Bearer " + data["token"]}
    assert client.post("/api/desktop/host", headers=headers,
                       json={"enabled": enabled, "control": control, "version": "0.1.0"}).status_code == 200
    return data, headers


def test_login_console_gate_and_hashed_device_tokens(desktop):
    app, folder = desktop
    guest, user = app.test_client(), owner(app, console=False)
    assert guest.get("/desktop").status_code == 401
    assert guest.get("/api/desktop/devices").status_code == 401
    assert guest.post("/api/desktop/register").status_code == 401
    device, headers = pair(user)
    assert user.get("/api/desktop/config").status_code == 403
    assert user.post("/api/desktop/sessions", json={"device": device["id"], "offer": "v=0\r\n"}).status_code == 403
    assert device["token"] not in (folder / "desktop_devices.json").read_text()
    # Viewer uses the JSON content-type for every request, including GET.
    listing = user.get("/api/desktop/devices", headers={"Content-Type": "application/json"}).get_json()["devices"]
    assert listing[0]["online"] is True
    assert "hash" not in listing[0] and "token" not in listing[0]
    assert guest.post("/api/desktop/host", json={}).status_code == 401
    assert guest.get("/api/desktop/config", headers=headers).status_code == 401


def test_signalling_is_scoped_to_own_device_and_own_viewer(desktop):
    app, _ = desktop
    viewer, other = owner(app), owner(app)
    device, agent = pair(viewer)
    _, wrong_agent = pair(other)
    created = viewer.post("/api/desktop/sessions", json={"device": device["id"], "offer": "v=0\r\no=offer", "control": True})
    assert created.status_code == 200
    cid = created.get_json()["id"]
    url = "/api/desktop/sessions/" + cid
    assert other.get(url).status_code == 404
    assert other.post(url, headers=wrong_agent, json={"answer": "v=0\r\no=wrong"}).status_code == 404
    assert viewer.post(url, json={"answer": "v=0\r\no=viewer"}).status_code == 404
    assert app.test_client().post(url, headers=agent, json={"answer": "v=0\r\no=answer"}).status_code == 200
    assert viewer.get(url).get_json()["answer"] == "v=0\r\no=answer"
    assert viewer.post("/api/desktop/sessions", json={"device": device["id"], "offer": "v=0"}).status_code == 409
    assert other.delete(url).status_code == 404
    assert viewer.delete(url).status_code == 200
    assert viewer.get(url).status_code == 404


def test_disabled_access_control_consent_and_revocation(desktop):
    app, _ = desktop
    viewer = owner(app)
    device, agent = pair(viewer, enabled=False, control=False)
    payload = {"device": device["id"], "offer": "v=0\r\n", "control": True}
    assert viewer.post("/api/desktop/sessions", json=payload).status_code == 409
    viewer.post("/api/desktop/host", headers=agent, json={"enabled": True, "control": False})
    created = viewer.post("/api/desktop/sessions", json=payload).get_json()
    assert created["control"] is False
    cid = created["id"]
    assert viewer.delete("/api/desktop/devices/" + device["id"]).status_code == 200
    assert viewer.get("/api/desktop/sessions/" + cid).status_code == 404
    assert viewer.post("/api/desktop/host", headers=agent, json={"enabled": True}).status_code == 401


def test_session_expires_when_viewer_disappears(desktop, monkeypatch):
    import blueprints.desktop as module
    app, _ = desktop
    user = owner(app)
    device, agent = pair(user)
    cid = user.post("/api/desktop/sessions", json={"device": device["id"], "offer": "v=0"}).get_json()["id"]
    now = module.time.time()
    monkeypatch.setattr(module.time, "time", lambda: now + 30)
    assert user.get("/api/desktop/sessions/" + cid).status_code == 404
    assert user.post("/api/desktop/host", headers=agent, json={"enabled": True}).get_json()["sessions"] == []


def test_rendered_browser_pages_have_valid_scripts(auth_client, app_module):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is needed for browser JavaScript syntax checks")
    for url in ("/cabinet", "/apps", "/music", "/netbird", "/desktop"):
        response = auth_client.get(url)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        for match in re.finditer(r"<script\b([^>]*)>([\s\S]*?)</script>", html):
            if "src=" in match[1] or not match[2].strip():
                continue
            checked = subprocess.run([node, "--check"], input=match[2], text=True,
                                     encoding="utf-8", capture_output=True, timeout=10)
            assert checked.returncode == 0, f"{url}: {checked.stderr}"
    engine = auth_client.get("/vg-player.js").get_data(as_text=True)
    checked = subprocess.run([node, "--check"], input=engine, text=True,
                             encoding="utf-8", capture_output=True, timeout=10)
    assert checked.returncode == 0, checked.stderr
    routes = [r for r in app_module.app.url_map.iter_rules() if r.endpoint != "static"]
    print(f"Route inventory: {len(routes)} rules, {len({r.rule for r in routes})} URLs")
