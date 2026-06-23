import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

import paramiko
from flask import Flask, jsonify, redirect, request, session, url_for
from flask_sock import Sock

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("VITAZGIO_SESSION_SECRET", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)
sock = Sock(app)

PASSWORD_SALT = base64.b64decode("vLsGUQ/owFhcITf4A6CVjw==")
PASSWORD_HASH = base64.b64decode("T+E27QxamfCbhsdxJ1JlEXo4yuBwfwQFtw9ODFkA+kg=")
PASSWORD_ITERATIONS = 600_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
login_attempts = defaultdict(deque)
login_attempts_lock = threading.Lock()

NETBIRD_DEVICES = [
    {"ip": "100.104.188.141", "name": "NOUTBOOK"},
    {"ip": "100.104.140.4", "name": "VitazComp"},
    {"ip": "100.104.1.172", "name": "windows10proxmox"},
    {"ip": "100.104.67.89", "name": "orangepizero3", "ssh_enabled": True, "ssh_user": "CHANGE_ME"},
    {"ip": "100.104.221.91", "name": "ubuntu-server", "ssh_enabled": True, "ssh_user": "CHANGE_ME"},
    {"ip": "100.104.160.121", "name": "windows10V"},
    {"ip": "100.104.111.39", "name": "ubuntuvitaz1", "ssh_enabled": True, "ssh_user": "CHANGE_ME"},
    {"ip": "100.104.86.103", "name": "MOBILA"},
]
PING_INTERVAL_SECONDS = 10
PING_TIMEOUT_SECONDS = 1
PING_LATENCY_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)

netbird_status = {device["ip"]: {"online": False, "latency_ms": None} for device in NETBIRD_DEVICES}
netbird_status_lock = threading.Lock()
ssh_devices_by_ip = {device["ip"]: device for device in NETBIRD_DEVICES if device.get("ssh_enabled")}

SSH_HOST_KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_host_key")
SSH_HOST_KEY_PATH = os.path.join(SSH_HOST_KEY_DIR, "id_rsa")


def load_or_create_ssh_host_key():
    os.makedirs(SSH_HOST_KEY_DIR, exist_ok=True)
    if not os.path.exists(SSH_HOST_KEY_PATH):
        key = paramiko.RSAKey.generate(4096)
        key.write_private_key_file(SSH_HOST_KEY_PATH)
        os.chmod(SSH_HOST_KEY_PATH, 0o600)
        public_line = f"{key.get_name()} {key.get_base64()} vitazgio-console"
        with open(SSH_HOST_KEY_PATH + ".pub", "w", encoding="utf-8") as pub_file:
            pub_file.write(public_line + "\n")
        print(f"[console] Сгенерирован новый SSH-ключ. Добавь в authorized_keys на устройствах:\n{public_line}")
        return key
    return paramiko.RSAKey.from_private_key_file(SSH_HOST_KEY_PATH)


ssh_host_key = load_or_create_ssh_host_key() if ssh_devices_by_ip else None

SSH_GATE_PASSWORD_PREFIX = os.environ.get("SSH_GATE_PASSWORD_PREFIX")
CONSOLE_LOGIN_WINDOW_SECONDS = 300
CONSOLE_LOGIN_MAX_ATTEMPTS = 5
console_login_attempts = defaultdict(deque)
console_login_attempts_lock = threading.Lock()


def console_password_today():
    now = datetime.now(ZoneInfo("Europe/Moscow"))
    return f"{SSH_GATE_PASSWORD_PREFIX}{now:%d%m}"


def ping_once(ip):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_SECONDS * 1000), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=PING_TIMEOUT_SECONDS + 1
        )
    except (subprocess.TimeoutExpired, OSError):
        return False, None
    if result.returncode != 0:
        return False, None
    match = PING_LATENCY_RE.search(result.stdout)
    return True, float(match.group(1)) if match else None


def netbird_ping_loop():
    while True:
        for device in NETBIRD_DEVICES:
            online, latency_ms = ping_once(device["ip"])
            with netbird_status_lock:
                netbird_status[device["ip"]] = {"online": online, "latency_ms": latency_ms}
        time.sleep(PING_INTERVAL_SECONDS)


threading.Thread(target=netbird_ping_loop, daemon=True).start()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("home"))
        return view(*args, **kwargs)

    return wrapped


def password_matches(password):
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), PASSWORD_SALT, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(candidate, PASSWORD_HASH)


@app.post("/api/login")
def login():
    client = request.remote_addr or "unknown"
    now = time.monotonic()

    with login_attempts_lock:
        attempts = login_attempts[client]
        while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not password_matches(password):
        with login_attempts_lock:
            login_attempts[client].append(now)
        return jsonify(error="Неверный пароль."), 401

    with login_attempts_lock:
        login_attempts.pop(client, None)
    session.clear()
    session["authenticated"] = True
    session.permanent = False
    return jsonify(redirect=url_for("cabinet"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.get("/api/netbird/status")
@login_required
def netbird_status_api():
    with netbird_status_lock:
        return jsonify(netbird_status)


@app.post("/api/console/login")
@login_required
def console_login():
    if not SSH_GATE_PASSWORD_PREFIX:
        return jsonify(error="Консоль не настроена."), 503

    client = request.remote_addr or "unknown"
    now = time.monotonic()

    with console_login_attempts_lock:
        attempts = console_login_attempts[client]
        while attempts and now - attempts[0] > CONSOLE_LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= CONSOLE_LOGIN_MAX_ATTEMPTS:
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or not hmac.compare_digest(password, console_password_today()):
        with console_login_attempts_lock:
            console_login_attempts[client].append(now)
        return jsonify(error="Неверный пароль."), 401

    with console_login_attempts_lock:
        console_login_attempts.pop(client, None)
    session["console_authenticated"] = True
    return jsonify(ok=True)


@sock.route("/ws/console/<ip>")
def console_ws(ws, ip):
    if not session.get("authenticated") or not session.get("console_authenticated"):
        ws.close()
        return
    device = ssh_devices_by_ip.get(ip)
    if device is None:
        ws.close()
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=device["ssh_user"], pkey=ssh_host_key, timeout=5)
    except (paramiko.SSHException, OSError):
        ws.send(json.dumps({"type": "data", "data": "\r\nНе удалось подключиться по SSH.\r\n"}))
        ws.close()
        return

    channel = client.invoke_shell(term="xterm")
    channel.settimeout(0.0)

    def pump_channel_to_ws():
        try:
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    ws.send(json.dumps({"type": "data", "data": chunk.decode(errors="replace")}))
                else:
                    time.sleep(0.03)
                if channel.closed:
                    break
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=pump_channel_to_ws, daemon=True)
    reader.start()

    try:
        while True:
            message = ws.receive()
            if message is None:
                break
            try:
                payload = json.loads(message)
            except ValueError:
                continue
            if payload.get("type") == "data":
                channel.send(payload.get("data", ""))
            elif payload.get("type") == "resize":
                cols = int(payload.get("cols", 80))
                rows = int(payload.get("rows", 24))
                channel.resize_pty(width=cols, height=rows)
    except (OSError, ValueError):
        pass
    finally:
        channel.close()
        client.close()


@app.get("/cabinet")
@login_required
def cabinet():
    device_items = "".join(
        f'<li class="device" data-ip="{device["ip"]}">'
        f'<button class="copy-ip" type="button" data-ip="{device["ip"]}">{device["ip"]}</button>'
        f'<span class="device-name">{device["name"]}</span>'
        f'<span class="device-status" data-status>проверка…</span>'
        + (
            f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}">Подключиться</button>'
            if device.get("ssh_enabled")
            else '<span class="connect-btn-empty"></span>'
        )
        + '<span class="copy-status">Скопировано</span>'
        + "</li>"
        for device in NETBIRD_DEVICES
    )
    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="robots" content="noindex, nofollow">
      <title>Личный кабинет · vitazgio.ru</title>
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100svh; color: #e9fbff; font-family: "Cascadia Code", Consolas, monospace; background: radial-gradient(circle at top left, #192a44, #0d1321 55%); }
        .cabinet { min-height: 100svh; padding: clamp(24px, 4vw, 54px); background: linear-gradient(135deg, rgba(10,18,32,.25), transparent 60%); }
        .cabinet-header { display: flex; align-items: center; gap: 20px; }
        h1 { margin: 0; font-size: clamp(2.1rem, 5vw, 4.2rem); letter-spacing: -.07em; text-shadow: 2px 0 #ff3fa4, -2px 0 #2de2ff; }
        .logout-form { margin: 0; }
        .logout-button { padding: 10px 16px; color: #dffaff; font: 700 .78rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.07); cursor: pointer; }
        .logout-button:hover { border-color: #2de2ff; background: rgba(45,226,255,.14); }
        [hidden] { display: none !important; }
        .workspace { width: 50%; min-width: 560px; margin-top: clamp(28px, 5vw, 56px); }
        .netbird { border: 1px solid rgba(255,112,38,.24); background: rgba(10,17,30,.72); box-shadow: 0 24px 70px rgba(0,0,0,.24); }
        .netbird-toggle { width: 100%; display: flex; align-items: center; gap: 16px; padding: 18px; text-align: left; border: 0; background: linear-gradient(100deg, rgba(255,105,22,.09), rgba(45,226,255,.035)); }
        .netbird-toggle:hover { border: 0; background: linear-gradient(100deg, rgba(255,105,22,.16), rgba(45,226,255,.07)); }
        .netbird-logo { width: 54px; height: 54px; padding: 6px; object-fit: contain; border-radius: 14px; background: #050608; }
        .netbird-title { display: block; color: #f8fbff; font-size: 1.25rem; font-weight: 800; }
        .netbird-count { display: block; margin-top: 5px; color: #8f99ab; font-size: .74rem; letter-spacing: .08em; text-transform: uppercase; }
        .netbird-arrow { margin-left: auto; color: #ff782f; font-size: 1.3rem; transition: transform .25s ease; }
        .netbird-toggle[aria-expanded="true"] .netbird-arrow { transform: rotate(180deg); }
        .device-list { margin: 0; padding: 8px 18px 18px; list-style: none; border-top: 1px solid rgba(255,255,255,.07); }
        .device { min-height: 48px; display: grid; grid-template-columns: 150px 1fr 70px 116px 82px; align-items: center; gap: 12px; border-bottom: 1px solid rgba(255,255,255,.06); }
        .device:last-child { border-bottom: 0; }
        .copy-ip { padding: 7px 8px; color: #69e8ff; text-align: left; border: 0; background: transparent; }
        .copy-ip:hover, .copy-ip:focus-visible { color: #fff; border: 0; outline: 1px solid rgba(45,226,255,.28); background: rgba(45,226,255,.08); }
        .device-name { color: #c4cad5; font-size: .84rem; overflow-wrap: anywhere; }
        .device-status { color: #6b7385; font-size: .76rem; text-align: right; white-space: nowrap; }
        .device-status::before { content: "● "; }
        .device-status.online { color: #63f5ad; }
        .device-status.offline { color: #ff6b81; }
        .connect-btn { padding: 6px 10px; color: #ff782f; font: 700 .7rem "Cascadia Code", Consolas, monospace; letter-spacing: .04em; text-transform: uppercase; border: 1px solid rgba(255,120,47,.35); background: rgba(255,120,47,.07); cursor: pointer; }
        .connect-btn:hover, .connect-btn:focus-visible { color: #fff; background: rgba(255,120,47,.22); outline: none; }
        .connect-btn-empty { display: block; }
        .copy-status { color: #63f5ad; font-size: .7rem; opacity: 0; transition: opacity .18s ease; }
        .copy-status.visible { opacity: 1; }
        @media (max-width: 900px) {
          .workspace { width: 100%; min-width: 0; }
        }
        @media (max-width: 560px) {
          .cabinet { padding-inline: 20px; }
          .cabinet-header { align-items: flex-start; justify-content: space-between; gap: 12px; }
          .device { grid-template-columns: 1fr auto; gap: 4px 10px; padding: 8px 0; }
          .device-name { grid-column: 1; grid-row: 2; padding-left: 8px; }
          .device-status { grid-column: 2; grid-row: 1; }
          .connect-btn, .connect-btn-empty { grid-column: 1; grid-row: 3; justify-self: start; margin-left: 8px; }
          .copy-status { grid-column: 2; grid-row: 2; text-align: right; }
        }

        .gate-modal { position: fixed; z-index: 100; inset: 0; display: grid; place-items: center; padding: 20px; }
        .gate-backdrop { position: absolute; inset: 0; background: rgba(3, 6, 13, .82); backdrop-filter: blur(12px); }
        .gate-panel { position: relative; width: min(380px, 100%); padding: 30px; color: #e8fbff; border: 1px solid rgba(255,120,47,.3); background: linear-gradient(145deg, rgba(16, 30, 47, .98), rgba(20, 16, 37, .98)); box-shadow: 0 32px 100px rgba(0,0,0,.65); }
        .gate-panel h2 { margin: 0 0 18px; font-size: 1.3rem; }
        .gate-panel input { width: 100%; height: 46px; padding: 0 14px; color: #f4fbff; font: 700 1rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.65); }
        .gate-panel input:focus { border-color: #ff782f; }
        .gate-submit { width: 100%; height: 46px; margin-top: 12px; color: #1a0d04; font: 800 .8rem "Cascadia Code", Consolas, monospace; letter-spacing: .06em; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #ff782f, #ffb35c); cursor: pointer; }
        .gate-error { min-height: 18px; margin: 10px 0 0; color: #ff6ba8; font-size: .78rem; }
        .gate-close { position: absolute; top: 12px; right: 14px; padding: 5px; color: #7d8799; font-size: 1.3rem; border: 0; background: none; cursor: pointer; }

        .term-overlay { position: fixed; z-index: 100; inset: 0; display: flex; flex-direction: column; background: #05070c; }
        .term-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; color: #c4cad5; font-size: .82rem; background: rgba(255,255,255,.04); border-bottom: 1px solid rgba(255,255,255,.08); }
        .term-close { padding: 7px 12px; color: #dffaff; font: 700 .76rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.16); background: transparent; cursor: pointer; }
        .term-close:hover { background: rgba(255,255,255,.08); }
        .term-body { flex: 1; padding: 10px; overflow: hidden; }
      </style>
    </head>
    <body>
      <main class="cabinet">
        <header class="cabinet-header">
          <h1>Личный кабинет</h1>
          <form class="logout-form" action="/logout" method="post"><button class="logout-button" type="submit">Выйти</button></form>
        </header>
        <div class="workspace">
          <section class="netbird">
          <button id="netbird-toggle" class="netbird-toggle" type="button" aria-expanded="false" aria-controls="netbird-devices">
            <img class="netbird-logo" src="/static/netbird-official.png" alt="">
            <span><span class="netbird-title">NetBird</span><span class="netbird-count">8 устройств</span></span>
            <span class="netbird-arrow" aria-hidden="true">⌄</span>
          </button>
          <div id="netbird-devices" hidden>
            <ul class="device-list">{{DEVICE_ITEMS}}</ul>
          </div>
          </section>
        </div>
      </main>

      <div id="gate-modal" class="gate-modal" hidden>
        <div class="gate-backdrop" data-gate-close></div>
        <section class="gate-panel" role="dialog" aria-modal="true" aria-labelledby="gate-title">
          <button class="gate-close" type="button" data-gate-close aria-label="Закрыть">×</button>
          <h2 id="gate-title">Пароль консоли</h2>
          <form id="gate-form">
            <input id="gate-password" name="password" type="password" autocomplete="off" required>
            <button class="gate-submit" type="submit">Войти</button>
            <p id="gate-error" class="gate-error" role="alert"></p>
          </form>
        </section>
      </div>

      <div id="term-overlay" class="term-overlay" hidden>
        <div class="term-header">
          <span id="term-title"></span>
          <button id="term-close" class="term-close" type="button">Закрыть</button>
        </div>
        <div id="term-body" class="term-body"></div>
      </div>

      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
      <script defer src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
      <script defer src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
      <script>
        (() => {
          const toggle = document.getElementById("netbird-toggle");
          const devices = document.getElementById("netbird-devices");
          const timers = new WeakMap();

          toggle.addEventListener("click", () => {
            const expanded = toggle.getAttribute("aria-expanded") === "true";
            toggle.setAttribute("aria-expanded", String(!expanded));
            devices.hidden = expanded;
          });

          const copyFallback = (text) => {
            const input = document.createElement("textarea");
            input.value = text;
            input.style.position = "fixed";
            input.style.opacity = "0";
            document.body.appendChild(input);
            input.select();
            document.execCommand("copy");
            input.remove();
          };

          document.querySelectorAll(".copy-ip").forEach((button) => {
            button.addEventListener("click", async () => {
              try {
                if (navigator.clipboard && window.isSecureContext) {
                  await navigator.clipboard.writeText(button.dataset.ip);
                } else {
                  copyFallback(button.dataset.ip);
                }
                const message = button.parentElement.querySelector(".copy-status");
                message.classList.add("visible");
                clearTimeout(timers.get(message));
                timers.set(message, setTimeout(() => message.classList.remove("visible"), 1800));
              } catch {
                const message = button.parentElement.querySelector(".copy-status");
                message.textContent = "Ошибка";
                message.classList.add("visible");
                setTimeout(() => { message.classList.remove("visible"); message.textContent = "Скопировано"; }, 1800);
              }
            });
          });
        })();

        (() => {
          const refreshStatus = async () => {
            let data;
            try {
              const response = await fetch("/api/netbird/status", { credentials: "same-origin" });
              if (!response.ok) return;
              data = await response.json();
            } catch {
              return;
            }
            document.querySelectorAll(".device").forEach((item) => {
              const info = data[item.dataset.ip];
              const statusEl = item.querySelector(".device-status");
              if (!info) return;
              if (info.online) {
                statusEl.textContent = info.latency_ms != null ? `${Math.round(info.latency_ms)} ms` : "онлайн";
                statusEl.className = "device-status online";
              } else {
                statusEl.textContent = "офлайн";
                statusEl.className = "device-status offline";
              }
            });
          };
          refreshStatus();
          setInterval(refreshStatus, 10000);
        })();

        (() => {
          const gateModal = document.getElementById("gate-modal");
          const gateForm = document.getElementById("gate-form");
          const gatePassword = document.getElementById("gate-password");
          const gateError = document.getElementById("gate-error");
          const termOverlay = document.getElementById("term-overlay");
          const termTitle = document.getElementById("term-title");
          const termBody = document.getElementById("term-body");
          const termClose = document.getElementById("term-close");

          let consoleAuthenticated = false;
          let pendingDevice = null;
          let term = null;
          let fitAddon = null;
          let ws = null;

          const closeGate = () => {
            gateModal.hidden = true;
            gateForm.reset();
            gateError.textContent = "";
            pendingDevice = null;
          };

          document.querySelectorAll("[data-gate-close]").forEach((el) => el.addEventListener("click", closeGate));

          gateForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            gateError.textContent = "";
            try {
              const response = await fetch("/api/console/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: gatePassword.value }),
              });
              const result = await response.json();
              if (!response.ok) {
                gateError.textContent = result.error || "Не удалось войти.";
                return;
              }
              consoleAuthenticated = true;
              const device = pendingDevice;
              closeGate();
              if (device) openTerminal(device.ip, device.name);
            } catch {
              gateError.textContent = "Сервер недоступен.";
            }
          });

          const closeTerminal = () => {
            termOverlay.hidden = true;
            if (ws) { ws.close(); ws = null; }
            if (term) { term.dispose(); term = null; }
            termBody.innerHTML = "";
          };
          termClose.addEventListener("click", closeTerminal);

          const openTerminal = (ip, name) => {
            termTitle.textContent = name + " — " + ip;
            termOverlay.hidden = false;
            if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
              termBody.textContent = "Не удалось загрузить библиотеку терминала (xterm.js) — проверьте сеть/CDN.";
              return;
            }
            term = new Terminal({ convertEol: true, fontFamily: "Cascadia Code, Consolas, monospace", fontSize: 14, theme: { background: "#05070c" } });
            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(termBody);
            fitAddon.fit();

            const protocol = location.protocol === "https:" ? "wss:" : "ws:";
            let gotData = false;
            ws = new WebSocket(`${protocol}//${location.host}/ws/console/${ip}`);

            ws.addEventListener("message", (event) => {
              gotData = true;
              try {
                const payload = JSON.parse(event.data);
                if (payload.type === "data") term.write(payload.data);
              } catch {}
            });

            ws.addEventListener("close", () => {
              if (!gotData) {
                term.write("\r\nНе удалось подключиться (проверь пароль консоли).\r\n");
                consoleAuthenticated = false;
              }
            });

            term.onData((data) => {
              if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "data", data }));
            });

            const sendResize = () => {
              fitAddon.fit();
              if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
              }
            };
            term.onResize(() => sendResize());
            window.addEventListener("resize", () => fitAddon.fit());
            ws.addEventListener("open", sendResize);
          };

          document.querySelectorAll(".connect-btn").forEach((button) => {
            button.addEventListener("click", () => {
              const device = { ip: button.dataset.ip, name: button.dataset.name };
              if (consoleAuthenticated) {
                openTerminal(device.ip, device.name);
              } else {
                pendingDevice = device;
                gateModal.hidden = false;
                requestAnimationFrame(() => gatePassword.focus());
              }
            });
          });
        })();
      </script>
    </body>
    </html>
    """
    return html.replace("{{DEVICE_ITEMS}}", device_items)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#080b12">
      <meta name="description" content="Витрина сервисов vitazgio.ru">
      <title>vitazgio.ru — мои сервисы</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #0d1321;
          --surface: rgba(25, 32, 48, 0.82);
          --line: rgba(255, 255, 255, 0.1);
          --text: #f7f8fc;
          --muted: #989fb2;
        }

        * { box-sizing: border-box; }

        html { scroll-behavior: smooth; }

        body {
          margin: 0;
          min-width: 320px;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at 12% 8%, rgba(57, 126, 255, 0.24), transparent 32rem),
            radial-gradient(circle at 88% 78%, rgba(149, 65, 255, 0.2), transparent 34rem),
            var(--bg);
          color: var(--text);
        }

        body::before {
          content: "";
          position: fixed;
          inset: 0;
          pointer-events: none;
          opacity: 0.16;
          background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
          background-size: 44px 44px;
          mask-image: linear-gradient(to bottom, black, transparent 80%);
        }

        .page {
          min-height: 100svh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          padding: clamp(32px, 6vw, 76px) 0 28px;
          overflow: hidden;
        }

        .hero {
          width: min(1380px, calc(100% - 40px));
          margin: 0 auto clamp(34px, 5vw, 58px);
        }

        .eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 22px;
          color: #cdd2df;
          font-size: 0.76rem;
          font-weight: 700;
          letter-spacing: 0.16em;
          text-transform: uppercase;
        }

        .eyebrow::before {
          content: "";
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #64e6a5;
          box-shadow: 0 0 16px #64e6a5;
        }

        .sr-only {
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip: rect(0, 0, 0, 0);
          white-space: nowrap;
          border: 0;
        }

        .cyber-terminal {
          position: relative;
          min-height: 164px;
          display: flex;
          align-items: center;
          margin: 0;
          padding: 34px clamp(22px, 4vw, 54px);
          overflow: hidden;
          border: 1px solid rgba(54, 228, 255, .24);
          background: linear-gradient(110deg, rgba(12, 28, 43, .92), rgba(20, 17, 38, .82));
          clip-path: polygon(0 0, calc(100% - 25px) 0, 100% 25px, 100% 100%, 25px 100%, 0 calc(100% - 25px));
          box-shadow: inset 0 0 38px rgba(38, 211, 255, .06);
        }

        .cyber-terminal::before,
        .cyber-terminal::after {
          content: "";
          position: absolute;
          height: 2px;
          background: linear-gradient(90deg, transparent, #2de2ff, #ff3fa4, transparent);
          opacity: .72;
        }

        .cyber-terminal::before { top: 0; left: 4%; width: 42%; }
        .cyber-terminal::after { right: 5%; bottom: 0; width: 30%; }

        .terminal-prompt {
          margin-right: .35em;
          color: #ff3fa4;
          font-family: "Cascadia Code", Consolas, monospace;
          font-size: clamp(1.4rem, 5vw, 4.7rem);
          font-weight: 800;
          text-shadow: 0 0 16px rgba(255, 63, 164, .7);
        }

        .cyber-text {
          position: relative;
          display: inline-block;
          min-height: 1.1em;
          white-space: nowrap;
          color: #dffaff;
          font-family: "Cascadia Code", Consolas, "Courier New", monospace;
          font-size: clamp(1.15rem, 4.7vw, 4.4rem);
          font-weight: 800;
          letter-spacing: -.065em;
          line-height: 1;
          text-shadow: 2px 0 #ff3fa4, -2px 0 #21dcff, 0 0 20px rgba(33, 220, 255, .35);
        }

        .cyber-text::before,
        .cyber-text::after {
          content: attr(data-text);
          position: absolute;
          inset: 0;
          pointer-events: none;
          opacity: 0;
        }

        .cyber-text::before { color: #2de2ff; clip-path: inset(18% 0 57% 0); animation: glitch-top 4.2s infinite; }
        .cyber-text::after { color: #ff3fa4; clip-path: inset(62% 0 16% 0); animation: glitch-bottom 4.2s infinite; }

        .terminal-cursor {
          width: .12em;
          height: clamp(1.4rem, 4.7vw, 4.4rem);
          margin-left: .14em;
          background: #2de2ff;
          box-shadow: 0 0 14px #2de2ff;
          animation: cursor-blink .72s step-end infinite;
        }

        @keyframes cursor-blink { 50% { opacity: 0; } }
        @keyframes glitch-top {
          0%, 88%, 100% { opacity: 0; transform: translate(0); }
          89% { opacity: .9; transform: translate(5px, -1px); }
          91% { opacity: .65; transform: translate(-4px, 1px); }
          93% { opacity: 0; }
        }
        @keyframes glitch-bottom {
          0%, 91%, 100% { opacity: 0; transform: translate(0); }
          92% { opacity: .85; transform: translate(-6px, 1px); }
          94% { opacity: .6; transform: translate(3px, -1px); }
          96% { opacity: 0; }
        }

        .services-wrap {
          width: 100%;
          overflow-x: auto;
          padding: 14px max(20px, calc((100vw - 1380px) / 2)) 36px;
          scrollbar-width: thin;
          scrollbar-color: rgba(255,255,255,.22) transparent;
        }

        .services {
          display: grid;
          grid-template-columns: repeat(5, minmax(210px, 1fr));
          gap: 14px;
          min-width: 1110px;
          max-width: 1380px;
          margin: 0 auto;
        }

        .service {
          --accent: #6c8cff;
          --glow: rgba(108, 140, 255, 0.2);
          position: relative;
          isolation: isolate;
          min-height: 310px;
          display: flex;
          flex-direction: column;
          padding: 26px;
          overflow: hidden;
          color: inherit;
          text-decoration: none;
          background: linear-gradient(145deg, rgba(27, 33, 48, .9), var(--surface));
          border: 1px solid var(--line);
          border-radius: 26px;
          box-shadow: 0 20px 70px rgba(0, 0, 0, 0.25);
          transition: transform .3s ease, border-color .3s ease, box-shadow .3s ease;
        }

        .service::before {
          content: "";
          position: absolute;
          z-index: -1;
          width: 180px;
          height: 180px;
          top: -95px;
          right: -70px;
          border-radius: 50%;
          background: var(--accent);
          filter: blur(55px);
          opacity: .24;
          transition: opacity .3s ease, transform .3s ease;
        }

        .service:hover,
        .service:focus-visible {
          transform: translateY(-9px);
          border-color: color-mix(in srgb, var(--accent), white 18%);
          box-shadow: 0 28px 80px rgba(0,0,0,.4), 0 0 38px var(--glow);
          outline: none;
        }

        .service:hover::before { opacity: .42; transform: scale(1.15); }
        .service--ha { --accent: #41bdf5; --glow: rgba(65,189,245,.2); }
        .service--cloud { --accent: #1687d9; --glow: rgba(22,135,217,.22); }
        .service--jellyfin { --accent: #aa5cc3; --glow: rgba(170,92,195,.22); }
        .service--npm { --accent: #f04477; --glow: rgba(240,68,119,.2); }
        .service--mc { --accent: #7fbd58; --glow: rgba(127,189,88,.2); }

        .service-top { display: flex; align-items: flex-start; justify-content: space-between; }

        .logo {
          width: 62px;
          height: 62px;
          display: grid;
          place-items: center;
          border-radius: 18px;
          color: var(--accent);
          background: rgba(255,255,255,.055);
          border: 1px solid rgba(255,255,255,.09);
          box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
        }

        .logo svg,
        .logo img { width: 38px; height: 38px; object-fit: contain; }

        .arrow {
          width: 38px;
          height: 38px;
          display: grid;
          place-items: center;
          border-radius: 50%;
          color: #b9c0d0;
          background: rgba(255,255,255,.045);
          transition: color .25s ease, background .25s ease, transform .25s ease;
        }

        .service:hover .arrow { color: #fff; background: var(--accent); transform: rotate(45deg); }
        .arrow svg { width: 17px; }

        .service-copy { margin-top: auto; }
        .service h2 { margin: 0 0 8px; font-size: 1.42rem; letter-spacing: -.035em; }
        .service p { min-height: 44px; margin: 0 0 18px; color: var(--muted); line-height: 1.45; }
        .domain { color: var(--accent); font-size: .74rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }

        footer {
          width: min(1380px, calc(100% - 40px));
          display: flex;
          justify-content: space-between;
          gap: 20px;
          margin: auto auto 0;
          padding-top: 28px;
          color: #686f80;
          font-size: .82rem;
        }

        [hidden] { display: none !important; }

        .secret-trigger {
          position: fixed;
          z-index: 50;
          right: 0;
          bottom: 0;
          width: 64px;
          height: 64px;
          padding: 0;
          opacity: 0;
          border: 0;
          background: transparent;
          cursor: default;
        }

        .secret-trigger:focus-visible { opacity: .14; outline: 1px solid #2de2ff; }

        .auth-modal {
          position: fixed;
          z-index: 100;
          inset: 0;
          display: grid;
          place-items: center;
          padding: 20px;
        }

        .auth-backdrop {
          position: absolute;
          inset: 0;
          background: rgba(3, 6, 13, .82);
          backdrop-filter: blur(12px);
        }

        .auth-panel {
          position: relative;
          width: min(430px, 100%);
          padding: 38px;
          color: #e8fbff;
          border: 1px solid rgba(45, 226, 255, .3);
          background: linear-gradient(145deg, rgba(16, 30, 47, .98), rgba(20, 16, 37, .98));
          clip-path: polygon(0 0, calc(100% - 22px) 0, 100% 22px, 100% 100%, 22px 100%, 0 calc(100% - 22px));
          box-shadow: 0 32px 100px rgba(0,0,0,.65), inset 0 0 40px rgba(45,226,255,.05);
        }

        .auth-kicker { color: #2de2ff; font: 700 .7rem/1 "Cascadia Code", Consolas, monospace; letter-spacing: .16em; text-transform: uppercase; }
        .auth-panel h2 { margin: 16px 0 8px; font: 800 clamp(2rem, 8vw, 3rem)/1 "Cascadia Code", Consolas, monospace; letter-spacing: -.07em; text-shadow: 2px 0 #ff3fa4, -2px 0 #2de2ff; }
        .auth-hint { margin: 0 0 26px; color: #8792a6; line-height: 1.55; }
        .auth-close { position: absolute; top: 15px; right: 17px; padding: 5px; color: #7d8799; font-size: 1.35rem; border: 0; background: none; cursor: pointer; }
        .auth-close:hover { color: #fff; }
        .auth-form label { display: block; margin-bottom: 9px; color: #b8c1d2; font-size: .78rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
        .auth-form input { width: 100%; height: 50px; padding: 0 15px; color: #f4fbff; font: 700 1rem "Cascadia Code", Consolas, monospace; border: 1px solid rgba(255,255,255,.12); outline: none; background: rgba(4,10,20,.65); }
        .auth-form input:focus { border-color: #2de2ff; box-shadow: 0 0 0 3px rgba(45,226,255,.09); }
        .auth-submit { width: 100%; height: 50px; margin-top: 14px; color: #071018; font: 800 .82rem "Cascadia Code", Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; border: 0; background: linear-gradient(90deg, #2de2ff, #65f2bd); cursor: pointer; }
        .auth-submit:hover { filter: brightness(1.08); }
        .auth-submit:disabled { opacity: .55; cursor: wait; }
        .auth-error { min-height: 20px; margin: 12px 0 0; color: #ff6ba8; font-size: .8rem; }
        body.modal-open { overflow: hidden; }

        @media (max-width: 700px) {
          .page { justify-content: flex-start; }
          .hero { margin-bottom: 22px; }
          .cyber-terminal { min-height: 126px; padding-inline: 18px; }
          .terminal-prompt { margin-right: .2em; }
          .cyber-text { letter-spacing: -.08em; }
          .services { grid-template-columns: repeat(5, 78vw); min-width: max-content; }
          .service { min-height: 280px; scroll-snap-align: center; }
          .services-wrap { scroll-snap-type: x mandatory; }
          footer { flex-direction: column; }
          .auth-panel { padding: 34px 25px 28px; }
        }

        @media (prefers-reduced-motion: reduce) {
          * { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
        }
      </style>
    </head>
    <body>
      <main class="page">
        <section class="hero" aria-labelledby="page-title">
          <div class="eyebrow">vitazgio.ru · мои домены</div>
          <h1 id="page-title" class="cyber-terminal" aria-label="Мои веб-сервисы, Vitazgio Network, Domain Control">
            <span class="terminal-prompt" aria-hidden="true">&gt;</span>
            <span id="cyber-text" class="cyber-text" data-text="МОИ ВЕБ-СЕРВИСЫ" aria-hidden="true">МОИ ВЕБ-СЕРВИСЫ</span>
            <span class="terminal-cursor" aria-hidden="true"></span>
          </h1>
        </section>

        <nav class="services-wrap" aria-label="Сервисы vitazgio.ru">
          <div class="services">
            <a class="service service--ha" href="https://ha.vitazgio.ru" aria-label="Открыть Home Assistant">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/home-assistant.png" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Home Assistant</h2><p>Умный дом и автоматизация</p><span class="domain">ha.vitazgio.ru</span></div>
            </a>

            <a class="service service--cloud" href="https://cloud.vitazgio.ru" aria-label="Открыть Nextcloud">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="9" stroke="currentColor" stroke-width="4"/><circle cx="7.5" cy="24" r="5.5" stroke="currentColor" stroke-width="4"/><circle cx="40.5" cy="24" r="5.5" stroke="currentColor" stroke-width="4"/></svg></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Nextcloud</h2><p>Личное облачное хранилище</p><span class="domain">cloud.vitazgio.ru</span></div>
            </a>

            <a class="service service--jellyfin" href="https://jel.vitazgio.ru" aria-label="Открыть Jellyfin">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/jellyfin.svg" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Jellyfin</h2><p>Фильмы и сериалы</p><span class="domain">jel.vitazgio.ru</span></div>
            </a>

            <a class="service service--npm" href="https://npm.vitazgio.ru" aria-label="Открыть Nginx Proxy Manager">
              <div class="service-top">
                <span class="logo" aria-hidden="true"><img src="/static/nginx-proxy-manager.svg" alt=""></span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Nginx Proxy</h2><p>Управление доменами и прокси</p><span class="domain">npm.vitazgio.ru</span></div>
            </a>

            <a class="service service--mc" href="https://mc.vitazgio.ru" aria-label="Открыть Minecraft сервер">
              <div class="service-top">
                <span class="logo" aria-hidden="true">
                  <svg viewBox="0 0 48 48" fill="none" shape-rendering="geometricPrecision">
                    <defs>
                      <linearGradient id="grass-top" x1="8" y1="9" x2="39" y2="23" gradientUnits="userSpaceOnUse"><stop stop-color="#a8db68"/><stop offset="1" stop-color="#6eae48"/></linearGradient>
                      <linearGradient id="dirt-left" x1="7" y1="17" x2="25" y2="42" gradientUnits="userSpaceOnUse"><stop stop-color="#b98253"/><stop offset="1" stop-color="#855333"/></linearGradient>
                      <linearGradient id="dirt-right" x1="24" y1="24" x2="41" y2="39" gradientUnits="userSpaceOnUse"><stop stop-color="#98623d"/><stop offset="1" stop-color="#6b4029"/></linearGradient>
                    </defs>
                    <path d="m24 5 18 9.5L24 24 6 14.5 24 5Z" fill="url(#grass-top)"/>
                    <path d="m6 14.5 18 9.5v19L6 33.5v-19Z" fill="url(#dirt-left)"/>
                    <path d="M42 14.5 24 24v19l18-9.5v-19Z" fill="url(#dirt-right)"/>
                    <path d="m6 14.5 18 9.5 18-9.5M24 24v19" stroke="#d6efa5" stroke-opacity=".42" stroke-width="1.2"/>
                    <path d="m6 14.5 18 9.5v4l-4-2.1v3.4l-4-2.1v-3.4l-4-2.1v3.4L6 22v-7.5Z" fill="#79b64d"/>
                    <path d="M42 14.5 24 24v4l4-2.1v3.4l4-2.1v-3.4l4-2.1v3.4l6-3.1v-7.5Z" fill="#659b40"/>
                    <path d="m10 27 4 2.1v4.2L10 31v-4Zm8 7.2 3 1.6v4.1l-3-1.6v-4.1Zm18-6.4 3-1.6v4.2L36 32v-4.2Zm-8 5.3 4-2.1v4.2l-4 2.1v-4.2Z" fill="#5b3523" fill-opacity=".68"/>
                  </svg>
                </span>
                <span class="arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7m0 0H8m9 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              </div>
              <div class="service-copy"><h2>Minecraft</h2><p>Игровой сервер для друзей</p><span class="domain">mc.vitazgio.ru</span></div>
            </a>
          </div>
        </nav>

        <footer><span>© 2026 vitazgio.ru · Основан 2:12 04.05.2026</span></footer>
      </main>
      <button id="secret-trigger" class="secret-trigger" type="button" aria-label="Открыть личный кабинет"></button>
      <div id="auth-modal" class="auth-modal" hidden>
        <div class="auth-backdrop" data-auth-close></div>
        <section class="auth-panel" role="dialog" aria-modal="true" aria-labelledby="auth-title">
          <button class="auth-close" type="button" data-auth-close aria-label="Закрыть">×</button>
          <div class="auth-kicker">Restricted area // 01</div>
          <h2 id="auth-title">Авторизация</h2>
          <p class="auth-hint">Введите пароль для доступа к личному кабинету.</p>
          <form id="auth-form" class="auth-form">
            <label for="auth-password">Пароль</label>
            <input id="auth-password" name="password" type="password" autocomplete="current-password" required>
            <button class="auth-submit" type="submit">Получить доступ</button>
            <p id="auth-error" class="auth-error" role="alert"></p>
          </form>
        </section>
      </div>
      <script>
        (() => {
          const output = document.getElementById("cyber-text");
          const phrases = ["МОИ ВЕБ-СЕРВИСЫ", "VITAZGIO NETWORK", "DOMAIN CONTROL"];
          const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
          const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
          const render = (text) => {
            output.textContent = text;
            output.dataset.text = text;
          };

          if (reduceMotion) {
            render(phrases[0]);
            return;
          }

          const runTerminal = async () => {
            let phraseIndex = 0;
            while (true) {
              const phrase = phrases[phraseIndex];
              render("");
              for (let index = 1; index <= phrase.length; index += 1) {
                render(phrase.slice(0, index));
                await wait(78);
              }
              await wait(1450);
              for (let index = phrase.length - 1; index >= 0; index -= 1) {
                render(phrase.slice(0, index));
                await wait(42);
              }
              await wait(260);
              phraseIndex = (phraseIndex + 1) % phrases.length;
            }
          };

          runTerminal();
        })();

        (() => {
          const trigger = document.getElementById("secret-trigger");
          const modal = document.getElementById("auth-modal");
          const form = document.getElementById("auth-form");
          const password = document.getElementById("auth-password");
          const error = document.getElementById("auth-error");
          const submit = form.querySelector("button[type='submit']");

          const openModal = () => {
            modal.hidden = false;
            document.body.classList.add("modal-open");
            error.textContent = "";
            requestAnimationFrame(() => password.focus());
          };

          const closeModal = () => {
            modal.hidden = true;
            document.body.classList.remove("modal-open");
            form.reset();
            error.textContent = "";
            trigger.focus();
          };

          trigger.addEventListener("click", openModal);
          modal.querySelectorAll("[data-auth-close]").forEach((element) => element.addEventListener("click", closeModal));
          document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && !modal.hidden) closeModal();
          });

          form.addEventListener("submit", async (event) => {
            event.preventDefault();
            error.textContent = "";
            submit.disabled = true;
            try {
              const response = await fetch("/api/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: password.value }),
              });
              const result = await response.json();
              if (!response.ok) {
                error.textContent = result.error || "Не удалось выполнить вход.";
                password.select();
                return;
              }
              window.location.assign(result.redirect);
            } catch {
              error.textContent = "Сервер недоступен. Повторите попытку.";
            } finally {
              submit.disabled = false;
            }
          });
        })();
      </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
