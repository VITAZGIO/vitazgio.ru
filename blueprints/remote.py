import codecs
import hmac
import json
import os
import shlex
import socket
import threading
import time

import paramiko
from flask import Blueprint, jsonify, request, session


def create_remote_blueprint(
    *,
    sock,
    template,
    icon_links,
    login_required,
    netbird_devices,
    netbird_status,
    netbird_status_lock,
    ssh_gate_password_prefix,
    console_password_today,
    client_ip,
    rate_blocked,
    rate_hit,
    rate_clear,
    console_login_attempts,
    console_login_attempts_lock,
    console_login_window_seconds,
    console_login_max_attempts,
    log_login,
    ssh_enabled_ips,
    rdp_enabled_ips,
    vnc_enabled_ips,
    claude_ready,
    claude_host,
    claude_host_name,
    claude_dir,
    claude_bin,
    claude_tabs_max,
    claude_prefix,
    claude_name_re,
    claude_run,
    claude_tabs,
    claude_free_name,
    guacd_host,
    guacd_port,
    rdp_quality,
    guac_handshake,
    guac_handshake_vnc,
    wol_relay,
    wol_broadcasts,
):
    remote_bp = Blueprint("remote", __name__)

    @remote_bp.get("/api/netbird/status")
    @login_required
    def netbird_status_api():
        with netbird_status_lock:
            return jsonify(netbird_status)

    @remote_bp.post("/api/console/login")
    @login_required
    def console_login():
        if not ssh_gate_password_prefix:
            return jsonify(error="Консоль не настроена."), 503

        client = client_ip()
        if rate_blocked(console_login_attempts, console_login_attempts_lock, client,
                        console_login_window_seconds, console_login_max_attempts):
            return jsonify(error="Слишком много попыток. Попробуйте через 5 минут."), 429

        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(
            password.encode(), console_password_today().encode()
        ):
            rate_hit(console_login_attempts, console_login_attempts_lock, client)
            log_login("неверный суточный пароль (консоль)", kind="fail")
            return jsonify(error="Неверный пароль."), 401

        rate_clear(console_login_attempts, console_login_attempts_lock, client)
        session["console_authenticated"] = True
        return jsonify(ok=True)

    def current_claude_host():
        return claude_host() if callable(claude_host) else claude_host

    @sock.route("/ws/console/<ip>", bp=remote_bp)
    def console_ws(ws, ip):
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        if ip not in ssh_enabled_ips:
            ws.close()
            return

        message = ws.receive(timeout=15)
        try:
            auth = json.loads(message) if message else {}
        except ValueError:
            auth = {}
        username = auth.get("username") if auth.get("type") == "auth" else None
        password = auth.get("password") if auth.get("type") == "auth" else None
        if not username or not password:
            ws.close()
            return

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                ip, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False
            )
        except (paramiko.SSHException, OSError):
            ws.send(json.dumps({"type": "data", "data": "\r\nНе удалось подключиться (проверь логин/пароль).\r\n"}))
            ws.close()
            return

        client.get_transport().set_keepalive(20)
        channel = client.invoke_shell(term="xterm")
        channel.settimeout(0.0)

        stop_event = threading.Event()

        def pump_channel_to_ws():
            try:
                while not stop_event.is_set():
                    if channel.recv_ready():
                        chunk = channel.recv(4096)
                        if not chunk:
                            break
                        ws.send(json.dumps({"type": "data", "data": chunk.decode(errors="replace")}))
                    else:
                        time.sleep(0.03)
                    if channel.closed:
                        break
            except Exception:
                pass
            finally:
                stop_event.set()

        reader = threading.Thread(target=pump_channel_to_ws, daemon=True)
        reader.start()

        def ssh_keepalive():
            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                try:
                    ws.send(json.dumps({"type": "ping"}))
                except Exception:
                    stop_event.set()

        threading.Thread(target=ssh_keepalive, daemon=True).start()

        try:
            while not stop_event.is_set():
                message = ws.receive(timeout=120)
                if message is None:
                    continue
                try:
                    payload = json.loads(message)
                except ValueError:
                    continue
                ptype = payload.get("type")
                if ptype == "data":
                    channel.send(payload.get("data", ""))
                elif ptype == "resize":
                    cols = int(payload.get("cols", 80))
                    rows = int(payload.get("rows", 24))
                    channel.resize_pty(width=cols, height=rows)
                elif ptype == "ping":
                    ws.send(json.dumps({"type": "pong"}))
        except Exception:
            pass
        finally:
            stop_event.set()
            channel.close()
            client.close()

    @sock.route("/ws/claude", bp=remote_bp)
    def claude_ws(ws):
        """Один канал на весь разговор: и список вкладок, и сам терминал."""
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        if not claude_ready():
            ws.close()
            return

        message = ws.receive(timeout=15)
        try:
            auth = json.loads(message) if message else {}
        except ValueError:
            auth = {}
        if auth.get("type") != "auth":
            ws.close()
            return
        username = auth.get("username")
        password = auth.get("password")
        if not username or not password:
            ws.close()
            return

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(current_claude_host(), username=username, password=password,
                           timeout=6, look_for_keys=False, allow_agent=False)
        except (paramiko.SSHException, OSError):
            try:
                ws.send(json.dumps({"type": "fail",
                                    "text": "Не удалось зайти на машину — проверь логин и пароль."}))
            except Exception:
                pass
            ws.close()
            return

        client.get_transport().set_keepalive(20)

        code, _out = claude_run(client, "command -v tmux >/dev/null 2>&1")
        if code != 0:
            ws.send(json.dumps({"type": "fail",
                                "text": "На машине нет tmux. Поставь: sudo apt install tmux"}))
            client.close()
            ws.close()
            return
        code, _out = claude_run(client, f"command -v {shlex.quote(claude_bin)} >/dev/null 2>&1")
        if code != 0:
            ws.send(json.dumps({"type": "fail",
                                "text": f"На машине нет команды «{claude_bin}». "
                                        "Поставь Claude Code и зайди в него один раз: claude"}))
            client.close()
            ws.close()
            return

        state = {"channel": None, "tab": None, "cols": 100, "rows": 30}
        stop_event = threading.Event()
        send_lock = threading.Lock()

        def say(payload):
            with send_lock:
                ws.send(json.dumps(payload))

        def tabs_out():
            say({"type": "tabs", "tabs": claude_tabs(client), "open": state["tab"]})

        def tabs_out_when(name):
            def wait():
                for _ in range(16):
                    if stop_event.is_set():
                        return
                    tabs = claude_tabs(client)
                    if name in {t["id"] for t in tabs}:
                        say({"type": "tabs", "tabs": tabs, "open": state["tab"]})
                        return
                    time.sleep(0.25)
                tabs_out()

            threading.Thread(target=wait, daemon=True).start()

        def close_tab_channel():
            channel = state["channel"]
            state["channel"] = None
            state["tab"] = None
            if channel:
                try:
                    channel.close()
                except Exception:
                    pass

        def open_tab(name):
            if not claude_name_re.match(name or ""):
                say({"type": "fail", "text": "Странное имя вкладки."})
                return
            tabs = claude_tabs(client)
            if name not in {t["id"] for t in tabs} and len(tabs) >= claude_tabs_max:
                say({"type": "fail", "text": f"Больше {claude_tabs_max} вкладок сразу не держим."})
                return

            close_tab_channel()
            session_name = shlex.quote(claude_prefix + name)
            start = f"tmux new-session -A -D -s {session_name}"
            if claude_dir:
                start += f" -c {shlex.quote(claude_dir)}"
            start += f" {shlex.quote(claude_bin)}"

            channel = client.invoke_shell(term="xterm-256color",
                                          width=state["cols"], height=state["rows"])
            channel.settimeout(0.0)
            channel.send(start + "\n")
            state["channel"] = channel
            state["tab"] = name

            def pump():
                try:
                    while not stop_event.is_set() and state["channel"] is channel:
                        if channel.recv_ready():
                            chunk = channel.recv(8192)
                            if not chunk:
                                break
                            say({"type": "data", "data": chunk.decode(errors="replace")})
                        else:
                            time.sleep(0.03)
                        if channel.closed:
                            break
                except Exception:
                    pass
                finally:
                    if state["channel"] is channel:
                        state["channel"] = None
                        state["tab"] = None

            threading.Thread(target=pump, daemon=True).start()
            say({"type": "open", "tab": name})
            tabs_out_when(name)

        def kill_tab(name):
            if not claude_name_re.match(name or ""):
                return
            if state["tab"] == name:
                close_tab_channel()
            claude_run(client, f"tmux kill-session -t {shlex.quote(claude_prefix + name)} 2>/dev/null || true")
            tabs_out()

        def keepalive():
            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                try:
                    say({"type": "ping"})
                except Exception:
                    stop_event.set()

        threading.Thread(target=keepalive, daemon=True).start()

        try:
            say({"type": "ready", "host": claude_host_name(), "dir": claude_dir})
            tabs_out()
            while not stop_event.is_set():
                message = ws.receive(timeout=120)
                if message is None:
                    continue
                try:
                    payload = json.loads(message)
                except ValueError:
                    continue
                kind = payload.get("type")
                if kind == "data":
                    channel = state["channel"]
                    if channel:
                        channel.send(payload.get("data", ""))
                elif kind == "resize":
                    try:
                        state["cols"] = max(20, min(500, int(payload.get("cols", 100))))
                        state["rows"] = max(5, min(200, int(payload.get("rows", 30))))
                    except (TypeError, ValueError):
                        continue
                    channel = state["channel"]
                    if channel:
                        channel.resize_pty(width=state["cols"], height=state["rows"])
                elif kind == "open":
                    open_tab(str(payload.get("tab", "")))
                elif kind == "new":
                    tabs = claude_tabs(client)
                    name = claude_free_name(tabs)
                    if not name:
                        say({"type": "fail", "text": f"Больше {claude_tabs_max} вкладок сразу не держим."})
                    else:
                        open_tab(name)
                elif kind == "kill":
                    kill_tab(str(payload.get("tab", "")))
                elif kind == "list":
                    tabs_out()
                elif kind == "ping":
                    say({"type": "pong"})
        except Exception:
            pass
        finally:
            stop_event.set()
            close_tab_channel()
            client.close()

    @sock.route("/ws/rdp/<ip>", bp=remote_bp)
    def rdp_ws(ws, ip):
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        if ip not in rdp_enabled_ips:
            ws.close()
            return

        message = ws.receive(timeout=15)
        try:
            auth = json.loads(message) if message else {}
        except ValueError:
            auth = {}
        if auth.get("type") != "auth":
            ws.close()
            return
        username = auth.get("username")
        password = auth.get("password")
        width = int(auth.get("width", 1280))
        height = int(auth.get("height", 720))
        quality = auth.get("quality") if auth.get("quality") in rdp_quality else "medium"
        if not username or not password:
            ws.close()
            return

        try:
            guac_sock = socket.create_connection((guacd_host, guacd_port), timeout=5)
        except OSError as e:
            print(f"[rdp] guacd connect error ({ip}): {e}", flush=True)
            ws.close()
            return

        try:
            guac_handshake(guac_sock, ip, username, password, width, height, quality)
        except Exception as e:
            print(f"[rdp] handshake error ({ip}): {e}", flush=True)
            guac_sock.close()
            ws.close()
            return

        guac_sock.settimeout(2.0)
        stop_event = threading.Event()

        def pump_guac_to_ws():
            decoder = codecs.getincrementaldecoder("utf-8")()
            try:
                while not stop_event.is_set():
                    try:
                        data = guac_sock.recv(8192)
                    except socket.timeout:
                        continue
                    if not data:
                        print(f"[rdp] guacd closed connection ({ip})", flush=True)
                        break
                    text = decoder.decode(data)
                    if text:
                        ws.send(text)
            except Exception as e:
                print(f"[rdp] pump error ({ip}): {e}", flush=True)
            finally:
                stop_event.set()

        threading.Thread(target=pump_guac_to_ws, daemon=True).start()

        def rdp_keepalive():
            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                try:
                    ws.send("3.nop;")
                except Exception:
                    stop_event.set()

        threading.Thread(target=rdp_keepalive, daemon=True).start()

        try:
            while not stop_event.is_set():
                message = ws.receive(timeout=120)
                if message is None:
                    continue
                guac_sock.sendall(message.encode() if isinstance(message, str) else message)
        except Exception as e:
            print(f"[rdp] ws error ({ip}): {e}", flush=True)
        finally:
            stop_event.set()
            guac_sock.close()

    @sock.route("/ws/vnc/<ip>", bp=remote_bp)
    def vnc_ws(ws, ip):
        if not session.get("authenticated") or not session.get("console_authenticated"):
            ws.close()
            return
        if ip not in vnc_enabled_ips:
            ws.close()
            return

        message = ws.receive(timeout=15)
        try:
            auth = json.loads(message) if message else {}
        except ValueError:
            auth = {}
        if auth.get("type") != "auth":
            ws.close()
            return
        password = auth.get("password", "")
        width = int(auth.get("width", 1280))
        height = int(auth.get("height", 720))

        try:
            guac_sock = socket.create_connection((guacd_host, guacd_port), timeout=5)
        except OSError as e:
            print(f"[vnc] guacd connect error ({ip}): {e}", flush=True)
            ws.close()
            return

        try:
            guac_handshake_vnc(guac_sock, ip, password, width, height)
        except Exception as e:
            print(f"[vnc] handshake error ({ip}): {e}", flush=True)
            guac_sock.close()
            ws.close()
            return

        guac_sock.settimeout(2.0)
        stop_event = threading.Event()

        def pump_guac_to_ws():
            decoder = codecs.getincrementaldecoder("utf-8")()
            try:
                while not stop_event.is_set():
                    try:
                        data = guac_sock.recv(8192)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    text = decoder.decode(data)
                    if text:
                        ws.send(text)
            except Exception as e:
                print(f"[vnc] pump error ({ip}): {e}", flush=True)
            finally:
                stop_event.set()

        threading.Thread(target=pump_guac_to_ws, daemon=True).start()

        def vnc_keepalive():
            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                try:
                    ws.send("3.nop;")
                except Exception:
                    stop_event.set()

        threading.Thread(target=vnc_keepalive, daemon=True).start()

        try:
            while not stop_event.is_set():
                message = ws.receive(timeout=120)
                if message is None:
                    continue
                guac_sock.sendall(message.encode() if isinstance(message, str) else message)
        except Exception as e:
            print(f"[vnc] ws error ({ip}): {e}", flush=True)
        finally:
            stop_event.set()
            guac_sock.close()

    @remote_bp.post("/api/pc/shutdown")
    @login_required
    def pc_shutdown():
        host = os.environ.get("PC_SHUTDOWN_HOST")
        user = os.environ.get("PC_SHUTDOWN_USER")
        key_path = os.environ.get("PC_SHUTDOWN_KEY")
        if not host or not user or not key_path:
            return jsonify(error="PC_SHUTDOWN_* не настроены в .env"), 503
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=user, key_filename=key_path,
                           timeout=6, look_for_keys=False, allow_agent=False)
            client.exec_command("shutdown /s /t 0")
            client.close()
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(error=str(e)), 500

    @remote_bp.post("/api/wol")
    @login_required
    def wol():
        payload = request.get_json(silent=True) or {}
        mac = payload.get("mac", "")
        mac_clean = mac.replace(":", "").replace("-", "").upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            return jsonify(error="Неверный MAC-адрес."), 400

        packet_hex = "ff" * 6 + (mac_clean.lower() * 16)
        problem = wol_relay(packet_hex)
        if problem:
            return jsonify(error=f"Не удалось разбудить: {problem}"), 502

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                for addr in wol_broadcasts:
                    s.sendto(bytes.fromhex(packet_hex), (addr, 9))
        except OSError:
            pass
        return jsonify(ok=True)

    @remote_bp.get("/cabinet")
    @login_required
    def cabinet():
        device_items = "".join(
            f'<li class="device" data-ip="{device["ip"]}">'
            f'<button class="copy-ip" type="button" data-ip="{device["ip"]}">{device["ip"]}</button>'
            f'<span class="device-name">{device["name"]}</span>'
            f'<span class="device-status" data-status>проверка…</span>'
            + (
                f'<button class="wol-btn" type="button" data-mac="{device["wol_mac"]}" title="Wake-on-LAN">⚡</button>'
                if device.get("wol_mac") else '<span class="wol-empty"></span>'
            )
            + (
                f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="ssh">SSH</button>'
                if device.get("ssh_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="rdp">RDP</button>'
                if device.get("rdp_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="vnc">VNC</button>'
                if device.get("vnc_enabled")
                else '<span class="connect-btn-empty"></span>'
            )
            + '<span class="copy-status">Скопировано</span>'
            + "</li>"
            for device in netbird_devices
        )
        html = template("cabinet.html")
        return html.replace("{{DEVICE_ITEMS}}", device_items) \
                   .replace("__ICONLINKS__", icon_links)

    return remote_bp
