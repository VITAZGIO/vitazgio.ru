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

# Значки перед именем устройства во вкладке NetBird — эскизы в цвет текста
# (currentColor, без фона), масштаб под строку списка.
_NETBIRD_ICONS = {
    "phone": (
        '<svg class="dev-ic" viewBox="0 0 32 32" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M22,29H10a3,3,0,0,1-3-3V6a3,3,0,0,1,3-3H22a3,3,0,0,1,3,3V26A3,3,0,0,1,22,29Z'
        'M10,5A1,1,0,0,0,9,6V26a1,1,0,0,0,1,1H22a1,1,0,0,0,1-1V6a1,1,0,0,0-1-1Z"/>'
        '<path d="M18,7H14a2,2,0,0,1-2-2V4a1,1,0,0,1,1-1h6a1,1,0,0,1,1,1V5A2,2,0,0,1,18,7Z"/>'
        '</svg>'
    ),
    "laptop": (
        '<svg class="dev-ic" viewBox="0 0 32 32" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M29,24V6.44A1.46,1.46,0,0,0,27.5,5H4.5A1.46,1.46,0,0,0,3,6.44V24H0v0.44A2.55,2.55,0,0,0,2.5,27h27'
        'A2.55,2.55,0,0,0,32,24.44V24H29ZM4,6.44A0.46,0.46,0,0,1,4.5,6h23a0.46,0.46,0,0,1,.5.44V24H4V6.44Z'
        'M2.5,26a1.63,1.63,0,0,1-1.41-1H14v1H2.5Zm27,0H18V25H30.91A1.63,1.63,0,0,1,29.5,26Z"/>'
        '<path d="M5,23H27V7H5V23ZM6,8H26V22H6V8Z"/>'
        '</svg>'
    ),
    "pc": (
        '<svg class="dev-ic" viewBox="0 0 612 612" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M578.766,51.487v-0.895h-2.996H35.93h-2.996v0.895C15.272,52.701,2.095,66.753,0,83.808v3.002v355.724'
        'c0,6.898,1.795,12.712,4.791,17.949c6.893,12.137,17.068,18.269,31.14,18.269h197.012v49.695h-37.425'
        'c-9.281,0-16.467,7.218-16.467,16.48c0,9.262,7.186,16.479,16.467,16.479h220.666c9.281,0,16.768-7.218,16.768-16.479'
        'c0-9.263-7.486-16.48-16.768-16.48h-37.425v-49.695H575.77c14.078,0,24.343-6.132,31.14-18.269'
        'c3.085-5.493,5.091-11.37,5.091-17.949V86.811v-3.002C609.905,66.753,595.833,52.701,578.766,51.487z'
        'M578.766,86.811v355.724c0,2.108-0.895,3.002-2.996,3.002H35.93c-2.095,0-2.996-0.894-2.996-3.002V86.811v-3.002'
        'h545.831V86.811z"/>'
        '</svg>'
    ),
    "server": (
        '<svg class="dev-ic" viewBox="0 0 1800 1800" fill="currentColor" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<path d="M1713.195,662.483H86.805c-46.621,0-84.549,37.929-84.549,84.55v315.328c0,46.615,37.928,84.54,84.549,84.54'
        'h1626.391c46.625,0,84.55-37.925,84.55-84.54V747.033C1797.745,700.412,1759.82,662.483,1713.195,662.483z'
        'M1734.746,1062.361c0,11.882-9.668,21.541-21.551,21.541H86.805c-11.883,0-21.55-9.659-21.55-21.541V747.033'
        'c0-11.883,9.667-21.55,21.55-21.55h1626.391c11.883,0,21.551,9.667,21.551,21.55V1062.361z"/>'
        '<circle cx="262.693" cy="904.687" r="53.448"/>'
        '<circle cx="447.018" cy="904.687" r="53.451"/>'
        '<circle cx="631.339" cy="904.687" r="53.451"/>'
        '<path d="M1567.738,873.181H927.254c-17.394,0-31.5,14.102-31.5,31.497c0,17.402,14.106,31.5,31.5,31.5h640.484'
        'c17.394,0,31.5-14.098,31.5-31.5C1599.238,887.283,1585.132,873.181,1567.738,873.181z"/>'
        '<path d="M1713.195,1315.578H86.805c-46.621,0-84.549,37.934-84.549,84.551v315.329c0,46.616,37.928,84.54,84.549,84.54'
        'h1626.391c46.625,0,84.55-37.924,84.55-84.54v-315.329C1797.745,1353.512,1759.82,1315.578,1713.195,1315.578z'
        'M1734.746,1715.458c0,11.882-9.668,21.542-21.551,21.542H86.805c-11.883,0-21.55-9.66-21.55-21.542v-315.329'
        'c0-11.883,9.667-21.551,21.55-21.551h1626.391c11.883,0,21.551,9.668,21.551,21.551V1715.458z"/>'
        '<circle cx="262.693" cy="1557.784" r="53.445"/>'
        '<circle cx="447.018" cy="1557.784" r="53.451"/>'
        '<circle cx="631.339" cy="1557.784" r="53.451"/>'
        '<path d="M1567.738,1526.275H927.254c-17.394,0-31.5,14.107-31.5,31.5c0,17.402,14.106,31.5,31.5,31.5h640.484'
        'c17.394,0,31.5-14.098,31.5-31.5C1599.238,1540.383,1585.132,1526.275,1567.738,1526.275z"/>'
        '</svg>'
    ),
}


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
    sftp_enabled_ips,
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

    def _device_kind(device):
        """МОБИЛА — телефон, НОУТ — ноутбук по имени; для остальных смотрим на
        разрешённый протокол: RDP — обычно ПК, SSH — сервер/одноплатник."""
        name_lower = device["name"].lower()
        if "mobil" in name_lower:
            return "phone"
        if "nout" in name_lower:
            return "laptop"
        if device.get("rdp_enabled"):
            return "pc"
        if device.get("ssh_enabled"):
            return "server"
        if device.get("vnc_enabled"):
            return "phone"
        return None

    def _netbird_device_items():
        return "".join(
            f'<li class="device" data-ip="{device["ip"]}">'
            f'<button class="copy-ip" type="button" data-ip="{device["ip"]}">{device["ip"]}</button>'
            f'<span class="device-name">{_NETBIRD_ICONS.get(_device_kind(device), "")}'
            f'<span class="device-name-text" title="{device["name"]}">{device["name"]}</span></span>'
            f'<span class="device-lastseen" data-lastseen>—</span>'
            # Молния (WOL) — не своя колонка, а довесок к пингу: у большинства
            # устройств её нет, и отдельный столбец стоял бы пустым зазором.
            f'<span class="device-ping">'
            f'<span class="device-status" data-status>проверка…</span>'
            + (
                f'<button class="wol-btn" type="button" data-mac="{device["wol_mac"]}" title="Wake-on-LAN">⚡</button>'
                if device.get("wol_mac") else ''
            )
            + '</span>'
            + (
                f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="ssh">SSH</button>'
                if device.get("ssh_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="rdp">RDP</button>'
                if device.get("rdp_enabled")
                else f'<button class="connect-btn" type="button" data-ip="{device["ip"]}" data-name="{device["name"]}" data-type="vnc">VNC</button>'
                if device.get("vnc_enabled")
                else '<span class="connect-btn-empty"></span>'
            )
            # Файлы по SFTP — только там, где есть SSH-сервер. Остальным
            # (телефон, винды без OpenSSH) кнопка стоит местом на будущее.
            + (
                f'<a class="smb-btn" href="/files/{device["ip"]}" title="Файлы по SFTP">SFTP</a>'
                if device["ip"] in sftp_enabled_ips
                else '<button class="smb-btn" type="button" disabled title="Файлы сюда пока не настроены">СКОРО</button>'
            )
            + "</li>"
            for device in netbird_devices
        )

    @remote_bp.get("/cabinet")
    @login_required
    def cabinet():
        return template("cabinet.html").replace("__ICONLINKS__", icon_links)

    @remote_bp.get("/netbird")
    @login_required
    def netbird_page():
        html = template("netbird.html")
        return (html.replace("{{DEVICE_ITEMS}}", _netbird_device_items())
                    .replace("{{DEVICE_COUNT}}", str(len(netbird_devices)))
                    # Список машин, где живёт SFTP — чтобы кнопка «SFTP» в
                    # оверлее RDP/консоли знала, для какого IP пробовать
                    # подключиться теми же учётными данными, а для какого
                    # промолчать (VNC-устройства, телефон).
                    .replace("{{SFTP_IPS}}", json.dumps(sorted(sftp_enabled_ips)))
                    .replace("__ICONLINKS__", icon_links))

    return remote_bp
