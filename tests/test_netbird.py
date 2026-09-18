"""Список машин на /netbird: VPS сайта показан, но без кнопок подключения.

Строка VPS-Server — это только показания (IP, имя, пинг). Ни консоли, ни
файлов туда не заводим, и «СКОРО» там тоже не место: обе колонки пустые.
"""

VPS_IP = "100.104.94.83"
MOBILA_IP = "100.104.86.103"


def _row(page, ip):
    return page.split(f'data-ip="{ip}"', 1)[1].split("</li>", 1)[0]


def test_vps_is_listed_without_connect_and_files_buttons(auth_client):
    page = auth_client.get("/netbird").get_data(as_text=True)
    assert VPS_IP in page
    row = _row(page, VPS_IP)
    assert "VPS-Server" in row
    assert "connect-btn-empty" in row and "connect-btn\"" not in row
    assert "smb-btn-empty" in row
    assert "СКОРО" not in row and "SFTP" not in row


def test_vps_has_no_ssh_or_sftp_access(app_module):
    assert VPS_IP not in app_module.ssh_enabled_ips
    assert VPS_IP not in app_module.sftp_enabled_ips
    assert VPS_IP not in app_module.rdp_enabled_ips
    assert VPS_IP not in app_module.vnc_enabled_ips


def test_phone_stays_last_in_the_list(app_module):
    devices = app_module.NETBIRD_DEVICES
    assert devices[-1]["ip"] == MOBILA_IP, "телефон — самый нижний"
    assert devices[-2]["ip"] == VPS_IP, "VPS стоит прямо над телефоном"
