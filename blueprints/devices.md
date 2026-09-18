# devices.py — доверенные устройства (/devices)

**Назначение:** вкладка кабинета «Запомнить устройства» — список того, с
чего уже входили, переименование и отзыв. Своя страница, не аккордеон.

**Точки входа:** `/devices`, `POST /api/devices/trust` (запомнить это
устройство), `GET /api/devices`, `PATCH|DELETE /api/devices/<selector>`.

**Где данные:** сам список и логика доверия — **в `core/auth.py`**
(`trusted_devices`, `devices_lock`, `DEVICE_COOKIE`, `DEVICE_TTL_DAYS`),
не здесь: их использует `login_required` при автовходе, то есть это
общая инфраструктура, а не фича. Этот файл — только страница и API.

**Гейт:** `login_required` на всём.

**Инвариант:** автовход по доверенному устройству **сам пишет в журнал
входов** (`log_login` внутри `login_required`) — если менять логику
доверия, смотреть и `blueprints/login_log.py`, и `core/auth.py`, иначе
вход станет невидимым в журнале.

**Тест перед правкой:** `pytest tests/test_devices.py tests/test_auth.py -q`.
