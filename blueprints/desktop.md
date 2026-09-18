# desktop.py — оболочка Windows и просмотр экрана ПК (/desktop)

**Назначение:** серверная половина десктопного приложения (`desktop/`,
Electron): регистрация компьютеров, выдача/отзыв токенов и согласование
WebRTC-сессии для просмотра экрана ПК из браузера.

**Точки входа:** `/desktop` (зритель), `POST /api/desktop/register`,
`GET|DELETE /api/desktop/devices[/<did>]`, `POST /api/desktop/host`,
`/api/desktop/sessions` (POST — создать, затем GET/POST/DELETE по `<cid>`
— обмен offer/answer), `GET /api/desktop/config` (ICE-серверы),
`GET /api/desktop/version` (самообновление EXE).

**Где данные:** `data/desktop_devices.json`. `DESKTOP_ICE_SERVERS` в
`.env` — список STUN/TURN.

**Гейты:** `login_required` на управлении устройствами; `viewer_required`
на просмотре — там кроме сессии нужен ещё и суточный пароль консоли.
`/api/desktop/host` и обмен сессиями идут по токену устройства, а не по
куке (стучится сама оболочка, у неё сессии нет).

**Инвариант:** **медиа через сервер не идут** — сайт только сводит
стороны (signalling), сам поток WebRTC идёт напрямую. Не заводить здесь
проксирование видео: это не «недоделка», а смысл схемы.

**Подробности сборки EXE, границ LAN-режима и проверок:** `desktop/README.md`.

**Тест перед правкой:** `pytest tests/test_desktop.py -q` (+ `desktop/tests/*.cjs`).
