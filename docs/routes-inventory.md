# Опись роутов

Генерируется скриптом `scripts/gen_routes.py` — не редактировать руками, правки потеряются при следующем запуске. Расхождение с кодом ловит `tests/test_docs.py`.

Роутов: **175** (без `static`). Уникальных адресов: **154** — один URL под несколько HTTP-методов даёт несколько роутов на
один адрес, это не расхождение.

Группировка — по blueprint'у (по имени, переданному в `Blueprint(...)`), `app.py` — роуты без blueprint'а. Guards — decorator'ы, реально навешанные на функцию; пустая колонка не значит «без проверки» — где гейт сделан внутри функции (вебсокеты, живые SSH/SFTP-соединения и т.п.), подробности в `blueprints/<name>.md` рядом с кодом.

## app.py

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/diag` | GET | `diag_api` | login_required |
| `/api/login` | POST | `login` | - |
| `/api/metrics` | GET | `metrics_api` | login_required |
| `/api/session/probe` | GET | `session_probe` | - |
| `/api/uptime` | GET | `uptime_api` | login_required |
| `/logout` | POST | `logout` | - |

## ai

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/ai` | GET | `ai_page` | login_required |
| `/api/ai/chat` | POST | `ai_chat_new` | login_required |
| `/api/ai/chat/<chat_id>` | DELETE | `ai_chat_delete` | login_required |
| `/api/ai/chat/<chat_id>` | GET | `ai_chat_get` | login_required |
| `/api/ai/chat/<chat_id>` | PATCH | `ai_chat_rename` | login_required |
| `/api/ai/chat/<chat_id>/regenerate` | POST | `ai_chat_regenerate` | login_required |
| `/api/ai/chat/<chat_id>/send` | POST | `ai_chat_send` | login_required |
| `/api/ai/folder` | GET | `ai_folder_list` | login_required |
| `/api/ai/folder` | POST | `ai_folder_new` | login_required |
| `/api/ai/folder/<fid>` | DELETE | `ai_folder_delete` | login_required |
| `/api/ai/folder/<fid>` | PATCH | `ai_folder_rename` | login_required |
| `/api/ai/img/<img_id>` | GET | `ai_img_api` | login_required |
| `/api/ai/state` | GET | `ai_state_api` | login_required |
| `/api/claude/state` | GET | `claude_state_api` | login_required |
| `/claude` | GET | `claude_page` | login_required |
| `/neuro` | GET | `neuro_page` | login_required |

## apps

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/apps` | GET | `apps_page` | login_required |

## backup_sebastian

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/backup/export` | GET | `backup_export_api` | - |
| `/api/backup/import` | POST | `backup_import_api` | login_required |
| `/api/backup/state` | GET | `backup_state_api` | login_required |
| `/api/sebastian/ask` | POST | `sebastian_ask_api` | - |
| `/api/sebastian/state` | GET | `sebastian_state_api` | - |
| `/backup` | GET | `backup_page` | login_required |
| `/sebastian` | GET | `sebastian_page` | - |

## debts

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/debts` | GET | `debts_api` | debts_owner_required |
| `/api/debts/entries` | POST | `debts_entry_create_api` | debts_owner_required |
| `/api/debts/entries/<entry_id>` | DELETE | `debts_entry_delete_api` | debts_owner_required |
| `/api/debts/me` | GET | `debts_me_api` | - |
| `/api/debts/me/payment-requests/<request_id>` | DELETE | `debts_own_payment_request_cancel_api` | debtor_required |
| `/api/debts/payment-requests` | POST | `debts_payment_request_create_api` | - |
| `/api/debts/payment-requests/<request_id>` | DELETE | `debts_payment_request_cancel_api` | debts_owner_required |
| `/api/debts/payment-requests/<request_id>/approve` | POST | `debts_payment_request_approve_api` | debts_owner_required |
| `/api/debts/unlock` | POST | `debts_unlock_api` | - |
| `/api/debts/users` | POST | `debts_user_create_api` | debts_owner_required |
| `/api/debts/users/<user_id>` | DELETE | `debts_user_delete_api` | debts_owner_required |
| `/api/debts/users/<user_id>/color` | POST | `debts_user_color_api` | debts_owner_required |
| `/api/debts/users/<user_id>/password` | POST | `debts_user_password_api` | debts_owner_required |
| `/debts` | GET | `debts_page` | login_required |
| `/debts/me` | GET | `debts_me_page` | debtor_required |

## desktop

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/desktop/config` | GET | `config` | viewer_required |
| `/api/desktop/devices` | GET | `device_list` | login_required |
| `/api/desktop/devices/<did>` | DELETE | `revoke` | login_required |
| `/api/desktop/host` | POST | `host` | - |
| `/api/desktop/register` | POST | `register` | login_required |
| `/api/desktop/sessions` | POST | `create_session` | viewer_required |
| `/api/desktop/sessions/<cid>` | DELETE | `close_session` | - |
| `/api/desktop/sessions/<cid>` | GET | `read_session` | - |
| `/api/desktop/sessions/<cid>` | POST | `answer_session` | - |
| `/api/desktop/version` | GET | `version` | login_required |
| `/desktop` | GET | `desktop_page` | login_required |

## devices

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/devices` | GET | `devices_list_api` | login_required |
| `/api/devices/<selector>` | DELETE | `device_forget_api` | login_required |
| `/api/devices/<selector>` | PATCH | `device_rename_api` | login_required |
| `/api/devices/trust` | POST | `device_trust` | login_required |
| `/devices` | GET | `devices_page` | login_required |

## diy

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/diy` | GET | `diy_list_api` | - |
| `/api/diy` | POST | `diy_create_api` | diy_editor_required |
| `/api/diy/<item_id>` | DELETE | `diy_delete_api` | diy_editor_required |
| `/api/diy/<item_id>` | PATCH | `diy_update_api` | diy_editor_required |
| `/api/diy/<item_id>/asset` | POST | `diy_asset_upload_api` | diy_editor_required |
| `/api/diy/<item_id>/asset/<path:name>` | DELETE | `diy_asset_delete_api` | diy_editor_required |
| `/api/diy/<item_id>/cover` | DELETE | `diy_cover_delete_api` | diy_editor_required |
| `/api/diy/<item_id>/cover` | POST | `diy_cover_upload_api` | diy_editor_required |
| `/diy` | GET | `diy_page` | - |
| `/diy/a/<item_id>` | GET | `diy_article_page` | - |
| `/diy/asset/<item_id>/<path:name>` | GET | `diy_asset_api` | - |
| `/diy/cover/<item_id>` | GET | `diy_cover_api` | - |

## drop

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/drop/<item_id>` | DELETE | `drop_delete` | login_required |
| `/api/drop/<item_id>` | PATCH | `drop_update` | login_required |
| `/api/drop/<item_id>/restore` | POST | `drop_restore` | login_required |
| `/api/drop/download/<item_id>` | GET | `drop_download` | login_required |
| `/api/drop/folder` | POST | `drop_folder_create` | login_required |
| `/api/drop/list` | GET | `drop_list_api` | login_required |
| `/api/drop/op` | POST | `drop_op_start` | login_required |
| `/api/drop/op/<job_id>` | GET | `drop_op_status` | login_required |
| `/api/drop/qr` | GET | `drop_qr` | login_required |
| `/api/drop/share/<item_id>` | DELETE | `drop_share_revoke` | login_required |
| `/api/drop/share/<item_id>` | POST | `drop_share_create` | login_required |
| `/api/drop/text` | POST | `drop_upload_text` | login_required |
| `/api/drop/text/<item_id>` | GET | `drop_text_full` | login_required |
| `/api/drop/text/<item_id>` | PUT | `drop_text_update` | login_required |
| `/api/drop/thumb/<item_id>` | GET | `drop_thumb` | login_required |
| `/api/drop/trash` | DELETE | `drop_trash_empty` | login_required |
| `/api/drop/trash` | GET | `drop_trash_list` | login_required |
| `/api/drop/trash/<item_id>` | DELETE | `drop_trash_purge` | login_required |
| `/api/drop/trash/unlock` | POST | `drop_trash_unlock` | login_required |
| `/api/drop/upload/chunk/<upload_id>` | POST | `drop_upload_chunk` | login_required |
| `/api/drop/upload/finish/<upload_id>` | POST | `drop_upload_finish` | login_required |
| `/api/drop/upload/init` | POST | `drop_upload_init` | login_required |
| `/api/drop/view/<item_id>` | GET | `drop_view` | login_required |
| `/api/drop/zip/<item_id>` | GET | `drop_zip` | login_required |
| `/d/<token>` | GET | `drop_public` | - |
| `/d/<token>/raw` | GET | `drop_public_raw` | - |
| `/d/<token>/save` | GET | `drop_public_save` | - |
| `/drop` | GET | `drop_page` | login_required |

## files

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/files/connect` | POST | `files_connect` | login_required |
| `/api/files/disconnect` | POST | `files_disconnect` | login_required |
| `/api/files/download` | GET | `files_download` | login_required |
| `/api/files/list` | GET | `files_list` | login_required |
| `/api/files/op` | POST | `files_op` | login_required |
| `/api/files/session` | GET | `files_session` | login_required |
| `/api/files/to-drop` | POST | `files_to_drop` | login_required |
| `/api/files/to-drop/<job_id>` | GET | `files_to_drop_status` | login_required |
| `/api/files/upload` | POST | `files_upload` | login_required |
| `/api/files/zip` | GET | `files_zip` | login_required |
| `/files/<ip>` | GET | `files_page` | login_required |

## home

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/` | GET | `home` | - |
| `/api/arcade/scores` | GET | `arcade_scores_api` | - |
| `/api/arcade/scores` | POST | `arcade_score_add` | - |
| `/api/arcade/scores/delete` | POST | `arcade_score_delete` | - |
| `/servers` | GET | `servers_page` | - |
| `/servers/unlock` | POST | `servers_unlock` | - |
| `/themes` | GET | `themes_page` | login_required |

## login_log

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/login-log` | GET | `login_log_api` | login_required |
| `/login-log` | GET | `login_log_page` | login_required |

## music

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/music` | GET | `music_list_api` | music_editor_required |
| `/api/music` | POST | `music_upload_api` | music_editor_required |
| `/api/music/<track_id>` | DELETE | `music_delete_api` | music_editor_required |
| `/api/music/<track_id>` | PATCH | `music_rename_api` | music_editor_required |
| `/api/music/file/<track_id>` | GET | `music_file_api` | music_editor_required |
| `/api/music/folder` | POST | `music_folder_create_api` | music_editor_required |
| `/api/music/folder/<folder_id>` | DELETE | `music_folder_delete_api` | music_editor_required |
| `/api/music/folder/<folder_id>` | PATCH | `music_folder_patch_api` | music_editor_required |
| `/api/music/op` | POST | `music_op_api` | music_editor_required |
| `/api/player/tracks` | GET | `player_tracks` | login_required |
| `/music` | GET | `music_page` | login_required |
| `/player/pop` | GET | `player_pop_page` | login_required |
| `/vg-player.js` | GET | `vg_player_js` | - |

## notebook

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/notebook` | GET | `notebook_get_api` | login_required |
| `/api/notebook/entry` | POST | `notebook_entry_add` | login_required |
| `/api/notebook/entry/<eid>` | DELETE | `notebook_entry_delete` | login_required |
| `/api/notebook/entry/<eid>` | PATCH | `notebook_entry_edit` | login_required |
| `/api/notebook/entry/<eid>/pdf` | POST | `notebook_entry_pdf` | login_required |
| `/api/notebook/page` | POST | `notebook_page_add` | login_required |
| `/api/notebook/page/<pid>` | DELETE | `notebook_page_delete` | login_required |
| `/api/notebook/page/<pid>` | PATCH | `notebook_page_rename` | login_required |
| `/notebook` | GET | `notebook_page` | login_required |
| `/notebook/pdf/<eid>` | GET | `notebook_pdf_view` | login_required |

## phone

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/app/pull` | POST | `app_pull_api` | login_required |
| `/api/app/version` | GET | `app_version_api` | - |
| `/api/phone/agent` | GET | `phone_agent_api` | login_required |
| `/api/phone/token` | POST | `phone_token_issue` | login_required |
| `/api/phone/token/<token_id>` | DELETE | `phone_token_revoke` | login_required |
| `/api/phone/tokens` | GET | `phone_tokens_api` | login_required |
| `/app` | GET | `app_apk` | login_required |
| `/phone` | GET | `phone_page` | login_required |
| `/ws/agent` | GET | `agent_ws` | - |
| `/ws/phone` | GET | `phone_ws` | - |

## pwa

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/favicon.ico` | GET | `favicon` | - |
| `/icon-<int:size>.png` | GET | `app_icon` | - |
| `/icon-maskable-<int:size>.png` | GET | `app_icon_maskable` | - |
| `/manifest.webmanifest` | GET | `manifest` | - |
| `/share-target` | POST | `share_target_fallback` | login_required |
| `/sw.js` | GET | `service_worker` | - |

## remote

| URL | Метод | Функция | Guards |
| --- | --- | --- | --- |
| `/api/console/login` | POST | `console_login` | login_required |
| `/api/netbird/status` | GET | `netbird_status_api` | login_required |
| `/api/notifications` | DELETE | `notifications_clear_api` | login_required |
| `/api/notifications` | GET | `notifications_api` | login_required |
| `/api/notifications/<notification_id>/read` | POST | `notification_read_api` | login_required |
| `/api/notifications/read-all` | POST | `notifications_read_all_api` | login_required |
| `/api/pc/shutdown` | POST | `pc_shutdown` | login_required |
| `/api/wol` | POST | `wol` | login_required |
| `/cabinet` | GET | `cabinet` | login_required |
| `/netbird` | GET | `netbird_page` | login_required |
| `/notifications` | GET | `notifications_page` | login_required |
| `/ws/claude` | GET | `claude_ws` | - |
| `/ws/console/<ip>` | GET | `console_ws` | - |
| `/ws/rdp/<ip>` | GET | `rdp_ws` | - |
| `/ws/vnc/<ip>` | GET | `vnc_ws` | - |
