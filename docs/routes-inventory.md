# Flask Routes Inventory

Baseline before blueprint split:

- Source: `app.py`
- Route decorators: `123`
- Code changes in this inventory: none

Guards column includes route decorators such as `login_required`, `debtor_required`,
`music_editor_required`, plus existing domain guards where useful.

## core/auth

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/api/diag` | `@app.get("/api/diag")` | `diag_api` | `login_required` |
| `/api/login` | `@app.post("/api/login")` | `login` | - |
| `/logout` | `@app.post("/logout")` | `logout` | - |
| `/api/session/probe` | `@app.get("/api/session/probe")` | `session_probe` | - |
| `/api/login-log` | `@app.get("/api/login-log")` | `login_log_api` | `login_required` |
| `/api/devices/trust` | `@app.post("/api/devices/trust")` | `device_trust` | `login_required` |
| `/api/devices` | `@app.get("/api/devices")` | `devices_list_api` | `login_required` |
| `/api/devices/<selector>` | `@app.patch("/api/devices/<selector>")` | `device_rename_api` | `login_required` |
| `/api/devices/<selector>` | `@app.delete("/api/devices/<selector>")` | `device_forget_api` | `login_required` |

## cabinet

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/cabinet` | `@app.get("/cabinet")` | `cabinet` | `login_required` |
| `/api/metrics` | `@app.get("/api/metrics")` | `metrics_api` | `login_required` |
| `/api/uptime` | `@app.get("/api/uptime")` | `uptime_api` | `login_required` |

## drop

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/drop` | `@app.get("/drop")` | `drop_page` | `login_required` |
| `/api/drop/thumb/<item_id>` | `@app.get("/api/drop/thumb/<item_id>")` | `drop_thumb` | `login_required` |
| `/api/drop/text` | `@app.post("/api/drop/text")` | `drop_upload_text` | `login_required` |
| `/api/drop/text/<item_id>` | `@app.get("/api/drop/text/<item_id>")` | `drop_text_full` | `login_required` |
| `/api/drop/text/<item_id>` | `@app.put("/api/drop/text/<item_id>")` | `drop_text_update` | `login_required` |
| `/api/drop/folder` | `@app.post("/api/drop/folder")` | `drop_folder_create` | `login_required` |
| `/api/drop/upload/init` | `@app.post("/api/drop/upload/init")` | `drop_upload_init` | `login_required` |
| `/api/drop/upload/chunk/<upload_id>` | `@app.post("/api/drop/upload/chunk/<upload_id>")` | `drop_upload_chunk` | `login_required` |
| `/api/drop/upload/finish/<upload_id>` | `@app.post("/api/drop/upload/finish/<upload_id>")` | `drop_upload_finish` | `login_required` |
| `/api/drop/list` | `@app.get("/api/drop/list")` | `drop_list_api` | `login_required` |
| `/api/drop/download/<item_id>` | `@app.get("/api/drop/download/<item_id>")` | `drop_download` | `login_required` |
| `/api/drop/zip/<item_id>` | `@app.get("/api/drop/zip/<item_id>")` | `drop_zip` | `login_required` |
| `/api/drop/view/<item_id>` | `@app.get("/api/drop/view/<item_id>")` | `drop_view` | `login_required` |
| `/api/drop/<item_id>` | `@app.patch("/api/drop/<item_id>")` | `drop_update` | `login_required` |
| `/api/drop/op` | `@app.post("/api/drop/op")` | `drop_op_start` | `login_required` |
| `/api/drop/op/<job_id>` | `@app.get("/api/drop/op/<job_id>")` | `drop_op_status` | `login_required` |
| `/api/drop/share/<item_id>` | `@app.post("/api/drop/share/<item_id>")` | `drop_share_create` | `login_required` |
| `/api/drop/share/<item_id>` | `@app.delete("/api/drop/share/<item_id>")` | `drop_share_revoke` | `login_required` |
| `/d/<token>` | `@app.get("/d/<token>")` | `drop_public` | - |
| `/d/<token>/raw` | `@app.get("/d/<token>/raw")` | `drop_public_raw` | - |
| `/d/<token>/save` | `@app.get("/d/<token>/save")` | `drop_public_save` | - |
| `/api/drop/qr` | `@app.get("/api/drop/qr")` | `drop_qr` | `login_required` |
| `/api/drop/<item_id>` | `@app.delete("/api/drop/<item_id>")` | `drop_delete` | `login_required` |
| `/api/drop/trash/unlock` | `@app.post("/api/drop/trash/unlock")` | `drop_trash_unlock` | `login_required` |
| `/api/drop/trash` | `@app.get("/api/drop/trash")` | `drop_trash_list` | `login_required` |
| `/api/drop/<item_id>/restore` | `@app.post("/api/drop/<item_id>/restore")` | `drop_restore` | `login_required` |
| `/api/drop/trash/<item_id>` | `@app.delete("/api/drop/trash/<item_id>")` | `drop_trash_purge` | `login_required` |
| `/api/drop/trash` | `@app.delete("/api/drop/trash")` | `drop_trash_empty` | `login_required` |

## music/player

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/music` | `@app.get("/music")` | `music_page` | `login_required` |
| `/api/music` | `@app.get("/api/music")` | `music_list_api` | `music_editor_required` |
| `/api/music` | `@app.post("/api/music")` | `music_upload_api` | `music_editor_required` |
| `/api/music/<track_id>` | `@app.patch("/api/music/<track_id>")` | `music_rename_api` | `music_editor_required` |
| `/api/music/<track_id>` | `@app.delete("/api/music/<track_id>")` | `music_delete_api` | `music_editor_required` |
| `/api/music/folder` | `@app.post("/api/music/folder")` | `music_folder_create_api` | `music_editor_required` |
| `/api/music/folder/<folder_id>` | `@app.patch("/api/music/folder/<folder_id>")` | `music_folder_patch_api` | `music_editor_required` |
| `/api/music/folder/<folder_id>` | `@app.delete("/api/music/folder/<folder_id>")` | `music_folder_delete_api` | `music_editor_required` |
| `/api/music/op` | `@app.post("/api/music/op")` | `music_op_api` | `music_editor_required` |
| `/api/music/file/<track_id>` | `@app.get("/api/music/file/<track_id>")` | `music_file_api` | `music_editor_required` |
| `/api/player/tracks` | `@app.get("/api/player/tracks")` | `player_tracks` | `login_required` |
| `/vg-player.js` | `@app.get("/vg-player.js")` | `vg_player_js` | - |
| `/player/pop` | `@app.get("/player/pop")` | `player_pop_page` | `login_required` |

## diy

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/diy` | `@app.get("/diy")` | `diy_page` | - |
| `/api/diy` | `@app.get("/api/diy")` | `diy_list_api` | - |
| `/api/diy` | `@app.post("/api/diy")` | `diy_create_api` | `diy_editor_required` |
| `/api/diy/<item_id>` | `@app.patch("/api/diy/<item_id>")` | `diy_update_api` | `diy_editor_required` |
| `/api/diy/<item_id>` | `@app.delete("/api/diy/<item_id>")` | `diy_delete_api` | `diy_editor_required` |
| `/api/diy/<item_id>/asset` | `@app.post("/api/diy/<item_id>/asset")` | `diy_asset_upload_api` | `diy_editor_required` |
| `/api/diy/<item_id>/asset/<path:name>` | `@app.delete("/api/diy/<item_id>/asset/<path:name>")` | `diy_asset_delete_api` | `diy_editor_required` |
| `/diy/asset/<item_id>/<path:name>` | `@app.get("/diy/asset/<item_id>/<path:name>")` | `diy_asset_api` | - |
| `/api/diy/<item_id>/cover` | `@app.post("/api/diy/<item_id>/cover")` | `diy_cover_upload_api` | `diy_editor_required` |
| `/api/diy/<item_id>/cover` | `@app.delete("/api/diy/<item_id>/cover")` | `diy_cover_delete_api` | `diy_editor_required` |
| `/diy/cover/<item_id>` | `@app.get("/diy/cover/<item_id>")` | `diy_cover_api` | - |
| `/diy/a/<item_id>` | `@app.get("/diy/a/<item_id>")` | `diy_article_page` | - |

## notebook

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/notebook` | `@app.get("/notebook")` | `notebook_page` | `login_required` |
| `/api/notebook` | `@app.get("/api/notebook")` | `notebook_get_api` | `login_required` |
| `/api/notebook/page` | `@app.post("/api/notebook/page")` | `notebook_page_add` | `login_required` |
| `/api/notebook/page/<pid>` | `@app.patch("/api/notebook/page/<pid>")` | `notebook_page_rename` | `login_required` |
| `/api/notebook/page/<pid>` | `@app.delete("/api/notebook/page/<pid>")` | `notebook_page_delete` | `login_required` |
| `/api/notebook/entry` | `@app.post("/api/notebook/entry")` | `notebook_entry_add` | `login_required` |
| `/api/notebook/entry/<eid>` | `@app.patch("/api/notebook/entry/<eid>")` | `notebook_entry_edit` | `login_required` |
| `/api/notebook/entry/<eid>` | `@app.delete("/api/notebook/entry/<eid>")` | `notebook_entry_delete` | `login_required` |
| `/api/notebook/entry/<eid>/pdf` | `@app.post("/api/notebook/entry/<eid>/pdf")` | `notebook_entry_pdf` | `login_required` |
| `/notebook/pdf/<eid>` | `@app.get("/notebook/pdf/<eid>")` | `notebook_pdf_view` | `login_required` |

## debts

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/debts` | `@app.get("/debts")` | `debts_page` | `login_required` |
| `/debts/me` | `@app.get("/debts/me")` | `debts_me_page` | `debtor_required` |
| `/api/debts/unlock` | `@app.post("/api/debts/unlock")` | `debts_unlock_api` | - |
| `/api/debts` | `@app.get("/api/debts")` | `debts_api` | `debts_owner_required` |
| `/api/debts/users` | `@app.post("/api/debts/users")` | `debts_user_create_api` | `debts_owner_required` |
| `/api/debts/entries` | `@app.post("/api/debts/entries")` | `debts_entry_create_api` | `debts_owner_required` |
| `/api/debts/entries/<entry_id>` | `@app.delete("/api/debts/entries/<entry_id>")` | `debts_entry_delete_api` | `debts_owner_required` |
| `/api/debts/me` | `@app.get("/api/debts/me")` | `debts_me_api` | - |
| `/api/debts/users/<user_id>` | `@app.delete("/api/debts/users/<user_id>")` | `debts_user_delete_api` | `debts_owner_required` |
| `/api/debts/users/<user_id>/password` | `@app.post("/api/debts/users/<user_id>/password")` | `debts_user_password_api` | `debts_owner_required` |

## ai/neuro/claude

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/claude` | `@app.get("/claude")` | `claude_page` | `login_required` |
| `/api/claude/state` | `@app.get("/api/claude/state")` | `claude_state_api` | `login_required` |
| `/neuro` | `@app.get("/neuro")` | `neuro_page` | `login_required` |
| `/ai` | `@app.get("/ai")` | `ai_page` | `login_required` |
| `/api/ai/state` | `@app.get("/api/ai/state")` | `ai_state_api` | `login_required` |
| `/api/ai/chat/<chat_id>` | `@app.get("/api/ai/chat/<chat_id>")` | `ai_chat_get` | `login_required` |
| `/api/ai/chat` | `@app.post("/api/ai/chat")` | `ai_chat_new` | `login_required` |
| `/api/ai/chat/<chat_id>` | `@app.patch("/api/ai/chat/<chat_id>")` | `ai_chat_rename` | `login_required` |
| `/api/ai/folder` | `@app.get("/api/ai/folder")` | `ai_folder_list` | `login_required` |
| `/api/ai/folder` | `@app.post("/api/ai/folder")` | `ai_folder_new` | `login_required` |
| `/api/ai/folder/<fid>` | `@app.patch("/api/ai/folder/<fid>")` | `ai_folder_rename` | `login_required` |
| `/api/ai/folder/<fid>` | `@app.delete("/api/ai/folder/<fid>")` | `ai_folder_delete` | `login_required` |
| `/api/ai/chat/<chat_id>` | `@app.delete("/api/ai/chat/<chat_id>")` | `ai_chat_delete` | `login_required` |
| `/api/ai/img/<img_id>` | `@app.get("/api/ai/img/<img_id>")` | `ai_img_api` | `login_required` |
| `/api/ai/chat/<chat_id>/send` | `@app.post("/api/ai/chat/<chat_id>/send")` | `ai_chat_send` | `login_required` |
| `/api/ai/chat/<chat_id>/regenerate` | `@app.post("/api/ai/chat/<chat_id>/regenerate")` | `ai_chat_regenerate` | `login_required` |

## servers/themes/home

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/` | `@app.route("/")` | `home` | - |
| `/servers` | `@app.get("/servers")` | `servers_page` | - |
| `/themes` | `@app.get("/themes")` | `themes_page` | `login_required` |
| `/api/arcade/scores` | `@app.get("/api/arcade/scores")` | `arcade_scores_api` | - |
| `/api/arcade/scores` | `@app.post("/api/arcade/scores")` | `arcade_score_add` | - |
| `/api/arcade/scores/delete` | `@app.post("/api/arcade/scores/delete")` | `arcade_score_delete` | - |

## sebastian

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/sebastian` | `@app.get("/sebastian")` | `sebastian_page` | - |
| `/api/sebastian/state` | `@app.get("/api/sebastian/state")` | `sebastian_state_api` | - |
| `/api/sebastian/ask` | `@app.post("/api/sebastian/ask")` | `sebastian_ask_api` | - |

## backup

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/api/backup/state` | `@app.get("/api/backup/state")` | `backup_state_api` | `login_required` |
| `/api/backup/export` | `@app.get("/api/backup/export")` | `backup_export_api` | - |
| `/api/backup/import` | `@app.post("/api/backup/import")` | `backup_import_api` | `login_required` |

## pwa/icons

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/manifest.webmanifest` | `@app.get("/manifest.webmanifest")` | `manifest` | - |
| `/sw.js` | `@app.get("/sw.js")` | `service_worker` | - |
| `/favicon.ico` | `@app.get("/favicon.ico")` | `favicon` | - |
| `/icon-<int:size>.png` | `@app.get("/icon-<int:size>.png")` | `app_icon` | - |
| `/icon-maskable-<int:size>.png` | `@app.get("/icon-maskable-<int:size>.png")` | `app_icon_maskable` | - |
| `/share-target` | `@app.post("/share-target")` | `share_target_fallback` | `login_required` |

## websockets/remote access

| URL | Decorator | Function | Guards |
| --- | --- | --- | --- |
| `/api/netbird/status` | `@app.get("/api/netbird/status")` | `netbird_status_api` | `login_required` |
| `/api/console/login` | `@app.post("/api/console/login")` | `console_login` | `login_required` |
| `/api/pc/shutdown` | `@app.post("/api/pc/shutdown")` | `pc_shutdown` | `login_required` |
| `/api/wol` | `@app.post("/api/wol")` | `wol` | `login_required` |
