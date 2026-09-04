# Blueprints Migration Plan

This plan prepares the route split from `app.py` into Flask blueprints without
moving routes yet. Current baseline is documented in `docs/routes-inventory.md`:
`123` route decorators in `app.py`.

## Ground Rules

- Move one section at a time, one small commit per section.
- Keep behavior unchanged: route URLs, methods, decorators, response mimetypes,
  cache headers, ETags, redirects, sessions, and template replacements must stay
  the same.
- Register blueprints from the app factory/module only after the moved routes
  have identical test-client responses.
- Do not change `deploy.yml` during route moves.
- Keep `templates/` as plain text files read by `_template(...)`; do not switch
  to Jinja.

## Shared Helpers First

Before moving a section, identify the helpers it uses and decide whether they
should stay in `app.py` temporarily or move to a shared module. Prefer boring
shared modules over cross-importing blueprints from each other.

Likely shared modules:

- `blueprints/shared.py`: `_template`, common response helpers, app constants
  that do not own a route.
- `blueprints/auth_utils.py`: `login_required`, `music_editor_required`,
  `debtor_required`, `debts_owner_required`, session and password helpers.
- `blueprints/storage.py`: common data paths, atomic JSON helpers, backup-safe
  file helpers.
- `blueprints/icons.py`: `ICON_LINKS`, generated app icons, game icon data used
  by home/themes/Sebastian.

Leave helpers in `app.py` until a concrete move needs them. When moving a helper,
move only the helper and its direct constants/tests with the route section that
first needs it.

## Order

### 1. pwa/icons/static-ish routes

Move:

- `manifest`
- `service_worker`
- `favicon`
- `app_icon`
- `app_icon_maskable`
- `share_target_fallback`

Main dependencies:

- `Response`, `send_file`, `redirect`, `url_for`, `request`, `session`
- `_template`, `ICON_LINKS`
- app icon generation helpers and static path constants
- Drop share-target fallback helpers for imported shared files/text

Checks:

- `/manifest.webmanifest` content type unchanged
- `/sw.js` content type unchanged and body byte-equal
- `/favicon.ico`, `/icon-*.png`, `/icon-maskable-*.png` status/content type
- `/share-target` redirect behavior preserved

### 2. home/themes/servers public pages

Move:

- `home`
- `themes_page`
- `servers_page`
- arcade score routes if they remain owned by the home/games surface

Main dependencies:

- `_template`, `ICON_LINKS`, `_GAME_ICONS`
- theme/card data helpers
- arcade score data helpers

Checks:

- `/`, `/servers`, `/themes` auth behavior and rendered HTML unchanged
- arcade score API status and JSON shape unchanged

### 3. debts

Move:

- debts pages: `debts_page`, `debts_me_page`
- debts APIs: unlock, owner CRUD, entry CRUD, debtor API

Main dependencies:

- debt data locks, load/save helpers, `_today_iso`
- `login_required`, `debtor_required`, `debts_owner_required`
- `_debts_page_html`, `_template`

Checks:

- owner locked/unlocked page HTML byte-equal
- debtor page HTML byte-equal
- daily password/session behavior unchanged

### 4. notebook

Move:

- `notebook_page`
- notebook page/entry/PDF APIs
- `notebook_pdf_view`

Main dependencies:

- notebook data lock/load/save helpers
- PDF helpers and static/generated file paths
- `login_required`, `_template`, `ICON_LINKS`

Checks:

- `/notebook` rendered HTML unchanged
- CRUD JSON shape unchanged
- PDF generation/view status unchanged

### 5. diy

Move:

- `diy_page`
- `diy_article_page`
- DIY list/create/update/delete APIs
- DIY asset and cover routes

Main dependencies:

- DIY lock/load/save helpers, seeded data helpers
- `_diy_can_edit`, `diy_editor_required`
- `_diy_card`, `_diy_head`, `_diy_render_body`
- `_template`, `ICON_LINKS`

Checks:

- `/diy` and article HTML byte-equal
- asset/cover paths and send-file behavior unchanged
- editor guard unchanged

### 6. music/player

Move:

- `music_page`
- music track/folder/op APIs
- `music_file_api`
- `player_tracks`
- `vg_player_js`
- `player_pop_page`

Main dependencies:

- music data lock/load/save helpers
- file serving and folder helpers
- `login_required`, `music_editor_required`
- `_template`, ETag/md5 logic for `/vg-player.js`

Checks:

- `/vg-player.js` ETag equals md5 of `templates/vg_player.js.tpl`
- Cache-Control and mimetype unchanged
- music API auth and JSON shape unchanged

### 7. drop

Move:

- `drop_page`
- all `/api/drop/*` routes
- public `/d/<token>` routes
- `_drop_view_page`

Main dependencies:

- Drop metadata locks/load/save helpers
- file, zip, thumbnail, QR, share, trash, operation job helpers
- `login_required`, `_template`, `ICON_LINKS`

Checks:

- upload/list/download/view/share/trash behavior unchanged
- public preview/save/raw routes unchanged
- Drop page HTML byte-equal

### 8. ai/neuro/claude

Move:

- `neuro_page`
- `ai_page` and AI chat/folder/image/send/regenerate APIs
- `claude_page`
- `claude_state_api`

Main dependencies:

- AI chat storage helpers and provider request helpers
- Claude state helpers and websocket-adjacent config
- `login_required`, `_template`, `ICON_LINKS`
- `g.frameable` behavior for iframe pages

Checks:

- `/neuro`, `/ai`, `/claude` rendered HTML unchanged
- iframe/frame headers unchanged
- chat API JSON and streaming behavior unchanged

### 9. cabinet + remote access websockets

Move:

- `cabinet`
- remote access APIs: NetBird status, console login, PC shutdown, WOL
- websocket handlers for SSH/RDP/VNC/Claude if they share the same remote access
  helper layer

Main dependencies:

- `sock`
- NetBird device config, ping/status helpers
- SSH/RDP/VNC tunnel helpers, `paramiko`
- `login_required`, `_template`, `ICON_LINKS`

Checks:

- `/cabinet` rendered HTML unchanged
- SSH/RDP/VNC buttons and websocket paths unchanged
- NetBird and WOL API auth unchanged

### 10. backup/sebastian

Move:

- backup APIs
- `sebastian_page`
- `sebastian_state_api`
- `sebastian_ask_api`

Main dependencies:

- backup archive/import helpers and data path constants
- Sebastian env/config helpers, allow logic, prompt
- `_template`, `ICON_LINKS`, `_GAME_ICONS`

Checks:

- backup export/import status, auth, and filenames unchanged
- `/sebastian` public HTML unchanged
- Sebastian unavailable/error messages unchanged

## Per-step Checklist

- `python -c "import ast, pathlib; ast.parse(pathlib.Path('app.py').read_text(encoding='utf-8')); print('ast ok')"`
- Route decorators remain `123` until routes are actually moved.
- Test-client compare old/new responses for every moved page and representative
  APIs.
- `git diff` contains only the intended section and registration glue.
- Push and confirm GitHub Actions deploy is green.
