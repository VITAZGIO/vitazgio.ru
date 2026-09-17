'use strict';
const { app, BrowserWindow, Menu, Tray, nativeImage, ipcMain, shell, session, safeStorage, clipboard,
  desktopCapturer, screen, globalShortcut, net, powerMonitor } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { pathToFileURL } = require('node:url');
const { ORIGIN, REPO, siteURL, newer, releaseAsset } = require('./policy.cjs');
let main, player, agent, settingsWindow, tray, prefs, input, quitting = false, token = '', pairedId = '';
let playerReady = false, playerQueue = [], playerState = null, updateJob = null, registering = false;
let hostSessions = new Map(), hostSeen = 0, lastInput = 0;
const windows = new Map();
const partition = 'persist:vitazgio';
const localFile = name => pathToFileURL(path.join(__dirname, name)).href;
const localAllowed = (wc, role) => wc === (role === 'agent' ? agent : settingsWindow)?.webContents && wc.getURL() === localFile(role + '.html');
function authorized(event, role) {
  const wc = event.sender;
  if (event.senderFrame !== wc.mainFrame || !windows.has(wc.id)) throw new Error('Недопустимый вызов');
  const actual = windows.get(wc.id);
  if (role && actual !== role) throw new Error('Нет доступа');
  if (actual === 'agent' || actual === 'settings') {
    if (!localAllowed(wc, actual)) throw new Error('Нет доступа');
  } else if (!siteURL(event.senderFrame.url)) throw new Error('Нет доступа');
  return actual;
}
function persist() {
  const value = { ...prefs, pairedId, token: token ? safeStorage.encryptString(token).toString('base64') : '' };
  fs.writeFileSync(path.join(app.getPath('userData'), 'settings.json.tmp'), JSON.stringify(value));
  fs.renameSync(path.join(app.getPath('userData'), 'settings.json.tmp'), path.join(app.getPath('userData'), 'settings.json'));
}
function status() { return { version: app.getVersion(), name: os.hostname(), deviceId: pairedId,
  paired: !!token, enabled: prefs.enabled, control: prefs.control, startup: prefs.startup }; }
function sendAll(channel, value) {
  for (const win of BrowserWindow.getAllWindows()) if (!win.isDestroyed()) win.webContents.send(channel, value);
}
function stopRemote() {
  hostSessions.clear();
  input?.release();
  agent?.webContents.send('vg:stop');
}
function disableRemote() {
  prefs.enabled = false; persist(); stopRemote(); refreshTray();
}
function createWindow(role, options = {}) {
  const win = new BrowserWindow({ width: 1200, height: 840, backgroundColor: '#0d1321', show: false,
    icon: path.join(__dirname, 'assets', 'icon.ico'), title: 'Vitaz Gio',
    ...options, webPreferences: { preload: path.join(__dirname, 'preload.cjs'), partition,
      contextIsolation: true, sandbox: true, nodeIntegration: false, backgroundThrottling: role === 'main',
      autoplayPolicy: 'no-user-gesture-required', additionalArguments: ['--vg-role=' + role] } });
  windows.set(win.webContents.id, role);
  win.removeMenu();
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (siteURL(url) && new URL(url).pathname === '/player/pop') openPlayer();
    else if (siteURL(url)) { showMain(); main.loadURL(url); }
    else if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  const guard = (event, url) => {
    const allowed = ['agent','settings'].includes(role) ? url === localFile(role + '.html') : siteURL(url);
    if (!allowed) { event.preventDefault(); if (/^https?:\/\//i.test(url)) shell.openExternal(url); }
  };
  win.webContents.on('will-navigate', guard);
  win.webContents.on('will-redirect', guard);
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  const id = win.webContents.id;
  win.on('closed', () => windows.delete(id));
  return win;
}
function showMain() {
  if (!main || main.isDestroyed()) {
    main = createWindow('main');
    main.once('ready-to-show', () => { if (!process.argv.includes('--hidden')) main.show(); });
    main.on('close', event => { if (!quitting) { event.preventDefault(); main.hide(); } });
    main.webContents.on('did-finish-load', () => {
      if (siteURL(main.webContents.getURL())) pairAndStart().catch(() => {});
    });
    main.webContents.on('before-input-event', (event, key) => {
      if (key.type === 'keyDown' && (key.key === 'F5' || (key.control && key.key.toLowerCase() === 'r'))) {
        event.preventDefault(); main.webContents.reloadIgnoringCache();
        if (agent && !agent.isDestroyed() && !hostSessions.size) agent.webContents.reloadIgnoringCache();
      }
    });
    main.loadURL(ORIGIN + '/cabinet');
  } else { main.show(); main.focus(); }
}
function ensurePlayer() {
  if (player && !player.isDestroyed()) return;
  playerReady = false;
  player = createWindow('player', { width: 380, height: 280, minWidth: 300, minHeight: 220,
    frame: false, alwaysOnTop: true, skipTaskbar: true, resizable: true });
  player.on('close', event => { if (!quitting) { event.preventDefault(); player.hide(); } });
  player.webContents.on('render-process-gone', () => { playerReady = false; player.reload(); });
  player.loadURL(ORIGIN + '/player/pop');
}
function openPlayer() { ensurePlayer(); player.show(); player.setAlwaysOnTop(true, 'floating'); player.focus(); }
function openSettings() {
  if (!settingsWindow || settingsWindow.isDestroyed()) {
    settingsWindow = createWindow('settings', { width: 560, height: 610, resizable: false });
    settingsWindow.loadFile(path.join(__dirname, 'settings.html'));
    settingsWindow.once('ready-to-show', () => settingsWindow.show());
  } else { settingsWindow.show(); settingsWindow.focus(); }
}
async function pairAndStart() {
  if (registering) return;
  registering = true;
  try {
    const ses = session.fromPartition(partition);
    // Checking an authenticated endpoint avoids creating a token on the login page.
    const check = await ses.fetch(ORIGIN + '/api/desktop/devices');
    if (!check.ok || !check.headers.get('content-type')?.includes('application/json')) return;
    if (!token) {
      if (!safeStorage.isEncryptionAvailable()) throw new Error('Недоступно защищённое хранилище Windows');
      const response = await ses.fetch(ORIGIN + '/api/desktop/register', { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: os.hostname() }) });
      if (!response.ok) throw new Error('Не удалось привязать компьютер');
      const data = await response.json(); token = data.token; pairedId = data.id; persist();
    }
    ensurePlayer(); startAgent();
  } finally { registering = false; }
}
function startAgent() {
  if (!token || (agent && !agent.isDestroyed())) return;
  agent = createWindow('agent');
  agent.webContents.on('render-process-gone', () => { stopRemote(); agent.reload(); });
  agent.loadFile(path.join(__dirname, 'agent.html'));
}
async function hostRequest(route, data) {
  if (!token) throw new Error('Войди в кабинет, чтобы привязать компьютер');
  const response = await net.fetch(ORIGIN + route, { method: 'POST', credentials: 'omit',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(data), signal: AbortSignal.timeout(12000) });
  if (response.status === 401) {
    token = ''; pairedId = ''; prefs.enabled = false; persist(); stopRemote(); refreshTray();
  }
  if (!response.ok) throw new Error('Агент: сервер вернул ' + response.status);
  return response.json();
}
function refreshTray() {
  tray.setToolTip('Vitaz Gio · ' + (prefs.enabled ? 'доступ к экрану включён' : 'доступ к экрану выключен'));
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Открыть сайт', click: showMain }, { label: 'Мини-плеер', click: openPlayer },
    { label: 'Настройки и доступ к ПК', click: openSettings },
    { label: 'Отключить удалённый доступ', enabled: prefs.enabled, click: disableRemote },
    { label: 'Проверить обновления', click: () => { openSettings(); checkUpdates().catch(e => sendAll('vg:update-state', { message: e.message })); } },
    { type: 'separator' }, { label: 'Выход', click: () => app.quit() },
  ]));
}
async function checkUpdates() {
  if (updateJob) return updateJob;
  const report = message => { const value = { message }; sendAll('vg:update-state', value); return value; };
  updateJob = (async () => {
    report('Проверяю новую версию…');
    const res = await net.fetch(`https://api.github.com/repos/${REPO}/releases?per_page=100`, {
      headers: { Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error('GitHub недоступен: ' + res.status);
    const latest = releaseAsset(await res.json());
    if (!latest) return report('Опубликованных Windows-сборок пока нет.');
    if (!newer(latest.version, app.getVersion())) return report('Установлена актуальная версия ' + app.getVersion());
    if (!Number.isSafeInteger(latest.size) || latest.size < 1 || latest.size > 500 * 1024 * 1024) throw new Error('Некорректный размер сборки');
    const dest = path.join(app.getPath('downloads'), latest.name);
    // Download to a unique temporary file; never replace an existing user file.
    const temp = dest + '.' + crypto.randomBytes(6).toString('hex') + '.part';
    const fd = fs.openSync(temp, 'wx');
    const hash = crypto.createHash('sha256'); let count = 0, bucket = -1;
    try {
      const response = await net.fetch(latest.url, { signal: AbortSignal.timeout(300000) });
      if (!response.ok) throw new Error('Не удалось скачать установщик: ' + response.status);
      for await (const chunk of response.body) {
        count += chunk.length;
        if (count > latest.size) throw new Error('Размер скачанного файла не совпал');
        fs.writeSync(fd, chunk); hash.update(chunk);
        const progress = Math.floor(count / latest.size * 10);
        if (progress !== bucket) { bucket = progress; report(`Скачиваю ${latest.version}: ${Math.floor(count / latest.size * 100)}%`); }
      }
      if (count !== latest.size || hash.digest('hex') !== latest.sha256) throw new Error('Проверка целостности установщика не прошла');
    } catch (e) { fs.closeSync(fd); fs.unlinkSync(temp); throw e; }
    fs.closeSync(fd);
    let final = dest;
    if (fs.existsSync(final)) final = dest.replace(/\.exe$/, '-' + Date.now() + '.exe');
    fs.renameSync(temp, final); shell.showItemInFolder(final);
    return report(`Версия ${latest.version} сохранена в «Загрузки». Запусти установщик, когда будет удобно.`);
  })();
  try { return await updateJob; } finally { updateJob = null; }
}

ipcMain.handle('vg:status', event => { authorized(event); return status(); });
ipcMain.handle('vg:settings', event => { authorized(event); openSettings(); });
ipcMain.handle('vg:update', event => { authorized(event); return checkUpdates(); });
ipcMain.handle('vg:player-open', event => { authorized(event); openPlayer(); });
ipcMain.handle('vg:player-hide', event => { authorized(event); player?.hide(); });
ipcMain.handle('vg:clipboard-read', event => {
  authorized(event);
  // The browser Clipboard API is often denied even after a button click. A
  // bounded native read makes the site's explicit «Из буфера» button work in
  // this application, without exposing arbitrary filesystem paths.
  const image = clipboard.readImage();
  const png = image.isEmpty() ? null : image.toPNG();
  return {
    text: clipboard.readText().slice(0, 1024 * 1024),
    image: png && png.length <= 25 * 1024 * 1024 ? png.toString('base64') : null,
  };
});
ipcMain.handle('vg:settings-read', event => {
  authorized(event, 'settings');
  return { ...status(), ...prefs, displays: screen.getAllDisplays().map((d, i) => ({
    id: String(d.id), label: `${d.label || 'Экран ' + (i + 1)} · ${d.size.width} × ${d.size.height}` })) };
});
ipcMain.handle('vg:settings-save', (event, value) => {
  authorized(event, 'settings');
  if (!screen.getAllDisplays().some(d => String(d.id) === value.display)) throw new Error('Экран не найден');
  if (value.control && !input) input = require('./input.cjs')();
  stopRemote();
  prefs = { startup: value.startup === true, enabled: value.enabled === true, control: value.control === true, display: value.display };
  persist();
  if (app.isPackaged) app.setLoginItemSettings({ openAtLogin: prefs.startup, args: ['--hidden'] });
  refreshTray(); startAgent(); return status();
});
const playerCommands = new Set(['adopt','playAt','playId','toggle','next','prev','seek','volume','shuffle','reload','set','play','pause','load','state']);
ipcMain.on('vg:player-command', (event, value) => {
  try {
    authorized(event);
    if (!value || !playerCommands.has(value.command) || JSON.stringify(value).length > 2 * 1024 * 1024) return;
    if (value.command === 'state' && playerState) event.sender.send('vg:player-state', playerState);
    ensurePlayer();
    if (playerReady) player.webContents.send('vg:player-deliver', value);
    else if (playerQueue.length < 100) playerQueue.push(value);
  } catch {}
});
ipcMain.on('vg:player-ready', event => {
  try {
    authorized(event, 'player'); playerReady = true;
    for (const command of playerQueue) player.webContents.send('vg:player-deliver', command);
    playerQueue = [];
  } catch {}
});
ipcMain.on('vg:player-publish', (event, value) => {
  try { authorized(event, 'player'); playerState = value; sendAll('vg:player-state', value); } catch {}
});
ipcMain.handle('vg:host-poll', async event => {
  authorized(event, 'agent');
  const result = await hostRequest('/api/desktop/host', status());
  hostSeen = Date.now();
  hostSessions = new Map(result.sessions.map(s => [s.id, s]));
  if (!hostSessions.size) input?.release();
  return result;
});
ipcMain.handle('vg:host-answer', (event, id, value) => {
  authorized(event, 'agent');
  if (!hostSessions.has(id) || !prefs.enabled) throw new Error('Соединение закрыто');
  return hostRequest('/api/desktop/sessions/' + id, value);
});
ipcMain.on('vg:input', (event, id, value) => {
  try {
    authorized(event, 'agent');
    if (!prefs.enabled || !prefs.control || !hostSessions.get(id)?.control || Date.now() - hostSeen > 10000) return;
    const display = screen.getAllDisplays().find(d => String(d.id) === prefs.display);
    if (!display) return;
    const bounds = screen.dipToScreenRect(null, display.bounds);
    if (!input) input = require('./input.cjs')();
    input.send(value, bounds); lastInput = Date.now();
  } catch {}
});
ipcMain.on('vg:release-input', event => { try { authorized(event, 'agent'); input?.release(); } catch {} });

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', showMain);
  app.on('before-quit', () => { quitting = true; stopRemote(); });
  app.on('window-all-closed', () => {});
  app.whenReady().then(() => {
    app.setAppUserModelId('ru.vitazgio.desktop');
    let saved = {};
    try { saved = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'settings.json'), 'utf8')); } catch {}
    prefs = { startup: saved.startup !== false, enabled: saved.enabled === true, control: saved.control === true,
      display: String(saved.display || screen.getPrimaryDisplay().id) };
    try { if (saved.token) { token = safeStorage.decryptString(Buffer.from(saved.token, 'base64')); pairedId = saved.pairedId; } } catch { prefs.enabled = false; }
    const icon = nativeImage.createFromPath(path.join(__dirname, 'assets', 'icon.ico'));
    tray = new Tray(icon); tray.on('double-click', showMain); refreshTray();
    if (app.isPackaged) app.setLoginItemSettings({ openAtLogin: prefs.startup, args: ['--hidden'] });
    const ses = session.fromPartition(partition);
    ses.setPermissionRequestHandler((wc, permission, callback) => callback(
      ['display-capture', 'media'].includes(permission) && wc === agent?.webContents && prefs.enabled && localAllowed(wc, 'agent')));
    ses.setPermissionCheckHandler((wc, permission) => ['display-capture', 'media'].includes(permission)
      && wc === agent?.webContents && prefs.enabled && localAllowed(wc, 'agent'));
    ses.setDisplayMediaRequestHandler(async (request, callback) => {
      if (!prefs.enabled || !hostSessions.size || request.frame !== agent?.webContents.mainFrame) return callback({});
      let capture = {};
      try {
        const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 0, height: 0 } });
        const source = sources.find(s => s.display_id === prefs.display);
        if (source && prefs.enabled && hostSessions.size) capture = { video: source, ...(request.audioRequested ? { audio: 'loopback' } : {}) };
      } catch { /* a locked/disconnected Windows desktop may be unavailable */ }
      // Electron's callback is one-shot, including when it throws (e.g. the
      // requesting frame was destroyed while capture sources were enumerated).
      try { callback(capture); } catch (error) { console.warn('Desktop capture:', error.message); }
    });
    ses.on('will-download', (_event, item) => {
      const name = path.basename(item.getFilename()).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_');
      let dest = path.join(app.getPath('downloads'), name);
      if (fs.existsSync(dest)) dest = path.join(app.getPath('downloads'), Date.now() + '-' + name);
      item.setSavePath(dest);
    });
    globalShortcut.register('Control+Alt+Shift+F12', disableRemote);
    powerMonitor.on('lock-screen', stopRemote);
    screen.on('display-removed', () => { if (!screen.getAllDisplays().some(d => String(d.id) === prefs.display)) disableRemote(); });
    setInterval(() => {
      if (Date.now() - hostSeen > 12000 && hostSessions.size) stopRemote();
      if (Date.now() - lastInput > 5000) input?.release();
    }, 2000).unref();
    showMain(); startAgent();
  });
}
