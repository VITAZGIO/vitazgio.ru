// Run with Electron, not node. Every HTTP request is intercepted. Uses a fresh
// temporary profile and does not set autostart or send input to the real PC.
const { app, session, BrowserWindow, net } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-smoke-'));
app.setPath('userData', profile);
fs.mkdirSync(path.join(profile, 'downloads'));
app.setPath('downloads', path.join(profile, 'downloads'));
process.argv.push('--hidden');
let sample;
let remoteCall = null, hostEnabled = false;
const inputEvents = [];
const liveCapture = process.env.VG_SMOKE_CAPTURE === '1';
let publishUpdate = false, corruptUpdate = false;
const updateBytes = Buffer.from('Harmless smoke-test installer placeholder; never executed.');
const updateName = 'vitazgio-windows-999.0.0-x64.exe';
const updateURL = 'https://github.com/VITAZGIO/vitazgio.ru/releases/download/windows-v999.0.0/' + updateName;
function silentWave() {
  if (sample) return sample;
  sample = Buffer.alloc(44 + 44100 * 2 * 30);
  sample.write('RIFF', 0); sample.writeUInt32LE(sample.length - 8, 4); sample.write('WAVEfmt ', 8);
  sample.writeUInt32LE(16, 16); sample.writeUInt16LE(1, 20); sample.writeUInt16LE(1, 22);
  sample.writeUInt32LE(44100, 24); sample.writeUInt32LE(88200, 28); sample.writeUInt16LE(2, 32);
  sample.writeUInt16LE(16, 34); sample.write('data', 36); sample.writeUInt32LE(sample.length - 44, 40);
  return sample;
}
const track = { id:'m_test', title:'Тест непрерывного воспроизведения', artist:'Vitaz Gio', folder:'', url:'/api/music/file/test' };
const json = data => new Response(JSON.stringify(data), { headers:{ 'content-type':'application/json' } });
async function serve(request) {
  const url = new URL(request.url), route = url.pathname;
  if (url.host === 'api.github.com') return json(publishUpdate ? [
    { tag_name:'android-v999', assets:[] },
    { tag_name:'windows-v999.0.0', assets:[{ name:updateName, browser_download_url:updateURL,
      size:updateBytes.length, digest:'sha256:' + (corruptUpdate ? '0'.repeat(64) : crypto.createHash('sha256').update(updateBytes).digest('hex')) }] },
  ] : []);
  if (request.url === updateURL) return new Response(updateBytes);
  if (url.host !== 'vitazgio.ru') return new Response('', { status:404 });
  if (route === '/api/desktop/devices') return json({ devices:[{ id:'smoke-pc', name:'Test PC', online:true, enabled:hostEnabled }] });
  if (route === '/api/desktop/register') return json({ id:'smoke-pc', token:'smoke-token' });
  if (route === '/api/desktop/host') {
    const data = await request.json(); hostEnabled = data.enabled;
    if (!data.enabled) remoteCall = null;
    return json({ sessions:remoteCall ? [{ id:'smoke-call', offer:remoteCall.offer, control:remoteCall.control }] : [], iceServers:[] });
  }
  if (route === '/api/desktop/config') return json({ iceServers:[] });
  if (route === '/api/desktop/sessions' && request.method === 'POST') {
    remoteCall = await request.json(); return json({ id:'smoke-call', control:remoteCall.control });
  }
  if (route === '/api/desktop/sessions/smoke-call') {
    if (request.method === 'POST') { Object.assign(remoteCall, await request.json()); return json({ ok:true }); }
    if (request.method === 'DELETE') { remoteCall = null; return json({ ok:true }); }
    return remoteCall ? json(remoteCall) : new Response('{}', { status:404 });
  }
  if (route === '/api/desktop/version') return json({ version:null, url:null });
  if (route === '/api/player/tracks') return json({ tracks:[track], folders:[] });
  if (route === '/api/music') return json({ tracks:[{ ...track, id:'test' }], folders:[], used:0, quota:10000 });
  if (route === '/api/music/file/test') {
    const wav = silentWave(), range = request.headers.get('range');
    if (range) {
      const start = Number(/bytes=(\d+)/.exec(range)?.[1] || 0);
      return new Response(wav.subarray(start), { status:206, headers:{ 'content-type':'audio/wav', 'content-range':`bytes ${start}-${wav.length - 1}/${wav.length}`, 'accept-ranges':'bytes' } });
    }
    return new Response(wav, { headers:{ 'content-type':'audio/wav', 'accept-ranges':'bytes' } });
  }
  if (route === '/vg-player.js') return new Response(fs.readFileSync(path.join(root, 'templates/vg_player.js.tpl')), { headers:{'content-type':'application/javascript'} });
  if (route === '/player/pop') return new Response('<!doctype html><html><head></head><body style="margin:0;background:#0d1321"><script>window.VGP_POPUP=true;</script><script src="/vg-player.js"></script></body></html>', { headers:{'content-type':'text/html'} });
  if (['/cabinet','/apps','/music','/desktop'].includes(route)) return new Response(fs.readFileSync(path.join(root, 'templates', route.slice(1) + '.html'), 'utf8').replace('__ICONLINKS__',''), { headers:{'content-type':'text/html'} });
  if (route.startsWith('/static/') && !route.includes('..')) {
    const file = path.join(root, route.slice(1));
    if (fs.existsSync(file) && fs.statSync(file).isFile()) return new Response(fs.readFileSync(file), { headers:{ 'content-type':route.endsWith('.js') ? 'application/javascript' : 'image/png' } });
  }
  return json({ tokens:[], events:[], tracks:[], devices:[], items:[] });
}
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) { const value = await fn(); if (value) return value; await delay(100); }
  throw new Error('Timed out waiting for smoke check');
}
app.whenReady().then(async () => {
  for (const ses of [session.defaultSession, session.fromPartition('persist:vitazgio'), session.fromPartition('browser-test')]) await ses.protocol.handle('https', serve);
  require('../main.cjs');
  try {
    const main = await until(() => BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith('/cabinet')));
    const errors = [];
    main.webContents.on('console-message', event => { if (event.level === 'error') errors.push(event.message); });
    await until(() => main.webContents.executeJavaScript('!!window.VGP?.desktop').catch(() => false));
    const player = await until(() => BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith('/player/pop')));
    await until(() => player.webContents.executeJavaScript('!!window.VGP').catch(() => false));
    await main.webContents.executeJavaScript(`VGP.adopt([${JSON.stringify(track)}],0); VGP.playAt(0); VGP.popOut();`);
    await until(() => player.webContents.executeJavaScript('!VGP.audio.paused && VGP.audio.currentTime > 0.3'));
    const before = await player.webContents.executeJavaScript('VGP.audio.currentTime');
    const playerId = player.id;
    await main.loadURL('https://vitazgio.ru/apps');
    await delay(500);
    assert.ok(await player.webContents.executeJavaScript('VGP.audio.currentTime') > before);
    await main.loadURL('https://vitazgio.ru/music');
    await until(() => main.webContents.executeJavaScript('VGP.audio.currentTime > 0.3').catch(() => false));
    await main.webContents.executeJavaScript('VGP.popOut(); VGP.floatOut();');
    assert.equal(BrowserWindow.getAllWindows().filter(w => w.webContents.getURL().endsWith('/player/pop')).length, 1);
    assert.equal(player.id, playerId); assert.equal(player.isAlwaysOnTop(), true);
    assert.equal(await main.webContents.executeJavaScript('VGP.audio.paused'), false);
    await main.webContents.executeJavaScript('VGDesktop.openSettings()');
    const settings = await until(() => BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith('/settings.html')));
    await until(() => settings.webContents.executeJavaScript('document.getElementById("identity").textContent.includes("версия")').catch(() => false));
    const status = await settings.webContents.executeJavaScript('VGDesktop.getSettings()');
    assert.equal(status.enabled, false); assert.equal(status.name, os.hostname());
    // Prevent Explorer opening a real window; assert the download, not the UI.
    require('electron').shell.showItemInFolder = () => {};
    publishUpdate = true;
    await settings.webContents.executeJavaScript('VGDesktop.checkUpdates()');
    assert.deepEqual(fs.readFileSync(path.join(profile, 'downloads', updateName)), updateBytes);
    corruptUpdate = true;
    const rejected = await settings.webContents.executeJavaScript('VGDesktop.checkUpdates().then(()=>false,()=>true)');
    assert.equal(rejected, true);
    assert.deepEqual(fs.readdirSync(path.join(profile, 'downloads')), [updateName]);
    publishUpdate = false;
    // Loading the native API binds its functions; it does not move or press anything.
    require('../input.cjs')();
    require.cache[require.resolve('../input.cjs')].exports = () => ({ send:event => inputEvents.push(event), release:() => {} });
    fs.mkdirSync(path.join(root, 'desktop/dist'), { recursive:true });
    fs.writeFileSync(path.join(root, 'desktop/dist/player-smoke.png'), (await player.webContents.capturePage()).toPNG());
    fs.writeFileSync(path.join(root, 'desktop/dist/settings-smoke.png'), (await settings.webContents.capturePage()).toPNG());
    const fatal = errors.filter(x => /Uncaught|ReferenceError|TypeError/.test(x));
    assert.deepEqual(fatal, []);
    const agentWindow = await until(() => BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith('/agent.html')));
    if (!liveCapture) {
      // Deterministic media for CI/locked Windows sessions. Production code and
      // the native capture handler are untouched. VG_SMOKE_CAPTURE=1 uses the real screen.
      await agentWindow.webContents.executeJavaScript(`navigator.mediaDevices.getDisplayMedia = async () => {
        const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 360;
        const context = canvas.getContext('2d'); let i=0;
        const timer = setInterval(() => { context.fillStyle = i++ % 2 ? '#152844' : '#123456'; context.fillRect(0,0,640,360); }, 100);
        const stream = canvas.captureStream(10); stream.getVideoTracks()[0].addEventListener('ended', () => clearInterval(timer)); return stream;
      }; undefined;`);
    }
    await settings.webContents.executeJavaScript(`VGDesktop.saveSettings({startup:false,enabled:true,control:true,display:${JSON.stringify(status.display)}})`);
    await until(() => hostEnabled);
    await main.loadURL('https://vitazgio.ru/desktop');
    await until(() => main.webContents.executeJavaScript('!document.getElementById("connect").disabled').catch(() => false));
    await main.webContents.executeJavaScript('document.getElementById("control").checked=true; document.getElementById("connect").click()');
    try {
      await until(() => main.webContents.executeJavaScript('document.getElementById("screen").videoWidth > 0').catch(() => false), 25000);
    } catch (error) {
      console.error('VIEWER', await main.webContents.executeJavaScript('document.getElementById("state").textContent'), 'SIGNAL', remoteCall?.error);
      throw error;
    }
    const metrics = await main.webContents.executeJavaScript('({width:document.getElementById("screen").videoWidth, height:document.getElementById("screen").videoHeight, state:document.getElementById("state").textContent})');
    await main.webContents.executeJavaScript(`document.getElementById('screen').dispatchEvent(new KeyboardEvent('keydown',{code:'KeyA',key:'a'})); document.getElementById('screen').dispatchEvent(new KeyboardEvent('keyup',{code:'KeyA',key:'a'}));`);
    await until(() => inputEvents.some(event => event.type === 'key' && event.code === 'KeyA' && event.down === false));
    await main.webContents.executeJavaScript('document.getElementById("disconnect").click()');
    await until(() => !remoteCall);
    await settings.webContents.executeJavaScript(`VGDesktop.saveSettings({startup:false,enabled:false,control:false,display:${JSON.stringify(status.display)}})`);
    const browser = new BrowserWindow({ show:false, webPreferences:{ partition:'browser-test', nodeIntegration:false, contextIsolation:true, autoplayPolicy:'no-user-gesture-required' } });
    await browser.loadURL('https://vitazgio.ru/music');
    assert.equal(await browser.webContents.executeJavaScript('!window.VGDesktop && !VGP.desktop && VGP.audio instanceof HTMLAudioElement'), true);
    await browser.webContents.executeJavaScript(`VGP.adopt([${JSON.stringify(track)}],0); VGP.playAt(0);`);
    await until(() => browser.webContents.executeJavaScript('VGP.audio.currentTime > 0.2 && !VGP.audio.paused'));
    browser.destroy();
    console.log('SMOKE PASS: playback survives navigation; one always-on-top player; ordinary browser still plays without native bridge; native settings; input bindings load; remote access defaults off; update saved to Downloads and corrupt update rejected; input delivered to mocked driver; direct WebRTC', liveCapture ? 'screen' : 'test video', JSON.stringify(metrics));
    app.quit();
  } catch(error) { console.error('SMOKE FAIL', error); app.exit(1); }
});
