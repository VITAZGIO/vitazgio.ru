const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
test('desktop pages control one external player without constructing audio or opening popups', () => {
  const sent = []; let receive, opened = 0;
  const bridge = { role:'main', playerCommand:(...args) => sent.push(args), onPlayerState:fn => { receive = fn; },
    openPlayer:() => opened++, hidePlayer:() => {} };
  const window = { VGDesktop:bridge };
  const sandbox = { window, Event, EventTarget, Audio:class { constructor() { throw new Error('Unexpected local audio'); } } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../templates/vg_player.js.tpl'), 'utf8'), sandbox);
  const vgp = window.VGP;
  vgp.audio.src = '/api/music/file/example'; vgp.audio.play();
  vgp.adopt([{ id:'m_example', url:'/api/music/file/example' }], 0);
  vgp.popOut(); vgp.floatOut();
  assert.equal(opened, 2);
  assert.deepEqual(sent.map(row => row[0]), ['state','set','play','adopt']);
  let events = 0; vgp.audio.addEventListener('play', () => events++);
  receive({ state:{ playing:true, track:{ id:'m_example' } }, audio:{ src:'/api/music/file/example', currentTime:25, duration:180, paused:false, volume:0.5, muted:false } });
  assert.equal(vgp.audio.currentTime, 25); assert.equal(events, 1);
  assert.equal(vgp.state.track.id, 'm_example');
});
