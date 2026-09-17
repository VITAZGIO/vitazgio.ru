'use strict';
// Only mouse/keyboard events, never shell commands. The main process owns consent.
module.exports = function createInput() {
  const koffi = require('koffi');
  const lib = koffi.load('user32.dll');
  const setCursor = lib.func('int __stdcall SetCursorPos(int x, int y)');
  const mouse = lib.func('void __stdcall mouse_event(uint32_t flags, uint32_t dx, uint32_t dy, uint32_t data, uintptr_t extra)');
  const key = lib.func('void __stdcall keybd_event(uint8_t vk, uint8_t scan, uint32_t flags, uintptr_t extra)');
  const heldKeys = new Set(), heldButtons = new Set();
  const buttons = { 0: [2, 4], 1: [32, 64], 2: [8, 16] };
  const keys = { Backspace:8, Tab:9, Enter:13, ShiftLeft:16, ShiftRight:16, ControlLeft:17, ControlRight:17,
    AltLeft:18, AltRight:18, Escape:27, Space:32, PageUp:33, PageDown:34, End:35, Home:36,
    ArrowLeft:37, ArrowUp:38, ArrowRight:39, ArrowDown:40, Insert:45, Delete:46,
    MetaLeft:91, MetaRight:92, Semicolon:186, Equal:187, Comma:188, Minus:189, Period:190,
    Slash:191, Backquote:192, BracketLeft:219, Backslash:220, BracketRight:221, Quote:222 };
  for (let i = 0; i < 26; i++) keys['Key' + String.fromCharCode(65 + i)] = 65 + i;
  for (let i = 0; i < 10; i++) keys['Digit' + i] = 48 + i;
  for (let i = 1; i <= 12; i++) keys['F' + i] = 111 + i;
  const extended = vk => [33,34,35,36,37,38,39,40,45,46,91,92].includes(vk) ? 1 : 0;
  function release() {
    for (const vk of heldKeys) key(vk, 0, 2 | extended(vk), 0);
    for (const b of heldButtons) mouse(buttons[b][1], 0, 0, 0, 0);
    heldKeys.clear(); heldButtons.clear();
  }
  function send(event, bounds) {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'release') return release();
    if (['move','down','up'].includes(event.type)) {
      if (!Number.isFinite(event.x) || !Number.isFinite(event.y) || event.x < 0 || event.x > 1 || event.y < 0 || event.y > 1) return;
      setCursor(bounds.x + Math.round(event.x * (bounds.width - 1)), bounds.y + Math.round(event.y * (bounds.height - 1)));
      if (event.type !== 'move' && Number.isInteger(event.button) && Object.hasOwn(buttons, event.button)) {
        const down = event.type === 'down';
        mouse(buttons[event.button][down ? 0 : 1], 0, 0, 0, 0);
        if (down) heldButtons.add(event.button); else heldButtons.delete(event.button);
      }
    } else if (event.type === 'wheel' && Number.isFinite(event.delta)) {
      mouse(0x800, 0, 0, (Math.max(-1200, Math.min(1200, Math.round(-event.delta))) >>> 0), 0);
    } else if (event.type === 'key' && Object.hasOwn(keys, event.code) && typeof event.down === 'boolean') {
      const vk = keys[event.code];
      key(vk, 0, (event.down ? 0 : 2) | extended(vk), 0);
      if (event.down) heldKeys.add(vk); else heldKeys.delete(vk);
    }
  }
  return { send, release };
};
