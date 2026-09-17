'use strict';
const { contextBridge, ipcRenderer } = require('electron');
const role = process.argv.find(a => a.startsWith('--vg-role='))?.slice(10) || 'main';
const listen = (channel, fn) => {
  const listener = (_event, value) => fn(value);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
};
contextBridge.exposeInMainWorld('VGDesktop', Object.freeze({
  role,
  getStatus: () => ipcRenderer.invoke('vg:status'),
  openSettings: () => ipcRenderer.invoke('vg:settings'),
  checkUpdates: () => ipcRenderer.invoke('vg:update'),
  openPlayer: () => ipcRenderer.invoke('vg:player-open'),
  hidePlayer: () => ipcRenderer.invoke('vg:player-hide'),
  readClipboard: () => ipcRenderer.invoke('vg:clipboard-read'),
  playerCommand: (command, args) => ipcRenderer.send('vg:player-command', { command, args }),
  onPlayerState: fn => listen('vg:player-state', fn),
  onUpdate: fn => listen('vg:update-state', fn),
  ...(role === 'player' ? {
    onPlayerCommand: fn => listen('vg:player-deliver', fn),
    playerReady: () => ipcRenderer.send('vg:player-ready'),
    publishPlayerState: value => ipcRenderer.send('vg:player-publish', value),
  } : {}),
  ...(role === 'settings' ? {
    getSettings: () => ipcRenderer.invoke('vg:settings-read'),
    saveSettings: value => ipcRenderer.invoke('vg:settings-save', value),
  } : {}),
  ...(role === 'agent' ? {
    pollHost: () => ipcRenderer.invoke('vg:host-poll'),
    answer: (id, value) => ipcRenderer.invoke('vg:host-answer', id, value),
    input: (id, event) => ipcRenderer.send('vg:input', id, event),
    releaseInput: () => ipcRenderer.send('vg:release-input'),
    onStop: fn => listen('vg:stop', fn),
  } : {}),
}));
