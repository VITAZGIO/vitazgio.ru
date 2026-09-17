'use strict';
const bridge = window.VGDesktop;
const byId = id => document.getElementById(id);
bridge.getSettings().then(value => {
  byId('identity').textContent = `${value.name} · версия ${value.version}${value.paired ? '' : ' · войди в кабинет для привязки'}`;
  for (const key of ['startup','enabled','control']) byId(key).checked = value[key];
  for (const display of value.displays) {
    const option = document.createElement('option');
    option.value = display.id; option.textContent = display.label;
    byId('display').append(option);
  }
  byId('display').value = value.display;
}).catch(e => { byId('status').textContent = e.message; });
byId('save').onclick = async () => {
  try {
    await bridge.saveSettings({ startup: byId('startup').checked, enabled: byId('enabled').checked,
      control: byId('control').checked, display: byId('display').value });
    byId('status').textContent = 'Сохранено. Закрытие окна сайта оставляет приложение в трее.';
  } catch(e) { byId('status').textContent = e.message; }
};
byId('update').onclick = async () => {
  byId('update').disabled = true;
  try { byId('status').textContent = (await bridge.checkUpdates()).message; }
  catch(e) { byId('status').textContent = e.message; }
  finally { byId('update').disabled = false; }
};
bridge.onUpdate(value => { byId('status').textContent = value.message; });
