(() => {
  'use strict';
  const el = id => document.getElementById(id), video = el('screen');
  let config, pc, channel, callId, polling, diagnostics, generation = 0, controlGranted = false;
  const state = text => { el('state').textContent = text; };
  async function api(path, options = {}) {
    const response = await fetch(path, { credentials:'same-origin', ...options,
      headers: { 'Content-Type':'application/json', ...options.headers } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(data.error || 'Ошибка соединения: ' + response.status); error.consoleRequired = data.console_required; throw error; }
    if (response.redirected) throw new Error('Войди в кабинет заново');
    return data;
  }
  async function initialize() {
    try {
      config = await api('/api/desktop/config');
      el('gate').hidden = true;
      const { devices } = await api('/api/desktop/devices');
      el('devices').replaceChildren();
      for (const device of devices) {
        const option = document.createElement('option'); option.value = device.id;
        option.textContent = `${device.name} · ${device.online ? device.enabled ? 'доступ включён' : 'доступ выключен' : 'нет связи'}`;
        option.disabled = !device.online || !device.enabled; el('devices').append(option);
      }
      const selected = new URLSearchParams(location.search).get('device');
      const available = [...el('devices').options].filter(o => !o.disabled);
      el('devices').value = available.find(o => o.value === selected)?.value || available[0]?.value || '';
      el('connect').disabled = !available.length;
      state(available.length ? 'Выбери компьютер и подключись.' : 'Нет компьютеров с включённым доступом. Обнови страницу после включения.');
    } catch(error) {
      el('gate').hidden = !error.consoleRequired; state(error.message);
    }
  }
  el('gate').onsubmit = async event => {
    event.preventDefault();
    try { await api('/api/console/login', { method:'POST', body:JSON.stringify({ password:el('password').value }) }); el('password').value = ''; await initialize(); }
    catch(error) { state(error.message); }
  };
  function send(value) {
    if (controlGranted && el('control').checked && channel?.readyState === 'open' && channel.bufferedAmount < 32768) channel.send(JSON.stringify(value));
  }
  function release() {
    if (channel?.readyState === 'open') channel.send(JSON.stringify({ type:'release' }));
  }
  function disconnect() {
    generation++; release();
    clearTimeout(polling); clearInterval(diagnostics);
    pc?.close(); pc = null; channel = null; video.srcObject = null; controlGranted = false;
    if (callId) api('/api/desktop/sessions/' + callId, { method:'DELETE', keepalive:true }).catch(() => {});
    callId = null;
    for (const id of ['disconnect','fullscreen','sound']) el(id).disabled = true;
    el('connect').disabled = !config || !el('devices').value;
    el('devices').disabled = false;
  }
  async function gather(connection) {
    if (connection.iceGatheringState === 'complete') return;
    await new Promise(resolve => {
      const finish = () => { clearTimeout(timer); connection.removeEventListener('icegatheringstatechange', changed); resolve(); };
      const changed = () => { if (connection.iceGatheringState === 'complete') finish(); };
      const timer = setTimeout(finish, 7000); connection.addEventListener('icegatheringstatechange', changed);
    });
  }
  el('connect').onclick = async () => {
    disconnect(); const gen = generation;
    el('connect').disabled = true; el('devices').disabled = true; el('disconnect').disabled = false;
    state('Устанавливаю прямое соединение…');
    const connection = new RTCPeerConnection(config); pc = connection;
    connection.addTransceiver('video', { direction:'recvonly' });
    connection.addTransceiver('audio', { direction:'recvonly' });
    channel = connection.createDataChannel('input', { ordered:true });
    const stream = new MediaStream(); video.srcObject = stream;
    connection.ontrack = event => { stream.addTrack(event.track); video.play().catch(() => {}); };
    connection.onconnectionstatechange = () => {
      if (gen !== generation) return;
      if (connection.connectionState === 'connected') {
        state('Подключено' + (controlGranted ? ' · управление разрешено' : ' · просмотр'));
        el('fullscreen').disabled = false; el('sound').disabled = false;
      } else if (connection.connectionState === 'failed') {
        disconnect(); state('Прямой путь не найден. Для сложных сетей нужен TURN; RDP остаётся доступен.');
      } else if (connection.connectionState === 'disconnected') state('Связь прервалась, ожидаю восстановления…');
    };
    try {
      await connection.setLocalDescription(await connection.createOffer()); await gather(connection);
      if (gen !== generation) return;
      const created = await api('/api/desktop/sessions', { method:'POST', body:JSON.stringify({
        device:el('devices').value, offer:connection.localDescription.sdp, control:el('control').checked }) });
      if (gen !== generation) { api('/api/desktop/sessions/' + created.id, { method:'DELETE' }).catch(() => {}); return; }
      callId = created.id; controlGranted = created.control;
      const started = Date.now();
      async function poll() {
        try {
          const result = await api('/api/desktop/sessions/' + created.id);
          if (gen !== generation) return;
          if (result.error) throw new Error(result.error);
          if (result.answer && !connection.remoteDescription) await connection.setRemoteDescription({ type:'answer', sdp:result.answer });
          if (connection.connectionState !== 'connected' && Date.now() - started > 45000) throw new Error('Не удалось соединиться за 45 секунд. Проверь приложение и сеть.');
          polling = setTimeout(poll, 2000);
        } catch(error) { if (gen === generation) { disconnect(); state(error.message); } }
      }
      poll();
      diagnostics = setInterval(async () => {
        if (gen !== generation) return;
        const stats = await connection.getStats().catch(() => null); if (!stats) return;
        let pair, frames = '';
        stats.forEach(s => {
          if (s.type === 'transport' && s.selectedCandidatePairId) pair = stats.get(s.selectedCandidatePairId);
          if (s.type === 'inbound-rtp' && s.kind === 'video') frames = ` · ${s.frameWidth || '?'}×${s.frameHeight || '?'} · ${s.framesPerSecond || 0} кадров/с`;
        });
        if (pair) {
          const local = stats.get(pair.localCandidateId), remote = stats.get(pair.remoteCandidateId);
          const relay = local?.candidateType === 'relay' || remote?.candidateType === 'relay';
          el('metrics').textContent = `${relay ? 'Через TURN-ретранслятор' : 'Прямое соединение'} · RTT ${Math.round((pair.currentRoundTripTime || 0) * 1000)} мс${frames}`;
        }
      }, 2000);
    } catch(error) { if (gen === generation) { disconnect(); state(error.message); } }
  };
  el('disconnect').onclick = () => { disconnect(); state('Отключено.'); };
  el('fullscreen').onclick = () => el('stage').requestFullscreen().catch(error => state(error.message));
  el('sound').onclick = () => { video.muted = !video.muted; el('sound').textContent = video.muted ? 'Включить звук' : 'Выключить звук'; };
  el('control').onchange = () => { release(); if (el('control').checked && callId && !controlGranted) state('Для управления отключись и подключись с включённым переключателем.'); };
  function point(event) {
    const rect = video.getBoundingClientRect();
    const scale = Math.min(rect.width / (video.videoWidth || 1), rect.height / (video.videoHeight || 1));
    const width = video.videoWidth * scale, height = video.videoHeight * scale;
    const x = (event.clientX - rect.left - (rect.width - width) / 2) / width;
    const y = (event.clientY - rect.top - (rect.height - height) / 2) / height;
    return { x:Math.max(0, Math.min(1, x)), y:Math.max(0, Math.min(1, y)) };
  }
  let lastMove = 0;
  video.onpointerdown = event => { event.preventDefault(); video.focus(); video.setPointerCapture(event.pointerId); send({ type:'down', button:event.button, ...point(event) }); };
  video.onpointerup = event => { event.preventDefault(); send({ type:'up', button:event.button, ...point(event) }); };
  video.onpointercancel = release;
  video.onpointermove = event => { if (Date.now() - lastMove > 16) { lastMove = Date.now(); send({ type:'move', ...point(event) }); } };
  video.oncontextmenu = event => event.preventDefault();
  video.addEventListener('wheel', event => { if (controlGranted && el('control').checked) { event.preventDefault(); send({ type:'wheel', delta:event.deltaY }); } }, { passive:false });
  for (const type of ['keydown','keyup']) video.addEventListener(type, event => {
    if (!controlGranted || !el('control').checked) return;
    event.preventDefault(); send({ type:'key', code:event.code, down:type === 'keydown' });
  });
  document.querySelectorAll('[data-key]').forEach(button => { button.onclick = () => {
    send({ type:'key', code:button.dataset.key, down:true }); send({ type:'key', code:button.dataset.key, down:false });
  }; });
  window.addEventListener('blur', release);
  document.addEventListener('visibilitychange', () => { if (document.hidden) release(); });
  window.addEventListener('pagehide', disconnect);
  initialize();
})();
