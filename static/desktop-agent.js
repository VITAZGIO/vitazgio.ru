/* Runs in the desktop application's persistent agent window, independently of
   site navigation. This file ships from the website, not inside the EXE. */
(() => {
  'use strict';
  const bridge = window.VGDesktop;
  if (!bridge || bridge.role !== 'agent') return;
  const sessions = new Map();
  const failed = new Set();
  let generation = 0, lastSuccess = 0;
  const stop = id => {
    const call = sessions.get(id);
    if (!call) return;
    call.pc.close(); call.stream?.getTracks().forEach(t => t.stop());
    sessions.delete(id); bridge.releaseInput();
  };
  const stopAll = () => { generation++; for (const id of [...sessions.keys()]) stop(id); };
  bridge.onStop(stopAll);
  async function gathered(pc) {
    if (pc.iceGatheringState === 'complete') return;
    await new Promise(resolve => {
      const finish = () => { clearTimeout(timer); pc.removeEventListener('icegatheringstatechange', changed); resolve(); };
      const changed = () => { if (pc.iceGatheringState === 'complete') finish(); };
      const timer = setTimeout(finish, 7000);
      pc.addEventListener('icegatheringstatechange', changed);
    });
  }
  async function connect(request, iceServers) {
    const gen = generation;
    const pc = new RTCPeerConnection({ iceServers });
    const call = { pc, stream: null, control: request.control };
    sessions.set(request.id, call);
    try {
      call.stream = await navigator.mediaDevices.getDisplayMedia({
        video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30, max: 60 } }, audio: true,
      });
      if (gen !== generation || !sessions.has(request.id)) { call.stream.getTracks().forEach(t => t.stop()); pc.close(); return; }
      call.stream.getVideoTracks()[0].contentHint = 'detail';
      call.stream.getVideoTracks()[0].onended = () => stop(request.id);
      pc.ondatachannel = event => {
        if (event.channel.label !== 'input') { event.channel.close(); return; }
        const channel = event.channel;
        channel.onmessage = message => {
          if (!call.control || typeof message.data !== 'string' || message.data.length > 2048) return;
          try { bridge.input(request.id, JSON.parse(message.data)); } catch {}
        };
        channel.onclose = () => bridge.releaseInput();
      };
      pc.onconnectionstatechange = () => {
        if (['failed','closed'].includes(pc.connectionState)) stop(request.id);
        if (pc.connectionState === 'disconnected') bridge.releaseInput();
      };
      await pc.setRemoteDescription({ type: 'offer', sdp: request.offer });
      for (const track of call.stream.getTracks()) {
        const sender = pc.addTrack(track, call.stream);
        if (track.kind === 'video') {
          const params = sender.getParameters();
          params.encodings = [{ maxBitrate: 6000000, maxFramerate: 30 }];
          await sender.setParameters(params).catch(() => {});
        }
      }
      await pc.setLocalDescription(await pc.createAnswer());
      await gathered(pc);
      if (gen !== generation || !sessions.has(request.id)) return;
      await bridge.answer(request.id, { answer: pc.localDescription.sdp });
    } catch (error) {
      stop(request.id);
      failed.add(request.id);
      await bridge.answer(request.id, { error: 'Захват экрана не начался. Проверь, что Windows разблокирована и выбранный монитор доступен. ' + error.message }).catch(() => {});
    }
  }
  async function poll() {
    try {
      const result = await bridge.pollHost();
      lastSuccess = Date.now();
      const active = new Set(result.sessions.map(s => s.id));
      for (const id of failed) if (!active.has(id)) failed.delete(id);
      for (const id of [...sessions.keys()]) if (!active.has(id)) stop(id);
      for (const request of result.sessions) {
        if (!sessions.has(request.id) && !failed.has(request.id)) connect(request, result.iceServers).catch(() => {});
        else if (sessions.has(request.id)) sessions.get(request.id).control = request.control;
      }
    } catch {
      if (Date.now() - lastSuccess > 10000) stopAll();
    } finally { setTimeout(poll, 2000); }
  }
  poll();
})();
