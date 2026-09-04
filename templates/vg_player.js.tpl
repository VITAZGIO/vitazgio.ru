
(() => {
  "use strict";
  if (window.VGP) return;                       // второй раз не заводимся

  const KEY = "vgPlayerState";
  const POS = "vgPlayerBox";
  const headless = !!window.VGP_HEADLESS;       // движок без своего оверлея
  const popup = !!window.VGP_POPUP;             // это /player/pop — отдельное окно
  const lift = +(window.VGP_OFFSET || 0);       // поднять над нижней панелью

  /* ── состояние ─────────────────────────────────────────────────── */
  const audio = new Audio();
  audio.preload = "metadata";
  let queue = [];          // [{id,title,artist,folder,url}]
  let idx = -1;
  let ready = false;       // список загружен
  let shuffle = false;
  let allFolders = [];     // всё дерево папок фонотеки [{id,name,parent}]
  let favFolder = "";      // id избранной папки (звезда), "" если нет
  let curPick;             // selected folder for the current queue; undefined keeps the old default
  const subs = [];

  /* «Музыка ДОЛЖНА звучать» — намерение, а не текущее состояние звука.
     Разница важная: страницу только открыли, трек ещё грузится, автоподхват
     ещё не дозвонился до других вкладок — audio.paused в этот миг true, хотя
     музыка играет и должна играть дальше. Раньше save() писал в память
     ровно `!audio.paused`, поэтому быстрый переход по сайту (ушли со
     страницы, пока звук не успел стартовать) сохранял playing:false —
     и на следующей странице музыка уже не поднималась. Это и было
     «зависает при перелистывании». Теперь в память едет намерение. */
  let wantPlay = false;
  /* Служебная пауза: звук передаём вынесенному окну или уступаем другой
     вкладке. Намерение при этом не сбрасываем и в память не пишем. */
  let quiet = false;

  const save = () => {
    try {
      const t = queue[idx] || null;
      localStorage.setItem(KEY, JSON.stringify({
        id: t ? t.id : null,
        // адрес и подписи храним прямо тут: на новой странице трек ставится
        // сразу, не дожидаясь ответа со списком — из-за него и были заминки
        url: t ? t.url : "",
        title: t ? t.title : "",
        artist: t ? t.artist : "",
        folder: t ? t.folder : "",
        time: audio.currentTime || 0,
        playing: wantPlay,
        vol: audio.volume,
        shuffle: shuffle,
        queue: queue,
        idx: idx,
        pick: curPick,
      }));
    } catch (e) { /* приватное окно — переживём */ }
  };
  const stored = () => {
    try { return JSON.parse(localStorage.getItem(KEY) || "null"); }
    catch (e) { return null; }
  };

  /* Одна вкладка играет — остальные умолкают, как в нормальных плеерах. */
  let bus = null;
  try { bus = new BroadcastChannel("vgplayer"); } catch (e) { /* старый браузер */ }
  const shout = (what) => { if (bus) try { bus.postMessage(what); } catch (e) {} };
  if (bus) bus.onmessage = (e) => {
    if (e.data === "play" && !audio.paused) {
      // Играть будет она, а наше намерение остаётся: вернёмся — подхватим.
      quiet = true;
      audio.pause();
      setTimeout(() => { quiet = false; }, 120);
    }
    if (e.data === "sync") fire();
    if (e.data === "ping" && !audio.paused) shout("pong");
  };
  /* Спросить остальные вкладки: кто-то уже реально играет? Нужно перед
     автоподхватом на новой странице — иначе она бы просто перехватывала
     звук у уже открытой вкладки и та обрывалась («стопается» при открытии
     сайта во второй вкладке). Ждём отклика недолго и только если правда
     кто-то есть. */
  const askIfPlaying = () => {
    if (!bus) return Promise.resolve(false);
    return new Promise((resolve) => {
      let got = false;
      const onMsg = (e) => { if (e.data === "pong") got = true; };
      bus.addEventListener("message", onMsg);
      shout("ping");
      setTimeout(() => { bus.removeEventListener("message", onMsg); resolve(got); }, 220);
    });
  };

  const fire = () => { subs.forEach((f) => { try { f(state()); } catch (e) {} }); paint(); };
  const state = () => ({
    track: queue[idx] || null, idx, queue, playing: !audio.paused,
    time: audio.currentTime, duration: audio.duration, shuffle,
  });

  /* ── ядро ──────────────────────────────────────────────────────── */
  /* Человек уже сам трогал play/pause на этой странице? Тогда отложенный
     автоподхват (resume) со своим звуком не лезет — см. goIfAllowed. */
  let userActed = false;
  const load = (i, autoplay) => {
    if (i < 0 || i >= queue.length) return;
    userActed = true;
    idx = i;
    audio.src = queue[i].url;
    audio.load();
    if (autoplay) { wantPlay = true; shout("play"); audio.play().catch(() => fire()); }
    media();
    fire();
    save();
  };
  const shuffleQueue = () => {
    if (queue.length < 2) return;
    const cur = queue[idx] || null;
    for (let i = queue.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [queue[i], queue[j]] = [queue[j], queue[i]];
    }
    if (cur) idx = Math.max(0, queue.findIndex((t) => t.id === cur.id));
  };

  const api = {
    audio,
    get state() { return state(); },
    subscribe(fn) { subs.push(fn); try { fn(state()); } catch (e) {} },
    /* Кто-то другой (страница музыки) назначил очередь — принимаем её. */
    adopt(list, at, opts) {
      queue = list.slice();
      idx = Math.max(0, at | 0);
      if (opts && Object.prototype.hasOwnProperty.call(opts, "pick")) curPick = opts.pick;
      if (opts && Object.prototype.hasOwnProperty.call(opts, "shuffle")) shuffle = !!opts.shuffle;
      ready = true;
      media(); fire(); save();
    },
    playAt(i) { load(i, true); },
    playId(id) {
      const at = queue.findIndex((t) => t.id === id);
      if (at >= 0) load(at, true);
    },
    toggle() {
      userActed = true;
      if (idx < 0 && queue.length) { load(0, true); return; }
      if (audio.paused) { wantPlay = true; shout("play"); audio.play().catch(() => {}); }
      else { wantPlay = false; audio.pause(); }
    },
    next() { if (queue.length) load(idx + 1 >= queue.length ? 0 : idx + 1, true); },
    prev() {
      if (audio.currentTime > 3) { audio.currentTime = 0; return; }
      if (queue.length) load(idx - 1 < 0 ? queue.length - 1 : idx - 1, true);
    },
    seek(t) { if (isFinite(audio.duration)) audio.currentTime = t; },
    volume(v) { audio.volume = Math.min(1, Math.max(0, v)); save(); fire(); },
    shuffle(on) {
      shuffle = on === undefined ? !shuffle : !!on;
      if (shuffle) shuffleQueue();
      save(); fire();
      return shuffle;
    },
    /* Виджет сам не вылезает: его включают кнопкой в кабинете или на музыке,
       и с тех пор он ездит по всем страницам, пока его не выбросят в корзину. */
    open() {
      try { localStorage.setItem("vgPlayerOn", "1"); } catch (e) { /* и ладно */ }
      if (!box) build();
      setFolded(false);
      fetchList(true);
    },
    /* Вынести звук в отдельное окно браузера (/player/pop) — то же, что
       кнопка ⧉ в самом виджете. Зовут кнопки в кабинете и на музыке:
       раньше они звали open() и показывали виджет ПОВЕРХ страницы, из-за
       чего «вынести из браузера» не получалось — окна не было. */
    popOut() { openInWindow(); },
    /* Сразу ФИНАЛЬНАЯ плавашка, без промежуточного окна /player/pop.
       Chrome/Edge — живой виджет поверх всех окон (Document PiP), Firefox —
       видео-PiP как у ютуба. Где нет ни того ни другого — тогда уже окно
       /player/pop как запасной путь. Звук и очередь берём из движка этой
       же страницы, поэтому лишнего окна не нужно. */
    floatOut() {
      if ("documentPictureInPicture" in window) { onTop(); return; }
      if ("pictureInPictureEnabled" in document && document.pictureInPictureEnabled) {
        fetchList();
        // Если видео-PiP не пустили (заблокирован, нет жеста) — не оставляем
        // человека ни с чем: открываем обычное отдельное окно.
        Promise.resolve(videoPip()).then((ok) => { if (!ok) openInWindow(); });
        return;
      }
      openInWindow();
    },
    hide() {
      try { localStorage.setItem("vgPlayerOn", "0"); } catch (e) { /* и ладно */ }
      if (popWin && !popWin.closed) { try { popWin.close(); } catch (e) {} }
      popWin = null;
      if (box) { box.remove(); box = null; }
    },
    reload: () => fetchList(true),
  };
  window.VGP = api;

  /* Системные кнопки (наушники, медиаклавиши, шторка) */
  const media = () => {
    if (!("mediaSession" in navigator)) return;
    const t = queue[idx];
    if (!t) return;
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: t.title || "", artist: t.artist || "vitazgio.ru",
        album: t.folder || "фонотека",
      });
      navigator.mediaSession.setActionHandler("play", () => api.toggle());
      navigator.mediaSession.setActionHandler("pause", () => api.toggle());
      navigator.mediaSession.setActionHandler("nexttrack", () => api.next());
      navigator.mediaSession.setActionHandler("previoustrack", () => api.prev());
    } catch (e) { /* не поддержали — не беда */ }
  };

  audio.addEventListener("ended", () => api.next());
  audio.addEventListener("play", () => { wantPlay = true; shout("play"); fire(); save(); });
  audio.addEventListener("pause", () => {
    fire();
    // Настоящая пауза (человек нажал, звук кончился) — намерение снимаем.
    // Служебная (отдали звук окну или другой вкладке) — оставляем как есть.
    if (!quiet) { wantPlay = false; save(); }
  });
  audio.addEventListener("timeupdate", () => { paint(); });
  audio.addEventListener("loadedmetadata", () => fire());
  setInterval(() => { if (!audio.paused) save(); }, 3000);
  addEventListener("pagehide", save);

  /* ── список треков ─────────────────────────────────────────────── */
  const fetchList = async (force, pick) => {
    // pick: id папки фонотеки, "__all__" — вся музыка, undefined — по
    // умолчанию (избранная папка или вся музыка). При выборе папки всегда
    // грузим заново, даже если список уже был.
    if (ready && !force && pick === undefined) return queue;
    let d;
    try {
      const url = "/api/player/tracks" + (pick !== undefined ? "?folder=" + encodeURIComponent(pick) : "");
      const r = await fetch(url, { credentials: "same-origin" });
      if (!r.ok) { if (box) box.remove(); box = null; return []; }
      d = await r.json();
    } catch (e) { return []; }
    queue = (d.tracks || []).map((t) => ({
      id: t.id, title: t.title, artist: t.artist, folder: t.folder || "", url: t.url }));
    allFolders = d.folders || [];
    favFolder = d.fav || "";
    curPick = pick;
    ready = true;
    fire();
    return queue;
  };

  /* Подхват с прошлой страницы: тот же трек, та же секунда. */
  const resume = async () => {
    const s = stored();
    if (s && typeof s.vol === "number") audio.volume = s.vol;
    if (s && s.shuffle) shuffle = true;
    if (s && Object.prototype.hasOwnProperty.call(s, "pick")) curPick = s.pick;
    if (!s || !s.id) return;

    // Если состояние говорит «играет» — прежде чем правда включать звук,
    // проверим: вдруг это эхо другой, уже открытой и играющей вкладки (или
    // вынесенного окна). Опрос НЕ ждём здесь: раньше стояло `await`, и из-за
    // него каждый переход по сайту замирал на ~четверть секунды, пока трек
    // вообще не начинал ставиться — это и ощущалось как «зависает при
    // перелистывании». Теперь трек и позиция встают сразу, а решение
    // «включать ли звук» доезжает следом, само по себе.
    // Намерение восстанавливаем немедленно, не дожидаясь ни загрузки трека,
    // ни ответа опроса: иначе уход со страницы в эти миллисекунды сохранил бы
    // «не играет» и оборвал музыку на следующей странице.
    if (s.playing) wantPlay = true;
    const mayPlay = s.playing
      ? askIfPlaying().then((busy) => !busy)
      : Promise.resolve(false);

    // Автоподхват отменяется, если человек за эти миллисекунды сам нажал
    // play/pause: его выбор важнее припозднившегося ответа опроса.
    const goIfAllowed = () => mayPlay.then((go) => {
      if (go && !userActed && audio.paused) {
        audio.play().catch(() => { if (box) box.classList.add("vgp-wake"); });
      }
    });

    // Сначала — звук: ставим трек из сохранённого адреса, без похода на сервер.
    const savedQueue = Array.isArray(s.queue)
      ? s.queue.filter((t) => t && t.id && t.url)
      : [];
    if (savedQueue.length) {
      queue = savedQueue.slice();
      const bySavedId = queue.findIndex((t) => t.id === s.id);
      const bySavedIdx = Number.isInteger(s.idx) && s.idx >= 0 && s.idx < queue.length ? s.idx : -1;
      idx = bySavedId >= 0 ? bySavedId : (bySavedIdx >= 0 ? bySavedIdx : 0);
      ready = true;
      audio.src = queue[idx].url;
      audio.addEventListener("loadedmetadata", function once() {
        audio.removeEventListener("loadedmetadata", once);
        if (s.time) audio.currentTime = s.time;
        goIfAllowed();
      }, { once: true });
      media(); fire();
    } else if (s.url) {
      queue = [{ id: s.id, title: s.title || "", artist: s.artist || "",
                 folder: s.folder || "", url: s.url }];
      idx = 0;
      audio.src = s.url;
      audio.addEventListener("loadedmetadata", function once() {
        audio.removeEventListener("loadedmetadata", once);
        if (s.time) audio.currentTime = s.time;
        goIfAllowed();
      }, { once: true });
      media(); fire();
    }

    // А полный список подтянем следом — он нужен только для «дальше» и списка.
    const list = savedQueue.length
      ? queue
      : await fetchList(false, Object.prototype.hasOwnProperty.call(s, "pick") ? s.pick : undefined);
    const at = list.findIndex((t) => t.id === s.id);
    if (at >= 0) {
      idx = at;
      if (!s.url) {
        audio.src = list[at].url;
        audio.addEventListener("loadedmetadata", function once() {
          audio.removeEventListener("loadedmetadata", once);
          if (s.time) audio.currentTime = s.time;
          goIfAllowed();
        }, { once: true });
      }
      media(); fire();
    }
  };

  /* ── виджет ────────────────────────────────────────────────────── */
  let box = null, folded = true, bin = null, popWin = null;
  const paintFns = [];

  /* «Вынести»: настоящее отдельное окно браузера (window.open), а не
     Document Picture-in-Picture — то плавает красиво, но живёт вместе со
     вкладкой-открывашкой: сайт многостраничный, и любой переход на другую
     его страницу заново грузит вкладку, а с ней гаснет и такое окно, и
     звук. Тут же — эстафета: останавливаем звук в этой вкладке (это же
     запоминает точную секунду через save()) и открываем /player/pop —
     тот же движок, отдельным окном, подхватывает ровно с этого места и
     дальше живёт сам по себе, что бы в браузере ни делали. */
  /* «Поверх всех окон, без рамок» — это умеет только Document
     Picture-in-Picture, и только Chrome/Edge: рамку окна и адресную строку
     веб-страница убрать не может, а Firefox такого API не даёт вовсе.
     Важно, КТО открывает это окно: если сама страница сайта — оно умрёт при
     первом же переходе по сайту (на этом мы уже обожглись). Поэтому зовём
     его из окна /player/pop: то никуда не переходит, значит и плавающее
     окошко переживёт любую навигацию в основных вкладках. */
  const onTop = async () => {
    if (!("documentPictureInPicture" in window)) return;
    if (!box) build();                 // зовут прямо с сайта — виджета ещё нет
    let w;
    try {
      w = await documentPictureInPicture.requestWindow({ width: 360, height: 232 });
    } catch (e) { return; }
    const st = w.document.createElement("style");
    st.textContent = CSS;
    w.document.head.appendChild(st);
    w.document.body.style.margin = "0";
    w.document.body.style.background = "#0b0f18";
    // vgp-pip даёт полноразмерную раскладку (как в окне /player/pop),
    // vgp-top прячет кнопку «поверх окон» — мы уже поверх. В окне /player/pop
    // vgp-pip уже стоит и должен остаться после закрытия плавашки, поэтому
    // снимаем при возврате только то, чего раньше не было.
    const hadPip = box.classList.contains("vgp-pip");
    setFolded(false);
    box.classList.add("vgp-pip", "vgp-top");
    w.document.body.appendChild(box);
    w.addEventListener("pagehide", () => {
      if (!box) return;
      if (!hadPip) box.classList.remove("vgp-pip");
      box.classList.remove("vgp-top");
      document.body.appendChild(box);
    }, { once: true });
  };

  /* «Как в ютубе» — настоящая плавашка браузера без рамок и поверх всех
     окон. Это НЕ наш html, а нативный Picture-in-Picture: ровно то, что
     ютуб делает со своим маленьким окошком на рабочем столе. Document PiP
     (interactive, выше) есть только у Chrome/Edge, а в Firefox плавашку
     умеет лишь ВИДЕО. Поэтому рисуем плеер на холст, снимаем с него
     видеопоток и просим у браузера PiP — так же, как ютуб. Железное
     ограничение видео-PiP: внутри одни пиксели, кликать нечего, поэтому
     список треков туда не влезает — только обложка, название, полоса и
     родные кнопки браузера (play/pause/дальше/назад через mediaSession). */
  let pipVideo = null, pipCanvas = null, pipRaf = 0;
  const drawPip = () => {
    const c = pipCanvas, x = c.getContext("2d"), W = c.width, H = c.height;
    const g = x.createLinearGradient(0, 0, W, H);
    g.addColorStop(0, "#122036"); g.addColorStop(1, "#090e19");
    x.fillStyle = g; x.fillRect(0, 0, W, H);
    // мягкое бирюзовое зарево сверху
    const gl = x.createRadialGradient(W / 2, 0, 10, W / 2, 0, W * .8);
    gl.addColorStop(0, "rgba(45,226,255,.25)"); gl.addColorStop(1, "transparent");
    x.fillStyle = gl; x.fillRect(0, 0, W, H);
    const t = queue[idx] || {};
    // обложка-нота
    const cs = 96, cx = 40, cy = H / 2 - cs / 2;
    x.fillStyle = "rgba(45,226,255,.14)";
    if (x.roundRect) { x.beginPath(); x.roundRect(cx, cy, cs, cs, 20); x.fill(); }
    else x.fillRect(cx, cy, cs, cs);
    x.fillStyle = "#7df0ff"; x.font = "54px sans-serif"; x.textAlign = "center";
    x.textBaseline = "middle"; x.fillText("♪", cx + cs / 2, cy + cs / 2 + 3);
    // название и исполнитель
    const tx = cx + cs + 30;
    x.textAlign = "left"; x.fillStyle = "#f2fbff"; x.font = "700 30px sans-serif";
    const clip = (s, max) => {
      s = s || ""; if (x.measureText(s).width <= max) return s;
      while (s.length && x.measureText(s + "…").width > max) s = s.slice(0, -1);
      return s + "…";
    };
    x.fillText(clip(t.title || "Фонотека", W - tx - 30), tx, H / 2 - 34);
    x.fillStyle = "#8ba0b8"; x.font = "22px sans-serif";
    x.fillText(clip((t.artist || "vitazgio.ru") + (t.folder ? " · " + t.folder : ""), W - tx - 30), tx, H / 2 + 2);
    // полоса прогресса
    const bx = tx, bw = W - tx - 40, by = H / 2 + 42;
    const k = isFinite(audio.duration) && audio.duration ? audio.currentTime / audio.duration : 0;
    x.fillStyle = "rgba(255,255,255,.14)"; x.fillRect(bx, by, bw, 6);
    const pg = x.createLinearGradient(bx, 0, bx + bw, 0);
    pg.addColorStop(0, "#2de2ff"); pg.addColorStop(1, "#63f5ad");
    x.fillStyle = pg; x.fillRect(bx, by, bw * k, 6);
    x.fillStyle = "#6b7c8f"; x.font = "18px sans-serif";
    x.fillText(mmss(audio.currentTime) + " / " + mmss(audio.duration), bx, by + 26);
    pipRaf = requestAnimationFrame(drawPip);
  };
  const videoPip = async () => {
    if (!("pictureInPictureEnabled" in document) || !document.pictureInPictureEnabled) return false;
    if (pipVideo && document.pictureInPictureElement === pipVideo) {
      try { await document.exitPictureInPicture(); } catch (e) {}
      return true;
    }
    if (!pipCanvas) { pipCanvas = document.createElement("canvas"); pipCanvas.width = 480; pipCanvas.height = 270; }
    cancelAnimationFrame(pipRaf); drawPip();
    if (!pipVideo) {
      pipVideo = document.createElement("video");
      pipVideo.muted = true; pipVideo.playsInline = true;
      pipVideo.srcObject = pipCanvas.captureStream(20);
      pipVideo.addEventListener("leavepictureinpicture", () => {
        cancelAnimationFrame(pipRaf); pipRaf = 0;
      });
    }
    try {
      await pipVideo.play();
      await pipVideo.requestPictureInPicture();
      return true;
    } catch (e) { cancelAnimationFrame(pipRaf); pipRaf = 0; return false; }
  };

  /* Одна кнопка «поверх всех окон»: где есть Document PiP (Chrome/Edge) —
     наш живой виджет целиком; где нет (Firefox) — видео-PiP как у ютуба. */
  const floatOnTop = () => {
    if ("documentPictureInPicture" in window) return onTop();
    return videoPip();
  };
  const canFloat = () =>
    ("documentPictureInPicture" in window) ||
    ("pictureInPictureEnabled" in document && document.pictureInPictureEnabled);

  const openInWindow = (opts) => {
    if (popWin && !popWin.closed) { try { popWin.focus(); } catch (e) {} return; }
    // Звук уезжает в окно, значит эта вкладка сама включаться больше не
    // должна: автоподхват мог ещё не успеть стартовать (страницу только
    // открыли), и тогда он завёл бы второй голос уже ПОСЛЕ передачи.
    userActed = true;
    save();
    const s = stored();
    // «Играло» — это намерение, а не audio.paused: клик по ⧉ сразу после
    // открытия страницы иначе уносил бы в окно паузу, хотя трек вот-вот
    // должен был заиграть.
    const wasPlaying = wantPlay || !audio.paused || !!(s && s.playing);
    quiet = true;
    audio.pause();
    try {
      if (s) {
        s.playing = wasPlaying;
        // Секунду берём живую, а если подхват не начался — ту, что лежала.
        s.time = audio.currentTime || s.time || 0;
        s.queue = queue;
        s.idx = idx;
        s.pick = curPick;
        s.shuffle = shuffle;
        localStorage.setItem(KEY, JSON.stringify(s));
      }
    } catch (e) {}
    popWin = window.open("/player/pop", "vgplayer",
      "width=360,height=260,menubar=no,toolbar=no,location=no,status=no,resizable=yes");
    setTimeout(() => { quiet = false; }, 300);
  };

  /* Корзина, в которую можно выбросить сам плеер. Появляется только когда
     кружок подержали на месте — чтобы не мешала обычному перетаскиванию. */
  const showBin = () => {
    if (bin) return;
    bin = document.createElement("div");
    bin.className = "vgp-bin";
    bin.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13"/></svg><span>убрать плеер</span>';
    document.body.appendChild(bin);
    requestAnimationFrame(() => bin && bin.classList.add("in"));
  };
  const hideBin = () => { if (bin) { bin.remove(); bin = null; } };
  const overBin = (x, y) => {
    if (!bin) return false;
    const r = bin.getBoundingClientRect();
    return x >= r.left - 26 && x <= r.right + 26 && y >= r.top - 26 && y <= r.bottom + 26;
  };
  const paint = () => paintFns.forEach((f) => { try { f(); } catch (e) {} });
  const setFolded = (v) => {
    // В вынесенном окне сворачивать некуда: виджет и есть всё окно. Раньше
    // кнопка «свернуть» тут срабатывала и запирала плеер намертво: кружок
    // растягивался на весь вьюпорт, а вместе с телом виджета пряталась и
    // сама кнопка. Развернуть было нечем — обычно кружок разворачивают
    // тычком, но перетаскивание в этом окне намеренно отключено.
    if (popup) return;
    folded = v;
    if (!box) return;
    box.classList.toggle("vgp-folded", folded);
    box.classList.remove("vgp-wake");
    try { localStorage.setItem("vgPlayerFold", folded ? "1" : "0"); } catch (e) {}
  };

  const CSS = `
  .vgp { position:fixed; z-index:2147483000; right:22px; bottom:22px; width:326px;
         color:#eaf6ff; font:400 13px/1.45 "Cascadia Code",Consolas,monospace;
         border-radius:18px; overflow:hidden; isolation:isolate;
         background:linear-gradient(160deg, rgba(17,29,48,.93), rgba(9,14,25,.95));
         border:1px solid rgba(45,226,255,.24);
         box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.03) inset,
                    0 0 42px rgba(45,226,255,.09);
         backdrop-filter:blur(16px) saturate(1.2);
         transition:width .34s cubic-bezier(.22,1,.36,1), height .34s cubic-bezier(.22,1,.36,1),
                    border-radius .34s, opacity .2s;
         touch-action:none; }
  .vgp *, .vgp *::before, .vgp *::after { box-sizing:border-box; }
  /* мягкое бирюзовое зарево по верхнему краю — «живой» прибор */
  .vgp::before { content:""; position:absolute; inset:-40% -20% auto -20%; height:150px; pointer-events:none;
                 background:radial-gradient(60% 100% at 50% 0%, rgba(45,226,255,.20), transparent 70%);
                 opacity:.9; }
  .vgp-head { position:relative; display:flex; align-items:center; gap:11px; padding:13px 13px 9px; cursor:grab; }
  .vgp.vgp-drag .vgp-head { cursor:grabbing; }
  .vgp-art { position:relative; width:46px; height:46px; flex:none; border-radius:13px;
             display:grid; place-items:center; overflow:hidden;
             background:linear-gradient(145deg, rgba(45,226,255,.22), rgba(99,245,173,.12));
             box-shadow:0 0 0 1px rgba(45,226,255,.28) inset; }
  /* пока молчит — нота, заиграло — живые полоски */
  .vgp-note { width:21px; height:21px; color:#8ef2ff; opacity:.85; }
  .vgp.vgp-on .vgp-note { display:none; }
  .vgp:not(.vgp-on) .vgp-eq { display:none; }
  .vgp-eq { display:flex; align-items:flex-end; gap:3px; height:20px; }
  .vgp-eq i { width:3px; height:20px; transform:scaleY(.25); transform-origin:bottom center; border-radius:2px; background:linear-gradient(180deg,#7df0ff,#2de2ff);
              box-shadow:0 0 7px rgba(45,226,255,.75); }
  .vgp.vgp-on .vgp-eq i { animation:vgpBar .9s ease-in-out infinite; }
  .vgp.vgp-on .vgp-eq i:nth-child(2){ animation-duration:.62s }
  .vgp.vgp-on .vgp-eq i:nth-child(3){ animation-duration:1.05s }
  .vgp.vgp-on .vgp-eq i:nth-child(4){ animation-duration:.78s }
  @keyframes vgpBar { 0%,100%{transform:scaleY(.25)} 50%{transform:scaleY(.95)} }
  .vgp-meta { flex:1; min-width:0; }
  .vgp-t { font-size:13.5px; font-weight:700; color:#f2fbff; white-space:nowrap;
           overflow:hidden; text-overflow:ellipsis; }
  .vgp-a { margin-top:2px; font-size:11px; color:#7f93a8; white-space:nowrap;
           overflow:hidden; text-overflow:ellipsis; }
  .vgp-x { flex:none; width:28px; height:28px; display:grid; place-items:center; cursor:pointer;
           color:#7f93a8; border:0; background:none; border-radius:9px; transition:.16s; }
  .vgp-x:hover { color:#eaf6ff; background:rgba(255,255,255,.07); }
  .vgp-x svg { width:15px; height:15px; }

  .vgp-body { padding:0 13px 13px; }
  .vgp-line { display:flex; align-items:center; gap:9px; margin-bottom:11px; }
  .vgp-time { font-size:10.5px; color:#6b7c8f; font-variant-numeric:tabular-nums; flex:none; }
  .vgp-bar { position:relative; flex:1; height:16px; display:flex; align-items:center; cursor:pointer; }
  .vgp-bar u { position:absolute; left:0; right:0; height:4px; border-radius:3px;
               background:rgba(255,255,255,.11); }
  .vgp-bar i { position:absolute; left:0; height:4px; width:0; border-radius:3px;
               background:linear-gradient(90deg,#2de2ff,#63f5ad);
               box-shadow:0 0 10px rgba(45,226,255,.5); }
  .vgp-bar b { position:absolute; left:0; width:11px; height:11px; margin-left:-5px; border-radius:50%;
               background:#eafcff; box-shadow:0 0 10px rgba(45,226,255,.9); opacity:0; transition:opacity .16s; }
  .vgp-bar:hover b, .vgp-bar.vgp-grab b { opacity:1; }

  .vgp-keys { display:flex; align-items:center; justify-content:center; gap:8px; }
  .vgp-keys button { display:grid; place-items:center; cursor:pointer; color:#cfe2ee;
                     border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.04);
                     border-radius:50%; transition:.16s; }
  .vgp-keys button:hover { color:#fff; border-color:rgba(45,226,255,.5); background:rgba(45,226,255,.12); }
  .vgp-keys .vgp-side { width:34px; height:34px; }
  .vgp-keys .vgp-side svg { width:15px; height:15px; }
  .vgp-keys .vgp-play { width:46px; height:46px; color:#04121c; border:0;
                        background:linear-gradient(160deg,#7df0ff,#26cfe8);
                        box-shadow:0 6px 20px rgba(45,226,255,.35); }
  .vgp-keys .vgp-play:hover { filter:brightness(1.08); background:linear-gradient(160deg,#8ff5ff,#2de2ff); }
  .vgp-keys .vgp-play svg { width:20px; height:20px; }
  .vgp-keys .vgp-sm { width:30px; height:30px; }
  .vgp-keys .vgp-sm svg { width:13px; height:13px; }
  .vgp-keys .vgp-sm.on { color:#63f5ad; border-color:rgba(99,245,173,.45); background:rgba(99,245,173,.12); }

  .vgp-vline { margin:9px 0 0; }
  .vgp-vline .vgp-sm { flex:none; width:28px; height:28px; }
  .vgp-vline .vgp-bar { height:14px; }

  .vgp-list { max-height:0; overflow:hidden; transition:max-height .3s ease; }
  .vgp-list.open { max-height:220px; overflow-y:auto; margin-top:11px;
                   border-top:1px solid rgba(255,255,255,.08); padding-top:8px; }
  .vgp-row { display:flex; align-items:center; gap:8px; padding:7px 8px; border-radius:8px; cursor:pointer; }
  .vgp-row:hover { background:rgba(45,226,255,.08); }
  .vgp-row.on { background:rgba(45,226,255,.14); }
  .vgp-row .n { flex:1; min-width:0; }
  .vgp-row .n b { display:block; font-size:11.5px; font-weight:600; color:#dfe7f3;
                  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .vgp-row .n span { display:block; font-size:10px; color:#6b7c8f;
                     white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .vgp-row.on .n b { color:#2de2ff; }
  .vgp-row .fico { flex:none; width:20px; text-align:center; color:#7f93a8; font-size:13px; }
  .vgp-fold .n b, .vgp-back .n b { color:#dfe7f3; }
  .vgp-fold:hover .fico { color:#2de2ff; }
  .vgp-fold.on { background:rgba(45,226,255,.12); }
  .vgp-fold.on .n b { color:#2de2ff; }
  .vgp-back { color:#8ba0b8; }
  .vgp-back .fico { font-size:18px; line-height:1; }
  .vgp-lhdr { padding:8px 8px 3px; color:#6b7c8f; font-size:9.5px; letter-spacing:.08em;
              text-transform:uppercase; }

  /* ── свёрнутый вид: кружок с кольцом прогресса ── */
  .vgp.vgp-folded { width:60px; height:60px; border-radius:50%; }
  .vgp.vgp-folded .vgp-body, .vgp.vgp-folded .vgp-meta, .vgp.vgp-folded .vgp-x { display:none; }
  .vgp.vgp-folded .vgp-head { padding:0; height:100%; justify-content:center; }
  .vgp.vgp-folded .vgp-art { width:100%; height:100%; border-radius:50%; background:none; box-shadow:none; }
  .vgp-ring { position:absolute; inset:0; display:none; }
  .vgp.vgp-folded .vgp-ring { display:block; }
  .vgp-ring circle { fill:none; stroke-width:3; }
  .vgp-ring .bg { stroke:rgba(255,255,255,.12); }
  .vgp-ring .fg { stroke:#2de2ff; stroke-linecap:round; filter:drop-shadow(0 0 5px rgba(45,226,255,.8));
                  transition:stroke-dashoffset .25s linear; }
  /* корзина под плеером: выехала — значит можно выбросить */
  .vgp-bin { position:fixed; left:50%; bottom:26px; z-index:2147483001;
             display:flex; align-items:center; gap:10px; padding:13px 20px;
             transform:translate(-50%, 26px); opacity:0; pointer-events:none;
             color:#ff9aa6; font:700 .74rem "Cascadia Code",Consolas,monospace;
             letter-spacing:.04em; border:1px dashed rgba(255,90,110,.5); border-radius:14px;
             background:rgba(20,10,14,.92); backdrop-filter:blur(8px);
             transition:transform .22s cubic-bezier(.22,1,.36,1), opacity .22s, background .16s,
                        border-color .16s, color .16s; }
  .vgp-bin.in { transform:translate(-50%, 0); opacity:1; }
  .vgp-bin.hot { color:#fff; border-style:solid; border-color:#ff5a6e;
                 background:rgba(190,40,60,.92); transform:translate(-50%, 0) scale(1.06); }
  .vgp-bin svg { width:17px; height:17px; }

  /* «убрать плеер» — крестик всегда под рукой в развёрнутом виде: чтобы
     выбросить плеер, не надо зажимать и тащить в корзину. В вынесенном окне
     тем более — там тащить некуда. */
  .vgp [data-remove]:hover { color:#ff8f9b; }
  /* в вынесенном окне «свернуть» не нужно и опасно — см. setFolded */
  .vgp.vgp-pip [data-fold] { display:none; }
  /* кнопка «поверх всех окон» прячется, только когда мы уже поверх всех окон */
  .vgp.vgp-top [data-pip] { display:none; }
  /* в самом вынесенном окне (/player/pop) виджет — это весь его вьюпорт,
     без плавания и перетаскивания */
  .vgp.vgp-pip { position:static; inset:auto; right:auto; bottom:auto; left:auto; top:auto;
                 width:100%; height:auto; min-height:0; border-radius:0; box-shadow:none; }
  .vgp.vgp-pip .vgp-head { cursor:default; }

  /* автоплей не пустили — зовём нажать */
  .vgp.vgp-wake { animation:vgpWake 1.4s ease-in-out infinite; }
  @keyframes vgpWake { 0%,100%{ box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 0 rgba(45,226,255,.5) }
                        50%{ box-shadow:0 24px 70px rgba(0,0,0,.55), 0 0 0 12px rgba(45,226,255,0) } }
  @media (max-width:560px) { .vgp { right:12px; bottom:12px; width:calc(100vw - 24px); max-width:326px; } }
  @media (prefers-reduced-motion: reduce) { .vgp, .vgp * { animation:none !important; transition:none !important; } }
  `;

  const I = {
    play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7L8 5Z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 5h4v14H7zM13 5h4v14h-4z"/></svg>',
    prev: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 6v12H5V6h2Zm12 0v12l-9-6 9-6Z"/></svg>',
    next: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 6v12h2V6h-2ZM5 6v12l9-6-9-6Z"/></svg>',
    list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
    shuf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h4v4M20 4l-6 6M16 20h4v-4M20 20l-6-6M4 4l6 6M4 20l16-16"/></svg>',
    fold: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/></svg>',
    vol: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9v6h4l5 4V5L8 9H4Z"/><path d="M16.5 8.5a5 5 0 0 1 0 7"/></svg>',
    mute: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9v6h4l5 4V5L8 9H4Z"/><path d="M16 9l5 6M21 9l-5 6"/></svg>',
    pip: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><rect x="12" y="12" width="7" height="5" rx="1" fill="currentColor" stroke="none"/></svg>',
    remove: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>',
  };
  const mmss = (s) => {
    s = Math.max(0, Math.floor(s || 0));
    return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
  };

  const build = () => {
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);

    box = document.createElement("div");
    // В вынесенном окне (/player/pop) виджет сразу разворачивается и
    // занимает весь вьюпорт — сворачивать в кружок там некуда и незачем.
    box.className = popup ? "vgp vgp-pip" : "vgp vgp-folded";
    if (popup) folded = false;
    if (lift) box.style.bottom = (22 + lift) + "px";
    box.innerHTML =
      '<div class="vgp-head">' +
        '<svg class="vgp-ring" viewBox="0 0 60 60"><circle class="bg" cx="30" cy="30" r="27"/>' +
          '<circle class="fg" cx="30" cy="30" r="27" stroke-dasharray="169.6" stroke-dashoffset="169.6"/></svg>' +
        '<div class="vgp-art">' +
          '<svg class="vgp-note" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.8"/><circle cx="16.5" cy="16" r="2.8"/></svg>' +
          '<div class="vgp-eq"><i></i><i></i><i></i><i></i></div></div>' +
        '<div class="vgp-meta"><div class="vgp-t">Фонотека</div><div class="vgp-a">ничего не играет</div></div>' +
        '<button class="vgp-x" data-pip title="Вынести в отдельное окно">' + I.pip + '</button>' +
        '<button class="vgp-x" data-remove title="Убрать плеер">' + I.remove + '</button>' +
        '<button class="vgp-x" data-fold title="Свернуть">' + I.fold + '</button>' +
      '</div>' +
      '<div class="vgp-body">' +
        '<div class="vgp-line"><span class="vgp-time" data-at>0:00</span>' +
          '<div class="vgp-bar" data-bar><u></u><i></i><b></b></div>' +
          '<span class="vgp-time" data-all>0:00</span></div>' +
        '<div class="vgp-keys">' +
          '<button class="vgp-sm" data-shuf title="Вперемешку">' + I.shuf + '</button>' +
          '<button class="vgp-side" data-prev title="Назад">' + I.prev + '</button>' +
          '<button class="vgp-play" data-play title="Играть">' + I.play + '</button>' +
          '<button class="vgp-side" data-next title="Вперёд">' + I.next + '</button>' +
          '<button class="vgp-sm" data-list title="Список">' + I.list + '</button>' +
        '</div>' +
        '<div class="vgp-line vgp-vline">' +
          '<button class="vgp-sm" data-mute title="Звук">' + I.vol + '</button>' +
          '<div class="vgp-bar" data-volbar><u></u><i></i><b></b></div>' +
        '</div>' +
        '<div class="vgp-list" data-rows></div>' +
      '</div>';
    document.body.appendChild(box);

    const q = (s) => box.querySelector(s);
    const rows = q("[data-rows]");
    // Список умеет два уровня: сперва папки, внутри — их треки. null =
    // показываем папки (или сразу треки, если папка всего одна).
    // Выбранная в списке папка: id папки, "__all__" — вся музыка,
    // undefined — по умолчанию (избранная папка или вся музыка).
    /* положение помним между страницами */
    try {
      const p = JSON.parse(localStorage.getItem(POS) || "null");
      if (p && typeof p.x === "number") {
        box.style.left = p.x + "px"; box.style.top = p.y + "px";
        box.style.right = "auto"; box.style.bottom = "auto";
      }
      if (localStorage.getItem("vgPlayerFold") === "0") setFolded(false);
    } catch (e) {}

    /* таскаем за шапку */
    let drag = null;
    q(".vgp-head").addEventListener("pointerdown", (e) => {
      if (e.target.closest("button") || box.classList.contains("vgp-pip")) return;
      const r = box.getBoundingClientRect();
      drag = { dx: e.clientX - r.left, dy: e.clientY - r.top, moved: false, hold: 0 };
      box.classList.add("vgp-drag");
      try { q(".vgp-head").setPointerCapture(e.pointerId); } catch (err) {}
      // Подержал на месте — снизу выезжает корзина: значит плеер можно
      // выбросить. Если сразу потащил, корзина не появляется и не мешает.
      drag.hold = setTimeout(() => { if (drag && !drag.moved) showBin(); }, 420);
    });
    q(".vgp-head").addEventListener("pointermove", (e) => {
      if (!drag) return;
      const x = Math.min(innerWidth - box.offsetWidth - 6, Math.max(6, e.clientX - drag.dx));
      const y = Math.min(innerHeight - box.offsetHeight - 6, Math.max(6, e.clientY - drag.dy));
      if (Math.abs(x - (parseFloat(box.style.left) || 0)) > 2 ||
          Math.abs(y - (parseFloat(box.style.top) || 0)) > 2) {
        if (!drag.moved && !bin) clearTimeout(drag.hold);   // потащили — корзину не зовём
        drag.moved = true;
      }
      box.style.left = x + "px"; box.style.top = y + "px";
      box.style.right = "auto"; box.style.bottom = "auto";
      if (bin) bin.classList.toggle("hot", overBin(e.clientX, e.clientY));
    });
    const drop = (e) => {
      if (!drag) return;
      clearTimeout(drag.hold);
      box.classList.remove("vgp-drag");
      const moved = drag.moved;
      drag = null;
      // бросили в корзину — плеер уходит с глаз до следующего включения
      if (bin && overBin(e.clientX, e.clientY)) { hideBin(); api.hide(); return; }
      hideBin();
      try { localStorage.setItem(POS, JSON.stringify({
        x: parseFloat(box.style.left) || 0, y: parseFloat(box.style.top) || 0 })); } catch (err) {}
      // короткий тык по свёрнутому кружку — развернуть
      if (!moved && folded) { setFolded(false); fetchList(); }
    };
    q(".vgp-head").addEventListener("pointerup", drop);
    q(".vgp-head").addEventListener("pointercancel", drop);

    q("[data-fold]").addEventListener("click", () => setFolded(true));
    q("[data-play]").addEventListener("click", async () => { await fetchList(); api.toggle(); });
    q("[data-next]").addEventListener("click", () => api.next());
    q("[data-prev]").addEventListener("click", () => api.prev());
    q("[data-shuf]").addEventListener("click", () => api.shuffle());
    q("[data-list]").addEventListener("click", async () => {
      await fetchList(true, curPick);   // всегда свежий: могли докинуть треков
      rows.classList.toggle("open");
      q("[data-list]").classList.toggle("on", rows.classList.contains("open"));
      drawRows();
    });

    /* перемотка */
    const bar = q("[data-bar]");
    const seekAt = (e) => {
      const r = bar.getBoundingClientRect();
      const k = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
      if (isFinite(audio.duration)) audio.currentTime = k * audio.duration;
    };
    bar.addEventListener("pointerdown", (e) => {
      bar.classList.add("vgp-grab");
      try { bar.setPointerCapture(e.pointerId); } catch (err) {}
      seekAt(e);
    });
    bar.addEventListener("pointermove", (e) => { if (bar.classList.contains("vgp-grab")) seekAt(e); });
    const stopSeek = () => bar.classList.remove("vgp-grab");
    bar.addEventListener("pointerup", stopSeek);
    bar.addEventListener("pointercancel", stopSeek);

    /* громкость — тот же ползунок, что и перемотка, только крутит звук */
    const volBar = q("[data-volbar]");
    let volBeforeMute = audio.volume || 0.7;
    const volAt = (e) => {
      const r = volBar.getBoundingClientRect();
      const k = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
      api.volume(k);
    };
    volBar.addEventListener("pointerdown", (e) => {
      volBar.classList.add("vgp-grab");
      try { volBar.setPointerCapture(e.pointerId); } catch (err) {}
      volAt(e);
    });
    volBar.addEventListener("pointermove", (e) => { if (volBar.classList.contains("vgp-grab")) volAt(e); });
    const stopVol = () => volBar.classList.remove("vgp-grab");
    volBar.addEventListener("pointerup", stopVol);
    volBar.addEventListener("pointercancel", stopVol);
    q("[data-mute]").addEventListener("click", () => {
      if (audio.volume > 0) { volBeforeMute = audio.volume; api.volume(0); }
      else api.volume(volBeforeMute || 0.7);
    });

    // В вынесенном окне крестик закрывает само это окно, а не прячет
    // виджет на сайте (виджет там вообще не при чём — окно отдельное).
    q("[data-remove]").addEventListener("click", () => popup ? window.close() : api.hide());
    if (popup) {
      // В окне плеера ⧉ — это уже не «вынести» (мы вынесены), а «поверх всех
      // окон, без рамок» — как маленькое окошко ютуба. В Chrome/Edge это наш
      // живой виджет (Document PiP), в Firefox — видео-PiP из холста. Где не
      // умеет вообще ни то ни другое — кнопку прячем, чтобы не обманывать.
      const top = q("[data-pip]"); top.remove();
      if (canFloat()) {
        top.title = "Поверх всех окон, без рамок (как в ютубе)";
        top.addEventListener("click", floatOnTop);
      } else {
        top.remove();
      }
    } else {
      q("[data-pip]").addEventListener("click", openInWindow);
    }

    // Глубина папки по цепочке parent — для отступа в списке.
    const fdepth = (id) => {
      let d = 0, p = id; const seen = new Set();
      while (p) { const f = allFolders.find((x) => x.id === p);
        if (!f || seen.has(p)) break; seen.add(p); p = f.parent; d++; }
      return d;
    };
    const drawRows = () => {
      if (!rows.classList.contains("open")) return;
      // ВЕРХ списка — выбор папки из ПОЛНОГО дерева фонотеки (не только из
      // того, что сейчас в очереди). «Вся музыка» и каждая папка кликабельны:
      // тычок грузит эту папку с подпапками, треки ниже обновляются.
      let html = "";
      if (allFolders.length) {
        html += '<div class="vgp-lhdr">Папки</div>';
        html += '<div class="vgp-row vgp-fold" data-pick="__all__"><span class="fico">♪</span>' +
          '<div class="n"><b>Вся музыка</b><span></span></div></div>';
        html += allFolders.map(() =>
          '<div class="vgp-row vgp-fold" data-pick><span class="fico">🗀</span>' +
          '<div class="n"><b></b><span></span></div></div>').join("");
      }
      html += '<div class="vgp-lhdr">Треки</div>';
      html += queue.length
        ? queue.map((t, i) =>
            '<div class="vgp-row" data-i="' + i + '"><div class="n"><b></b><span></span></div></div>').join("")
        : '<div class="vgp-row"><div class="n"><b>Пусто</b>' +
          '<span>добавь треки в фонотеку или папку MUSIK</span></div></div>';
      rows.innerHTML = html;

      // имена папок, отступ по глубине, подсветка активной. Первый data-pick
      // в списке — «Вся музыка», дальше папки в порядке allFolders.
      const picks = [...rows.querySelectorAll("[data-pick]")];
      const allEl = picks[0];
      if (allEl) {
        allEl.classList.toggle("on", curPick === "__all__" || (curPick === undefined && !favFolder));
        allEl.addEventListener("click", () => choosePick("__all__"));
      }
      allFolders.forEach((f, k) => {
        const el = picks[k + 1];
        if (!el) return;
        el.dataset.pick = f.id;
        el.querySelector(".n b").textContent = f.name;
        el.style.paddingLeft = (8 + fdepth(f.parent) * 12) + "px";
        el.classList.toggle("on", curPick === f.id || (curPick === undefined && favFolder === f.id));
        el.addEventListener("click", () => choosePick(f.id));
      });

      // текст ставим через textContent — имена файлов бывают какие угодно
      rows.querySelectorAll(".vgp-row[data-i]").forEach((el) => {
        const t = queue[+el.dataset.i];
        el.classList.toggle("on", +el.dataset.i === idx);
        el.querySelector("b").textContent = t.title;
        el.querySelector("span").textContent = (t.artist || "") + (t.folder ? " · " + t.folder : "");
        el.addEventListener("click", () => { api.playAt(+el.dataset.i); drawRows(); });
      });
    };
    // выбрали папку: грузим её (с подпапками) и показываем треки, играть даём
    // тычком по треку — не пугаем внезапным стартом.
    const choosePick = async (pick) => {
      curPick = pick;
      await fetchList(true, pick);
      drawRows();
    };

    paintFns.push(() => {
      const t = queue[idx];
      q(".vgp-t").textContent = t ? t.title : "Фонотека";
      q(".vgp-a").textContent = t ? (t.artist || "vitazgio.ru") + (t.folder ? " · " + t.folder : "")
                                 : "ничего не играет";
      q("[data-play]").innerHTML = audio.paused ? I.play : I.pause;
      box.classList.toggle("vgp-on", !audio.paused);
      q("[data-shuf]").classList.toggle("on", shuffle);
      const k = isFinite(audio.duration) && audio.duration ? audio.currentTime / audio.duration : 0;
      q("[data-bar] i").style.width = (k * 100) + "%";
      q("[data-bar] b").style.left = (k * 100) + "%";
      q("[data-at]").textContent = mmss(audio.currentTime);
      q("[data-all]").textContent = mmss(audio.duration);
      q(".vgp-ring .fg").style.strokeDashoffset = String(169.6 * (1 - k));
      const vk = audio.volume;
      q("[data-volbar] i").style.width = (vk * 100) + "%";
      q("[data-volbar] b").style.left = (vk * 100) + "%";
      q("[data-mute]").innerHTML = vk > 0 ? I.vol : I.mute;
      // Подсветку играющего трека двигаем на месте, БЕЗ полной перерисовки —
      // иначе список (с папками) дёргался бы и прыгал бы скролл каждый кадр.
      if (rows.classList.contains("open")) {
        rows.querySelectorAll(".vgp-row[data-i]").forEach((el) =>
          el.classList.toggle("on", +el.dataset.i === idx));
      }
    });
    paint();
  };

  const start = () => {
    // Показываемся только если плеер включали кнопкой. Звук при этом живёт
    // всегда: трек, начатый на музыке, продолжается и без виджета.
    // /player/pop — исключение: там виджет и есть смысл окна, показываем
    // его всегда, независимо от того, включали ли где-то кнопку.
    let on = popup;
    if (!popup) { try { on = localStorage.getItem("vgPlayerOn") === "1"; } catch (e) { on = false; } }
    if (!headless && on) build();
    resume();
  };
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start);
  else start();
})();
