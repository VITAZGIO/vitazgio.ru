/* Аркада vitazgio.ru — оболочка: меню, запуск игр, панель кнопок, общий звук.
 *
 * Живёт отдельным файлом, а не внутри app.py, по двум причинам: игры весят
 * заметно больше остальной страницы, и грузить их всем подряд незачем — файл
 * подтягивается только когда открыли меню. Плюс статику отдаёт с диска сам
 * Flask, то есть в памяти процесса эти килобайты не лежат.
 *
 * На телефоне снизу разворачивается панель управления в духе игровых
 * автоматов: сверху экран, снизу крестовина и круглые кнопки. Каждая игра
 * описывает свою раскладку через api.deck(), а нажатия оболочка превращает в
 * те же действия, что и клавиатура.
 *
 * Игра регистрируется так:
 *   VitazArcade.register({ id, title, tagline, keys, accent, thumb(ctx,w,h,t), start(root, api) })
 * start() возвращает объект с destroy() — оболочка вызовет его при выходе.
 */
window.VitazArcade = (function () {
  "use strict";

  var games = [];
  var registry = {};
  var overlay = null;
  var stage = null;
  var deckEl = null;
  var running = null;      // { destroy }
  var menuTimer = 0;
  var selected = 0;
  var loaded = {};

  var FONT = '"Cascadia Code", Consolas, ui-monospace, monospace';

  // Пальцем или мышью. От этого зависит и панель кнопок, и тяжесть эффектов:
  // свечение на канвасе телефоны тянут заметно хуже настольных видеокарт.
  var TOUCH = false;
  try {
    TOUCH = (window.matchMedia && window.matchMedia("(pointer: coarse)").matches) ||
            ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
  } catch (e) { TOUCH = false; }

  /* ── Звук ────────────────────────────────────────────────────────────────
     Файлов со звуками нет и не будет: всё синтезируется на месте, поэтому
     аркада не тянет за собой ни одного лишнего байта по сети. */
  var audio = {
    ctx: null,
    muted: false,

    ensure: function () {
      if (!this.ctx) {
        var Ctor = window.AudioContext || window.webkitAudioContext;
        if (!Ctor) return null;
        this.ctx = new Ctor();
      }
      if (this.ctx.state === "suspended") this.ctx.resume();
      return this.ctx;
    },

    // Короткий тон. type: sine/square/sawtooth/triangle.
    tone: function (freq, dur, opts) {
      opts = opts || {};
      var ctx = this.ensure();
      if (!ctx || this.muted) return;
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.type = opts.type || "square";
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      if (opts.slideTo) {
        osc.frequency.exponentialRampToValueAtTime(
          Math.max(1, opts.slideTo), ctx.currentTime + dur);
      }
      var vol = (opts.volume == null ? 0.16 : opts.volume);
      gain.gain.setValueAtTime(vol, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
      osc.connect(gain).connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + dur + 0.02);
    },

    // Шумовой всплеск — основа для выстрелов, взрывов и ударов.
    noise: function (dur, opts) {
      opts = opts || {};
      var ctx = this.ensure();
      if (!ctx || this.muted) return;
      var frames = Math.max(1, Math.floor(ctx.sampleRate * dur));
      var buffer = ctx.createBuffer(1, frames, ctx.sampleRate);
      var data = buffer.getChannelData(0);
      for (var i = 0; i < frames; i++) {
        // Затухание к концу, иначе всплеск звучит как обрыв провода.
        data[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / frames, opts.decay || 2);
      }
      var src = ctx.createBufferSource();
      src.buffer = buffer;
      var gain = ctx.createGain();
      gain.gain.value = (opts.volume == null ? 0.2 : opts.volume);
      var node = src;
      if (opts.filter !== false) {
        var filter = ctx.createBiquadFilter();
        filter.type = opts.filterType || "lowpass";
        filter.frequency.setValueAtTime(opts.freq || 1200, ctx.currentTime);
        if (opts.freqTo) {
          filter.frequency.exponentialRampToValueAtTime(
            Math.max(20, opts.freqTo), ctx.currentTime + dur);
        }
        node = src.connect(filter);
      }
      node.connect(gain).connect(ctx.destination);
      src.start();
    },
  };

  /* ── Рекорды ─────────────────────────────────────────────────────────── */
  function best(key, value) {
    var full = "vitaz-arcade-" + key;
    try {
      var stored = parseInt(localStorage.getItem(full) || "0", 10) || 0;
      if (value == null) return stored;
      if (value > stored) { localStorage.setItem(full, String(value)); return value; }
      return stored;
    } catch (e) { return value || 0; }
  }

  /* ── Загрузка модулей игр по требованию ──────────────────────────────── */
  function loadScript(src) {
    if (loaded[src]) return loaded[src];
    loaded[src] = new Promise(function (resolve, reject) {
      var el = document.createElement("script");
      el.src = src;
      el.onload = resolve;
      el.onerror = function () { reject(new Error("не загрузился " + src)); };
      document.head.appendChild(el);
    });
    return loaded[src];
  }

  var MODULES = ["snake", "tetris", "doom"];

  function loadAll() {
    return Promise.all(MODULES.map(function (name) {
      return loadScript("/static/games/" + name + ".js");
    }));
  }

  /* ── Разметка оболочки ───────────────────────────────────────────────── */
  function css() {
    if (document.getElementById("arcade-style")) return;
    var style = document.createElement("style");
    style.id = "arcade-style";
    style.textContent = [
      "#arcade{position:fixed;inset:0;z-index:9999;background:#04060b;color:#dfeffa;",
      "font-family:" + FONT + ";display:flex;flex-direction:column;overflow:hidden;",
      "touch-action:none;-webkit-user-select:none;user-select:none;",
      "-webkit-tap-highlight-color:transparent}",
      "#arcade::after{content:'';position:absolute;inset:0;pointer-events:none;z-index:5;opacity:.35;",
      "background:repeating-linear-gradient(180deg,rgba(0,0,0,.45) 0 1px,transparent 1px 3px)}",
      "#arcade-bar{position:relative;z-index:6;display:flex;align-items:center;gap:12px;",
      "padding:12px clamp(12px,3vw,34px);border-bottom:1px solid rgba(255,255,255,.07);flex:none}",
      "#arcade-bar h2{margin:0;font-size:clamp(.95rem,2.4vw,1.45rem);letter-spacing:.14em;color:#eaf6ff}",
      "#arcade-bar h2 b{color:#ff3fa4}",
      "#arcade-bar .hint{margin-left:auto;color:#4a6379;font-size:.68rem;letter-spacing:.14em;text-transform:uppercase}",
      ".arcade-btn{padding:8px 14px;color:#bfe6f5;font:700 .72rem " + FONT + ";letter-spacing:.08em;",
      "text-transform:uppercase;border:1px solid rgba(45,226,255,.3);background:rgba(45,226,255,.07);cursor:pointer}",
      ".arcade-btn:hover{color:#fff;border-color:#2de2ff;background:rgba(45,226,255,.16)}",
      "#arcade-stage{position:relative;flex:1 1 auto;min-height:0;display:flex;align-items:center;",
      "justify-content:center;overflow:hidden}",
      "#arcade-stage canvas{max-width:100%;max-height:100%}",
      /* На телефоне экран прижат к верху, как в автомате: сверху картинка,
         снизу панель. Кнопки в шапке там прячем — они есть на панели. */
      "#arcade.touch #arcade-stage{align-items:flex-start}",
      "#arcade.touch #arcade-bar .arcade-btn{display:none}",
      "#arcade.touch #arcade-bar{justify-content:center;padding:6px 10px}",
      "#arcade-menu{display:grid;gap:clamp(12px,2.4vw,26px);padding:clamp(12px,3vw,30px);width:100%;",
      "max-width:1180px;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));align-content:center;",
      "max-height:100%;overflow-y:auto}",
      ".acard{position:relative;display:flex;flex-direction:column;gap:10px;padding:16px;cursor:pointer;",
      "border:1px solid rgba(255,255,255,.09);background:linear-gradient(160deg,rgba(18,26,40,.9),rgba(8,12,20,.9));",
      "transition:border-color .18s,transform .18s,box-shadow .18s}",
      ".acard:hover{transform:translateY(-3px)}",
      ".acard.sel{border-color:var(--ac);box-shadow:0 0 0 1px var(--ac),0 18px 50px rgba(0,0,0,.55)}",
      ".acard canvas{width:100%;height:auto;display:block;background:#05070d;border:1px solid rgba(255,255,255,.06)}",
      ".acard h3{margin:0;font-size:1.05rem;letter-spacing:.04em;color:var(--ac)}",
      ".acard p{margin:0;color:#8fa5b8;font-size:.74rem;line-height:1.5}",
      ".acard .keys{color:#4a6379;font-size:.66rem;letter-spacing:.06em}",
      ".acard .go{margin-top:auto;padding-top:8px;color:var(--ac);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase}",
      "#arcade-loading{color:#4a6379;font-size:.8rem;letter-spacing:.12em}",

      /* ── Панель управления: корпус игрового автомата ── */
      "#arcade-deck{position:relative;z-index:6;flex:none;padding:10px 10px calc(10px + env(safe-area-inset-bottom));",
      "background:linear-gradient(180deg,#2b3038,#171a20 30%,#0e1116);",
      "border-top:2px solid rgba(255,255,255,.09);box-shadow:0 -12px 30px rgba(0,0,0,.6);",
      "display:flex;flex-direction:column;gap:8px;touch-action:none}",
      "#arcade-deck::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;",
      "background:linear-gradient(90deg,transparent,rgba(255,255,255,.28),transparent)}",
      ".deck-row{display:flex;gap:8px;justify-content:center;flex-wrap:wrap}",
      ".deck-main{display:flex;gap:10px;align-items:center;justify-content:space-between}",
      ".deck-pad{display:grid;grid-template-columns:repeat(3,46px);grid-template-rows:repeat(3,46px);",
      "gap:3px;flex:none}",
      ".deck-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;flex:1}",

      ".dbtn{--bc:#2de2ff;position:relative;display:grid;place-items:center;padding:0;cursor:pointer;",
      "color:#eaf6ff;font:700 .68rem " + FONT + ";letter-spacing:.06em;text-transform:uppercase;",
      "border:1px solid rgba(255,255,255,.12);border-radius:8px;touch-action:none;",
      "background:linear-gradient(180deg,#3a424c,#232a32);",
      "box-shadow:0 3px 0 rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.14);",
      "min-width:46px;min-height:46px}",
      ".dbtn.on{transform:translateY(3px);box-shadow:0 0 0 rgba(0,0,0,.5),inset 0 2px 6px rgba(0,0,0,.55);",
      "border-color:var(--bc);color:var(--bc)}",
      ".dbtn.round{border-radius:50%;width:60px;height:60px;font-size:.6rem;",
      "background:radial-gradient(circle at 38% 32%,color-mix(in srgb,var(--bc) 55%,#2a3038),#1a1f26 72%);",
      "border:2px solid color-mix(in srgb,var(--bc) 60%,#111);}",
      ".dbtn.round.big{width:78px;height:78px;font-size:.66rem}",
      ".dbtn.wide{min-width:74px;padding:0 12px;height:38px;min-height:38px;font-size:.62rem}",
      ".dbtn.arrow{font-size:1.1rem;color:#9fd8ea}",
      ".dbtn[disabled]{opacity:.32;pointer-events:none}",
      ".deck-sys{display:flex;gap:8px;justify-content:center;padding-top:2px;",
      "border-top:1px solid rgba(255,255,255,.06)}",
      ".deck-sys .dbtn{--bc:#8fa5b8;height:34px;min-height:34px;font-size:.6rem;",
      "background:linear-gradient(180deg,#262c34,#181d23)}",
      ".deck-sys .dbtn.accent{--bc:#ff3fa4;color:#ffd9ec}",

      "@media (max-width:560px){#arcade-bar{padding:8px 10px;gap:8px}",
      "#arcade-bar .hint{display:none}",
      "#arcade-menu{grid-template-columns:1fr;gap:10px;padding:10px}",
      ".acard{padding:11px;gap:7px}.acard canvas{max-height:96px;object-fit:cover}",
      ".acard p{font-size:.7rem;line-height:1.4}}",
      "@media (max-height:520px){.acard canvas{display:none}}",
    ].join("");
    document.head.appendChild(style);
  }

  function build() {
    css();
    overlay = document.createElement("div");
    overlay.id = "arcade";
    if (TOUCH) overlay.className = "touch";
    overlay.innerHTML =
      '<div id="arcade-bar">' +
        '<h2>АР<b>КАДА</b></h2>' +
        '<button class="arcade-btn" id="arcade-back" type="button" hidden>В меню</button>' +
        '<button class="arcade-btn" id="arcade-sound" type="button">Звук: вкл</button>' +
        '<button class="arcade-btn" id="arcade-exit" type="button">Выход</button>' +
        '<span class="hint">Escape — назад</span>' +
      '</div>' +
      '<div id="arcade-stage"><div id="arcade-loading">загрузка…</div></div>';
    document.body.appendChild(overlay);
    document.body.style.overflow = "hidden";
    stage = overlay.querySelector("#arcade-stage");

    overlay.querySelector("#arcade-exit").addEventListener("click", close);
    overlay.querySelector("#arcade-back").addEventListener("click", function () { showMenu(); });
    var soundBtn = overlay.querySelector("#arcade-sound");
    soundBtn.addEventListener("click", function () {
      audio.muted = !audio.muted;
      soundBtn.textContent = "Звук: " + (audio.muted ? "выкл" : "вкл");
      syncSound();
    });

    if (TOUCH) {
      deckEl = document.createElement("div");
      deckEl.id = "arcade-deck";
      overlay.appendChild(deckEl);
    }

    document.addEventListener("keydown", onKey, true);
  }

  function syncSound() {
    if (!deckEl) return;
    var b = deckEl.querySelector('[data-sys="sound"]');
    if (b) b.querySelector("span").textContent = audio.muted ? "ЗВУК ВЫКЛ" : "ЗВУК ВКЛ";
    var top = overlay && overlay.querySelector("#arcade-sound");
    if (top) top.textContent = "Звук: " + (audio.muted ? "выкл" : "вкл");
  }

  /* ── Кнопки панели ───────────────────────────────────────────────────── */
  function makeButton(cfg) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "dbtn" + (cfg.round ? " round" : "") + (cfg.big ? " big" : "") +
                  (cfg.wide ? " wide" : "") + (cfg.arrow ? " arrow" : "") +
                  (cfg.className ? " " + cfg.className : "");
    if (cfg.color) b.style.setProperty("--bc", cfg.color);
    if (cfg.grid) b.style.gridArea = cfg.grid;
    b.innerHTML = "<span>" + cfg.label + "</span>";

    var held = false;
    var repeatTimer = 0;

    function press(e) {
      if (e) { e.preventDefault(); e.stopPropagation(); }
      if (held) return;
      held = true;
      b.classList.add("on");
      try { if (navigator.vibrate) navigator.vibrate(8); } catch (err) {}
      if (cfg.down) cfg.down();
      // Кнопки без удержания (поворот, сброс) повторяются пока держат палец.
      if (cfg.repeat) {
        repeatTimer = setTimeout(function tick() {
          if (!held) return;
          if (cfg.down) cfg.down();
          repeatTimer = setTimeout(tick, cfg.repeat);
        }, cfg.repeatDelay || 320);
      }
    }

    function release(e) {
      if (e) e.preventDefault();
      if (!held) return;
      held = false;
      b.classList.remove("on");
      clearTimeout(repeatTimer);
      if (cfg.up) cfg.up();
    }

    b.addEventListener("pointerdown", function (e) {
      try { b.setPointerCapture(e.pointerId); } catch (err) {}
      press(e);
    });
    b.addEventListener("pointerup", release);
    b.addEventListener("pointercancel", release);
    b.addEventListener("lostpointercapture", release);
    b.addEventListener("contextmenu", function (e) { e.preventDefault(); });
    return b;
  }

  function systemRow(inGame) {
    var row = document.createElement("div");
    row.className = "deck-sys";
    if (inGame) {
      var toMenu = makeButton({
        label: "ИГРЫ", wide: true, className: "accent",
        down: function () { showMenu(); },
      });
      toMenu.dataset.sys = "menu";
      row.appendChild(toMenu);
    }
    var sound = makeButton({
      label: audio.muted ? "ЗВУК ВЫКЛ" : "ЗВУК ВКЛ", wide: true,
      down: function () { audio.muted = !audio.muted; syncSound(); },
    });
    sound.dataset.sys = "sound";
    row.appendChild(sound);
    var exit = makeButton({ label: "ВЫХОД", wide: true, down: close });
    exit.dataset.sys = "exit";
    row.appendChild(exit);
    return row;
  }

  /* Раскладка панели для конкретной игры.
     spec = { pad: {up,down,left,right}, actions: [...], extra: [...] }
     Каждая кнопка: { label, color, down, up, round, big, wide, repeat } */
  function deck(spec) {
    if (!deckEl) return;
    deckEl.innerHTML = "";
    spec = spec || {};

    if (spec.extra && spec.extra.length) {
      var extraRow = document.createElement("div");
      extraRow.className = "deck-row";
      spec.extra.forEach(function (cfg) {
        extraRow.appendChild(makeButton(Object.assign({ wide: true }, cfg)));
      });
      deckEl.appendChild(extraRow);
    }

    if (spec.pad || (spec.actions && spec.actions.length)) {
      var main = document.createElement("div");
      main.className = "deck-main";

      if (spec.pad) {
        var pad = document.createElement("div");
        pad.className = "deck-pad";
        var places = {
          up: "1 / 2 / 2 / 3", left: "2 / 1 / 3 / 2",
          right: "2 / 3 / 3 / 4", down: "3 / 2 / 4 / 3",
        };
        var glyphs = { up: "▲", left: "◀", right: "▶", down: "▼" };
        ["up", "left", "right", "down"].forEach(function (dir) {
          if (!spec.pad[dir]) return;
          var cfg = spec.pad[dir];
          pad.appendChild(makeButton({
            label: glyphs[dir], arrow: true, grid: places[dir],
            down: cfg.down || cfg, up: cfg.up,
          }));
        });
        main.appendChild(pad);
      }

      var actions = document.createElement("div");
      actions.className = "deck-actions";
      (spec.actions || []).forEach(function (cfg) {
        actions.appendChild(makeButton(Object.assign({ round: true }, cfg)));
      });
      main.appendChild(actions);
      deckEl.appendChild(main);
    }

    deckEl.appendChild(systemRow(true));
  }

  function menuDeck() {
    if (!deckEl) return;
    deckEl.innerHTML = "";
    deckEl.appendChild(systemRow(false));
  }

  /* ── Клавиатура ──────────────────────────────────────────────────────── */
  function onKey(e) {
    if (!overlay) return;
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (running) showMenu(); else close();
      return;
    }
    if (running) return;                  // дальше — только навигация по меню
    var cards = Array.prototype.slice.call(overlay.querySelectorAll(".acard"));
    if (!cards.length) return;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      selected = (selected + 1) % cards.length; paintSelection(); e.preventDefault();
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      selected = (selected - 1 + cards.length) % cards.length; paintSelection(); e.preventDefault();
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      launch(games[selected].id);
    }
  }

  function paintSelection() {
    var cards = overlay.querySelectorAll(".acard");
    for (var i = 0; i < cards.length; i++) cards[i].classList.toggle("sel", i === selected);
  }

  function stopMenuAnimation() {
    if (menuTimer) { cancelAnimationFrame(menuTimer); menuTimer = 0; }
  }

  function showMenu() {
    if (running) {
      try { running.destroy(); } catch (e) { /* игра уже могла прибраться сама */ }
      running = null;
    }
    overlay.querySelector("#arcade-back").hidden = true;
    stage.innerHTML = '<div id="arcade-menu"></div>';
    menuDeck();
    var menu = stage.querySelector("#arcade-menu");
    var previews = [];

    games.forEach(function (game, index) {
      var card = document.createElement("div");
      card.className = "acard" + (index === selected ? " sel" : "");
      card.style.setProperty("--ac", game.accent);
      card.innerHTML =
        '<canvas width="320" height="160"></canvas>' +
        '<h3>' + game.title + '</h3>' +
        '<p>' + game.tagline + '</p>' +
        '<div class="keys">' + game.keys + '</div>' +
        '<div class="go">Играть →</div>';
      card.addEventListener("click", function () { launch(game.id); });
      card.addEventListener("mouseenter", function () { selected = index; paintSelection(); });
      menu.appendChild(card);
      previews.push({ game: game, ctx: card.querySelector("canvas").getContext("2d") });
    });

    stopMenuAnimation();
    var start = performance.now();
    (function animate(now) {
      menuTimer = requestAnimationFrame(animate);
      var t = (now - start) / 1000;
      previews.forEach(function (p) {
        try { p.game.thumb(p.ctx, 320, 160, t); } catch (e) { /* превью не критично */ }
      });
    })(start);
  }

  function launch(id) {
    var game = registry[id];
    if (!game) return;
    stopMenuAnimation();
    if (running) { try { running.destroy(); } catch (e) {} running = null; }
    audio.ensure();                       // жест пользователя уже был — звук разрешён
    stage.innerHTML = "";
    if (deckEl) deckEl.innerHTML = "";
    overlay.querySelector("#arcade-back").hidden = false;
    var root = document.createElement("div");
    root.style.cssText = "position:absolute;inset:0;display:flex;justify-content:center;" +
      "padding:6px;align-items:" + (TOUCH ? "flex-start" : "center");
    stage.appendChild(root);
    running = game.start(root, {
      audio: audio,
      best: best,
      exit: showMenu,
      font: FONT,
      touch: TOUCH,
      deck: deck,
    }) || { destroy: function () {} };
    // Игра могла не описать панель — тогда пусть будет хотя бы системный ряд.
    if (deckEl && !deckEl.children.length) menuDeck();
  }

  function open(id) {
    if (overlay) return;
    build();
    loadAll().then(function () {
      if (!overlay) return;
      if (id && registry[id]) { showMenu(); launch(id); }
      else showMenu();
    }).catch(function (err) {
      if (stage) stage.innerHTML = '<div id="arcade-loading">не получилось загрузить игры: ' +
        (err && err.message ? err.message : "ошибка") + '</div>';
    });
  }

  function close() {
    stopMenuAnimation();
    if (running) { try { running.destroy(); } catch (e) {} running = null; }
    document.removeEventListener("keydown", onKey, true);
    if (overlay) { overlay.remove(); overlay = null; stage = null; deckEl = null; }
    document.body.style.overflow = "";
  }

  function register(def) {
    if (registry[def.id]) return;
    registry[def.id] = def;
    games.push(def);
    // Порядок в меню фиксируем сами: файлы могут доехать в любом порядке.
    var order = MODULES;
    games.sort(function (a, b) { return order.indexOf(a.id) - order.indexOf(b.id); });
  }

  return {
    open: open, close: close, register: register,
    audio: audio, best: best, touch: TOUCH,
  };
})();
