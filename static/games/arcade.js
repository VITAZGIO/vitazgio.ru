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
  var deckInner = null;
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

  // Настоящие события касаний. Именно по ним решаем, показывать ли панель:
  // ноутбук с мышью её видеть не должен, даже если система рапортует иначе.
  var HAS_TOUCH_EVENTS = ("ontouchstart" in window) && navigator.maxTouchPoints > 0;
  TOUCH = TOUCH && HAS_TOUCH_EVENTS;

  // Короткая отдача в руку. Есть не везде (iOS её не даёт вовсе), поэтому
  // вызов обёрнут и при отказе молча ничего не делает.
  var buzzEnabled = true;
  function buzz(pattern) {
    if (!buzzEnabled) return;
    try { if (navigator.vibrate) navigator.vibrate(pattern); } catch (e) {}
  }

  /* ── Значки ──────────────────────────────────────────────────────────────
     Рисуем векторами, а не символами шрифта: «↻» и «▲» в разных системах
     выглядят по-разному, а половина телефонов подставляет вместо них эмодзи. */
  var ICONS = {
    up: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 5.5 19.5 17.5h-15z"/></svg>',
    down: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 18.5 4.5 6.5h15z"/></svg>',
    left: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M5.5 12 17.5 4.5v15z"/></svg>',
    right: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.5 12 6.5 19.5v-15z"/></svg>',
    // Завёрнутые стрелки поворота: дуга плюс наконечник.
    cw: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" ' +
        'stroke-linecap="round" stroke-linejoin="round">' +
        '<path d="M20 12a8 8 0 1 1-2.5-5.8"/><path d="M20 3.2V9h-5.8"/></svg>',
    ccw: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" ' +
         'stroke-linecap="round" stroke-linejoin="round">' +
         '<path d="M4 12a8 8 0 1 0 2.5-5.8"/><path d="M4 3.2V9h5.8"/></svg>',
    drop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" ' +
          'stroke-linecap="round" stroke-linejoin="round">' +
          '<path d="M12 3v12"/><path d="M6.5 9.5 12 15.5l5.5-6"/><path d="M5 20h14"/></svg>',
    hold: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" ' +
          'stroke-linejoin="round"><rect x="4" y="6" width="10" height="12" rx="1.5"/>' +
          '<path d="M17 9v9M20 9v9"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4.4" height="16" rx="1"/>' +
           '<rect x="13.6" y="4" width="4.4" height="16" rx="1"/></svg>',
    replay: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
            'stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M20 12a8 8 0 1 1-2.5-5.8"/><path d="M20 3.2V9h-5.8"/></svg>',
    fire: '<svg viewBox="0 0 24 24" fill="currentColor">' +
          '<path d="M12 2c.8 3.2 3.2 4.4 4.4 7 1.6 3.4-.4 8-4.4 8s-6-4.6-4.4-8c.5-1 1.2-1.7 1.8-2.4' +
          '.2 1.3.8 2.2 1.6 2.6-.4-2.6.2-5 1-7.2z"/>' +
          '<path d="M12 12.5c.6 1 1.6 1.6 1.6 2.8a1.6 1.6 0 0 1-3.2 0c0-1.2 1-1.8 1.6-2.8z" fill="#fff" opacity=".55"/></svg>',
    door: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" ' +
          'stroke-linejoin="round"><path d="M5 3h9v18H5z"/><circle cx="11.4" cy="12" r="1.1" fill="currentColor"/>' +
          '<path d="M17 8v8"/></svg>',
    map: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" ' +
         'stroke-linejoin="round"><path d="M3 6.5 9 4l6 2.5L21 4v13.5L15 20l-6-2.5L3 20z"/>' +
         '<path d="M9 4v13.5M15 6.5V20"/></svg>',
    gun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" ' +
         'stroke-linejoin="round"><path d="M3 8h13v4h-4l-2 3H6l-1-3H3z"/><path d="M16 8h5v3h-5"/></svg>',
  };

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
      "overflow:hidden;border:1px solid rgba(255,255,255,.09);",
      "background:repeating-linear-gradient(135deg,rgba(255,255,255,.014) 0 6px,transparent 6px 12px),",
      "linear-gradient(160deg,rgba(18,26,40,.92),rgba(8,12,20,.94));",
      "transition:border-color .18s,transform .18s,box-shadow .18s}",
      ".acard:hover{transform:translateY(-3px)}",
      ".acard.sel{border-color:var(--ac);box-shadow:0 0 0 1px var(--ac),0 18px 50px rgba(0,0,0,.55)}",
      /* уголок-акцент и блик, пробегающий по выбранной карточке */
      ".acard::before{content:'';position:absolute;top:0;left:0;width:34px;height:34px;",
      "background:linear-gradient(135deg,var(--ac) 0 50%,transparent 50%);opacity:.5}",
      ".acard::after{content:'';position:absolute;top:0;bottom:0;width:38%;pointer-events:none;",
      "background:linear-gradient(100deg,transparent,rgba(255,255,255,.07),transparent);",
      "transform:translateX(-140%)}",
      ".acard.sel::after{animation:cardSheen 2.6s ease-in-out infinite}",
      "@keyframes cardSheen{0%{transform:translateX(-140%)}55%,100%{transform:translateX(360%)}}",
      /* появление меню: карточки выезжают по очереди, оболочка проявляется */
      "#arcade{animation:arcadeIn .28s ease-out}",
      "@keyframes arcadeIn{from{opacity:0;transform:scale(1.03)}to{opacity:1;transform:none}}",
      ".acard{animation:cardIn .42s cubic-bezier(.2,.9,.3,1.25) backwards}",
      "@keyframes cardIn{from{opacity:0;transform:translateY(26px) scale(.94)}",
      "to{opacity:1;transform:none}}",
      ".acard canvas{width:100%;height:auto;display:block;background:#05070d;border:1px solid rgba(255,255,255,.06)}",
      ".acard h3{margin:0;font-size:1.05rem;letter-spacing:.04em;color:var(--ac)}",
      ".acard p{margin:0;color:#8fa5b8;font-size:.74rem;line-height:1.5}",
      ".acard .keys{color:#4a6379;font-size:.66rem;letter-spacing:.06em}",
      ".acard .go{margin-top:auto;padding-top:8px;color:var(--ac);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase}",
      "#arcade-loading{color:#4a6379;font-size:.8rem;letter-spacing:.12em}",

      /* ── Панель управления: корпус игрового автомата ──
         Шлифованный металл собран из повторяющихся градиентов, а не картинки:
         ни одного лишнего запроса, и на любом экране одинаково резко. */
      "#arcade-deck{position:relative;z-index:6;flex:none;",
      "padding:14px 12px calc(12px + env(safe-area-inset-bottom));",
      "background:",
      "linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,0) 14%),",
      "repeating-linear-gradient(90deg,rgba(255,255,255,.022) 0 2px,rgba(0,0,0,.03) 2px 4px),",
      "radial-gradient(120% 80% at 50% -20%,rgba(45,226,255,.09),transparent 60%),",
      "linear-gradient(180deg,#333a43,#1d222a 44%,#0c0f14);",
      "border-top:2px solid rgba(255,255,255,.1);",
      "box-shadow:0 -14px 34px rgba(0,0,0,.66),inset 0 1px 0 rgba(255,255,255,.13);",
      "display:flex;flex-direction:column;gap:10px;touch-action:none}",

      /* бегущая световая лента по верхней кромке корпуса */
      ".deck-led{position:absolute;top:0;left:0;right:0;height:2px;pointer-events:none;",
      "background:linear-gradient(90deg,#2de2ff,#ff3fa4,#ffd84a,#63f5ad,#2de2ff);",
      "background-size:250% 100%;animation:deckLed 7s linear infinite;opacity:.6}",
      "@keyframes deckLed{to{background-position:250% 0}}",
      "#deck-inner{display:flex;flex-direction:column;gap:10px;position:relative;z-index:1}",

      /* винты по углам — мелочь, которая и делает «корпус» корпусом */
      ".deck-screw{position:absolute;width:11px;height:11px;border-radius:50%;pointer-events:none;",
      "background:radial-gradient(circle at 34% 30%,#828b99,#3d454f 58%,#191d23);",
      "box-shadow:inset 0 -1px 2px rgba(0,0,0,.7),0 1px 0 rgba(255,255,255,.09)}",
      ".deck-screw::after{content:'';position:absolute;left:1px;right:1px;top:4.5px;height:2px;",
      "background:#14181d;transform:rotate(38deg);border-radius:1px}",

      ".deck-row{display:flex;gap:8px;justify-content:center;flex-wrap:wrap}",
      ".deck-main{display:flex;gap:12px;align-items:center;justify-content:space-between}",
      ".deck-actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;",
      "justify-content:flex-end;flex:1}",

      /* крестовина — цельная деталь, кнопки лежат прозрачными накладками */
      /* аналоговая ручка: основание с насечкой и шляпка, которая ходит за пальцем */
      ".deck-stick{position:relative;width:150px;height:150px;flex:none;border-radius:50%;",
      "background:",
      "repeating-conic-gradient(from 0deg,rgba(255,255,255,.04) 0 6deg,transparent 6deg 12deg),",
      "radial-gradient(circle at 50% 42%,#39424e,#161a20 72%);",
      "box-shadow:inset 0 6px 14px rgba(0,0,0,.7),inset 0 -2px 0 rgba(255,255,255,.06),",
      "0 4px 0 rgba(0,0,0,.5),0 8px 16px rgba(0,0,0,.45)}",
      ".stick-ring{position:absolute;inset:14px;border-radius:50%;pointer-events:none;",
      "border:1px dashed rgba(45,226,255,.22)}",
      ".stick-knob{position:absolute;left:50%;top:50%;width:64px;height:64px;margin:-32px 0 0 -32px;",
      "border-radius:50%;pointer-events:none;transition:transform .07s ease-out;",
      "background:radial-gradient(circle at 36% 28%,#8fa6bd,#3c4653 52%,#1b2027 100%);",
      "border:2px solid rgba(0,0,0,.55);",
      "box-shadow:0 5px 10px rgba(0,0,0,.55),inset 0 -4px 8px rgba(0,0,0,.4),",
      "inset 0 3px 6px rgba(255,255,255,.3)}",
      ".deck-stick.on .stick-knob{transition:none;",
      "box-shadow:0 3px 7px rgba(0,0,0,.6),inset 0 -3px 7px rgba(0,0,0,.45),",
      "inset 0 2px 5px rgba(255,255,255,.35),0 0 0 2px rgba(45,226,255,.35)}",
      /* раскладка «крестовина по центру, мелочь по краям» — для змейки */
      ".deck-main.center{justify-content:center;gap:14px}",
      ".deck-side{display:flex;flex-direction:column;gap:8px;flex:none}",
      ".deck-side .dbtn{min-width:60px;min-height:42px;font-size:.58rem}",
      ".deck-pad.big{width:190px;height:190px}",
      "@media (max-width:430px){.deck-stick{width:132px;height:132px}",
      ".stick-knob{width:56px;height:56px;margin:-28px 0 0 -28px}",
      ".deck-pad.big{width:168px;height:168px}",
      ".deck-side .dbtn{min-width:54px;min-height:38px}}",
      ".deck-pad{position:relative;width:148px;height:148px;flex:none}",
      ".deck-pad::before{content:'';position:absolute;inset:0;",
      "background:linear-gradient(160deg,#464f5b,#262d36 46%,#171c22);",
      "clip-path:polygon(34% 0,66% 0,66% 34%,100% 34%,100% 66%,66% 66%,66% 100%,34% 100%,",
      "34% 66%,0 66%,0 34%,34% 34%);",
      "filter:drop-shadow(0 4px 0 rgba(0,0,0,.55)) drop-shadow(0 7px 10px rgba(0,0,0,.45))}",
      ".deck-pad::after{content:'';position:absolute;left:50%;top:50%;width:34px;height:34px;",
      "margin:-17px 0 0 -17px;border-radius:50%;pointer-events:none;",
      "background:radial-gradient(circle at 38% 34%,#4d5764,#20262e 70%);",
      "box-shadow:inset 0 2px 4px rgba(0,0,0,.6),0 1px 0 rgba(255,255,255,.07)}",
      ".deck-pad .dbtn{position:absolute;min-width:0;min-height:0;border:0;border-radius:6px;",
      "background:transparent;box-shadow:none;color:#a9d9ea;width:34%;height:34%}",
      ".deck-pad .dbtn.on{transform:none;background:rgba(45,226,255,.16);color:#fff;",
      "box-shadow:inset 0 2px 7px rgba(0,0,0,.6)}",
      ".pad-up{left:33%;top:0}.pad-down{left:33%;bottom:0}",
      ".pad-left{left:0;top:33%}.pad-right{right:0;top:33%}",

      ".dbtn{--bc:#2de2ff;position:relative;display:grid;place-items:center;padding:0;cursor:pointer;",
      "color:#eaf6ff;font:700 .68rem " + FONT + ";letter-spacing:.06em;text-transform:uppercase;",
      "border:1px solid rgba(255,255,255,.13);border-radius:9px;touch-action:none;",
      "background:linear-gradient(180deg,#414a55,#242b33 60%,#1b2027);",
      "box-shadow:0 3px 0 rgba(0,0,0,.6),0 5px 9px rgba(0,0,0,.4),",
      "inset 0 1px 0 rgba(255,255,255,.16);",
      "min-width:48px;min-height:48px;transition:transform .06s,box-shadow .06s,color .12s}",
      ".dbtn svg{width:54%;height:54%;display:block}",
      ".dbtn.on{transform:translateY(3px);color:var(--bc);border-color:var(--bc);",
      "box-shadow:0 0 0 rgba(0,0,0,.5),inset 0 3px 8px rgba(0,0,0,.6)}",
      /* расходящееся кольцо при нажатии */
      ".dbtn::after{content:'';position:absolute;inset:-5px;border-radius:inherit;opacity:0;",
      "border:2px solid var(--bc);pointer-events:none}",
      ".dbtn.on::after{animation:deckRing .34s ease-out}",
      "@keyframes deckRing{from{opacity:.85;transform:scale(.84)}to{opacity:0;transform:scale(1.16)}}",

      /* круглые кнопки как на автомате: глянец сверху, тень снизу */
      ".dbtn.round{border-radius:50%;width:64px;height:64px;font-size:.58rem;",
      "border:2px solid rgba(0,0,0,.5);color:#0d1218;text-shadow:0 1px 0 rgba(255,255,255,.35);",
      "background:",
      "radial-gradient(circle at 34% 26%,rgba(255,255,255,.62),rgba(255,255,255,0) 46%),",
      "radial-gradient(circle at 50% 118%,rgba(0,0,0,.7),rgba(0,0,0,0) 62%),",
      "var(--bc);",
      "box-shadow:0 5px 0 rgba(0,0,0,.5),0 9px 16px rgba(0,0,0,.5),",
      "inset 0 -4px 8px rgba(0,0,0,.32),inset 0 3px 6px rgba(255,255,255,.3)}",
      ".dbtn.round svg{width:46%;height:46%}",
      ".dbtn.round.on{transform:translateY(5px);color:#0d1218;",
      "box-shadow:0 1px 0 rgba(0,0,0,.5),inset 0 4px 10px rgba(0,0,0,.45)}",
      ".dbtn.round.big{width:84px;height:84px;font-size:.66rem}",
      ".dbtn.round.big svg{width:44%;height:44%}",

      ".dbtn.wide{min-width:78px;padding:0 13px;height:40px;min-height:40px;font-size:.62rem;",
      "background:linear-gradient(180deg,#3c444f,#20262d);",
      "background-image:repeating-linear-gradient(90deg,rgba(255,255,255,.03) 0 2px,",
      "transparent 2px 4px),linear-gradient(180deg,#3c444f,#20262d)}",
      ".dbtn.wide svg{width:20px;height:20px}",
      ".dbtn.icon-text{display:flex;flex-direction:column;gap:2px}",
      ".dbtn.icon-text svg{width:19px;height:19px}",
      ".dbtn.icon-text span{font-size:.52rem;letter-spacing:.04em}",
      ".dbtn[disabled]{opacity:.32;pointer-events:none}",

      ".deck-sys{display:flex;gap:8px;justify-content:center;padding-top:8px;",
      "border-top:1px solid rgba(255,255,255,.07);",
      "box-shadow:inset 0 1px 0 rgba(0,0,0,.5)}",
      ".deck-sys .dbtn{--bc:#8fa5b8;height:36px;min-height:36px;font-size:.6rem}",
      ".deck-sys .dbtn.accent{--bc:#ff3fa4;color:#ffd9ec;border-color:rgba(255,63,164,.35);",
      "background:linear-gradient(180deg,#3a2434,#241620)}",

      /* На узких экранах ужимаем железо, иначе круглые кнопки переносятся
         на вторую строку и панель разъезжается. */
      "@media (max-width:430px){.deck-pad{width:130px;height:130px}",
      ".dbtn.round{width:58px;height:58px}.dbtn.round.big{width:74px;height:74px}",
      ".deck-actions{gap:9px}.deck-main{gap:9px}}",
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
      // Декор корпуса живёт отдельно от кнопок: deck() перерисовывает
      // содержимое при каждой смене игры, а лента и винты остаются.
      var led = document.createElement("div");
      led.className = "deck-led";
      deckEl.appendChild(led);
      deckInner = document.createElement("div");
      deckInner.id = "deck-inner";
      deckEl.appendChild(deckInner);
      deckEl.addEventListener("touchstart", onDeckTouchStart, { passive: false });
      deckEl.addEventListener("touchmove", onDeckTouchMove, { passive: false });
      deckEl.addEventListener("touchend", onDeckTouchEnd);
      deckEl.addEventListener("touchcancel", onDeckTouchEnd);
      [["left:7px;top:9px"], ["right:7px;top:9px"],
       ["left:7px;bottom:9px"], ["right:7px;bottom:9px"]].forEach(function (pos) {
        var screw = document.createElement("div");
        screw.className = "deck-screw";
        screw.style.cssText = pos[0];
        deckEl.appendChild(screw);
      });
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

    var icon = cfg.icon && ICONS[cfg.icon] ? ICONS[cfg.icon] : "";
    if (icon && cfg.label) {
      b.classList.add("icon-text");
      b.innerHTML = icon + "<span>" + cfg.label + "</span>";
    } else {
      b.innerHTML = icon || "<span>" + (cfg.label || "") + "</span>";
    }
    if (cfg.aria || cfg.label) b.setAttribute("aria-label", cfg.aria || cfg.label);

    var held = false;
    var repeatTimer = 0;

    function press(e) {
      if (e) { e.preventDefault(); e.stopPropagation(); }
      if (held) return;
      held = true;
      b.classList.add("on");
      buzz(cfg.buzz || 9);
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

    b._press = press;
    b._release = release;
    b._held = function () { return held; };

    // На устройствах с настоящими касаниями всем управляет слой ниже: он
    // отслеживает каждый палец сам. Указательные события там не вешаем —
    // браузер отменяет их при малейшем сдвиге пальца, и кнопка «отлипала»
    // прямо во время удержания, из-за чего персонаж вставал на месте.
    if (!HAS_TOUCH_EVENTS) {
      b.addEventListener("pointerdown", function (e) {
        try { b.setPointerCapture(e.pointerId); } catch (err) {}
        press(e);
      });
      b.addEventListener("pointerup", release);
      b.addEventListener("pointercancel", release);
      b.addEventListener("lostpointercapture", release);
    }
    b.addEventListener("contextmenu", function (e) { e.preventDefault(); });
    return b;
  }

  /* ── Аналоговый джойстик ──────────────────────────────────────────────
     Как ручка на корпусе автомата: наклон в любую сторону, а не четыре
     фиксированных направления. Возвращает игре пару -1..1. */
  function makeStick(cfg) {
    var base = document.createElement("div");
    base.className = "deck-stick";
    base.innerHTML = '<div class="stick-ring"></div><div class="stick-knob"></div>';
    var knob = base.querySelector(".stick-knob");

    base._stickMove = function (dx, dy, radius) {
      var len = Math.hypot(dx, dy);
      if (len > radius) { dx = dx / len * radius; dy = dy / len * radius; }
      knob.style.transform = "translate(" + dx + "px," + dy + "px)";
      base.classList.add("on");
      if (cfg.move) cfg.move(dx / radius, dy / radius);
    };
    base._stickEnd = function () {
      knob.style.transform = "";
      base.classList.remove("on");
      if (cfg.move) cfg.move(0, 0);
    };
    return base;
  }

  /* ── Слой касаний ─────────────────────────────────────────────────────
     Каждый палец ведём отдельно и на каждом движении заново смотрим, над
     чем он находится. Отсюда сразу три полезных свойства: удержание не
     срывается от дрожи руки, палец можно сдвинуть с кнопки на соседнюю,
     и несколько кнопок жмутся одновременно. */
  var touchOwners = {};       // id пальца -> элемент управления

  function controlAt(x, y) {
    var el = document.elementFromPoint(x, y);
    while (el && el !== deckEl) {
      if (el.classList && (el.classList.contains("dbtn") ||
                           el.classList.contains("deck-stick"))) return el;
      el = el.parentElement;
    }
    return null;
  }

  function releaseControl(el) {
    if (!el) return;
    if (el._release) el._release();
    else if (el._stickEnd) el._stickEnd();
  }

  function pressControl(el, touch) {
    if (!el) return;
    if (el._stickMove) {
      var rect = el.getBoundingClientRect();
      el._stickMove(touch.clientX - (rect.left + rect.width / 2),
                    touch.clientY - (rect.top + rect.height / 2), rect.width / 2);
      buzz(6);
    } else if (el._press) {
      el._press();
    }
  }

  function onDeckTouchStart(e) {
    for (var i = 0; i < e.changedTouches.length; i++) {
      var t = e.changedTouches[i];
      var el = controlAt(t.clientX, t.clientY);
      if (!el) continue;
      touchOwners[t.identifier] = el;
      pressControl(el, t);
    }
    if (Object.keys(touchOwners).length) e.preventDefault();
  }

  function onDeckTouchMove(e) {
    for (var i = 0; i < e.changedTouches.length; i++) {
      var t = e.changedTouches[i];
      var owner = touchOwners[t.identifier];
      if (!owner) continue;
      if (owner._stickMove) {                      // джойстик ведём за пальцем
        var rect = owner.getBoundingClientRect();
        owner._stickMove(t.clientX - (rect.left + rect.width / 2),
                         t.clientY - (rect.top + rect.height / 2), rect.width / 2);
        continue;
      }
      var now = controlAt(t.clientX, t.clientY);
      if (now === owner) continue;
      // Соскользнули с кнопки: отпускаем прежнюю, жмём новую.
      releaseControl(owner);
      if (now && now._press) { touchOwners[t.identifier] = now; pressControl(now, t); }
      else delete touchOwners[t.identifier];
    }
    if (Object.keys(touchOwners).length) e.preventDefault();
  }

  function onDeckTouchEnd(e) {
    for (var i = 0; i < e.changedTouches.length; i++) {
      var t = e.changedTouches[i];
      var owner = touchOwners[t.identifier];
      if (!owner) continue;
      releaseControl(owner);
      delete touchOwners[t.identifier];
    }
  }

  function releaseAllControls() {
    Object.keys(touchOwners).forEach(function (id) {
      releaseControl(touchOwners[id]);
      delete touchOwners[id];
    });
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
    if (!deckInner) return;
    releaseAllControls();
    deckInner.innerHTML = "";
    spec = spec || {};

    if (spec.extra && spec.extra.length) {
      var extraRow = document.createElement("div");
      extraRow.className = "deck-row";
      spec.extra.forEach(function (cfg) {
        extraRow.appendChild(makeButton(Object.assign({ wide: true }, cfg)));
      });
      deckInner.appendChild(extraRow);
    }

    if (spec.pad || spec.stick || spec.side || (spec.actions && spec.actions.length)) {
      var main = document.createElement("div");
      main.className = "deck-main";

      if (spec.stick) {
        main.appendChild(makeStick(spec.stick));
      }

      if (spec.side && spec.side.length) main.classList.add("center");
      if (spec.side) {
        var leftCol = document.createElement("div");
        leftCol.className = "deck-side";
        spec.side.slice(0, Math.ceil(spec.side.length / 2)).forEach(function (cfg) {
          leftCol.appendChild(makeButton(cfg));
        });
        main.appendChild(leftCol);
      }

      if (spec.pad) {
        var pad = document.createElement("div");
        pad.className = "deck-pad" + (spec.padBig ? " big" : "");
        var names = { up: "вверх", left: "влево", right: "вправо", down: "вниз" };
        ["up", "left", "right", "down"].forEach(function (dir) {
          if (!spec.pad[dir]) return;
          var cfg = spec.pad[dir];
          var btn = makeButton({
            icon: dir, aria: names[dir],
            down: cfg.down || cfg, up: cfg.up,
          });
          btn.classList.add("pad-" + dir);
          pad.appendChild(btn);
        });
        main.appendChild(pad);
      }

      if (spec.side) {
        var rightCol = document.createElement("div");
        rightCol.className = "deck-side";
        spec.side.slice(Math.ceil(spec.side.length / 2)).forEach(function (cfg) {
          rightCol.appendChild(makeButton(cfg));
        });
        main.appendChild(rightCol);
      }

      var actions = document.createElement("div");
      actions.className = "deck-actions";
      (spec.actions || []).forEach(function (cfg) {
        actions.appendChild(makeButton(Object.assign({ round: true }, cfg)));
      });
      main.appendChild(actions);
      deckInner.appendChild(main);
    }

    deckInner.appendChild(systemRow(true));
  }

  function menuDeck() {
    if (!deckInner) return;
    releaseAllControls();
    deckInner.innerHTML = "";
    deckInner.appendChild(systemRow(false));
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
      card.style.animationDelay = (index * 90) + "ms";
      card.innerHTML =
        '<canvas width="320" height="160"></canvas>' +
        '<h3>' + game.title + '</h3>' +
        '<p>' + game.tagline + '</p>' +
        '<div class="keys">' + ((TOUCH && game.keysTouch) || game.keys) + '</div>' +
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
    if (deckInner) deckInner.innerHTML = "";
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
      buzz: buzz,
    }) || { destroy: function () {} };
    // Игра могла не описать панель — тогда пусть будет хотя бы системный ряд.
    if (deckInner && !deckInner.children.length) menuDeck();
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
    if (overlay) { overlay.remove(); overlay = null; stage = null; deckEl = null; deckInner = null; }
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
    audio: audio, best: best, touch: TOUCH, buzz: buzz,
  };
})();
