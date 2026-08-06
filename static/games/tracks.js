/* Раздел «Треки» — не игра, а проигрыватель тем аркады.
 *
 * Стоит последним в списке, чтобы не мешался между играми. Тут можно
 * послушать все темы подряд; подпись слева говорит, где каждая звучит.
 * Привязка групп к играм живёт в arcade.js одной таблицей.
 */
(function () {
  "use strict";

  var ACCENT = "#b57cff";

  /* Превью: столбики частот скачут под воображаемую музыку. Считаются
     от времени, а не от настоящего звука, — карточка живёт и когда всё
     выключено. */
  function thumb(ctx, w, h, t) {
    ctx.fillStyle = "#06090f";
    ctx.fillRect(0, 0, w, h);
    var bars = 18, gap = 3;
    var bw = (w - 24 - gap * (bars - 1)) / bars;
    var base = h - 18;
    for (var i = 0; i < bars; i++) {
      // Три несовпадающих синуса дают неповторяющийся, но плавный рисунок
      var v = 0.5 + 0.5 * Math.sin(t * 3.1 + i * 0.7) * Math.sin(t * 1.3 + i * 0.31);
      var tall = Math.max(4, v * (h - 46));
      var g = ctx.createLinearGradient(0, base - tall, 0, base);
      g.addColorStop(0, "#d7b3ff");
      g.addColorStop(1, "#6b3fb0");
      ctx.fillStyle = g;
      ctx.fillRect(12 + i * (bw + gap), base - tall, bw, tall);
    }
    ctx.fillStyle = "rgba(181,124,255,.25)";
    ctx.fillRect(12, base + 2, w - 24, 2);
  }

  function start(root, api) {
    var music = window.VitazMusic;

    var css = document.createElement("style");
    css.textContent = [
      ".tk{display:flex;flex-direction:column;gap:10px;width:100%;max-width:760px;",
      "height:100%;min-height:0;font-family:" + api.font + "}",
      ".tk-head{flex:none;display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;",
      "font:700 .74rem " + api.font + ";letter-spacing:.1em;color:#8fa5b8}",
      ".tk-head b{color:" + ACCENT + ";font-size:.95rem;letter-spacing:.04em}",
      ".tk-list{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;",
      "touch-action:pan-y;display:grid;gap:6px;",
      "grid-template-columns:repeat(auto-fill,minmax(280px,1fr));align-content:start;",
      "padding:4px;border:1px solid rgba(181,124,255,.2);background:rgba(6,10,17,.8)}",
      ".tk-item{display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer;",
      "border:1px solid rgba(255,255,255,.07);background:rgba(255,255,255,.02);",
      "color:#cfe2ee;font:700 .76rem " + api.font + ";letter-spacing:.04em;text-align:left}",
      ".tk-item:hover{border-color:rgba(181,124,255,.5);background:rgba(181,124,255,.08)}",
      ".tk-item .n{flex:none;width:22px;color:#4a6379;font-size:.7rem}",
      ".tk-item .t{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
      ".tk-item .b{flex:none;color:#4a6379;font-size:.66rem}",
      ".tk-item .w{flex:none;color:#8a6ac0;font-size:.66rem;font-weight:800;",
      "letter-spacing:.04em}",
      ".tk-item.tagged{border-color:rgba(181,124,255,.24)}",
      ".tk-item.on{border-color:" + ACCENT + ";background:rgba(181,124,255,.18);color:#fff}",
      ".tk-item.on .n,.tk-item.on .b{color:#d7b3ff}",
      ".tk-note{flex:none;color:#4a6379;font-size:.68rem;line-height:1.6}",
      ".tk-eq{display:inline-flex;gap:2px;align-items:flex-end;height:12px;margin-left:2px}",
      ".tk-eq i{width:3px;background:" + ACCENT + ";animation:tkEq .6s ease-in-out infinite}",
      ".tk-eq i:nth-child(2){animation-delay:.2s}.tk-eq i:nth-child(3){animation-delay:.4s}",
      "@keyframes tkEq{0%,100%{height:3px}50%{height:12px}}",
    ].join("");

    var wrap = document.createElement("div");
    wrap.className = "tk";
    wrap.innerHTML =
      '<div class="tk-head"><b>ТРЕКИ АРКАДЫ</b>' +
        '<span data-now>ничего не играет</span></div>' +
      '<div class="tk-list"></div>' +
      '<div class="tk-note">Тыкни в тему — заиграет, тыкни ещё раз — замолчит. ' +
      'Спокойные без подписи крутятся во всех тихих играх вперемешку и ' +
      'меняются каждые полторы минуты.</div>';
    root.appendChild(css);
    root.appendChild(wrap);

    var list = wrap.querySelector(".tk-list");
    var now = wrap.querySelector("[data-now]");
    var items = [];

    function paint() {
      var cur = music ? music.index : -1;
      items.forEach(function (el, i) { el.classList.toggle("on", i === cur); });
      if (cur < 0) { now.textContent = "ничего не играет"; return; }
      now.innerHTML = 'играет: ' + escapeHtml(music.list()[cur].name) +
        '<span class="tk-eq"><i></i><i></i><i></i></span>';
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }

    /* Подпись слева от названия говорит, где тема звучит. У меню и у игр с
       музыкой по уровням это конкретное место, у спокойных — ничего:
       они крутятся во всех тихих играх вперемешку. */
    var TANK_MAPS = ["карта 1", "карта 2", "карта 3", "карта 4"];
    var DOOM_ZONES = ["ангар", "реактор", "склад", "канализация", "логово"];

    function whereOf(t, seen) {
      var n = seen[t.group] = (seen[t.group] || 0) + 1;
      if (t.group === "menu") return "меню " + n;
      if (t.group === "tanks") return "танчики · " + (TANK_MAPS[n - 1] || n);
      if (t.group === "doom") return "дум · " + (DOOM_ZONES[n - 1] || n);
      return "";
    }

    if (!music) {
      list.innerHTML = '<div class="tk-note">Музыкальный модуль не загрузился.</div>';
    } else {
      var seen = {};
      music.list().forEach(function (t, i) {
        var where = whereOf(t, seen);
        var el = document.createElement("button");
        el.type = "button";
        el.className = "tk-item" + (where ? " tagged" : "");
        el.innerHTML = '<span class="n">' + (i + 1) + '</span>' +
                       (where ? '<span class="w">' + escapeHtml(where) + '</span>' : "") +
                       '<span class="t">' + escapeHtml(t.name) + '</span>' +
                       '<span class="b">' + t.bpm + '</span>';
        el.addEventListener("click", function () {
          // Повторный тык по играющей теме выключает её: иначе, чтобы
          // прекратить, пришлось бы глушить всю музыку целиком.
          if (music.index === i) music.stop();
          else {
            if (music.muted) music.setMuted(false);
            music.play(i, api.audio);
          }
          paint();
        });
        list.appendChild(el);
        items.push(el);
      });
    }

    var beat = setInterval(paint, 400);
    paint();

    api.deck({
      slim: true,
      extra: [
        { icon: "replay", label: "СЛУЧАЙНАЯ", aria: "случайная тема",
          down: function () {
            if (!music) return;
            if (music.muted) music.setMuted(false);
            music.play(Math.floor(Math.random() * music.count()), api.audio);
            paint();
          } },
        { icon: "pause", label: "ТИШИНА", aria: "остановить",
          down: function () { if (music) music.stop(); paint(); } },
      ],
    });

    return {
      destroy: function () {
        clearInterval(beat);
        css.remove();
      },
    };
  }

  window.VitazArcade.register({
    id: "tracks",
    title: "ТРЕКИ",
    tagline: "Двадцать семь коротких зацикленных тем в духе восьми бит: три для " +
             "меню, пятнадцать спокойных, четыре под карты танчиков и пять " +
             "ревущих под зоны DOOM. Никаких файлов — всё считается из нотной записи.",
    keys: "Тык по теме — играет, тык ещё раз — тишина",
    keysTouch: "Тык по теме — играет, тык ещё раз — тишина",
    accent: ACCENT,
    thumb: thumb,
    start: start,
  });
})();
