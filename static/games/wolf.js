/* «Ну, погоди!» — та самая «Электроника ИМ-02».
 *
 * Волк с корзиной стоит на одном из четырёх углов, по четырём жёлобам
 * скатываются яйца. Поймал — очко, не поймал — разбилось. Три разбитых, и
 * всё; на полусотне и на сотне одно битое прощается — так было в оригинале,
 * и без этого игра слишком злая.
 *
 * Экран рисуем не «под ЖК», а честными пикселями в цветах аркады: подделка
 * под серо-зелёный дисплей выглядела бы уныло рядом с остальными играми.
 */
(function () {
  "use strict";

  var W = 560, H = 420;
  /* Волк стоит в одном из четырёх углов, и от каждого угла идёт свой жёлоб
     к своему насесту. Координаты корзины и конца жёлоба считаются из одних
     и тех же чисел — иначе яйцо доезжает мимо корзины. */
  var WOLF_X = { l: 232, r: 328 };
  var WOLF_Y = { t: 210, b: 262 };
  var BASKET_DX = 36;

  // 0 лево-верх, 1 лево-низ, 2 право-верх, 3 право-низ
  function wolfAt(spot) {
    var left = spot < 2, top = spot % 2 === 0;
    var x = left ? WOLF_X.l : WOLF_X.r;
    return { x: x, y: top ? WOLF_Y.t : WOLF_Y.b, side: left ? -1 : 1,
             bx: x + (left ? -BASKET_DX : BASKET_DX) };
  }
  var C = { wolf: "#8e9bb0", wolfDark: "#5d6878", egg: "#ffd84a", hen: "#e8e2d4",
            basket: "#a4703a", bg: "#080d14", chute: "#2a3a4d" };

  /* Превью рисуем той же схемой, что и игру: два курятника по краям,
     четыре жёлоба, волк с корзиной посередине. Раньше тут были две палки
     и непохожий волк, а яйца катились мимо всего. */
  /* Волка рисуем одной функцией и для игры, и для карточки в меню — иначе
     на превью получается непохожий на себя зверь. k — масштаб, w — то, что
     вернул wolfAt(): точка, где он стоит, сторона взгляда и место корзины. */
  /* Жёлоб идёт от насеста к тому месту, где встанет корзина, если волк
     займёт этот угол. Начало — край курятника, конец — сама корзина. */
  function laneAt(i) {
    var w = wolfAt(i);
    return {
      x0: i < 2 ? 116 : W - 116,
      y0: i % 2 === 0 ? 104 : 176,
      x1: w.bx, y1: w.y + 4,
    };
  }

  function paintWolf(ctx, w, k) {
    var x = w.x, y = w.y, s = w.side, bx = w.bx;
    var R = function (dx, dy, dw, dh) {
      ctx.fillRect(x + dx * k, y + dy * k, dw * k, dh * k);
    };
    var T = function (pts) {                      // треугольник (уши)
      ctx.beginPath();
      ctx.moveTo(x + pts[0] * k, y + pts[1] * k);
      ctx.lineTo(x + pts[2] * k, y + pts[3] * k);
      ctx.lineTo(x + pts[4] * k, y + pts[5] * k);
      ctx.closePath(); ctx.fill();
    };

    ctx.fillStyle = C.wolfDark;
    R(-13, 40, 10, 26); R(3, 40, 10, 26);         // ноги
    R(-20, -4, 40, 48);                            // тень корпуса
    ctx.fillStyle = C.wolf;
    R(-17, -1, 34, 42);                            // корпус
    ctx.beginPath(); ctx.arc(x, y - 20 * k, 17 * k, 0, 7); ctx.fill();   // голова
    ctx.fillStyle = C.wolfDark;
    T([-16, -30, -8, -42, -4, -30]);
    T([4, -30, 8, -42, 16, -30]);
    // Морда смотрит в сторону своего жёлоба. Прямоугольник рисуется от
    // левого края, поэтому при взгляде влево его надо отодвинуть на всю
    // ширину — иначе он уезжает внутрь головы и нос пропадает.
    ctx.fillStyle = C.wolf;
    R(s > 0 ? 14 : -26, -24, 12, 9);
    ctx.fillStyle = "#1a1f28";
    R(s > 0 ? 24 : -28, -23, 4, 4);                // нос
    R(s * 4 - 2, -26, 4, 5);                       // глаз
    // Корзина ровно там, где кончается жёлоб: те же числа, что у laneGeom
    var b = (bx - x) / k;
    ctx.fillStyle = "#5f4020";
    R(b - 15, -6, 30, 20);
    ctx.fillStyle = C.basket;
    R(b - 13, -4, 26, 16);
    ctx.fillStyle = "#7d5228";
    for (var i = 0; i < 4; i++) R(b - 10 + i * 6, -4, 2, 16);
    ctx.fillStyle = "rgba(255,255,255,.18)";
    R(b - 13, -4, 26, 3);
    ctx.fillStyle = C.wolf;                        // рука к корзине
    R(s < 0 ? b + 10 : 14, 1, Math.abs(b) - 24, 8);
  }

  /* Превью — уменьшенная копия игрового экрана: те же курятники, те же
     четыре жёлоба и тот же волк, нарисованный тем же кодом. */
  function thumb(ctx, w, h, t) {
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, w, h);

    var k = Math.min(w / W, h / H);                // вписываем поле в карточку
    var ox = (w - W * k) / 2, oy = (h - H * k) / 2;
    ctx.save();
    ctx.translate(ox, oy);
    ctx.scale(k, k);

    // курятники
    [0, 1].forEach(function (side) {
      var x = side ? W - 116 : 24;
      ctx.fillStyle = "#141d2a";
      ctx.fillRect(x, 60, 92, 250);
      ctx.strokeStyle = "#233246"; ctx.lineWidth = 2;
      ctx.strokeRect(x + 1, 61, 90, 248);
      [0, 1].forEach(function (r) {
        var cy = 104 + r * 72;
        ctx.fillStyle = C.hen;
        ctx.beginPath(); ctx.ellipse(x + 46, cy, 25, 18, 0, 0, 7); ctx.fill();
        ctx.beginPath(); ctx.arc(x + (side ? 26 : 66), cy - 14, 10, 0, 7); ctx.fill();
        ctx.fillStyle = "#ff6b6b";
        ctx.fillRect(x + (side ? 22 : 62), cy - 27, 8, 6);
        ctx.fillStyle = "#1a1f28";
        ctx.fillRect(x + (side ? 22 : 68), cy - 17, 3, 3);
      });
    });

    // Волк по очереди обходит все четыре угла, и яйцо катится ровно в тот
    // жёлоб, под которым он стоит: превью показывает удачную ловлю.
    var step = 1.5;
    var spot = Math.floor(t / step) % 4;
    var k2 = (t % step) / step;
    var wolf = wolfAt(spot);

    for (var i = 0; i < 4; i++) {
      var g = laneAt(i);
      ctx.strokeStyle = C.chute; ctx.lineWidth = 8; ctx.lineCap = "round";
      ctx.beginPath(); ctx.moveTo(g.x0, g.y0); ctx.lineTo(g.x1, g.y1); ctx.stroke();
      ctx.strokeStyle = "#3d5570"; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(g.x0, g.y0 - 3); ctx.lineTo(g.x1, g.y1 - 3); ctx.stroke();
    }
    ctx.lineCap = "butt";

    var g2 = laneAt(spot);
    ctx.fillStyle = C.egg;
    ctx.beginPath();
    ctx.ellipse(g2.x0 + (g2.x1 - g2.x0) * k2, g2.y0 + (g2.y1 - g2.y0) * k2,
                8, 10, 0, 0, 7);
    ctx.fill();

    paintWolf(ctx, wolf, 1);
    ctx.restore();
  }

  function start(root, api) {
    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;" +
      "width:100%;height:100%;max-height:100%;min-height:0";
    var hud = document.createElement("div");
    hud.style.cssText = "display:flex;gap:16px;flex:none;font:700 .8rem " + api.font +
      ";letter-spacing:.08em;color:#8fa5b8";
    var canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    canvas.style.cssText = (api.touch
      ? "flex:0 1 auto;width:100%;height:auto;max-height:100%;"
      : "flex:1 1 auto;width:100%;height:100%;min-width:0;") +
      "min-height:0;object-fit:contain;border:1px solid rgba(255,216,74,.22);background:" + C.bg;
    var tip = document.createElement("div");
    tip.style.cssText = "color:#7fd6ea;font-size:.85rem;letter-spacing:.08em;flex:none;text-align:center";
    tip.textContent = api.touch
      ? "КРЕСТОВИНА — УГОЛ, КУДА ВСТАТЬ · ЛОВИ ЯЙЦА КОРЗИНОЙ"
      : "СТРЕЛКИ — УГОЛ, КУДА ВСТАТЬ · ENTER — ЗАНОВО";
    wrap.append(hud, canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d");
    var raf = 0, last = 0;

    var spot, eggs, broken, score, alive, saved, spawnT, shellT, flashT, pardons;
    var paused = false;
    var startedAt = 0, finalScore = 0, finalMult = 1;

    function reset() {
      spot = 1;                    // 0 лево-верх, 1 лево-низ, 2 право-верх, 3 право-низ
      eggs = []; broken = 0; score = 0; alive = true; saved = false;
      startedAt = performance.now(); finalScore = 0; finalMult = 1;
      paused = false;
      spawnT = 1.2; shellT = 0; flashT = 0; pardons = 0;
      hud_();
    }

    function hud_() {
      hud.innerHTML =
        '<span>ПОЙМАНО <b style="color:#ffd84a">' + score + "</b></span>" +
        '<span>РАЗБИТО <b style="color:#ff6b9d">' + broken + " / 3</b></span>" +
        (api.top ? '<span>РЕКОРД <b style="color:#63f5ad">' + (api.top("wolf") || 0) +
          "</b></span>" : "");
    }

    // Чем больше поймал, тем быстрее катятся и тем чаще выкатываются.
    function rollTime() { return Math.max(1.05, 2.6 - score * 0.016); }
    function gap() { return Math.max(0.42, 1.5 - score * 0.012); }

    var laneGeom = laneAt;

    function step(dt) {
      if (shellT > 0) shellT -= dt;
      if (flashT > 0) flashT -= dt;

      spawnT -= dt;
      if (spawnT <= 0) {
        var free = [0, 1, 2, 3].filter(function (i) {
          return !eggs.some(function (e) { return e.lane === i && e.t < 0.35; });
        });
        if (free.length) {
          eggs.push({ lane: free[Math.floor(Math.random() * free.length)],
                      t: 0, dur: rollTime(), state: "roll" });
          api.audio.tone(760, 0.03, { type: "square", volume: 0.05 });
        }
        spawnT = gap();
      }

      for (var i = eggs.length - 1; i >= 0; i--) {
        var e = eggs[i];
        if (e.state === "fall") {
          e.fy += e.fv * dt; e.fv += 900 * dt;
          if (e.fy > H - 40) eggs.splice(i, 1);
          continue;
        }
        e.t += dt / e.dur;
        if (e.t >= 1) {
          if (e.lane === spot) {
            score++;
            // На полусотне и на сотне игра прощает одно битое яйцо.
            if ((score === 50 || score === 100) && broken > 0) { broken--; pardons++; }
            api.audio.tone(980, 0.05, { type: "square", volume: 0.08 });
            api.buzz(10);
            eggs.splice(i, 1);
          } else {
            broken++;
            flashT = 0.25;
            shellT = 0.7;
            e.state = "fall";
            var g = laneGeom(e.lane);
            e.fx = g.x1; e.fy = g.y1; e.fv = 40;
            api.audio.tone(150, 0.16, { type: "sawtooth", volume: 0.11 });
            api.buzz([40, 40, 40]);
            if (broken >= 3) alive = false;
          }
          hud_();
        }
      }
    }

    function draw(now) {
      ctx.fillStyle = C.bg;
      ctx.fillRect(0, 0, W, H);
      if (flashT > 0) {
        ctx.fillStyle = "rgba(255,107,157," + (flashT * 0.5) + ")";
        ctx.fillRect(0, 0, W, H);
      }

      // курятники по краям
      [0, 1].forEach(function (s) {
        var x = s ? W - 116 : 24;
        ctx.fillStyle = "#141d2a";
        ctx.fillRect(x, 60, 92, 250);
        ctx.strokeStyle = "#233246"; ctx.lineWidth = 2;
        ctx.strokeRect(x + 1, 61, 90, 248);
        [0, 1].forEach(function (r) {
          var cy = 104 + r * 72;
          ctx.fillStyle = C.hen;
          ctx.beginPath(); ctx.ellipse(x + 46, cy, 25, 18, 0, 0, 7); ctx.fill();
          ctx.beginPath(); ctx.arc(x + (s ? 26 : 66), cy - 14, 10, 0, 7); ctx.fill();
          ctx.fillStyle = "#ff6b6b";
          ctx.fillRect(x + (s ? 22 : 62), cy - 27, 8, 6);
          ctx.fillStyle = "#1a1f28";
          ctx.fillRect(x + (s ? 22 : 68), cy - 17, 3, 3);
        });
      });

      // жёлоба
      for (var i = 0; i < 4; i++) {
        var g = laneGeom(i);
        ctx.strokeStyle = C.chute;
        ctx.lineWidth = 8;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(g.x0, g.y0); ctx.lineTo(g.x1, g.y1); ctx.stroke();
        ctx.strokeStyle = "#3d5570";
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(g.x0, g.y0 - 3); ctx.lineTo(g.x1, g.y1 - 3); ctx.stroke();
      }
      ctx.lineCap = "butt";

      // яйца
      eggs.forEach(function (e) {
        var x, y;
        if (e.state === "fall") { x = e.fx; y = e.fy; }
        else {
          var g2 = laneGeom(e.lane);
          x = g2.x0 + (g2.x1 - g2.x0) * e.t;
          y = g2.y0 + (g2.y1 - g2.y0) * e.t;
        }
        ctx.fillStyle = C.egg;
        ctx.beginPath();
        ctx.ellipse(x, y, 8, 10, e.state === "fall" ? e.fy * 0.05 : 0, 0, 7);
        ctx.fill();
        ctx.fillStyle = "rgba(255,255,255,.45)";
        ctx.beginPath(); ctx.ellipse(x - 2, y - 3, 3, 4, 0, 0, 7); ctx.fill();
      });

      drawWolf();

      // скорлупа внизу — счётчик промахов, видимый без цифр
      for (var b = 0; b < broken; b++) {
        var sx = W / 2 - 40 + b * 40;
        ctx.fillStyle = "#c9b06a";
        ctx.beginPath();
        ctx.moveTo(sx - 11, H - 22); ctx.lineTo(sx - 5, H - 32); ctx.lineTo(sx, H - 24);
        ctx.lineTo(sx + 6, H - 33); ctx.lineTo(sx + 11, H - 22);
        ctx.closePath(); ctx.fill();
      }

      if (alive && paused) {
        ctx.fillStyle = "rgba(8,13,20,.72)";
        ctx.fillRect(0, H / 2 - 30, W, 60);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ffd84a";
        ctx.font = 'bold 26px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ПАУЗА", W / 2, H / 2 + 9);
        ctx.textAlign = "left";
      }
      if (!alive) {
        ctx.fillStyle = "rgba(8,13,20,.86)";
        ctx.fillRect(0, H / 2 - 58, W, 116);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ff6b9d";
        ctx.font = 'bold 30px "Cascadia Code", Consolas, monospace';
        ctx.fillText("НУ, ПОГОДИ!", W / 2, H / 2 - 12);
        ctx.fillStyle = "#8fa5b8";
        ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
        ctx.fillText(score + " × темп " + finalMult.toFixed(2) + " = " + finalScore,
                     W / 2, H / 2 + 16);
        ctx.fillStyle = "#4a6379";
        ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText(api.touch ? "КРАСНАЯ КНОПКА — ЗАНОВО" : "ENTER — ЗАНОВО", W / 2, H / 2 + 42);
        ctx.textAlign = "left";
      }
    }

    function drawWolf() {
      var w = wolfAt(spot);
      var x = w.x, y = w.y, s = w.side;

      // ноги
      ctx.fillStyle = C.wolfDark;
      ctx.fillRect(x - 13, y + 40, 10, 26);
      ctx.fillRect(x + 3, y + 40, 10, 26);
      // туловище
      ctx.fillStyle = C.wolfDark;
      ctx.fillRect(x - 20, y - 4, 40, 48);
      ctx.fillStyle = C.wolf;
      ctx.fillRect(x - 17, y - 1, 34, 42);
      // голова
      ctx.fillStyle = C.wolf;
      ctx.beginPath(); ctx.arc(x, y - 20, 17, 0, 7); ctx.fill();
      ctx.fillStyle = C.wolfDark;
      ctx.beginPath(); ctx.moveTo(x - 16, y - 30); ctx.lineTo(x - 8, y - 42);
      ctx.lineTo(x - 4, y - 30); ctx.closePath(); ctx.fill();
      ctx.beginPath(); ctx.moveTo(x + 4, y - 30); ctx.lineTo(x + 8, y - 42);
      ctx.lineTo(x + 16, y - 30); ctx.closePath(); ctx.fill();
      // Морда смотрит в сторону своего жёлоба. Прямоугольник рисуется от
      // левого края, поэтому при взгляде влево его надо отодвинуть на всю
      // ширину — иначе он уезжал внутрь головы, и нос пропадал.
      ctx.fillStyle = C.wolf;
      ctx.fillRect(s > 0 ? x + 14 : x - 26, y - 24, 12, 9);
      ctx.fillStyle = "#1a1f28";
      ctx.fillRect(s > 0 ? x + 24 : x - 28, y - 23, 4, 4);   // нос
      ctx.fillRect(x + s * 4 - 2, y - 26, 4, 5);             // глаз
      // Корзина стоит ровно там, где кончается жёлоб: те же координаты,
      // что считает laneGeom, — промахнуться нечем.
      var bx = w.bx;
      ctx.fillStyle = "#5f4020";
      ctx.fillRect(bx - 15, y - 6, 30, 20);
      ctx.fillStyle = C.basket;
      ctx.fillRect(bx - 13, y - 4, 26, 16);
      ctx.fillStyle = "#7d5228";
      for (var i = 0; i < 4; i++) ctx.fillRect(bx - 10 + i * 6, y - 4, 2, 16);
      ctx.fillStyle = "rgba(255,255,255,.18)";
      ctx.fillRect(bx - 13, y - 4, 26, 3);
      // рука тянется к корзине
      ctx.fillStyle = C.wolf;
      ctx.fillRect(s < 0 ? bx + 10 : x + 14, y + 1, Math.abs(bx - x) - 24, 8);
    }

    function loop(now) {
      raf = requestAnimationFrame(loop);
      var dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (alive && !paused) step(dt);
      else if (!saved) {
        saved = true;
        var t = api.tempo(score, (performance.now() - startedAt) / 1000, 30);
        finalScore = t.total; finalMult = t.mult;
        api.best("wolf", finalScore);
        if (finalScore > 0) api.record("wolf", finalScore);
      }
      draw(now);
    }

    function go(i) { if (alive) spot = i; }

    function onKey(e) {
      if (e.key === "Enter") { if (!alive) reset(); e.preventDefault(); return; }
      if (e.key === " ") {
        if (alive) paused = !paused; else reset();
        e.preventDefault(); return;
      }
      // Крестовина ложится на четыре угла естественно: верх-низ выбирают
      // ярус, влево-вправо — сторону.
      var map = { ArrowUp: [0, 2], ArrowDown: [1, 3], ArrowLeft: [0, 1], ArrowRight: [2, 3] };
      var m = map[e.key];
      if (!m) return;
      e.preventDefault();
      if (e.key === "ArrowUp" || e.key === "ArrowDown") go(spot < 2 ? m[0] : m[1]);
      else go(spot % 2 === 0 ? m[0] : m[1]);
    }

    api.deck({
      pad: {
        up: function () { go(spot < 2 ? 0 : 2); },
        down: function () { go(spot < 2 ? 1 : 3); },
        left: function () { go(spot % 2 === 0 ? 0 : 1); },
        right: function () { go(spot % 2 === 0 ? 2 : 3); },
      },
      padBig: true,
      corners: [
        { icon: "pause", aria: "пауза",
          down: function () { if (alive) paused = !paused; } },
        { icon: "replay", aria: "заново", down: reset },
      ],
    });

    document.addEventListener("keydown", onKey);
    reset();
    last = performance.now();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKey);
      },
    };
  }

  window.VitazArcade.register({
    id: "wolf",
    title: "НУ, ПОГОДИ!",
    tagline: "Волк с корзиной и четыре жёлоба с яйцами — та самая «Электроника». " +
             "Чем больше поймал, тем быстрее катятся; на 50 и на 100 одно " +
             "разбитое прощается.",
    keys: "Стрелки — в какой угол встать · Enter — заново",
    keysTouch: "Крестовина — в какой угол встать",
    accent: "#ffd84a",
    thumb: thumb,
    start: start,
  });
})();
