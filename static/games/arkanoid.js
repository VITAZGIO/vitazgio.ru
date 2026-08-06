/* Арканоид. Ракетка, шарик, кирпичи и бонусы.
 *
 * Отскок считаем не по физике, а по месту удара о ракетку: чем дальше от
 * центра, тем острее угол. Так делали в оригинале, и это единственная
 * причина, по которой в арканоид вообще можно играть — настоящий отскок
 * от плоскости лишил бы игрока управления.
 *
 * Скорость шарика растёт от числа отбитых ударов, но угол не даём положить
 * почти горизонтально: иначе шарик залипает между стенками на полминуты.
 */
(function () {
  "use strict";

  var W = 480, H = 620;
  var COLS = 11, BW = 40, BH = 18, TOP = 60, LEFT = 20;
  var PAD_Y = H - 40, PAD_H = 12;

  var TINT = ["#ff6b9d", "#ffb35c", "#ffd84a", "#63f5ad", "#2de2ff", "#5f9bff", "#b57cff"];

  /* Уровни: строки по 11 символов. Цифра — цвет и прочность (1-2),
     S — серебряный в три удара, . — пусто. */
  var LEVELS = [
    ["...........",
     "..1111111..",
     "..2222222..",
     "..3333333..",
     "..4444444.."],

    ["11111111111",
     "1.........1",
     "1.2222222.1",
     "1.2.....2.1",
     "1.2.333.2.1",
     "1.2222222.1",
     "1.........1",
     "11111111111"],

    ["....S......",
     "...S1S.....",
     "..S121S....",
     ".S12321S...",
     "S1234321S..",
     ".S12321S...",
     "..S121S....",
     "...S1S....."],

    ["5.5.5.5.5.5",
     ".4.4.4.4.4.",
     "3.3.3.3.3.3",
     ".2.2.2.2.2.",
     "1.1.1.1.1.1",
     ".S.S.S.S.S.",
     "6.6.6.6.6.6"],

    ["SS.......SS",
     "S1.......1S",
     ".1.22222.1.",
     ".1.2SSS2.1.",
     ".1.22222.1.",
     "S1.......1S",
     "SS.......SS",
     "...33333...",
     "...44444..."],

    ["11111111111",
     "22222222222",
     "33333333333",
     "SSSSSSSSSSS",
     "44444444444",
     "55555555555",
     "66666666666"],
  ];

  var DROPS = [
    { id: "wide",  color: "#63f5ad", text: "Ш" },   // ракетка шире
    { id: "slow",  color: "#2de2ff", text: "М" },   // шарик медленнее
    { id: "multi", color: "#ffd84a", text: "×3" },  // ещё два шарика
    { id: "life",  color: "#ff6b9d", text: "+" },   // жизнь
  ];

  /* Превью гоняет настоящую мини-игру, а не рисует красивую картинку:
     шарик летит, отскакивает от бортов и ракетки и выбивает ровно тот
     кирпич, в который попал. Раньше дырка появлялась в заранее выбранном
     месте, и было видно, что шарик тут вообще ни при чём. */
  var demo = null;

  function demoReset(w, h) {
    var cols = 9, rows = 4;
    var bw = w / cols, bh = 11, top = 14;
    var bricks = [];
    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        bricks.push({ x: c * bw + 2, y: top + r * (bh + 3),
                      w: bw - 4, h: bh, c: TINT[(r + c) % TINT.length] });
      }
    }
    return {
      w: w, h: h, bricks: bricks, t: 0,
      padW: Math.round(w / 4), padX: w / 2, padY: h - 22,
      x: w / 2, y: h - 60, vx: 74, vy: -96, r: 5,
    };
  }

  function thumb(ctx, w, h, t) {
    if (!demo || demo.w !== w || demo.h !== h || t < demo.t) demo = demoReset(w, h);
    // Идём фиксированным шагом от прошлого кадра: так отскоки честные и
    // не зависят от того, с какой частотой браузер зовёт отрисовку.
    var dt = Math.min(0.05, Math.max(0, t - demo.t));
    demo.t = t;
    var d = demo, steps = Math.ceil(dt / 0.008) || 1;
    for (var i = 0; i < steps; i++) {
      var s2 = dt / steps;
      d.x += d.vx * s2;
      d.y += d.vy * s2;
      if (d.x - d.r < 0) { d.x = d.r; d.vx = Math.abs(d.vx); }
      if (d.x + d.r > w) { d.x = w - d.r; d.vx = -Math.abs(d.vx); }
      if (d.y - d.r < 0) { d.y = d.r; d.vy = Math.abs(d.vy); }

      // Ракетка едет к шарику и всегда успевает — она тут для вида
      d.padX += (d.x - d.padX) * Math.min(1, s2 * 6);
      d.padX = Math.max(d.padW / 2, Math.min(w - d.padW / 2, d.padX));
      if (d.vy > 0 && d.y + d.r >= d.padY && d.y - d.r <= d.padY + 8 &&
          d.x > d.padX - d.padW / 2 && d.x < d.padX + d.padW / 2) {
        d.y = d.padY - d.r;
        var off = (d.x - d.padX) / (d.padW / 2);
        var sp = Math.sqrt(d.vx * d.vx + d.vy * d.vy);
        var a = -Math.PI / 2 + off * 0.9;
        d.vx = Math.cos(a) * sp; d.vy = Math.sin(a) * sp;
      }
      if (d.y - d.r > h) { demo = demoReset(w, h); return thumb(ctx, w, h, t); }

      for (var b = 0; b < d.bricks.length; b++) {
        var br = d.bricks[b];
        if (d.x + d.r < br.x || d.x - d.r > br.x + br.w ||
            d.y + d.r < br.y || d.y - d.r > br.y + br.h) continue;
        // По какой грани попали: сравниваем перекрытия и отражаем по ней
        var ox = Math.min(d.x + d.r - br.x, br.x + br.w - (d.x - d.r));
        var oy = Math.min(d.y + d.r - br.y, br.y + br.h - (d.y - d.r));
        if (ox < oy) d.vx = -d.vx; else d.vy = -d.vy;
        d.bricks.splice(b, 1);
        break;
      }
    }
    if (!d.bricks.length) demo = demoReset(w, h);

    ctx.fillStyle = "#05070d";
    ctx.fillRect(0, 0, w, h);
    d.bricks.forEach(function (br) {
      ctx.fillStyle = br.c;
      ctx.globalAlpha = 0.92;
      ctx.fillRect(br.x, br.y, br.w, br.h);
      ctx.globalAlpha = 1;
      ctx.fillStyle = "rgba(255,255,255,.25)";
      ctx.fillRect(br.x, br.y, br.w, 2);
    });

    var grad = ctx.createLinearGradient(0, d.padY, 0, d.padY + 8);
    grad.addColorStop(0, "#7df9ff");
    grad.addColorStop(1, "#1a8fb0");
    ctx.fillStyle = grad;
    ctx.fillRect(d.padX - d.padW / 2, d.padY, d.padW, 8);

    ctx.fillStyle = "rgba(255,255,255,.22)";
    ctx.beginPath(); ctx.arc(d.x, d.y, d.r + 4, 0, 7); ctx.fill();
    ctx.fillStyle = "#fff";
    ctx.beginPath(); ctx.arc(d.x, d.y, d.r, 0, 7); ctx.fill();
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
      "min-height:0;object-fit:contain;border:1px solid rgba(45,226,255,.22);background:#05070d";
    var tip = document.createElement("div");
    tip.style.cssText = "color:#7fd6ea;font-size:.85rem;letter-spacing:.08em;flex:none;text-align:center";
    tip.textContent = api.touch
      ? "ВЕДИ ПАЛЬЦЕМ ПО ЭКРАНУ ИЛИ РУЧКОЙ · КРАСНАЯ — ПУСК"
      : "СТРЕЛКИ ИЛИ МЫШЬ — РАКЕТКА · ПРОБЕЛ — ПУСК · ENTER — ЗАНОВО";
    wrap.append(hud, canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d");
    var raf = 0, last = 0;

    var bricks, balls, drops, sparks;
    var padX, padW, level, score, lives, alive, stuck, saved;
    var slowT, wideT, held = 0, aimT = 0;

    function buildLevel(n) {
      var map = LEVELS[n % LEVELS.length];
      bricks = [];
      map.forEach(function (row, r) {
        for (var c = 0; c < COLS; c++) {
          var ch = row.charAt(c);
          if (!ch || ch === ".") continue;
          var hp = ch === "S" ? 3 : 1;
          var tint = ch === "S" ? "#c8d4e0" : TINT[(parseInt(ch, 10) - 1) % TINT.length];
          bricks.push({
            x: LEFT + c * BW, y: TOP + r * BH, hp: hp, max: hp,
            c: tint, silver: ch === "S",
          });
        }
      });
    }

    function newBall(x, y, vx, vy) {
      return { x: x, y: y, vx: vx, vy: vy, r: 6 };
    }

    function resetBall() {
      balls = [newBall(padX, PAD_Y - 10, 0, 0)];
      stuck = true;
      aimT = 0;
    }

    function reset(full) {
      if (full) { level = 0; score = 0; lives = 3; }
      padW = 78; padX = W / 2;
      slowT = 0; wideT = 0;
      drops = []; sparks = [];
      buildLevel(level);
      resetBall();
      alive = true; saved = false;
      hud_();
    }

    function hud_() {
      hud.innerHTML =
        '<span>УРОВЕНЬ <b style="color:#ffd84a">' + (level + 1) + "</b></span>" +
        '<span>ОЧКИ <b style="color:#eaf6ff">' + score + "</b></span>" +
        '<span>ЖИЗНИ <b style="color:#ff6b9d">' + lives + "</b></span>" +
        (api.top ? '<span>РЕКОРД <b style="color:#63f5ad">' + (api.top("arkanoid") || 0) +
          "</b></span>" : "");
    }

    /* Борта поля занимают по восемь пикселей с каждой стороны, и раньше
       ракетка их не учитывала — краем заезжала под рамку. */
    var WALL = 8;
    function clampPad(x) {
      return Math.max(WALL + padW / 2, Math.min(W - WALL - padW / 2, x));
    }

    function speed() { return (300 + level * 18) * (slowT > 0 ? 0.62 : 1); }

    function launch() {
      if (!alive) { reset(true); return; }
      if (!stuck) return;
      stuck = false;
      var a = -Math.PI / 2 + (Math.random() - 0.5) * 0.7;
      balls[0].vx = Math.cos(a) * speed();
      balls[0].vy = Math.sin(a) * speed();
      api.audio.tone(440, 0.06, { type: "square", volume: 0.08 });
    }

    function spark(x, y, c, n) {
      for (var i = 0; i < n; i++) {
        var a = Math.random() * Math.PI * 2, sp = 40 + Math.random() * 120;
        sparks.push({ x: x, y: y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp,
                      t: 0, life: 0.3 + Math.random() * 0.3, c: c });
      }
    }

    function hitBrick(b, ball) {
      b.hp--;
      spark(b.x + BW / 2, b.y + BH / 2, b.c, b.hp <= 0 ? 12 : 5);
      api.audio.tone(b.hp <= 0 ? 660 : 330, 0.04, { type: "square", volume: 0.07 });
      if (b.hp > 0) return;
      score += b.silver ? 150 : 50;
      // Бонус падает изредка и только с обычных кирпичей
      if (Math.random() < 0.14) {
        var d = DROPS[Math.floor(Math.random() * DROPS.length)];
        drops.push({ x: b.x + BW / 2, y: b.y + BH / 2, kind: d, vy: 130 });
      }
      var i = bricks.indexOf(b);
      if (i >= 0) bricks.splice(i, 1);
      hud_();
    }

    function takeDrop(d) {
      api.audio.tone(880, 0.1, { type: "square", volume: 0.09 });
      score += 100;
      if (d.kind.id === "wide") { wideT = 18; padW = 116; padX = clampPad(padX); }
      else if (d.kind.id === "slow") slowT = 12;
      else if (d.kind.id === "life") lives++;
      else if (d.kind.id === "multi") {
        var src = balls[0];
        if (src && balls.length < 6) {
          [-0.5, 0.5].forEach(function (turn) {
            var a = Math.atan2(src.vy, src.vx) + turn;
            balls.push(newBall(src.x, src.y, Math.cos(a) * speed(), Math.sin(a) * speed()));
          });
        }
      }
      hud_();
    }

    function step(dt) {
      if (slowT > 0) slowT -= dt;
      if (wideT > 0) { wideT -= dt; if (wideT <= 0) padW = 78; }

      if (held) padX += held * 460 * dt;
      padX = clampPad(padX);

      if (stuck) {
        aimT += dt;
        balls[0].x = padX;
        balls[0].y = PAD_Y - 10;
        return;
      }

      for (var i = balls.length - 1; i >= 0; i--) {
        var b = balls[i];
        // Шаг дробим: на большой скорости шарик иначе проскакивает кирпич
        var steps = Math.max(1, Math.ceil(Math.max(Math.abs(b.vx), Math.abs(b.vy)) * dt / 6));
        for (var s = 0; s < steps; s++) {
          b.x += b.vx * dt / steps;
          b.y += b.vy * dt / steps;

          if (b.x - b.r < 8) { b.x = 8 + b.r; b.vx = Math.abs(b.vx); wallSound(); }
          if (b.x + b.r > W - 8) { b.x = W - 8 - b.r; b.vx = -Math.abs(b.vx); wallSound(); }
          if (b.y - b.r < 30) { b.y = 30 + b.r; b.vy = Math.abs(b.vy); wallSound(); }

          // ракетка
          if (b.vy > 0 && b.y + b.r >= PAD_Y && b.y - b.r <= PAD_Y + PAD_H &&
              b.x > padX - padW / 2 - b.r && b.x < padX + padW / 2 + b.r) {
            var off = (b.x - padX) / (padW / 2);            // -1 .. 1
            off = Math.max(-1, Math.min(1, off));
            var a = -Math.PI / 2 + off * 1.05;               // не круче 60 градусов
            var sp = Math.min(speed() * 1.5, Math.sqrt(b.vx * b.vx + b.vy * b.vy) * 1.012);
            b.vx = Math.cos(a) * sp;
            b.vy = Math.sin(a) * sp;
            b.y = PAD_Y - b.r - 1;
            api.audio.tone(520, 0.045, { type: "square", volume: 0.08 });
            api.buzz(8);
          }

          // кирпичи
          for (var k = 0; k < bricks.length; k++) {
            var br = bricks[k];
            if (b.x + b.r < br.x || b.x - b.r > br.x + BW ||
                b.y + b.r < br.y || b.y - b.r > br.y + BH) continue;
            // По какой стороне попали: сравниваем перекрытия
            var ox = Math.min(b.x + b.r - br.x, br.x + BW - (b.x - b.r));
            var oy = Math.min(b.y + b.r - br.y, br.y + BH - (b.y - b.r));
            if (ox < oy) b.vx = -b.vx; else b.vy = -b.vy;
            hitBrick(br, b);
            break;
          }
        }

        if (b.y - b.r > H) {
          balls.splice(i, 1);
          if (!balls.length) {
            lives--;
            api.audio.tone(140, 0.3, { type: "sawtooth", volume: 0.12 });
            api.buzz(60);
            if (lives < 0) { alive = false; }
            else { padW = 78; wideT = 0; slowT = 0; resetBall(); }
            hud_();
          }
        }
      }

      for (var d = drops.length - 1; d >= 0; d--) {
        var dr = drops[d];
        dr.y += dr.vy * dt;
        if (dr.y > PAD_Y - 8 && dr.y < PAD_Y + PAD_H + 8 &&
            dr.x > padX - padW / 2 && dr.x < padX + padW / 2) {
          takeDrop(dr); drops.splice(d, 1);
        } else if (dr.y > H) drops.splice(d, 1);
      }

      for (var p = sparks.length - 1; p >= 0; p--) {
        var sp2 = sparks[p];
        sp2.t += dt;
        sp2.x += sp2.vx * dt; sp2.y += sp2.vy * dt; sp2.vy += 200 * dt;
        if (sp2.t >= sp2.life) sparks.splice(p, 1);
      }

      if (!bricks.length) {
        level++;
        score += 500;
        api.audio.tone(700, 0.12, { type: "square", volume: 0.1 });
        setTimeout(function () { api.audio.tone(1000, 0.2, { type: "square", volume: 0.09 }); }, 130);
        padW = 78; wideT = 0; slowT = 0; drops = [];
        buildLevel(level);
        resetBall();
        hud_();
      }
    }

    var wallT = 0;
    function wallSound() {
      if (performance.now() - wallT < 40) return;
      wallT = performance.now();
      api.audio.tone(300, 0.03, { type: "square", volume: 0.05 });
    }

    function draw(now) {
      ctx.fillStyle = "#05070d";
      ctx.fillRect(0, 0, W, H);

      // рамка-борт
      ctx.fillStyle = "#131c29";
      ctx.fillRect(0, 22, 8, H - 22);
      ctx.fillRect(W - 8, 22, 8, H - 22);
      ctx.fillRect(0, 22, W, 8);
      ctx.fillStyle = "#22344a";
      for (var i = 0; i < H / 20; i++) ctx.fillRect(2, 26 + i * 20, 4, 12);
      for (var j = 0; j < H / 20; j++) ctx.fillRect(W - 6, 26 + j * 20, 4, 12);

      bricks.forEach(function (b) {
        var wear = b.hp / b.max;
        ctx.fillStyle = "rgba(0,0,0,.5)";
        ctx.fillRect(b.x + 2, b.y + 2, BW - 3, BH - 3);
        ctx.fillStyle = b.c;
        ctx.globalAlpha = 0.45 + wear * 0.55;
        ctx.fillRect(b.x + 1, b.y + 1, BW - 3, BH - 3);
        ctx.globalAlpha = 1;
        ctx.fillStyle = "rgba(255,255,255,.28)";
        ctx.fillRect(b.x + 1, b.y + 1, BW - 3, 3);
        if (b.silver && b.hp > 1) {
          ctx.fillStyle = "rgba(0,0,0,.35)";
          ctx.fillRect(b.x + 4, b.y + 7, BW - 9, 2);
        }
      });

      drops.forEach(function (d) {
        ctx.fillStyle = d.kind.color;
        ctx.fillRect(d.x - 13, d.y - 8, 26, 16);
        ctx.fillStyle = "#04060b";
        ctx.font = 'bold 12px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "center";
        ctx.fillText(d.kind.text, d.x, d.y + 4);
        ctx.textAlign = "left";
      });

      // ракетка
      var grad = ctx.createLinearGradient(0, PAD_Y, 0, PAD_Y + PAD_H);
      grad.addColorStop(0, wideT > 0 ? "#9dffd0" : "#7df9ff");
      grad.addColorStop(1, wideT > 0 ? "#2fbf6a" : "#1a8fb0");
      ctx.fillStyle = grad;
      ctx.fillRect(padX - padW / 2, PAD_Y, padW, PAD_H);
      ctx.fillStyle = "rgba(255,255,255,.5)";
      ctx.fillRect(padX - padW / 2 + 3, PAD_Y + 2, padW - 6, 2);

      balls.forEach(function (b) {
        ctx.fillStyle = "rgba(255,255,255,.25)";
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r + 3, 0, 7); ctx.fill();
        ctx.fillStyle = "#ffffff";
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, 7); ctx.fill();
      });

      sparks.forEach(function (p) {
        ctx.globalAlpha = Math.max(0, 1 - p.t / p.life);
        ctx.fillStyle = p.c;
        ctx.fillRect(p.x - 2, p.y - 2, 4, 4);
      });
      ctx.globalAlpha = 1;

      if (stuck && alive) {
        // Пунктир показывает, куда полетит: без него первый пуск вслепую
        var a = -Math.PI / 2 + Math.sin(aimT * 2) * 0.6;
        ctx.strokeStyle = "rgba(125,249,255,.5)";
        ctx.setLineDash([5, 6]);
        ctx.beginPath();
        ctx.moveTo(padX, PAD_Y - 12);
        ctx.lineTo(padX + Math.cos(a) * 70, PAD_Y - 12 + Math.sin(a) * 70);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.textAlign = "center";
        ctx.fillStyle = "#4a6379";
        ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText(api.touch ? "КРАСНАЯ КНОПКА — ПУСК" : "ПРОБЕЛ — ПУСК", W / 2, PAD_Y - 40);
        ctx.textAlign = "left";
      }

      if (!alive) {
        ctx.fillStyle = "rgba(4,7,13,.85)";
        ctx.fillRect(0, H / 2 - 60, W, 120);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ff6b9d";
        ctx.font = 'bold 32px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ШАРИКИ КОНЧИЛИСЬ", W / 2, H / 2 - 12);
        ctx.fillStyle = "#8fa5b8";
        ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ОЧКОВ: " + score + " · УРОВЕНЬ " + (level + 1), W / 2, H / 2 + 16);
        ctx.fillStyle = "#4a6379";
        ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText(api.touch ? "КРАСНАЯ КНОПКА — ЗАНОВО" : "ENTER — ЗАНОВО", W / 2, H / 2 + 42);
        ctx.textAlign = "left";
      }
    }

    function loop(now) {
      raf = requestAnimationFrame(loop);
      var dt = Math.min(0.04, (now - last) / 1000);
      last = now;
      if (alive) step(dt);
      else if (!saved) {
        saved = true;
        api.best("arkanoid", score);
        if (score > 0) api.record("arkanoid", score);
      }
      draw(now);
    }

    function onKey(e) {
      if (e.key === "Enter") { if (!alive) reset(true); e.preventDefault(); return; }
      if (e.key === " ") { launch(); e.preventDefault(); return; }
      if (e.key === "ArrowLeft") { held = -1; e.preventDefault(); }
      if (e.key === "ArrowRight") { held = 1; e.preventDefault(); }
    }
    function onKeyUp(e) {
      if (e.key === "ArrowLeft" && held < 0) held = 0;
      if (e.key === "ArrowRight" && held > 0) held = 0;
    }

    // Мышь и палец водят ракетку напрямую — так удобнее всего.
    function moveTo(clientX) {
      var r = canvas.getBoundingClientRect();
      padX = clampPad((clientX - r.left) / r.width * W);
    }
    canvas.addEventListener("mousemove", function (e) { if (!api.touch) moveTo(e.clientX); });
    canvas.addEventListener("touchmove", function (e) {
      moveTo(e.touches[0].clientX);
      e.preventDefault();
    }, { passive: false });
    canvas.addEventListener("touchstart", function (e) { moveTo(e.touches[0].clientX); },
                            { passive: true });
    canvas.addEventListener("click", launch);

    api.deck({
      stick: {
        // Ручка даёт плавность, которой не даёт крестовина: ракетка идёт
        // ровно настолько, насколько отклонили.
        move: function (dx) { held = Math.abs(dx) < 0.12 ? 0 : dx; },
        end: function () { held = 0; },
      },
      actions: [
        { icon: "fire", aria: "пуск", label: "ПУСК", color: "#ff3fa4", big: true, down: launch },
      ],
      side: [
        { icon: "replay", aria: "заново", down: function () { reset(true); } },
      ],
    });

    document.addEventListener("keydown", onKey);
    document.addEventListener("keyup", onKeyUp);
    reset(true);
    last = performance.now();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKey);
        document.removeEventListener("keyup", onKeyUp);
      },
    };
  }

  window.VitazArcade.register({
    id: "arkanoid",
    title: "АРКАНОИД",
    tagline: "Ракетка, шарик и шесть уровней кирпича. Угол отскока зависит от " +
             "места удара о ракетку, серебряный кирпич держит три попадания, " +
             "из обычного изредка падает бонус.",
    keys: "Стрелки или мышь — ракетка · пробел — пуск · Enter — заново",
    keysTouch: "Ручка или палец по экрану — ракетка, красная — пуск",
    accent: "#2de2ff",
    thumb: thumb,
    start: start,
  });
})();
