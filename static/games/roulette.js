/* Рулетка. Европейская, с одним зеро: 37 лунок, колесо крутится в одну
 * сторону, шарик в другую, потом сваливается в лунку.
 *
 * Денег и ставок тут нет и не будет — это проверка удачи, а не казино.
 * Вместо фишек серия: угадал — очки капнули по честному коэффициенту
 * (красное-чёрное 1, число 35), промахнулся — серия оборвалась, и в таблицу
 * рекордов уезжает набранное. Коэффициенты настоящие, поэтому осторожная игра
 * по цвету и рискованная по числу в среднем дают примерно поровну — смысл
 * жать на число не в выгоде, а в том, что это куда веселее.
 */
(function () {
  "use strict";

  // Порядок лунок на настоящем европейском колесе — он не по возрастанию,
  // соседние числа специально разведены по разным секторам.
  var WHEEL = [0, 32, 15, 19, 4, 21, 2, 25, 17, 34, 6, 27, 13, 36, 11, 30, 8,
               23, 10, 5, 24, 16, 33, 1, 20, 14, 31, 9, 22, 18, 29, 7, 28, 12, 35, 3, 26];
  var REDS = { 1: 1, 3: 1, 5: 1, 7: 1, 9: 1, 12: 1, 14: 1, 16: 1, 18: 1, 19: 1,
               21: 1, 23: 1, 25: 1, 27: 1, 30: 1, 32: 1, 34: 1, 36: 1 };

  // Канвас крупный: на телефоне он ужимается по ширине, а на мониторе
  // мелкая картинка выглядела бы марочкой в углу.
  var W = 760, H = 540;
  var CX = 268, CY = 270, R = 226;          // колесо слева, справа — табло
  var PX = 534;                             // левый край табло

  function colorOf(n) { return n === 0 ? "zero" : (REDS[n] ? "red" : "black"); }
  function inkOf(n) {
    return n === 0 ? "#2fbf6a" : (REDS[n] ? "#c8322f" : "#1b1f26");
  }

  /* Ставки. pays — настоящий коэффициент, hit — попадание. */
  var BETS = [
    { id: "red",   label: "КРАСНОЕ", color: "#c8322f", pays: 1,  odds: 18,
      hit: function (n) { return colorOf(n) === "red"; } },
    { id: "black", label: "ЧЁРНОЕ",  color: "#2b3239", pays: 1,  odds: 18,
      hit: function (n) { return colorOf(n) === "black"; } },
    { id: "even",  label: "ЧЁТ",     color: "#3b6ea5", pays: 1,  odds: 18,
      hit: function (n) { return n !== 0 && n % 2 === 0; } },
    { id: "odd",   label: "НЕЧЕТ",   color: "#3b6ea5", pays: 1,  odds: 18,
      hit: function (n) { return n % 2 === 1; } },
    { id: "zero",  label: "ЗЕРО",    color: "#2fbf6a", pays: 35, odds: 1,
      hit: function (n) { return n === 0; } },
    { id: "num",   label: "ЧИСЛО",   color: "#ffd84a", pays: 35, odds: 1, pick: true,
      hit: function (n, pick) { return n === pick; } },
  ];

  function easeOut(t) { return 1 - Math.pow(1 - t, 4); }

  /* ── Превью на карточке: то же колесо, только крутится без остановки ── */
  function thumb(ctx, w, h, t) {
    ctx.fillStyle = "#0a0705";
    ctx.fillRect(0, 0, w, h);
    var cx = w / 2, cy = h / 2 + 4, r = Math.min(w, h) * 0.42;
    drawWheel(ctx, cx, cy, r, t * 0.9, false);
    var a = -t * 2.4;
    ctx.fillStyle = "#f4f7fb";
    ctx.beginPath();
    ctx.arc(cx + Math.cos(a) * r * 0.86, cy + Math.sin(a) * r * 0.86, r * 0.055, 0, 7);
    ctx.fill();
  }

  /* Колесо целиком: обод, лунки, числа, ступица. */
  function drawWheel(ctx, cx, cy, r, angle, labels) {
    var step = Math.PI * 2 / WHEEL.length;

    ctx.save();
    ctx.translate(cx, cy);

    // деревянный обод
    ctx.fillStyle = "#3a2415";
    ctx.beginPath(); ctx.arc(0, 0, r * 1.14, 0, 7); ctx.fill();
    ctx.strokeStyle = "rgba(0,0,0,.55)"; ctx.lineWidth = r * 0.05;
    ctx.beginPath(); ctx.arc(0, 0, r * 1.11, 0, 7); ctx.stroke();
    ctx.fillStyle = "#59381f";
    ctx.beginPath(); ctx.arc(0, 0, r * 1.07, 0, 7); ctx.fill();

    ctx.rotate(angle);

    // сектора
    for (var i = 0; i < WHEEL.length; i++) {
      var n = WHEEL[i];
      var a0 = i * step - step / 2, a1 = a0 + step;
      ctx.fillStyle = inkOf(n);
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, r, a0, a1);
      ctx.closePath();
      ctx.fill();
      // перегородка между лунками
      ctx.strokeStyle = "rgba(214,224,236,.45)";
      ctx.lineWidth = Math.max(1, r * 0.012);
      ctx.beginPath();
      ctx.moveTo(Math.cos(a0) * r * 0.42, Math.sin(a0) * r * 0.42);
      ctx.lineTo(Math.cos(a0) * r, Math.sin(a0) * r);
      ctx.stroke();

      if (labels) {
        ctx.save();
        ctx.rotate(a0 + step / 2);
        ctx.translate(r * 0.83, 0);
        ctx.rotate(Math.PI / 2);
        ctx.fillStyle = "#f2f6fa";
        ctx.font = 'bold ' + Math.round(r * 0.115) + 'px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(String(n), 0, 0);
        ctx.restore();
      }
    }

    // ступица с крестовиной
    ctx.fillStyle = "#2a3038";
    ctx.beginPath(); ctx.arc(0, 0, r * 0.4, 0, 7); ctx.fill();
    ctx.strokeStyle = "#8a949f"; ctx.lineWidth = Math.max(2, r * 0.035);
    for (var k = 0; k < 4; k++) {
      var ang = k * Math.PI / 2;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(Math.cos(ang) * r * 0.38, Math.sin(ang) * r * 0.38);
      ctx.stroke();
    }
    ctx.fillStyle = "#c9a24a";
    ctx.beginPath(); ctx.arc(0, 0, r * 0.11, 0, 7); ctx.fill();
    ctx.restore();
  }

  function start(root, api) {
    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;" +
      "width:100%;max-height:100%;min-height:0";
    var canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    canvas.style.cssText = (api.touch
      ? "width:100%;height:auto;max-height:100%;"
      : "max-width:100%;max-height:100%;width:auto;height:auto;") +
      "min-height:0;object-fit:contain;border:1px solid rgba(45,226,255,.22);background:#0a0705";
    var tip = document.createElement("div");
    tip.style.cssText = "color:#4a6379;font-size:.66rem;letter-spacing:.1em;flex:none;text-align:center";
    tip.textContent = api.touch
      ? "ВВЕРХ-ВНИЗ — НА ЧТО СТАВИШЬ · ВЛЕВО-ВПРАВО — НОМЕР · КРАСНАЯ — КРУТИТЬ"
      : "СТРЕЛКИ ВВЕРХ-ВНИЗ — НА ЧТО СТАВИШЬ · ВЛЕВО-ВПРАВО — НОМЕР · ПРОБЕЛ — КРУТИТЬ";
    wrap.append(canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d");
    var raf = 0, running = true;

    var bet = 0, pick = 7;          // выбранная ставка и номер для ставки «число»
    var spins = 0;                  // сколько раз уже крутили: правила показываем до первого
    var streak = 0, points = 0;
    var history = [];               // последние выпавшие числа
    var phase = "idle";             // idle | spin | result
    var result = -1, won = false;
    var wheelAngle = 0, ballAngle = 0, ballRadius = 1;
    var spinT = 0, spinDur = 0, spinFrom = 0, spinTurns = 0, ballTurns = 0, ballTarget = 0;
    var flashT = 0, lastFrame = 0;

    /* Число выбираем честно и заранее, а анимацию потом подгоняем так, чтобы
       шарик встал именно в эту лунку. Обратный порядок (сначала крутим, потом
       смотрим, где встало) на дробных углах даёт промахи на соседнюю лунку. */
    function pickResult() {
      try {
        var buf = new Uint32Array(1);
        crypto.getRandomValues(buf);
        return WHEEL[buf[0] % WHEEL.length];
      } catch (e) {
        return WHEEL[Math.floor(Math.random() * WHEEL.length)];
      }
    }

    function spin() {
      if (phase === "spin") return;
      phase = "spin";
      spins++;                       // с первой прокруткой правила уходят
      result = pickResult();
      var index = WHEEL.indexOf(result);
      var step = Math.PI * 2 / WHEEL.length;

      spinFrom = wheelAngle;
      spinTurns = 4 + Math.random() * 2;
      // Куда шарик придёт относительно самого колеса: в центр своей лунки.
      ballTarget = index * step;
      ballTurns = -(6 + Math.random() * 2);        // против вращения колеса
      spinT = 0;
      spinDur = 4200 + Math.random() * 900;
      api.buzz(18);
      api.audio.noise(0.5, { volume: 0.1, freq: 900, freqTo: 300, decay: 1.1 });
    }

    function settle() {
      phase = "result";
      var b = BETS[bet];
      won = b.hit(result, pick);
      history.unshift(result);
      if (history.length > 12) history.pop();
      flashT = 1;
      if (won) {
        streak++;
        points += b.pays;
        api.buzz([30, 40, 60]);
        api.audio.tone(520, 0.12, { type: "square", volume: 0.14 });
        setTimeout(function () {
          api.audio.tone(780, 0.16, { type: "square", volume: 0.13 });
        }, 110);
      } else {
        api.buzz([90, 60, 140]);
        api.audio.tone(200, 0.4, { type: "sawtooth", slideTo: 60, volume: 0.13 });
        if (points > 0) {
          // Рекорд держим только на самом устройстве. В общую таблицу
          // рулетка не идёт: колесо — генератор случайных чисел, и место в
          // ней говорит про везение, а не про игрока.
          api.best("roulette", points);
        }
        streak = 0;
        points = 0;
      }
    }

    function moveBet(step) {
      bet = (bet + step + BETS.length) % BETS.length;
      api.audio.tone(420, 0.05, { type: "square", volume: 0.08 });
    }

    function movePick(step) {
      pick = (pick + step + 37) % 37;
      api.audio.tone(360, 0.04, { type: "square", volume: 0.07 });
    }

    /* ── Отрисовка ────────────────────────────────────────────────────── */
    function draw() {
      // сукно
      ctx.fillStyle = "#0d2a1c";
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = "rgba(0,0,0,.22)";
      for (var s = 0; s < H; s += 4) ctx.fillRect(0, s, W, 2);
      ctx.strokeStyle = "rgba(201,162,74,.35)";
      ctx.lineWidth = 2;
      ctx.strokeRect(4.5, 4.5, W - 9, H - 9);

      drawWheel(ctx, CX, CY, R, wheelAngle, true);

      // Выигравшую лунку обводим: указателя у настоящего колеса нет,
      // результат определяет та лунка, в которой лёг шарик.
      if (phase === "result") {
        var step = Math.PI * 2 / WHEEL.length;
        var a0 = wheelAngle + WHEEL.indexOf(result) * step - step / 2;
        ctx.save();
        ctx.strokeStyle = won ? "#63f5ad" : "#ffd84a";
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.moveTo(CX + Math.cos(a0) * R * 0.42, CY + Math.sin(a0) * R * 0.42);
        ctx.arc(CX, CY, R, a0, a0 + step);
        ctx.lineTo(CX + Math.cos(a0 + step) * R * 0.42, CY + Math.sin(a0 + step) * R * 0.42);
        ctx.arc(CX, CY, R * 0.42, a0 + step, a0, true);
        ctx.stroke();
        ctx.restore();
      }

      // шарик
      var bx = CX + Math.cos(ballAngle) * R * ballRadius;
      var by = CY + Math.sin(ballAngle) * R * ballRadius;
      ctx.fillStyle = "rgba(0,0,0,.45)";
      ctx.beginPath(); ctx.arc(bx + 2, by + 3, 10, 0, 7); ctx.fill();
      var grad = ctx.createRadialGradient(bx - 3, by - 4, 1, bx, by, 11);
      grad.addColorStop(0, "#ffffff");
      grad.addColorStop(1, "#9aa6b4");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(bx, by, 10, 0, 7); ctx.fill();

      drawPanel();
      drawRules();
    }

    function drawPanel() {
      var x = PX, y = 44;
      ctx.textAlign = "left";
      ctx.textBaseline = "alphabetic";

      ctx.fillStyle = "rgba(4,10,8,.72)";
      ctx.fillRect(x - 16, 22, W - x, H - 44);
      ctx.strokeStyle = "rgba(201,162,74,.28)";
      ctx.lineWidth = 1;
      ctx.strokeRect(x - 15.5, 22.5, W - x - 1, H - 45);

      ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
      ctx.fillStyle = "#7fd6ea";
      ctx.fillText("СТАВКА", x, y);
      y += 8;

      BETS.forEach(function (b, i) {
        var on = i === bet;
        y += 31;
        if (on) {
          ctx.fillStyle = "rgba(255,216,74,.16)";
          ctx.fillRect(x - 8, y - 19, W - x - 8, 26);
        }
        ctx.fillStyle = b.color;
        ctx.fillRect(x, y - 14, 13, 13);
        ctx.fillStyle = on ? "#ffd84a" : "#8fa5b8";
        ctx.font = 'bold 16px "Cascadia Code", Consolas, monospace';
        // У ставки «число» рисуем стрелки вокруг номера: иначе неоткуда
        // догадаться, что его вообще можно менять.
        ctx.fillText(b.pick ? b.label + (on ? "  \u25c4 " + pick + " \u25ba" : "  " + pick)
                            : b.label, x + 21, y);
        ctx.textAlign = "right";
        ctx.fillStyle = on ? "#c9a24a" : "#46606f";
        ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText("x" + b.pays, W - 26, y);
        // Шанс словами — тогда видно, что коэффициент не с потолка:
        // редкое событие платит больше ровно во столько же раз.
        ctx.fillStyle = on ? "#7f8ea0" : "#38505e";
        ctx.font = 'bold 11px "Cascadia Code", Consolas, monospace';
        ctx.fillText(b.odds + " из 37", W - 26, y + 12);
        ctx.textAlign = "left";
      });

      // Разделитель между ставками и счётом
      y += 24;
      ctx.strokeStyle = "rgba(201,162,74,.22)";
      ctx.beginPath(); ctx.moveTo(x - 8, y - 8); ctx.lineTo(W - 26, y - 8); ctx.stroke();

      y += 14;
      ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
      ctx.fillStyle = "#7fd6ea";
      ctx.fillText("СЕРИЯ", x, y);
      ctx.fillStyle = "#eaf6ff";
      ctx.font = 'bold 24px "Cascadia Code", Consolas, monospace';
      ctx.textAlign = "right";
      ctx.fillText(String(streak), W - 26, y + 2);
      ctx.textAlign = "left";

      y += 34;
      ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
      ctx.fillStyle = "#7fd6ea";
      ctx.fillText("ОЧКИ", x, y);
      ctx.fillStyle = "#63f5ad";
      ctx.font = 'bold 24px "Cascadia Code", Consolas, monospace';
      ctx.textAlign = "right";
      ctx.fillText(String(points), W - 26, y + 2);
      ctx.textAlign = "left";

      y += 26;
      ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
      ctx.fillStyle = "#46606f";
      ctx.fillText("РЕКОРД " + api.best("roulette"), x, y);

      // последние выпавшие
      y += 30;
      ctx.fillStyle = "#7fd6ea";
      ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
      ctx.fillText("ВЫПАДАЛО", x, y);
      for (var i = 0; i < Math.min(history.length, 9); i++) {
        var col = i % 3, row = Math.floor(i / 3);
        var hx = x + col * 44, hy = y + 12 + row * 28;
        ctx.fillStyle = inkOf(history[i]);
        ctx.fillRect(hx, hy, 38, 23);
        ctx.strokeStyle = "rgba(255,255,255,.2)";
        ctx.strokeRect(hx + 0.5, hy + 0.5, 37, 22);
        ctx.fillStyle = "#f2f6fa";
        ctx.textAlign = "center";
        ctx.fillText(String(history[i]), hx + 19, hy + 16);
        ctx.textAlign = "left";
      }

      // Итог спина крупно поверх колеса.
      if (phase === "result" && flashT > 0) {
        var alpha = Math.min(1, flashT * 2);
        ctx.textAlign = "center";
        ctx.fillStyle = "rgba(4,10,8," + (0.68 * alpha) + ")";
        ctx.fillRect(CX - 150, CY - 60, 300, 120);
        ctx.strokeStyle = won ? "rgba(99,245,173," + alpha + ")"
                              : "rgba(255,107,157," + alpha + ")";
        ctx.lineWidth = 2;
        ctx.strokeRect(CX - 149.5, CY - 59.5, 299, 119);
        ctx.fillStyle = inkOf(result);
        ctx.fillRect(CX - 36, CY - 46, 72, 52);
        ctx.strokeStyle = "rgba(255,255,255,.35)";
        ctx.lineWidth = 1;
        ctx.strokeRect(CX - 35.5, CY - 45.5, 71, 51);
        ctx.fillStyle = "#ffffff";
        ctx.font = 'bold 34px "Cascadia Code", Consolas, monospace';
        ctx.fillText(String(result), CX, CY - 8);
        ctx.font = 'bold 19px "Cascadia Code", Consolas, monospace';
        ctx.fillStyle = won ? "#63f5ad" : "#ff6b9d";
        ctx.fillText(won ? "+" + BETS[bet].pays + " · СЕРИЯ " + streak : "МИМО",
                     CX, CY + 40);
        ctx.textAlign = "left";
      }
    }

    /* Пока не крутили ни разу, поверх колеса висит короткое объяснение.
       После первой прокрутки исчезает навсегда и больше не мешает. */
    function drawRules() {
      if (spins > 0 || phase !== "idle") return;
      var bw = 322, bh = 176;
      ctx.fillStyle = "rgba(4,10,8,.92)";
      ctx.fillRect(CX - bw / 2, CY - bh / 2, bw, bh);
      ctx.strokeStyle = "rgba(201,162,74,.55)";
      ctx.lineWidth = 2;
      ctx.strokeRect(CX - bw / 2 + 1, CY - bh / 2 + 1, bw - 2, bh - 2);

      ctx.textAlign = "center";
      ctx.fillStyle = "#ffd84a";
      ctx.font = 'bold 16px "Cascadia Code", Consolas, monospace';
      ctx.fillText("КАК ЭТО РАБОТАЕТ", CX, CY - bh / 2 + 28);

      ctx.textAlign = "left";
      ctx.font = 'bold 12px "Cascadia Code", Consolas, monospace';
      var lines = [
        ["#8fa5b8", "В колесе 37 лунок: 0 и числа 1-36."],
        ["#8fa5b8", "Слева выбери, на что ставишь, и крути."],
        ["#63f5ad", "Угадал - очки по коэффициенту, серия +1."],
        ["#ff6b9d", "Ошибся - серия обрывается и уходит"],
        ["#ff6b9d", "в таблицу рекордов."],
        ["#c9a24a", "Чем реже событие, тем больше платит:"],
        ["#c9a24a", "цвет x1 (18 из 37), число x35 (1 из 37)."],
      ];
      var ly = CY - bh / 2 + 52;
      lines.forEach(function (l) {
        ctx.fillStyle = l[0];
        ctx.fillText(l[1], CX - bw / 2 + 16, ly);
        ly += 17;
      });
      ctx.textAlign = "left";
    }

    /* ── Ход времени ──────────────────────────────────────────────────── */
    function tick(dt) {
      if (phase === "spin") {
        spinT += dt;
        var t = Math.min(1, spinT / spinDur);
        var e = easeOut(t);
        wheelAngle = spinFrom + spinTurns * Math.PI * 2 * e;
        // Шарик приходит ровно в свою лунку: к концу добавка обнуляется.
        ballAngle = wheelAngle + ballTarget + ballTurns * Math.PI * 2 * (1 - e);
        // Сначала катится по борту, к финалу сваливается на дорожку лунок.
        var drop = Math.max(0, (t - 0.55) / 0.45);
        ballRadius = 0.97 - 0.14 * easeOut(drop);
        // Подскоки на перегородках у самого конца
        if (t > 0.82 && t < 0.99) {
          ballRadius += Math.sin((t - 0.82) * 90) * 0.012 * (0.99 - t) * 12;
        }
        if (t >= 1) settle();
      } else {
        wheelAngle += dt * 0.00018;           // между ставками колесо тихо крутится
        ballAngle = wheelAngle + ballTarget;
      }
      if (flashT > 0) flashT = Math.max(0, flashT - dt / 2600);
    }

    function loop(now) {
      if (!running) return;
      raf = requestAnimationFrame(loop);
      var dt = Math.min(50, now - lastFrame || 16);
      lastFrame = now;
      tick(dt);
      draw();
    }

    /* ── Управление ───────────────────────────────────────────────────── */
    function onKey(e) {
      var k = e.key;
      if (k === "ArrowUp" || k === "w" || k === "ц") { moveBet(-1); e.preventDefault(); }
      else if (k === "ArrowDown" || k === "s" || k === "ы") { moveBet(1); e.preventDefault(); }
      else if (k === "ArrowLeft" || k === "a" || k === "ф") { movePick(-1); e.preventDefault(); }
      else if (k === "ArrowRight" || k === "d" || k === "в") { movePick(1); e.preventDefault(); }
      else if (k === " " || k === "Enter") { spin(); e.preventDefault(); }
    }

    api.deck({
      pad: {
        up: function () { moveBet(-1); },
        down: function () { moveBet(1); },
        left: function () { movePick(-1); },
        right: function () { movePick(1); },
      },
      padBig: true,
      actions: [
        { icon: "replay", aria: "крутить", label: "", color: "#ff3fa4", big: true,
          down: spin },
      ],
    });

    document.addEventListener("keydown", onKey);
    lastFrame = performance.now();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        running = false;
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKey);
      },
    };
  }

  window.VitazArcade.register({
    id: "roulette",
    title: "РУЛЕТКА",
    tagline: "Европейское колесо с одним зеро, 37 лунок. Денег и фишек нет — есть серия: угадал " +
             "цвет или число, очки капнули по настоящему коэффициенту; промахнулся — всё сначала.",
    keys: "Вверх-вниз — на что ставишь · влево-вправо — номер · пробел — крутить",
    keysTouch: "Крестовина — ставка и номер · круглая кнопка — крутить",
    accent: "#c9a24a",
    thumb: thumb,
    start: start,
  });
})();
