/* Змейка. Та же, что была на главной по коду Konami, только с нормальной
 * отрисовкой: плавное движение между клетками, свечение, частицы и разгон. */
(function () {
  "use strict";

  var COLS = 26, ROWS = 20, CELL = 26;
  var W = COLS * CELL, H = ROWS * CELL;
  var HEAD = "#7df9ff", BODY = "#2de2ff", FOOD = "#ff782f";

  function thumb(ctx, w, h, t) {
    ctx.fillStyle = "#05070d";
    ctx.fillRect(0, 0, w, h);
    var cell = 16, cols = Math.floor(w / cell), rows = Math.floor(h / cell);
    ctx.strokeStyle = "rgba(255,255,255,.05)";
    ctx.lineWidth = 1;
    for (var x = 0; x <= cols; x++) {
      ctx.beginPath(); ctx.moveTo(x * cell, 0); ctx.lineTo(x * cell, rows * cell); ctx.stroke();
    }
    for (var y = 0; y <= rows; y++) {
      ctx.beginPath(); ctx.moveTo(0, y * cell); ctx.lineTo(cols * cell, y * cell); ctx.stroke();
    }
    // Змейка ползёт по кругу — просто чтобы карточка не была статичной.
    var path = [];
    for (var i = 0; i < cols - 4; i++) path.push([2 + i, 2]);
    for (var j = 0; j < rows - 4; j++) path.push([cols - 3, 2 + j]);
    for (var k = 0; k < cols - 4; k++) path.push([cols - 3 - k, rows - 3]);
    for (var m = 0; m < rows - 4; m++) path.push([2, rows - 3 - m]);
    var head = Math.floor(t * 9) % path.length;
    for (var s = 0; s < 11; s++) {
      var p = path[(head - s + path.length * 2) % path.length];
      ctx.fillStyle = s === 0 ? HEAD : "rgba(45,226,255," + (0.85 - s * 0.06) + ")";
      ctx.fillRect(p[0] * cell + 2, p[1] * cell + 2, cell - 4, cell - 4);
    }
    var fp = path[(head + 14) % path.length];
    ctx.fillStyle = FOOD;
    ctx.shadowColor = FOOD; ctx.shadowBlur = 10;
    ctx.fillRect(fp[0] * cell + 4, fp[1] * cell + 4, cell - 8, cell - 8);
    ctx.shadowBlur = 0;
  }

  function start(root, api) {
    // Свечение через shadowBlur перерисовывается для каждого сегмента и на
    // телефоне режет частоту кадров вдвое. Там рисуем без него.
    var GLOW = !api.touch;

    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;" +
      "width:100%;height:100%;max-height:100%;min-height:0";
    var hud = document.createElement("div");
    hud.style.cssText = "display:flex;gap:18px;flex:none;font:700 .8rem " + api.font +
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
      ? "КРЕСТОВИНА — ДВИЖЕНИЕ · СВАЙП ПО ЭКРАНУ ТОЖЕ РАБОТАЕТ"
      : "СТРЕЛКИ ИЛИ WASD — ДВИЖЕНИЕ · ПРОБЕЛ — ПАУЗА · ENTER — ЗАНОВО";
    wrap.append(hud, canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d");
    var snake, dir, queue, food, score, alive, paused, speed, particles, shake;
    var lastStep = 0, raf = 0, prevSnake = null;

    function rnd(n) { return Math.floor(Math.random() * n); }

    function placeFood() {
      var free = [];
      for (var x = 0; x < COLS; x++) {
        for (var y = 0; y < ROWS; y++) {
          var busy = false;
          for (var i = 0; i < snake.length; i++) {
            if (snake[i].x === x && snake[i].y === y) { busy = true; break; }
          }
          if (!busy) free.push({ x: x, y: y });
        }
      }
      food = free.length ? free[rnd(free.length)] : { x: 0, y: 0 };
    }

    function reset() {
      snake = [{ x: 12, y: 10 }, { x: 11, y: 10 }, { x: 10, y: 10 }];
      prevSnake = snake.map(function (s) { return { x: s.x, y: s.y }; });
      dir = { x: 1, y: 0 };
      queue = [];
      score = 0; alive = true; paused = false;
      speed = 130; particles = []; shake = 0;
      placeFood();
      lastStep = performance.now();
    }

    function hud_() {
      hud.innerHTML =
        '<span style="color:#2de2ff">ОЧКИ: ' + score + '</span>' +
        '<span>РЕКОРД: ' + api.best("snake") + '</span>' +
        '<span>ДЛИНА: ' + snake.length + '</span>' +
        (paused ? '<span style="color:#ffb35c">ПАУЗА</span>' : '');
    }

    function step() {
      // Повороты копим в очередь: иначе за один шаг можно развернуться на 180°
      // двумя быстрыми нажатиями и въехать в собственную шею.
      if (queue.length) {
        var next = queue.shift();
        if (!(next.x === -dir.x && next.y === -dir.y)) dir = next;
      }
      prevSnake = snake.map(function (s) { return { x: s.x, y: s.y }; });
      var head = {
        x: (snake[0].x + dir.x + COLS) % COLS,
        y: (snake[0].y + dir.y + ROWS) % ROWS,
      };
      for (var i = 0; i < snake.length - 1; i++) {
        if (snake[i].x === head.x && snake[i].y === head.y) {
          alive = false;
          shake = 14;
          api.buzz([70, 50, 160]);
          api.audio.noise(0.35, { volume: 0.25, freq: 700, freqTo: 90, decay: 1.6 });
          api.audio.tone(180, 0.5, { type: "sawtooth", slideTo: 40, volume: 0.14 });
          api.best("snake", score);
          if (api.record) api.record("snake", score);
          return;
        }
      }
      snake.unshift(head);
      if (head.x === food.x && head.y === food.y) {
        score += 10;
        speed = Math.max(58, speed - 2.4);   // разгон, но не до неиграбельного
        for (var p = 0; p < 16; p++) {
          particles.push({
            x: (food.x + 0.5) * CELL, y: (food.y + 0.5) * CELL,
            vx: (Math.random() - 0.5) * 5, vy: (Math.random() - 0.5) * 5,
            life: 1,
          });
        }
        api.buzz(12);
        api.audio.tone(520 + Math.min(600, score * 4), 0.09, { type: "square", volume: 0.13 });
        placeFood();
      } else {
        snake.pop();
      }
      hud_();
    }

    function roundRect(c, x, y, w, h, r) {
      c.beginPath();
      c.moveTo(x + r, y);
      c.arcTo(x + w, y, x + w, y + h, r);
      c.arcTo(x + w, y + h, x, y + h, r);
      c.arcTo(x, y + h, x, y, r);
      c.arcTo(x, y, x + w, y, r);
      c.closePath();
    }

    function draw(alpha, now) {
      ctx.save();
      if (shake > 0) {
        ctx.translate((Math.random() - 0.5) * shake, (Math.random() - 0.5) * shake);
        shake *= 0.85;
        if (shake < 0.4) shake = 0;
      }
      ctx.fillStyle = "#05070d";
      ctx.fillRect(-20, -20, W + 40, H + 40);

      ctx.strokeStyle = "rgba(255,255,255,.035)";
      ctx.lineWidth = 1;
      for (var x = 0; x <= COLS; x++) {
        ctx.beginPath(); ctx.moveTo(x * CELL, 0); ctx.lineTo(x * CELL, H); ctx.stroke();
      }
      for (var y = 0; y <= ROWS; y++) {
        ctx.beginPath(); ctx.moveTo(0, y * CELL); ctx.lineTo(W, y * CELL); ctx.stroke();
      }

      // Еда пульсирует, чтобы её было видно боковым зрением.
      var pulse = 1 + Math.sin(now / 160) * 0.12;
      var fs = (CELL - 8) * pulse;
      if (GLOW) { ctx.shadowColor = FOOD; ctx.shadowBlur = 18; }
      ctx.fillStyle = FOOD;
      roundRect(ctx, (food.x + 0.5) * CELL - fs / 2, (food.y + 0.5) * CELL - fs / 2, fs, fs, 4);
      ctx.fill();
      ctx.shadowBlur = 0;

      for (var i = particles.length - 1; i >= 0; i--) {
        var p = particles[i];
        p.x += p.vx; p.y += p.vy; p.vy += 0.12; p.life -= 0.035;
        if (p.life <= 0) { particles.splice(i, 1); continue; }
        ctx.fillStyle = "rgba(255,120,47," + p.life + ")";
        ctx.fillRect(p.x - 2, p.y - 2, 4, 4);
      }

      // Тело рисуем с интерполяцией между шагами — иначе движение дёргается.
      if (GLOW) { ctx.shadowColor = BODY; ctx.shadowBlur = 12; }
      for (var s = snake.length - 1; s >= 0; s--) {
        var cur = snake[s];
        var old = prevSnake[Math.min(s, prevSnake.length - 1)] || cur;
        var dx = cur.x - old.x, dy = cur.y - old.y;
        // Через край поля не интерполируем: змейка «телепортируется» честно.
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1) { old = cur; dx = dy = 0; }
        var px = (old.x + dx * alpha) * CELL;
        var py = (old.y + dy * alpha) * CELL;
        var pad = s === 0 ? 1.5 : 2;      // сегменты должны смыкаться, а не висеть бусами
        ctx.fillStyle = s === 0 ? HEAD
          : "rgba(45,226,255," + Math.max(0.28, 0.92 - s * 0.02) + ")";
        roundRect(ctx, px + pad, py + pad, CELL - pad * 2, CELL - pad * 2, s === 0 ? 7 : 5);
        ctx.fill();

        if (s === 0) {
          if (GLOW) ctx.shadowBlur = 0;
          ctx.fillStyle = "#04121c";
          var ex = px + CELL / 2, ey = py + CELL / 2;
          var ox = dir.x * 4, oy = dir.y * 4;
          var sx = dir.x ? 0 : 4, sy = dir.y ? 0 : 4;
          ctx.fillRect(ex + ox - sx - 2, ey + oy - sy - 2, 3, 3);
          ctx.fillRect(ex + ox + sx - 1, ey + oy + sy - 1, 3, 3);
          if (GLOW) { ctx.shadowColor = BODY; ctx.shadowBlur = 12; }
        }
      }
      ctx.shadowBlur = 0;

      if (!alive) {
        ctx.fillStyle = "rgba(4,6,11,.82)";
        ctx.fillRect(0, 0, W, H);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ff6b81";
        ctx.font = '700 34px "Cascadia Code", Consolas, monospace';
        ctx.fillText("КОНЕЦ ИГРЫ", W / 2, H / 2 - 16);
        ctx.fillStyle = "#dfeffa";
        ctx.font = '600 17px "Cascadia Code", Consolas, monospace';
        ctx.fillText("Очков: " + score + "   ·   Рекорд: " + api.best("snake"), W / 2, H / 2 + 18);
        ctx.fillStyle = "#4a6379";
        ctx.font = '600 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ENTER — заново    ESCAPE — в меню", W / 2, H / 2 + 48);
      } else if (paused) {
        ctx.fillStyle = "rgba(4,6,11,.7)";
        ctx.fillRect(0, 0, W, H);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ffb35c";
        ctx.font = '700 28px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ПАУЗА", W / 2, H / 2);
      }
      ctx.restore();
    }

    function loop(now) {
      raf = requestAnimationFrame(loop);
      if (alive && !paused) {
        while (now - lastStep >= speed) {
          lastStep += speed;
          step();
          if (!alive) break;
        }
      } else {
        lastStep = now;
      }
      var alpha = alive && !paused ? Math.min(1, (now - lastStep) / speed) : 1;
      draw(alpha, now);
    }

    var DIRS = {
      ArrowUp: { x: 0, y: -1 }, ArrowDown: { x: 0, y: 1 },
      ArrowLeft: { x: -1, y: 0 }, ArrowRight: { x: 1, y: 0 },
      w: { x: 0, y: -1 }, s: { x: 0, y: 1 }, a: { x: -1, y: 0 }, d: { x: 1, y: 0 },
      ц: { x: 0, y: -1 }, ы: { x: 0, y: 1 }, ф: { x: -1, y: 0 }, в: { x: 1, y: 0 },
    };

    function onKey(e) {
      var key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      if (key === "enter") { /* нижний регистр не для Enter */ }
      if (e.key === "Enter") {
        if (!alive) { reset(); hud_(); }
        e.preventDefault();
        return;
      }
      if (e.key === " ") {
        if (alive) { paused = !paused; hud_(); }
        e.preventDefault();
        return;
      }
      var nd = DIRS[key];
      if (nd) {
        var last = queue.length ? queue[queue.length - 1] : dir;
        if (!(nd.x === -last.x && nd.y === -last.y) && !(nd.x === last.x && nd.y === last.y)) {
          if (queue.length < 2) queue.push(nd);
        }
        e.preventDefault();
      }
    }

    // Свайпы — чтобы играть можно было и с телефона.
    var touchStart = null;
    canvas.addEventListener("touchstart", function (e) {
      touchStart = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    }, { passive: true });
    canvas.addEventListener("touchend", function (e) {
      if (!touchStart) return;
      var t = e.changedTouches[0];
      var dx = t.clientX - touchStart.x, dy = t.clientY - touchStart.y;
      if (Math.abs(dx) < 24 && Math.abs(dy) < 24) { if (alive) paused = !paused; hud_(); return; }
      var nd = Math.abs(dx) > Math.abs(dy)
        ? { x: dx > 0 ? 1 : -1, y: 0 } : { x: 0, y: dy > 0 ? 1 : -1 };
      var last = queue.length ? queue[queue.length - 1] : dir;
      if (!(nd.x === -last.x && nd.y === -last.y) && queue.length < 2) queue.push(nd);
      touchStart = null;
    }, { passive: true });

    // Поворот из панели идёт по тому же пути, что и стрелка на клавиатуре.
    function turn(x, y) {
      var nd = { x: x, y: y };
      var last = queue.length ? queue[queue.length - 1] : dir;
      if ((nd.x === -last.x && nd.y === -last.y) || (nd.x === last.x && nd.y === last.y)) return;
      if (queue.length < 2) queue.push(nd);
    }

    api.deck({
      pad: {
        up: function () { turn(0, -1); },
        down: function () { turn(0, 1); },
        left: function () { turn(-1, 0); },
        right: function () { turn(1, 0); },
      },
      // Крестовина крупная и по центру — в змейке кроме неё ничего не нужно,
      // а пауза с рестартом уходят мелочью по краям, чтобы не мешались.
      padBig: true,
      side: [
        { icon: "pause", aria: "пауза",
          down: function () { if (alive) { paused = !paused; hud_(); } } },
        { icon: "replay", aria: "заново",
          down: function () { reset(); hud_(); } },
      ],
    });

    document.addEventListener("keydown", onKey);
    reset();
    hud_();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKey);
      },
    };
  }

  window.VitazArcade.register({
    id: "snake",
    title: "ЗМЕЙКА",
    tagline: "Классика без стен: поле закольцовано, скорость растёт с каждой съеденной точкой.",
    keys: "Стрелки / WASD · пробел — пауза",
    keysTouch: "Крестовина · пауза и рестарт на панели",
    accent: "#2de2ff",
    thumb: thumb,
    start: start,
  });
})();
