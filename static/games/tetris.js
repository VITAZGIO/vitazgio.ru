/* Тетрис по современным правилам (SRS): семь фигур из мешка, вращение с
 * отталкиванием от стен, карман, очередь из пяти, тень, задержка фиксации,
 * T-спины, back-to-back и комбо. Всё поле, панели и цифры рисуются на канвасе,
 * поэтому вёрстка снаружи не нужна и ничего не разъезжает. */
(function () {
  "use strict";

  var COLS = 10, ROWS = 22, HIDDEN = 2;     // две верхние строки — зона появления
  var CELL = 32;
  var PANEL = 148;
  var PAD = 18;
  var BOARD_W = COLS * CELL, BOARD_H = (ROWS - HIDDEN) * CELL;
  var W = PANEL + BOARD_W + PANEL + PAD * 4;
  var H = BOARD_H + PAD * 2;
  var BX = PANEL + PAD * 2, BY = PAD;

  var COLORS = {
    I: "#31d0ef", J: "#4f6bff", L: "#ff9021", O: "#ffd422",
    S: "#43d15e", T: "#c04dd0", Z: "#ff3b53",
  };

  // Фигуры описаны построчно для каждого из четырёх поворотов: так поведение
  // в точности совпадает с эталонным SRS, без догадок про центр вращения.
  var SHAPES = {
    I: [["....", "XXXX", "....", "...."], ["..X.", "..X.", "..X.", "..X."],
        ["....", "....", "XXXX", "...."], [".X..", ".X..", ".X..", ".X.."]],
    J: [["X..", "XXX", "..."], [".XX", ".X.", ".X."],
        ["...", "XXX", "..X"], [".X.", ".X.", "XX."]],
    L: [["..X", "XXX", "..."], [".X.", ".X.", ".XX"],
        ["...", "XXX", "X.."], ["XX.", ".X.", ".X."]],
    O: [[".XX.", ".XX.", "....", "...."], [".XX.", ".XX.", "....", "...."],
        [".XX.", ".XX.", "....", "...."], [".XX.", ".XX.", "....", "...."]],
    S: [[".XX", "XX.", "..."], [".X.", ".XX", "..X"],
        ["...", ".XX", "XX."], ["X..", "XX.", ".X."]],
    T: [[".X.", "XXX", "..."], [".X.", ".XX", ".X."],
        ["...", "XXX", ".X."], [".X.", "XX.", ".X."]],
    Z: [["XX.", ".XX", "..."], ["..X", ".XX", ".X."],
        ["...", "XX.", ".XX"], [".X.", "XX.", "X.."]],
  };

  // Смещения при вращении у стены. В оригинальных таблицах ось Y смотрит вверх,
  // здесь строки растут вниз — поэтому знак Y уже перевёрнут.
  var KICKS_JLSTZ = {
    "01": [[0, 0], [-1, 0], [-1, -1], [0, 2], [-1, 2]],
    "10": [[0, 0], [1, 0], [1, 1], [0, -2], [1, -2]],
    "12": [[0, 0], [1, 0], [1, 1], [0, -2], [1, -2]],
    "21": [[0, 0], [-1, 0], [-1, -1], [0, 2], [-1, 2]],
    "23": [[0, 0], [1, 0], [1, -1], [0, 2], [1, 2]],
    "32": [[0, 0], [-1, 0], [-1, 1], [0, -2], [-1, -2]],
    "30": [[0, 0], [-1, 0], [-1, 1], [0, -2], [-1, -2]],
    "03": [[0, 0], [1, 0], [1, -1], [0, 2], [1, 2]],
  };
  var KICKS_I = {
    "01": [[0, 0], [-2, 0], [1, 0], [-2, 1], [1, -2]],
    "10": [[0, 0], [2, 0], [-1, 0], [2, -1], [-1, 2]],
    "12": [[0, 0], [-1, 0], [2, 0], [-1, -2], [2, 1]],
    "21": [[0, 0], [1, 0], [-2, 0], [1, 2], [-2, -1]],
    "23": [[0, 0], [2, 0], [-1, 0], [2, -1], [-1, 2]],
    "32": [[0, 0], [-2, 0], [1, 0], [-2, 1], [1, -2]],
    "30": [[0, 0], [1, 0], [-2, 0], [1, 2], [-2, -1]],
    "03": [[0, 0], [-1, 0], [2, 0], [-1, -2], [2, 1]],
  };

  var DAS = 150, ARR = 40, SOFT = 28, LOCK_DELAY = 500, LOCK_RESETS = 15;

  function cellsOf(type, rot) {
    var rows = SHAPES[type][rot], out = [];
    for (var y = 0; y < rows.length; y++) {
      for (var x = 0; x < rows[y].length; x++) {
        if (rows[y][x] === "X") out.push({ x: x, y: y });
      }
    }
    return out;
  }

  function gravityFor(level) {
    // Табличная формула: на первом уровне ~0.8 с на клетку, к двадцатому — кадры.
    var lv = Math.min(level, 20);
    return Math.pow(0.8 - (lv - 1) * 0.007, lv - 1) * 1000;
  }

  /* ── Отрисовка блока: скос сверху, тень снизу, лёгкий блик ───────────── */
  function block(ctx, px, py, size, color, opts) {
    opts = opts || {};
    var inset = opts.ghost ? 2 : 1;
    var x = px + inset, y = py + inset, s = size - inset * 2;
    if (opts.ghost) {
      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.45;
      ctx.lineWidth = 2;
      ctx.strokeRect(x + 1, y + 1, s - 2, s - 2);
      ctx.globalAlpha = 1;
      return;
    }
    var grad = ctx.createLinearGradient(x, y, x, y + s);
    grad.addColorStop(0, color);
    grad.addColorStop(1, shade(color, -0.34));
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, s, s);
    ctx.fillStyle = "rgba(255,255,255,.32)";
    ctx.fillRect(x, y, s, 3);
    ctx.fillRect(x, y, 3, s);
    ctx.fillStyle = "rgba(0,0,0,.32)";
    ctx.fillRect(x, y + s - 3, s, 3);
    ctx.fillRect(x + s - 3, y, 3, s);
    if (opts.flash) {
      ctx.fillStyle = "rgba(255,255,255," + opts.flash + ")";
      ctx.fillRect(x, y, s, s);
    }
  }

  function shade(hex, amount) {
    var n = parseInt(hex.slice(1), 16);
    var r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    var f = function (v) {
      return Math.max(0, Math.min(255, Math.round(v + (amount > 0 ? (255 - v) : v) * amount)));
    };
    return "rgb(" + f(r) + "," + f(g) + "," + f(b) + ")";
  }

  function thumb(ctx, w, h, t) {
    ctx.fillStyle = "#05070d";
    ctx.fillRect(0, 0, w, h);
    var size = 14, cols = 8, rows = Math.floor(h / size);
    var ox = (w - cols * size) / 2;
    ctx.strokeStyle = "rgba(255,255,255,.05)";
    ctx.strokeRect(ox, 0, cols * size, rows * size);
    // Стопка внизу плюс падающая фигура — статичная карточка выглядит мёртвой.
    var stack = [[0, 1, 1, 0, 1, 1, 1, 0], [1, 1, 1, 1, 0, 1, 1, 1]];
    var keys = ["I", "T", "L", "S", "Z", "J", "O"];
    for (var r = 0; r < stack.length; r++) {
      for (var c = 0; c < cols; c++) {
        if (!stack[r][c]) continue;
        block(ctx, ox + c * size, (rows - 2 + r) * size, size, COLORS[keys[(r + c) % 7]]);
      }
    }
    var fall = (t * 2.4) % (rows - 3);
    var piece = cellsOf("T", Math.floor(t) % 4);
    for (var i = 0; i < piece.length; i++) {
      block(ctx, ox + (3 + piece[i].x) * size, Math.floor(fall + piece[i].y) * size, size, COLORS.T);
    }
  }

  function start(root, api) {
    var canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    canvas.style.cssText = (api.touch
      ? "width:100%;height:auto;max-height:100%;"
      : "max-width:100%;max-height:100%;width:auto;height:auto;") +
      "min-height:0;object-fit:contain";
    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;" +
      "width:100%;max-height:100%;min-height:0";
    var tip = document.createElement("div");
    tip.style.cssText = "color:#4a6379;font-size:.64rem;letter-spacing:.09em;text-align:center;flex:none";
    tip.textContent = api.touch
      ? "КРЕСТОВИНА — ДВИГАТЬ И УСКОРИТЬ · КРУГЛЫЕ — ПОВОРОТ И СБРОС"
      : "← → — двигать · ↑/X — поворот · Z — против часовой · ↓ — ускорить · " +
        "ПРОБЕЛ — сбросить · C — карман · P — пауза";
    wrap.append(canvas, tip);
    root.appendChild(wrap);
    var ctx = canvas.getContext("2d");

    var board, bag, queue, hold, holdUsed, piece, score, lines, level, combo, b2b;
    var over, paused, dropTimer, lockTimer, lockResets, clearing, message, messageTime;
    var raf = 0, last = 0;
    var keyState = {}, dasTimer = 0, arrTimer = 0, dasDir = 0;

    function newBoard() {
      var b = [];
      for (var y = 0; y < ROWS; y++) {
        b.push(new Array(COLS).fill(null));
      }
      return b;
    }

    function refillBag() {
      var types = ["I", "J", "L", "O", "S", "T", "Z"];
      for (var i = types.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var tmp = types[i]; types[i] = types[j]; types[j] = tmp;
      }
      bag = bag.concat(types);
    }

    function nextType() {
      if (bag.length < 8) refillBag();
      return bag.shift();
    }

    function spawn(type) {
      var t = type || queue.shift();
      while (queue.length < 5) queue.push(nextType());
      var p = {
        type: t, rot: 0,
        x: t === "I" || t === "O" ? 3 : 3,
        y: 0,
        lastKick: 0, lastWasRotate: false,
      };
      if (collides(p, 0, 0, 0)) { over = true; api.best("tetris", score); flash("КОНЕЦ ИГРЫ"); }
      piece = p;
      holdUsed = false;
      lockTimer = 0; lockResets = 0;
      return p;
    }

    function collides(p, dx, dy, drot) {
      var rot = (p.rot + (drot || 0) + 4) % 4;
      var cells = cellsOf(p.type, rot);
      for (var i = 0; i < cells.length; i++) {
        var x = p.x + cells[i].x + dx;
        var y = p.y + cells[i].y + dy;
        if (x < 0 || x >= COLS || y >= ROWS) return true;
        if (y >= 0 && board[y][x]) return true;
      }
      return false;
    }

    function move(dx, dy) {
      if (collides(piece, dx, dy, 0)) return false;
      piece.x += dx; piece.y += dy;
      piece.lastWasRotate = false;
      if (dx !== 0) resetLock();
      return true;
    }

    function rotate(dir) {
      var from = piece.rot, to = (piece.rot + dir + 4) % 4;
      if (piece.type === "O") return false;
      var table = piece.type === "I" ? KICKS_I : KICKS_JLSTZ;
      var kicks = table["" + from + to] || [[0, 0]];
      for (var i = 0; i < kicks.length; i++) {
        var dx = kicks[i][0], dy = kicks[i][1];
        if (!collides(piece, dx, dy, dir)) {
          piece.x += dx; piece.y += dy; piece.rot = to;
          piece.lastWasRotate = true;
          piece.lastKick = i;
          resetLock();
          api.audio.tone(320, 0.05, { type: "square", volume: 0.07 });
          return true;
        }
      }
      return false;
    }

    function resetLock() {
      if (lockTimer > 0 && lockResets < LOCK_RESETS) { lockTimer = 0; lockResets++; }
    }

    function ghostY() {
      var dy = 0;
      while (!collides(piece, 0, dy + 1, 0)) dy++;
      return piece.y + dy;
    }

    // Правило трёх углов: T-спин засчитывается, когда после поворота фигура
    // заперта углами. «Передние» углы — те, куда смотрит выступ буквы T.
    function detectTSpin() {
      if (piece.type !== "T" || !piece.lastWasRotate) return null;
      var cx = piece.x + 1, cy = piece.y + 1;
      var corners = [[-1, -1], [1, -1], [1, 1], [-1, 1]];
      var filled = corners.map(function (c) {
        var x = cx + c[0], y = cy + c[1];
        return x < 0 || x >= COLS || y >= ROWS || (y >= 0 && !!board[y][x]);
      });
      var count = filled.filter(Boolean).length;
      if (count < 3) return null;
      var frontPairs = [[0, 1], [1, 2], [2, 3], [3, 0]];
      var pair = frontPairs[piece.rot];
      var frontFilled = (filled[pair[0]] ? 1 : 0) + (filled[pair[1]] ? 1 : 0);
      if (frontFilled === 2) return "full";
      return piece.lastKick >= 3 ? "full" : "mini";
    }

    function lockPiece() {
      var tspin = detectTSpin();
      var cells = cellsOf(piece.type, piece.rot);
      for (var i = 0; i < cells.length; i++) {
        var x = piece.x + cells[i].x, y = piece.y + cells[i].y;
        if (y >= 0) board[y][x] = piece.type;
      }
      api.audio.tone(150, 0.06, { type: "triangle", volume: 0.08 });

      var full = [];
      for (var y2 = 0; y2 < ROWS; y2++) {
        var complete = true;
        for (var x2 = 0; x2 < COLS; x2++) { if (!board[y2][x2]) { complete = false; break; } }
        if (complete) full.push(y2);
      }

      if (full.length) {
        clearing = { rows: full, time: 0, tspin: tspin };
        award(full.length, tspin);
      } else {
        if (tspin) { award(0, tspin); }
        else { combo = -1; }
        piece = null;
        spawn();
      }
    }

    function award(cleared, tspin) {
      var base = 0, name = "";
      if (tspin === "full") {
        base = [400, 800, 1200, 1600][cleared];
        name = ["T-СПИН", "T-СПИН СИНГЛ", "T-СПИН ДАБЛ", "T-СПИН ТРИПЛ"][cleared];
      } else if (tspin === "mini") {
        base = [100, 200, 400, 400][cleared];
        name = cleared ? "МИНИ T-СПИН" : "МИНИ T-СПИН";
      } else {
        base = [0, 100, 300, 500, 800][cleared];
        name = ["", "", "ДАБЛ", "ТРИПЛ", "ТЕТРИС"][cleared];
      }
      var difficult = (cleared === 4) || (tspin && cleared > 0);
      if (difficult && b2b) { base = Math.round(base * 1.5); name = "B2B " + name; }
      if (cleared > 0) b2b = difficult;

      if (cleared > 0) { combo++; } else { combo = -1; }
      var comboBonus = combo > 0 ? 50 * combo * level : 0;
      score += base * level + comboBonus;
      lines += cleared;
      var newLevel = Math.floor(lines / 10) + 1;
      if (newLevel > level) {
        level = newLevel;
        api.audio.tone(660, 0.12, { type: "square", volume: 0.12, slideTo: 990 });
      }
      if (name) flash(name + (combo > 0 ? "  ×" + (combo + 1) : ""));

      if (cleared === 4) {
        api.audio.tone(520, 0.3, { type: "sawtooth", volume: 0.14, slideTo: 1040 });
        api.audio.noise(0.3, { volume: 0.12, freq: 2400, freqTo: 400 });
      } else if (cleared > 0) {
        api.audio.tone(400 + cleared * 90, 0.14, { type: "square", volume: 0.11 });
      }
      api.best("tetris", score);
    }

    function flash(text) { message = text; messageTime = 1400; }

    function finishClear() {
      var rows = clearing.rows.slice().sort(function (a, b) { return a - b; });
      for (var i = 0; i < rows.length; i++) {
        board.splice(rows[i], 1);
        board.unshift(new Array(COLS).fill(null));
      }
      clearing = null;
      piece = null;
      spawn();
    }

    function doHold() {
      if (holdUsed || !piece) return;
      var current = piece.type;
      if (hold) { var swap = hold; hold = current; piece = null; spawn(swap); }
      else { hold = current; piece = null; spawn(); }
      holdUsed = true;
      api.audio.tone(240, 0.07, { type: "triangle", volume: 0.09 });
    }

    function hardDrop() {
      var dy = 0;
      while (!collides(piece, 0, dy + 1, 0)) dy++;
      piece.y += dy;
      score += dy * 2;
      piece.lastWasRotate = false;
      api.audio.noise(0.09, { volume: 0.13, freq: 900, freqTo: 160 });
      lockPiece();
    }

    function reset() {
      board = newBoard();
      bag = []; queue = [];
      refillBag();
      while (queue.length < 5) queue.push(nextType());
      hold = null; holdUsed = false;
      score = 0; lines = 0; level = 1; combo = -1; b2b = false;
      over = false; paused = false; clearing = null;
      dropTimer = 0; lockTimer = 0; lockResets = 0;
      message = ""; messageTime = 0;
      piece = null;
      spawn();
    }

    /* ── Отрисовка ──────────────────────────────────────────────────────── */
    function panelBox(x, y, w, h, title) {
      ctx.fillStyle = "rgba(10,16,26,.9)";
      ctx.fillRect(x, y, w, h);
      ctx.strokeStyle = "rgba(255,255,255,.09)";
      ctx.lineWidth = 1;
      ctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
      ctx.fillStyle = "#4a6379";
      ctx.font = '700 11px "Cascadia Code", Consolas, monospace';
      ctx.textAlign = "left";
      ctx.fillText(title, x + 10, y + 18);
    }

    function drawMini(type, cx, cy, size) {
      var cells = cellsOf(type, 0);
      var minX = 9, maxX = -9, minY = 9, maxY = -9;
      cells.forEach(function (c) {
        minX = Math.min(minX, c.x); maxX = Math.max(maxX, c.x);
        minY = Math.min(minY, c.y); maxY = Math.max(maxY, c.y);
      });
      var w = (maxX - minX + 1) * size, h = (maxY - minY + 1) * size;
      cells.forEach(function (c) {
        block(ctx, cx - w / 2 + (c.x - minX) * size, cy - h / 2 + (c.y - minY) * size,
              size, COLORS[type]);
      });
    }

    function draw(dt) {
      ctx.fillStyle = "#080b12";
      ctx.fillRect(0, 0, W, H);

      // Поле
      ctx.fillStyle = "#05070d";
      ctx.fillRect(BX, BY, BOARD_W, BOARD_H);
      ctx.strokeStyle = "rgba(255,255,255,.05)";
      ctx.lineWidth = 1;
      for (var gx = 1; gx < COLS; gx++) {
        ctx.beginPath(); ctx.moveTo(BX + gx * CELL + 0.5, BY);
        ctx.lineTo(BX + gx * CELL + 0.5, BY + BOARD_H); ctx.stroke();
      }
      for (var gy = 1; gy < ROWS - HIDDEN; gy++) {
        ctx.beginPath(); ctx.moveTo(BX, BY + gy * CELL + 0.5);
        ctx.lineTo(BX + BOARD_W, BY + gy * CELL + 0.5); ctx.stroke();
      }

      var flashAmount = 0;
      if (clearing) {
        clearing.time += dt;
        flashAmount = Math.max(0, 1 - clearing.time / 260);
        if (clearing.time >= 260) { finishClear(); }
      }

      for (var y = HIDDEN; y < ROWS; y++) {
        for (var x = 0; x < COLS; x++) {
          var t = board[y] && board[y][x];
          if (!t) continue;
          var isClearing = clearing && clearing.rows.indexOf(y) >= 0;
          block(ctx, BX + x * CELL, BY + (y - HIDDEN) * CELL, CELL, COLORS[t],
                isClearing ? { flash: flashAmount } : null);
        }
      }

      if (piece && !clearing) {
        var gy2 = ghostY();
        var cells = cellsOf(piece.type, piece.rot);
        var i;
        for (i = 0; i < cells.length; i++) {
          var ghY = gy2 + cells[i].y;
          if (ghY >= HIDDEN) {
            block(ctx, BX + (piece.x + cells[i].x) * CELL, BY + (ghY - HIDDEN) * CELL,
                  CELL, COLORS[piece.type], { ghost: true });
          }
        }
        for (i = 0; i < cells.length; i++) {
          var py = piece.y + cells[i].y;
          if (py >= HIDDEN) {
            block(ctx, BX + (piece.x + cells[i].x) * CELL, BY + (py - HIDDEN) * CELL,
                  CELL, COLORS[piece.type]);
          }
        }
      }

      ctx.strokeStyle = "rgba(45,226,255,.28)";
      ctx.lineWidth = 2;
      ctx.strokeRect(BX - 1, BY - 1, BOARD_W + 2, BOARD_H + 2);

      // Левая колонка: карман и статистика
      var lx = PAD, ly = BY;
      panelBox(lx, ly, PANEL, 116, "КАРМАН");
      if (hold) {
        ctx.globalAlpha = holdUsed ? 0.35 : 1;
        drawMini(hold, lx + PANEL / 2, ly + 68, 22);
        ctx.globalAlpha = 1;
      }
      var stats = [["ОЧКИ", String(score)], ["РЕКОРД", String(Math.max(score, api.best("tetris")))],
                   ["ЛИНИИ", String(lines)], ["УРОВЕНЬ", String(level)]];
      var sy = ly + 132;
      for (var s = 0; s < stats.length; s++) {
        panelBox(lx, sy, PANEL, 58, stats[s][0]);
        ctx.fillStyle = "#eaf6ff";
        ctx.font = '700 21px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "right";
        ctx.fillText(stats[s][1], lx + PANEL - 12, sy + 45);
        sy += 66;
      }

      // Правая колонка: очередь
      var rx = BX + BOARD_W + PAD, ry = BY;
      panelBox(rx, ry, PANEL, 300, "ДАЛЬШE");
      for (var q = 0; q < Math.min(5, queue.length); q++) {
        ctx.globalAlpha = q === 0 ? 1 : 0.75 - q * 0.09;
        drawMini(queue[q], rx + PANEL / 2, ry + 58 + q * 54, q === 0 ? 20 : 17);
        ctx.globalAlpha = 1;
      }
      panelBox(rx, ry + 316, PANEL, 58, "КОМБО");
      ctx.fillStyle = combo > 0 ? "#ffb35c" : "#2b3a4a";
      ctx.font = '700 21px "Cascadia Code", Consolas, monospace';
      ctx.textAlign = "right";
      ctx.fillText(combo > 0 ? "×" + (combo + 1) : "—", rx + PANEL - 12, ry + 361);
      if (b2b) {
        ctx.fillStyle = "#ff3fa4";
        ctx.font = '700 12px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "left";
        ctx.fillText("BACK-TO-BACK", rx + 10, ry + 392);
      }

      // Всплывающая подпись про тетрис/спин
      if (messageTime > 0) {
        messageTime -= dt;
        var alpha = Math.min(1, messageTime / 420);
        ctx.globalAlpha = alpha;
        ctx.textAlign = "center";
        ctx.fillStyle = "#ff3fa4";
        ctx.font = '700 26px "Cascadia Code", Consolas, monospace';
        ctx.fillText(message, BX + BOARD_W / 2, BY + BOARD_H / 2);
        ctx.globalAlpha = 1;
      }

      if (over || paused) {
        ctx.fillStyle = "rgba(4,6,11,.86)";
        ctx.fillRect(BX, BY, BOARD_W, BOARD_H);
        ctx.textAlign = "center";
        ctx.fillStyle = over ? "#ff6b81" : "#ffb35c";
        ctx.font = '700 30px "Cascadia Code", Consolas, monospace';
        ctx.fillText(over ? "КОНЕЦ ИГРЫ" : "ПАУЗА", BX + BOARD_W / 2, BY + BOARD_H / 2 - 10);
        ctx.fillStyle = "#8fa5b8";
        ctx.font = '600 14px "Cascadia Code", Consolas, monospace';
        if (over) {
          ctx.fillText("Очков: " + score, BX + BOARD_W / 2, BY + BOARD_H / 2 + 22);
        }
        ctx.fillStyle = "#4a6379";
        ctx.font = '600 12px "Cascadia Code", Consolas, monospace';
        ctx.fillText(over ? "ENTER — заново" : "P — продолжить",
                     BX + BOARD_W / 2, BY + BOARD_H / 2 + 50);
      }
    }

    /* ── Ввод ─────────────────────────────────────────────────────────────
       Клавиатура и панель на телефоне дёргают одни и те же действия, чтобы
       автоповтор и удержание вели себя одинаково. */
    function actionDown(name) {
      if (name === "restart") { if (over) reset(); return; }
      if (name === "pause") { if (!over) paused = !paused; return; }
      if (over || paused || !piece) return;
      switch (name) {
        case "left": move(-1, 0); dasDir = -1; dasTimer = DAS; arrTimer = 0; break;
        case "right": move(1, 0); dasDir = 1; dasTimer = DAS; arrTimer = 0; break;
        case "softdrop": keyState.ArrowDown = true; break;
        case "cw": rotate(1); break;
        case "ccw": rotate(-1); break;
        case "flip": rotate(2); break;
        case "drop": hardDrop(); break;
        case "hold": doHold(); break;
      }
    }

    function actionUp(name) {
      if (name === "left" && dasDir === -1) dasDir = 0;
      if (name === "right" && dasDir === 1) dasDir = 0;
      if (name === "softdrop") keyState.ArrowDown = false;
    }

    function onKeyDown(e) {
      var k = e.key;
      var lower = k.length === 1 ? k.toLowerCase() : k;
      if (k === "Enter" && over) { reset(); e.preventDefault(); return; }
      if (lower === "p" || lower === "з") {
        if (!over) { paused = !paused; }
        e.preventDefault(); return;
      }
      if (over || paused || !piece) return;
      if (keyState[k]) { e.preventDefault(); return; }   // автоповтор системы игнорируем
      keyState[k] = true;

      if (k === "ArrowLeft") { actionDown("left"); e.preventDefault(); }
      else if (k === "ArrowRight") { actionDown("right"); e.preventDefault(); }
      else if (k === "ArrowDown") { e.preventDefault(); }
      else if (k === "ArrowUp" || lower === "x" || lower === "ч") { actionDown("cw"); e.preventDefault(); }
      else if (lower === "z" || lower === "я" || k === "Control") { actionDown("ccw"); e.preventDefault(); }
      else if (lower === "a" || lower === "ф") { actionDown("flip"); e.preventDefault(); }
      else if (k === " ") { actionDown("drop"); e.preventDefault(); }
      else if (lower === "c" || lower === "с" || k === "Shift") { actionDown("hold"); e.preventDefault(); }
    }

    function onKeyUp(e) {
      keyState[e.key] = false;
      if ((e.key === "ArrowLeft" && dasDir === -1) || (e.key === "ArrowRight" && dasDir === 1)) {
        dasDir = 0;
      }
    }

    function handleAutoRepeat(dt) {
      if (!dasDir || over || paused || !piece) return;
      if (dasTimer > 0) {
        dasTimer -= dt;
        if (dasTimer <= 0) { arrTimer = 0; move(dasDir, 0); }
        return;
      }
      arrTimer -= dt;
      while (arrTimer <= 0) { move(dasDir, 0); arrTimer += ARR; }
    }

    function tick(dt) {
      if (over || paused || clearing) return;
      handleAutoRepeat(dt);
      var gravity = gravityFor(level);
      if (keyState.ArrowDown) gravity = Math.min(gravity, SOFT);
      dropTimer += dt;
      while (dropTimer >= gravity) {
        dropTimer -= gravity;
        if (!collides(piece, 0, 1, 0)) {
          piece.y++;
          piece.lastWasRotate = false;
          if (keyState.ArrowDown) score += 1;
        } else {
          break;
        }
      }
      if (collides(piece, 0, 1, 0)) {
        lockTimer += dt;
        if (lockTimer >= LOCK_DELAY) lockPiece();
      } else {
        lockTimer = 0;
      }
    }

    function loop(now) {
      raf = requestAnimationFrame(loop);
      var dt = Math.min(64, now - last || 16);
      last = now;
      tick(dt);
      draw(dt);
    }

    function padButton(name) {
      return { down: function () { actionDown(name); }, up: function () { actionUp(name); } };
    }

    api.deck({
      pad: {
        // Вверх — поворот, как на приставках: иначе верхний луч крестовины
        // пустует, а самое частое действие уезжает на дальнюю кнопку.
        up: { down: function () { actionDown("cw"); } },
        left: padButton("left"),
        right: padButton("right"),
        down: padButton("softdrop"),
      },
      actions: [
        { icon: "ccw", aria: "поворот против часовой", color: "#2de2ff",
          down: function () { actionDown("ccw"); } },
        { icon: "cw", aria: "поворот по часовой", color: "#2de2ff",
          down: function () { actionDown("cw"); } },
        { icon: "drop", aria: "сбросить", color: "#ff3fa4", big: true,
          down: function () { actionDown("drop"); } },
      ],
      extra: [
        { icon: "hold", label: "Карман", down: function () { actionDown("hold"); } },
        { icon: "pause", label: "Пауза", down: function () { actionDown("pause"); } },
        { icon: "replay", label: "Заново", down: function () { reset(); } },
      ],
    });

    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("keyup", onKeyUp);
    reset();
    last = performance.now();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKeyDown);
        document.removeEventListener("keyup", onKeyUp);
      },
    };
  }

  window.VitazArcade.register({
    id: "tetris",
    title: "ТЕТРИС",
    tagline: "Правила современного тетриса: мешок из семи фигур, отталкивание от стен, карман, тень и T-спины.",
    keys: "← → ↓ · ↑/X поворот · пробел — сброс · C — карман",
    keysTouch: "Крестовина: вверх — поворот · круглые — поворот и сброс",
    accent: "#ffd422",
    thumb: thumb,
    start: start,
  });
})();
