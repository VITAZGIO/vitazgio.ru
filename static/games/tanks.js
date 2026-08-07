/* Танчики — по мотивам Battle City с денди.
 *
 * Поле 26x26 клеток по 16 пикселей, танк размером в две клетки. Кирпич
 * лежит блоками два на два и выбивается блоком целиком, броня не берётся
 * вовсе, штаб внизу по центру.
 * Проиграл, если снесли штаб или кончились жизни.
 *
 * Враги ходят по простому правилу: едут вперёд, упёрлись — поворачивают,
 * иногда сворачивают сами, и чем дальше уровень, тем чаще целятся в штаб.
 * Полноценный поиск пути тут лишний: в оригинале его тоже не было, и именно
 * из-за этой бестолковости за ними и весело гоняться.
 */
(function () {
  "use strict";

  var N = 26, S = 16, W = N * S, H = N * S;
  var EMPTY = 0, BRICK = 1, STEEL = 2, BASE = 3, DEAD = 4;

  var C = {
    brick: "#a4553a", brickDark: "#6d3524", steel: "#9fb2c4", steelDark: "#5c6f80",
    me: "#f2d16b", meDark: "#a8873a", foe: "#cfd8e3", foeDark: "#7c8a9b",
    fast: "#63f5ad", heavy: "#ff6b9d", base: "#ffd84a", bg: "#05070d",
  };

  /* Карты: 13 строк по 13 символов, каждая клетка карты — 2x2 клетки поля.
     # кирпич, @ броня, . пусто. Штаб дорисовывается сам. */
  var MAPS = [
    ["....#....#...",
     ".##.#.##.#.##",
     ".##.#.##.#.##",
     "....#....#...",
     "##.###.###.##",
     ".............",
     ".#.@..@..@.#.",
     ".#.........#.",
     "..###...###..",
     ".............",
     ".##.#####.##.",
     ".##.......##.",
     "....#...#...."],

    ["#####...#####",
     "#...#.#.#...#",
     "#.#.....#.#.#",
     "..#..###..#..",
     ".....#@#.....",
     "###.......###",
     "..#.@...@.#..",
     "..#.......#..",
     "###.#####.###",
     "....#...#....",
     ".##.......##.",
     ".##.#####.##.",
     "....#...#...."],

    ["..@.......@..",
     ".###.....###.",
     ".#.#.###.#.#.",
     ".#...#.#...#.",
     "...#.....#...",
     "##.#..#..#.##",
     "...@.###.@...",
     "##.#.....#.##",
     "...#..#..#...",
     ".####...####.",
     ".....###.....",
     ".###.....###.",
     "...#.....#..."],

    ["#.#.#.#.#.#.#",
     ".............",
     "#.@@.....@@.#",
     ".............",
     "#.#..###..#.#",
     "....#...#....",
     "@.#.......#.@",
     "....#...#....",
     "#.#..###..#.#",
     ".............",
     "#.@@.....@@.#",
     ".............",
     "#.#.#.#.#.#.#"],
  ];

  /* Превью. Кирпичное поле с коридором посередине: внизу мой танк, над ним
     блок стены, а сразу за стеной — вражеский. Мой стреляет, блок
     разлетается, в проём становится виден враг, потом стена отстраивается
     и всё повторяется.

     Раскладка задана картой по клеткам, а не координатами на глаз: так
     танки гарантированно стоят в пустых клетках и не наезжают на кладку.
     Кирпич везде обычный — брони на превью нет. */
  var THUMB_MAP = [
    "##.B.##",
    "#..W..#",
    "#..M..#",
    "##...##",
  ];

  function thumb(ctx, w, h, t) {
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, w, h);

    var cols = THUMB_MAP[0].length, rows = THUMB_MAP.length;
    var cell = Math.floor(Math.min(w / cols, h / rows));
    var ox = Math.round((w - cell * cols) / 2);
    var oy = Math.round((h - cell * rows) / 2);

    var cyc = 2.8, k = (t % cyc) / cyc;
    var broken = k > 0.5 && k < 0.88;          // окно, когда стены нет

    function brick(cx, cy) {
      var x = ox + cx * cell, y = oy + cy * cell;
      ctx.fillStyle = C.brickDark;
      ctx.fillRect(x, y, cell, cell);
      ctx.fillStyle = C.brick;
      // кладка в три ряда со смещением, как в самой игре
      for (var r = 0; r < 3; r++) {
        var top = y + 2 + r * (cell / 3);
        var hgt = cell / 3 - 3;
        var shift = r % 2 ? cell / 4 : 0;
        ctx.fillRect(x + 2, top, cell / 2 - 3 + shift, hgt);
        ctx.fillRect(x + cell / 2 + shift, top, cell / 2 - 2 - shift, hgt);
      }
    }

    var me = null, foe = null, wall = null;
    for (var cy = 0; cy < rows; cy++) {
      for (var cx = 0; cx < cols; cx++) {
        var ch = THUMB_MAP[cy].charAt(cx);
        if (ch === "#") brick(cx, cy);
        else if (ch === "W") { wall = [cx, cy]; if (!broken) brick(cx, cy); }
        else if (ch === "M") me = [cx, cy];
        else if (ch === "B") foe = [cx, cy];
      }
    }

    // Танки ровно в своих клетках, с небольшим полем — гусеницы не должны
    // касаться кладки, иначе кажется, что танк въехал в стену.
    var pad = Math.round(cell * 0.08), size = cell - pad * 2;
    if (foe) drawTankArt(ctx, ox + foe[0] * cell + pad, oy + foe[1] * cell + pad,
                         size, 2, C.foe, C.foeDark);
    if (me) drawTankArt(ctx, ox + me[0] * cell + pad, oy + me[1] * cell + pad,
                        size, 0, C.me, C.meDark);

    if (me && wall) {
      var mx = ox + me[0] * cell + cell / 2;
      var fromY = oy + me[1] * cell;
      var toY = oy + (wall[1] + 1) * cell;
      if (k < 0.5) {                            // снаряд идёт к стене
        var f = k / 0.5;
        ctx.fillStyle = "#fff";
        ctx.fillRect(mx - 2, fromY - f * (fromY - toY), 4, Math.max(6, cell * 0.16));
      } else if (k < 0.62) {                    // вспышка на месте блока
        var a = 1 - (k - 0.5) / 0.12;
        ctx.fillStyle = "rgba(255,179,92," + a.toFixed(2) + ")";
        ctx.fillRect(ox + wall[0] * cell - 4, oy + wall[1] * cell - 4, cell + 8, cell + 8);
      }
    }
  }

  /* Танк рисуем руками: корпус, гусеницы полосками, башня и ствол по
     направлению. Спрайтов нет — так проще красить в любой цвет. */
  function drawTankArt(ctx, x, y, size, dir, body, dark) {
    var u = size / 16;
    ctx.save();
    ctx.translate(x + size / 2, y + size / 2);
    ctx.rotate(dir * Math.PI / 2);
    ctx.translate(-size / 2, -size / 2);
    ctx.fillStyle = dark;
    ctx.fillRect(0, u, 4 * u, 14 * u);
    ctx.fillRect(12 * u, u, 4 * u, 14 * u);
    for (var i = 0; i < 5; i++) {
      ctx.fillStyle = body;
      ctx.fillRect(0, (2 + i * 3) * u, 4 * u, 1.4 * u);
      ctx.fillRect(12 * u, (2 + i * 3) * u, 4 * u, 1.4 * u);
    }
    ctx.fillStyle = body;
    ctx.fillRect(4 * u, 3 * u, 8 * u, 11 * u);
    ctx.fillStyle = dark;
    ctx.fillRect(5 * u, 5 * u, 6 * u, 6 * u);
    ctx.fillStyle = body;
    ctx.fillRect(7 * u, 0, 2 * u, 6 * u);
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
      "min-height:0;object-fit:contain;border:1px solid rgba(242,209,107,.22);background:" + C.bg;
    var tip = document.createElement("div");
    tip.style.cssText = "color:#7fd6ea;font-size:.85rem;letter-spacing:.08em;flex:none;text-align:center";
    tip.textContent = api.touch
      ? "КРЕСТОВИНА — ЕХАТЬ · КРАСНАЯ — ОГОНЬ"
      : "СТРЕЛКИ — ЕХАТЬ · ПРОБЕЛ — ОГОНЬ · ENTER — ЗАНОВО";
    wrap.append(hud, canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d");
    var raf = 0, last = 0;

    var grid, me, foes, shots, boom, level, score, lives, alive, paused;
    var toSpawn, spawnT, baseAlive, overT, shieldT;
    var startedAt = 0, finalScore = 0, finalMult = 1, skipped = false;
    var held = { x: 0, y: 0 };

    function buildLevel(n) {
      if (api.track) api.track(n);          // у каждой карты своя тема
      var map = MAPS[n % MAPS.length];
      grid = [];
      for (var y = 0; y < N; y++) {
        grid.push([]);
        for (var x = 0; x < N; x++) grid[y].push(EMPTY);
      }
      for (var my = 0; my < 13; my++) {
        for (var mx = 0; mx < 13; mx++) {
          var ch = map[my].charAt(mx);
          var v = ch === "#" ? BRICK : ch === "@" ? STEEL : EMPTY;
          if (!v) continue;
          for (var dy = 0; dy < 2; dy++) {
            for (var dx = 0; dx < 2; dx++) grid[my * 2 + dy][mx * 2 + dx] = v;
          }
        }
      }
      // Штаб внизу по центру в кирпичной коробке
      for (var y2 = N - 4; y2 < N; y2++) {
        for (var x2 = 10; x2 < 16; x2++) grid[y2][x2] = BRICK;
      }
      grid[N - 2][12] = BASE; grid[N - 2][13] = BASE;
      grid[N - 1][12] = BASE; grid[N - 1][13] = BASE;
      for (var y3 = N - 2; y3 < N; y3++) {
        for (var x3 = 12; x3 < 14; x3++) grid[y3][x3] = BASE;
      }
      // площадки под старт: свои и вражеские
      clearBox(10, N - 2, 2, 2); clearBox(14, N - 2, 2, 2);
      clearBox(0, 0, 2, 2); clearBox(12, 0, 2, 2); clearBox(N - 2, 0, 2, 2);
    }

    function clearBox(x, y, w, h) {
      for (var j = 0; j < h; j++) {
        for (var i = 0; i < w; i++) {
          if (grid[y + j] && grid[y + j][x + i] !== BASE) grid[y + j][x + i] = EMPTY;
        }
      }
    }

    function tank(x, y, dir, kind) {
      return {
        x: x, y: y, dir: dir, kind: kind, cool: 0, turn: 0,
        speed: kind === "fast" ? 1.5 : kind === "heavy" ? 0.72 : 1.05,
        hp: kind === "heavy" ? 3 : 1, born: 0,
      };
    }

    function reset(full) {
      if (full) {
        level = 0; score = 0; lives = 3;
        startedAt = performance.now(); finalScore = 0; finalMult = 1;
        skipped = false;
      }
      buildLevel(level);
      me = tank(10 * S, (N - 2) * S, 0, "me");
      foes = []; shots = []; boom = [];
      toSpawn = 12 + level * 4;
      spawnT = 0; baseAlive = true; alive = true; paused = false; overT = 0;
      shieldT = 3;
      hud_();
    }

    function hud_() {
      hud.innerHTML =
        '<span>УРОВЕНЬ <b style="color:#f2d16b">' + (level + 1) + "</b></span>" +
        '<span>ОЧКИ <b style="color:#eaf6ff">' + score + "</b></span>" +
        '<span>ЖИЗНИ <b style="color:#ff6b9d">' + lives + "</b></span>" +
        '<span>ОСТАЛОСЬ <b style="color:#8fa5b8">' + (toSpawn + foes.length) + "</b></span>" +
        (api.top ? '<span>РЕКОРД <b style="color:#63f5ad">' + (api.top("tanks") || 0) +
          "</b></span>" : "");
    }

    /* ── Геометрия ───────────────────────────────────────────────────── */
    var TS = 2 * S;                     // танк — две клетки

    function blockedAt(px, py, skip) {
      if (px < 0 || py < 0 || px + TS > W || py + TS > H) return true;
      var x0 = Math.floor(px / S), x1 = Math.floor((px + TS - 1) / S);
      var y0 = Math.floor(py / S), y1 = Math.floor((py + TS - 1) / S);
      for (var y = y0; y <= y1; y++) {
        for (var x = x0; x <= x1; x++) {
          var v = grid[y][x];
          if (v === BRICK || v === STEEL || v === BASE) return true;
        }
      }
      var all = foes.concat([me]);
      for (var i = 0; i < all.length; i++) {
        var t = all[i];
        if (t === skip || !t) continue;
        if (px < t.x + TS && px + TS > t.x && py < t.y + TS && py + TS > t.y) return true;
      }
      return false;
    }

    var DX = [0, 1, 0, -1], DY = [-1, 0, 1, 0];

    function drive(t, dir, dt) {
      t.dir = dir;
      var d = t.speed * dt * 60;
      var nx = t.x + DX[dir] * d, ny = t.y + DY[dir] * d;
      // Лёгкое подруливание к сетке: иначе в проёмы шириной ровно в танк
      // попасть почти невозможно, и это бесит сильнее любой сложности.
      if (dir === 0 || dir === 2) nx = snap(t.x, nx);
      else ny = snap(t.y, ny);
      if (!blockedAt(nx, ny, t)) { t.x = nx; t.y = ny; return true; }
      if (!blockedAt(dir % 2 ? nx : t.x, dir % 2 ? t.y : ny, t)) {
        if (dir % 2) t.x = nx; else t.y = ny;
        return true;
      }
      return false;
    }

    function snap(cur, next) {
      var g = Math.round(cur / S) * S;
      if (Math.abs(g - cur) < 6) return g;
      return cur;
    }

    function fire(t) {
      if (t.cool > 0) return;
      t.cool = t.kind === "me" ? 0.34 : 0.9 + Math.random() * 0.8;
      shots.push({
        x: t.x + TS / 2 - 3, y: t.y + TS / 2 - 3,
        dir: t.dir, mine: t.kind === "me",
        speed: t.kind === "me" ? 420 : 300,
      });
      api.audio.tone(t.kind === "me" ? 300 : 200, 0.05,
                     { type: "square", volume: 0.06 });
    }

    function hitCell(x, y, mine) {
      if (x < 0 || y < 0 || x >= N || y >= N) return true;
      var v = grid[y][x];
      if (v === BRICK) { breakBlock(x, y); return true; }
      if (v === STEEL) return true;
      if (v === BASE) {
        if (baseAlive) {
          baseAlive = false; alive = false; overT = 0;
          burst(x * S, y * S, "#ffd84a", 34);
          api.audio.tone(90, 0.5, { type: "sawtooth", volume: 0.16 });
          api.buzz([70, 60, 140]);
        }
        return true;
      }
      return false;
    }

    /* Кирпич на карте лежит блоками два на два: одна клетка карты — четыре
       клетки поля. Выбивать по одной бессмысленно — в проделанную щель
       шириной в полклетки танк всё равно не проедет и будет стоять перед
       наполовину снесённой стеной. Поэтому снаряд уносит блок целиком. */
    function breakBlock(x, y) {
      var bx = x - (x % 2), by = y - (y % 2);
      for (var j = 0; j < 2; j++) {
        for (var i = 0; i < 2; i++) {
          var gy = by + j, gx = bx + i;
          if (grid[gy] && grid[gy][gx] === BRICK) grid[gy][gx] = EMPTY;
        }
      }
    }

    function burst(x, y, color, n) {
      for (var i = 0; i < n; i++) {
        var a = Math.random() * Math.PI * 2, sp = 40 + Math.random() * 150;
        boom.push({ x: x, y: y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp,
                    life: 0.4 + Math.random() * 0.4, t: 0, c: color });
      }
    }

    /* ── Шаг игры ─────────────────────────────────────────────────────── */
    function step(dt) {
      if (shieldT > 0) shieldT -= dt;
      if (me.cool > 0) me.cool -= dt;

      if (held.x || held.y) {
        drive(me, held.y < 0 ? 0 : held.y > 0 ? 2 : held.x > 0 ? 1 : 3, dt);
      }

      // подвоз врагов
      spawnT -= dt;
      if (toSpawn > 0 && foes.length < Math.min(4, 2 + level) && spawnT <= 0) {
        var spots = [[0, 0], [12 * S, 0], [(N - 2) * S, 0]];
        var sp = spots[Math.floor(Math.random() * spots.length)];
        if (!blockedAt(sp[0], sp[1], null)) {
          var r = Math.random();
          var kind = r < 0.18 + level * 0.04 ? "heavy" : r < 0.45 ? "fast" : "foe";
          var f = tank(sp[0], sp[1], 2, kind);
          f.born = 1;
          foes.push(f);
          toSpawn--;
          spawnT = 2.4;
          hud_();
        } else spawnT = 0.5;
      }

      foes.forEach(function (f) {
        if (f.born > 0) { f.born -= dt; return; }
        if (f.cool > 0) f.cool -= dt;
        f.turn -= dt;
        if (f.turn <= 0) {
          f.turn = 0.5 + Math.random() * 1.6;
          // Чем дальше уровень, тем охотнее враги идут к штабу, а не гуляют
          if (Math.random() < 0.35 + level * 0.06) {
            f.dir = f.x > 12 * S + 20 ? 3 : f.x < 12 * S - 20 ? 1 : 2;
          } else f.dir = Math.floor(Math.random() * 4);
        }
        if (!drive(f, f.dir, dt)) f.turn = 0;
        if (Math.random() < dt * 1.1) fire(f);
      });

      // снаряды
      for (var i = shots.length - 1; i >= 0; i--) {
        var s = shots[i];
        var d = s.speed * dt;
        s.x += DX[s.dir] * d; s.y += DY[s.dir] * d;
        var cx = Math.floor((s.x + 3) / S), cy = Math.floor((s.y + 3) / S);
        var gone = false;
        if (s.x < 0 || s.y < 0 || s.x > W || s.y > H) gone = true;
        else if (hitCell(cx, cy, s.mine)) {
          burst(s.x, s.y, "#ffb35c", 8); gone = true;
        } else if (s.mine) {
          for (var k = foes.length - 1; k >= 0; k--) {
            var f2 = foes[k];
            if (s.x > f2.x && s.x < f2.x + TS && s.y > f2.y && s.y < f2.y + TS) {
              f2.hp--;
              gone = true;
              if (f2.hp <= 0) {
                burst(f2.x + TS / 2, f2.y + TS / 2, C.foe, 26);
                foes.splice(k, 1);
                score += f2.kind === "heavy" ? 400 : f2.kind === "fast" ? 200 : 100;
                api.audio.tone(520, 0.1, { type: "square", volume: 0.09 });
                hud_();
              } else {
                burst(s.x, s.y, C.heavy, 8);
                api.audio.tone(240, 0.05, { type: "square", volume: 0.06 });
              }
              break;
            }
          }
        } else if (shieldT <= 0 &&
                   s.x > me.x && s.x < me.x + TS && s.y > me.y && s.y < me.y + TS) {
          gone = true;
          lives--;
          burst(me.x + TS / 2, me.y + TS / 2, C.me, 26);
          api.audio.tone(120, 0.3, { type: "sawtooth", volume: 0.13 });
          api.buzz(60);
          if (lives < 0) { alive = false; overT = 0; }
          else { me.x = 10 * S; me.y = (N - 2) * S; me.dir = 0; shieldT = 2.5; }
          hud_();
        }
        if (gone) shots.splice(i, 1);
      }

      for (var b = boom.length - 1; b >= 0; b--) {
        var p = boom[b];
        p.t += dt;
        p.x += p.vx * dt; p.y += p.vy * dt; p.vy += 120 * dt;
        if (p.t >= p.life) boom.splice(b, 1);
      }

      if (alive && toSpawn === 0 && foes.length === 0) {
        level++;
        if (api.unlock) api.unlock(level);
        api.audio.tone(700, 0.12, { type: "square", volume: 0.1 });
        setTimeout(function () { api.audio.tone(950, 0.2, { type: "square", volume: 0.09 }); }, 130);
        reset(false);
      }
    }

    /* ── Рисование ────────────────────────────────────────────────────── */
    function draw(now) {
      ctx.fillStyle = C.bg;
      ctx.fillRect(0, 0, W, H);

      for (var y = 0; y < N; y++) {
        for (var x = 0; x < N; x++) {
          var v = grid[y][x];
          if (v === EMPTY) continue;
          var px = x * S, py = y * S;
          if (v === BRICK) {
            ctx.fillStyle = C.brickDark; ctx.fillRect(px, py, S, S);
            ctx.fillStyle = C.brick;
            ctx.fillRect(px + 1, py + 1, S - 2, 6);
            ctx.fillRect(px + 1, py + 9, S - 2, 6);
          } else if (v === STEEL) {
            ctx.fillStyle = C.steelDark; ctx.fillRect(px, py, S, S);
            ctx.fillStyle = C.steel; ctx.fillRect(px + 2, py + 2, S - 4, S - 4);
          }
        }
      }

      // штаб
      var bx = 12 * S, by = (N - 2) * S;
      if (baseAlive) {
        ctx.fillStyle = "#6b5a1e"; ctx.fillRect(bx, by, S * 2, S * 2);
        ctx.fillStyle = C.base;
        ctx.beginPath();
        ctx.moveTo(bx + 16, by + 5); ctx.lineTo(bx + 27, by + 27);
        ctx.lineTo(bx + 5, by + 27); ctx.closePath(); ctx.fill();
        ctx.fillStyle = "#7a5f14"; ctx.fillRect(bx + 12, by + 16, 8, 11);
      } else {
        ctx.fillStyle = "#3a3a3a"; ctx.fillRect(bx, by, S * 2, S * 2);
        ctx.fillStyle = "#ff6b9d";
        ctx.fillRect(bx + 8, by + 8, 16, 4);
        ctx.fillRect(bx + 14, by + 4, 4, 20);
      }

      foes.forEach(function (f) {
        if (f.born > 0) {
          // мигающая звезда на месте появления — как в оригинале
          var r = 8 + Math.sin(now * 0.02) * 5;
          ctx.strokeStyle = "#7df9ff"; ctx.lineWidth = 2;
          ctx.strokeRect(f.x + TS / 2 - r, f.y + TS / 2 - r, r * 2, r * 2);
          return;
        }
        var col = f.kind === "fast" ? C.fast : f.kind === "heavy" ? C.heavy : C.foe;
        var dk = f.kind === "fast" ? "#2c9c68" : f.kind === "heavy" ? "#a13c60" : C.foeDark;
        drawTankArt(ctx, f.x, f.y, TS, f.dir, col, dk);
      });

      if (alive || lives >= 0) {
        if (shieldT <= 0 || Math.floor(now / 60) % 2) {
          drawTankArt(ctx, me.x, me.y, TS, me.dir, C.me, C.meDark);
        }
        if (shieldT > 0) {
          ctx.strokeStyle = "rgba(125,249,255,.8)"; ctx.lineWidth = 2;
          ctx.strokeRect(me.x - 2, me.y - 2, TS + 4, TS + 4);
        }
      }

      ctx.fillStyle = "#fff";
      shots.forEach(function (s) { ctx.fillRect(s.x, s.y, 6, 6); });

      boom.forEach(function (p) {
        ctx.globalAlpha = Math.max(0, 1 - p.t / p.life);
        ctx.fillStyle = p.c;
        ctx.fillRect(p.x - 2, p.y - 2, 4, 4);
      });
      ctx.globalAlpha = 1;

      if (!alive) {
        ctx.fillStyle = "rgba(4,7,13,.82)";
        ctx.fillRect(0, H / 2 - 62, W, 124);
        ctx.textAlign = "center";
        ctx.fillStyle = "#ff6b9d";
        ctx.font = 'bold 34px "Cascadia Code", Consolas, monospace';
        ctx.fillText(baseAlive ? "ТАНК ПОДБИТ" : "ШТАБ РАЗРУШЕН", W / 2, H / 2 - 12);
        ctx.fillStyle = "#8fa5b8";
        ctx.font = 'bold 15px "Cascadia Code", Consolas, monospace';
        ctx.fillText(score + " × темп " + finalMult.toFixed(2) + " = " + finalScore,
                     W / 2, H / 2 + 18);
        ctx.fillStyle = "#4a6379";
        ctx.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx.fillText(api.touch ? "КРАСНАЯ КНОПКА — ЗАНОВО" : "ENTER — ЗАНОВО", W / 2, H / 2 + 44);
        ctx.textAlign = "left";
      } else if (paused) {
        ctx.fillStyle = "rgba(4,7,13,.7)";
        ctx.fillRect(0, H / 2 - 30, W, 60);
        ctx.textAlign = "center";
        ctx.fillStyle = "#f2d16b";
        ctx.font = 'bold 26px "Cascadia Code", Consolas, monospace';
        ctx.fillText("ПАУЗА", W / 2, H / 2 + 9);
        ctx.textAlign = "left";
      }
    }

    function loop(now) {
      raf = requestAnimationFrame(loop);
      var dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (alive && !paused) step(dt);
      else if (!alive) {
        overT += dt;
        if (overT > 0.6 && !me.saved) {
          me.saved = true;
          var t = api.tempo(score, (performance.now() - startedAt) / 1000, 500);
          finalScore = t.total; finalMult = t.mult;
          api.best("tanks", finalScore);
          if (finalScore > 0 && !skipped) api.record("tanks", finalScore);
        }
      }
      draw(now);
    }

    function restart() { me.saved = false; reset(true); }

    /* Выбор карты. Начал не с первой — очки в таблицу не идут: врагов на
       поздних картах столько же, а первые волны пропущены. */
    function pickLevel() {
      if (!api.levels) return;
      api.levels(MAPS.map(function (_, i) { return "Карта " + (i + 1); }), function (i) {
        me.saved = false;
        reset(true);
        level = i;
        skipped = i > 0;
        reset(false);
      });
    }

    function onKey(e) {
      if (e.key === "Enter") { if (!alive) restart(); e.preventDefault(); return; }
      if (e.key === "p" || e.key === "P" || e.key === "з" || e.key === "З") {
        if (alive) paused = !paused;
        e.preventDefault(); return;
      }
      if (e.key === " ") {
        if (alive && !paused) fire(me); else if (!alive) restart();
        e.preventDefault(); return;
      }
      var d = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0] }[e.key];
      if (d) { held.x = d[0]; held.y = d[1]; e.preventDefault(); }
    }
    function onKeyUp(e) {
      var d = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0] }[e.key];
      if (d && held.x === d[0] && held.y === d[1]) { held.x = 0; held.y = 0; }
    }

    function hold(x, y) {
      return { down: function () { held.x = x; held.y = y; },
               up: function () { if (held.x === x && held.y === y) { held.x = 0; held.y = 0; } } };
    }

    api.deck({
      pad: { up: hold(0, -1), down: hold(0, 1), left: hold(-1, 0), right: hold(1, 0) },
      // Просвет между крестовиной и огнём: вплотную большой палец задевал
      // курок, пока разворачивал танк.
      airy: true,
      actions: [
        { icon: "fire", aria: "огонь", label: "ОГОНЬ", color: "#ff3fa4", big: true,
          down: function () { if (alive && !paused) fire(me); else restart(); } },
      ],
      // Пауза и «заново» подняты в верхний ряд: по бокам они отнимали у
      // крестовины ширину, а нужны раз в партию.
      extra: [
        { icon: "hold", label: "КАРТА", aria: "выбрать карту", down: pickLevel },
        { icon: "pause", label: "ПАУЗА", aria: "пауза",
          down: function () { if (alive) paused = !paused; } },
        { icon: "replay", label: "ЗАНОВО", aria: "заново", down: restart },
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
    id: "tanks",
    title: "ТАНЧИКИ",
    tagline: "Оборона штаба по мотивам Battle City. Кирпич выбивается по кускам, " +
             "броня не берётся, враги лезут волнами и с каждым уровнем наглее.",
    keys: "Стрелки — ехать · пробел — огонь · P — пауза · Enter — заново",
    keysTouch: "Крестовина — ехать, красная — огонь",
    accent: "#f2d16b",
    thumb: thumb,
    start: start,
  });
})();
