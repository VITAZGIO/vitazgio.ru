/* Шахматы с движком целиком в браузере.
 *
 * Сервер не участвует вообще: он отдаёт этот файл один раз, и дальше всё
 * считает вкладка на устройстве. Оперативной памяти на сервере игра не
 * занимает ни байта, сколько бы человек ни играло одновременно.
 *
 * Доска — массив на 128 клеток («0x88»): у настоящих клеток старшие биты
 * индекса нулевые, поэтому выход за край ловится одним сравнением
 * (sq & 0x88), без проверок на границы. Приём старый и до сих пор самый
 * дешёвый для перебора.
 *
 * Перебор: альфа-бета с итеративным углублением, сортировкой ходов по
 * ценности жертвы и добором взятий в конце (иначе движок «зевает» ферзя
 * ровно на границе глубины). Бюджет по времени и по узлам — чтобы вкладка
 * не подвисала на слабом телефоне.
 */
(function () {
  "use strict";

  var EMPTY = 0, P = 1, N = 2, B = 3, R = 4, Q = 5, K = 6;
  var VAL = [0, 100, 320, 330, 500, 900, 20000];

  /* Позиционные таблицы: насколько фигуре хорошо на этой клетке. Взгляд
     белых, для чёрных зеркалим по вертикали. Без них движок играет
     формально верно и совершенно бессмысленно — все ходы «равны». */
  var PST = {};
  PST[P] = [
     0,  0,  0,  0,  0,  0,  0,  0,
    50, 50, 50, 50, 50, 50, 50, 50,
    10, 10, 20, 30, 30, 20, 10, 10,
     5,  5, 10, 25, 25, 10,  5,  5,
     0,  0,  0, 20, 20,  0,  0,  0,
     5, -5,-10,  0,  0,-10, -5,  5,
     5, 10, 10,-20,-20, 10, 10,  5,
     0,  0,  0,  0,  0,  0,  0,  0];
  PST[N] = [
   -50,-40,-30,-30,-30,-30,-40,-50,
   -40,-20,  0,  0,  0,  0,-20,-40,
   -30,  0, 10, 15, 15, 10,  0,-30,
   -30,  5, 15, 20, 20, 15,  5,-30,
   -30,  0, 15, 20, 20, 15,  0,-30,
   -30,  5, 10, 15, 15, 10,  5,-30,
   -40,-20,  0,  5,  5,  0,-20,-40,
   -50,-40,-30,-30,-30,-30,-40,-50];
  PST[B] = [
   -20,-10,-10,-10,-10,-10,-10,-20,
   -10,  0,  0,  0,  0,  0,  0,-10,
   -10,  0,  5, 10, 10,  5,  0,-10,
   -10,  5,  5, 10, 10,  5,  5,-10,
   -10,  0, 10, 10, 10, 10,  0,-10,
   -10, 10, 10, 10, 10, 10, 10,-10,
   -10,  5,  0,  0,  0,  0,  5,-10,
   -20,-10,-10,-10,-10,-10,-10,-20];
  PST[R] = [
     0,  0,  0,  0,  0,  0,  0,  0,
     5, 10, 10, 10, 10, 10, 10,  5,
    -5,  0,  0,  0,  0,  0,  0, -5,
    -5,  0,  0,  0,  0,  0,  0, -5,
    -5,  0,  0,  0,  0,  0,  0, -5,
    -5,  0,  0,  0,  0,  0,  0, -5,
    -5,  0,  0,  0,  0,  0,  0, -5,
     0,  0,  0,  5,  5,  0,  0,  0];
  PST[Q] = [
   -20,-10,-10, -5, -5,-10,-10,-20,
   -10,  0,  0,  0,  0,  0,  0,-10,
   -10,  0,  5,  5,  5,  5,  0,-10,
    -5,  0,  5,  5,  5,  5,  0, -5,
     0,  0,  5,  5,  5,  5,  0, -5,
   -10,  5,  5,  5,  5,  5,  0,-10,
   -10,  0,  5,  0,  0,  0,  0,-10,
   -20,-10,-10, -5, -5,-10,-10,-20];
  PST[K] = [
   -30,-40,-40,-50,-50,-40,-40,-30,
   -30,-40,-40,-50,-50,-40,-40,-30,
   -30,-40,-40,-50,-50,-40,-40,-30,
   -30,-40,-40,-50,-50,-40,-40,-30,
   -20,-30,-30,-40,-40,-30,-30,-20,
   -10,-20,-20,-20,-20,-20,-20,-10,
    20, 20,  0,  0,  0,  0, 20, 20,
    20, 30, 10,  0,  0, 10, 30, 20];
  // Король в эндшпиле должен идти в центр, а не прятаться в углу
  var PST_KE = [
   -50,-40,-30,-20,-20,-30,-40,-50,
   -30,-20,-10,  0,  0,-10,-20,-30,
   -30,-10, 20, 30, 30, 20,-10,-30,
   -30,-10, 30, 40, 40, 30,-10,-30,
   -30,-10, 30, 40, 40, 30,-10,-30,
   -30,-10, 20, 30, 30, 20,-10,-30,
   -30,-30,  0,  0,  0,  0,-30,-30,
   -50,-30,-30,-30,-30,-30,-30,-50];

  var OFF = {};
  OFF[N] = [-33, -31, -18, -14, 14, 18, 31, 33];
  OFF[B] = [-17, -15, 15, 17];
  OFF[R] = [-16, -1, 1, 16];
  OFF[Q] = [-17, -16, -15, -1, 1, 15, 16, 17];
  OFF[K] = [-17, -16, -15, -1, 1, 15, 16, 17];

  function sq120(f, r) { return r * 16 + f; }        // f 0..7 слева, r 0..7 сверху
  function fileOf(s) { return s & 15; }
  function rankOf(s) { return s >> 4; }
  function idx64(s) { return rankOf(s) * 8 + fileOf(s); }

  /* ── Пиксельные фигуры ───────────────────────────────────────────────
     Юникодные знаки шахмат есть не в каждом шрифте на телефоне, и там,
     где их нет, доска превращается в квадратики. Рисуем сами. */
  /* Силуэты нарочно сделаны непохожими друг на друга: на клетке в сорок
     пикселей различаются не детали, а общая форма. Ладья — коробка, ферзь —
     talia с зубцами, король — крест, слон — острый верх, конь — угловатый
     профиль влево, пешка — маленький столбик. */
  var SPR = {};
  SPR[P] = [
    "............", "............", "....####....", "....####....",
    "....####....", ".....##.....", "....####....", "...######...",
    "..########..", ".##########.", "############", "............"];
  SPR[N] = [
    "............", "...##.......", "..####......", ".######.....",
    ".#..#####...", ".#.#######..", "...#######..", "...#######..",
    "..########..", ".##########.", "############", "............"];
  SPR[B] = [
    ".....##.....", "....####....", "...######...", "...##..##...",
    "...######...", "....####....", "....####....", "...######...",
    "..########..", ".##########.", "############", "............"];
  SPR[R] = [
    "............", "##.##..##.##", "##.##..##.##", "############",
    ".##########.", ".##########.", ".##########.", ".##########.",
    ".##########.", "############", "############", "............"];
  SPR[Q] = [
    ".#.#.##.#.#.", ".#.#.##.#.#.", "############", ".##########.",
    "..########..", "...######...", "...######...", "..########..",
    ".##########.", "############", "############", "............"];
  SPR[K] = [
    ".....##.....", ".....##.....", "...######...", "...######...",
    ".....##.....", "....####....", "...######...", "..########..",
    ".##########.", "############", "############", "............"];

  /* Фигуры рисуем один раз в маленькие холсты и дальше просто копируем:
     иначе на каждый кадр уходит под двадцать тысяч заливок, и на телефоне
     доска начинает подтормаживать на ровном месте. */
  var pieceCache = {};
  var CACHE_PX = 96;

  function pieceCanvas(piece) {
    if (pieceCache[piece]) return pieceCache[piece];
    var rows = SPR[Math.abs(piece)];
    var white = piece > 0;
    var cv = document.createElement("canvas");
    cv.width = cv.height = CACHE_PX;
    var g = cv.getContext("2d");
    var u = CACHE_PX / 13;                 // полклетки по краям под обводку
    var off = u * 0.5;

    function stamp(dx, dy, color) {
      g.fillStyle = color;
      for (var r = 0; r < rows.length; r++) {
        for (var c = 0; c < 12; c++) {
          if (rows[r].charAt(c) === "#") {
            g.fillRect(off + (c + dx) * u, off + (r + dy) * u, u + 0.7, u + 0.7);
          }
        }
      }
    }
    // Обводка тем же силуэтом со сдвигом на четыре стороны: у белой фигуры
    // тёмная, у чёрной светлая — и та и другая видны на любой клетке.
    var edge = white ? "#05070d" : "#b6c6d8";
    stamp(-0.45, 0, edge); stamp(0.45, 0, edge);
    stamp(0, -0.45, edge); stamp(0, 0.45, edge);
    stamp(0, 0, white ? "#f4f8fc" : "#2b3441");
    // Блик по верхней трети — фигура перестаёт быть плоским пятном
    g.save();
    g.beginPath();
    g.rect(0, 0, CACHE_PX, CACHE_PX * 0.36);
    g.clip();
    stamp(0, 0, white ? "#ffffff" : "#4a5a6d");
    g.restore();

    pieceCache[piece] = cv;
    return cv;
  }

  function drawPiece(ctx, piece, x, y, size) {
    if (!SPR[Math.abs(piece)]) return;
    ctx.drawImage(pieceCanvas(piece), x, y, size, size);
  }

  /* ── Позиция ─────────────────────────────────────────────────────────── */
  function newGame() {
    var b = new Int8Array(128);
    var back = [R, N, B, Q, K, B, N, R];
    for (var f = 0; f < 8; f++) {
      b[sq120(f, 0)] = -back[f];
      b[sq120(f, 1)] = -P;
      b[sq120(f, 6)] = P;
      b[sq120(f, 7)] = back[f];
    }
    return { b: b, side: 1, castle: 15, ep: -1, half: 0 };
  }

  function cloneState(s) {
    return { b: Int8Array.from(s.b), side: s.side, castle: s.castle, ep: s.ep, half: s.half };
  }

  function kingSq(s, side) {
    for (var i = 0; i < 128; i++) {
      if (i & 0x88) continue;
      if (s.b[i] === side * K) return i;
    }
    return -1;
  }

  /* Бьётся ли клетка стороной by. Идём от клетки наружу — так дешевле,
     чем перебирать все фигуры соперника. */
  function attacked(s, sq, by) {
    var i, t, d, x;
    // пешки
    var pd = by > 0 ? [15, 17] : [-15, -17];
    for (i = 0; i < 2; i++) {
      x = sq + pd[i];
      if (!(x & 0x88) && s.b[x] === by * P) return true;
    }
    // конь и король
    for (i = 0; i < OFF[N].length; i++) {
      x = sq + OFF[N][i];
      if (!(x & 0x88) && s.b[x] === by * N) return true;
    }
    for (i = 0; i < OFF[K].length; i++) {
      x = sq + OFF[K][i];
      if (!(x & 0x88) && s.b[x] === by * K) return true;
    }
    // скользящие
    for (i = 0; i < OFF[Q].length; i++) {
      d = OFF[Q][i];
      var diag = (d === -17 || d === -15 || d === 15 || d === 17);
      x = sq + d;
      while (!(x & 0x88)) {
        t = s.b[x];
        if (t) {
          if (t * by > 0) {
            var a = Math.abs(t);
            if (a === Q || (diag && a === B) || (!diag && a === R)) return true;
          }
          break;
        }
        x += d;
      }
    }
    return false;
  }

  function inCheck(s, side) { return attacked(s, kingSq(s, side), -side); }

  /* Псевдолегальные ходы: без проверки на собственный шах. */
  function genMoves(s, capturesOnly) {
    var out = [], side = s.side, from, piece, i, d, to, t;
    for (from = 0; from < 128; from++) {
      if (from & 0x88) continue;
      piece = s.b[from];
      if (!piece || piece * side <= 0) continue;
      var a = Math.abs(piece);

      if (a === P) {
        var dir = side > 0 ? -16 : 16;
        var startRank = side > 0 ? 6 : 1;
        var lastRank = side > 0 ? 0 : 7;
        to = from + dir;
        if (!capturesOnly && !(to & 0x88) && !s.b[to]) {
          push(out, from, to, rankOf(to) === lastRank);
          var to2 = from + dir * 2;
          if (rankOf(from) === startRank && !s.b[to2]) out.push(mv(from, to2, 0, "double"));
        }
        var caps = [dir - 1, dir + 1];
        for (i = 0; i < 2; i++) {
          to = from + caps[i];
          if (to & 0x88) continue;
          t = s.b[to];
          if (t && t * side < 0) push(out, from, to, rankOf(to) === lastRank);
          else if (!t && to === s.ep) out.push(mv(from, to, 0, "ep"));
        }
        continue;
      }

      var slide = (a === B || a === R || a === Q);
      var offs = OFF[a];
      for (i = 0; i < offs.length; i++) {
        d = offs[i];
        to = from + d;
        while (!(to & 0x88)) {
          t = s.b[to];
          if (t) {
            if (t * side < 0) out.push(mv(from, to));
            break;
          }
          if (!capturesOnly) out.push(mv(from, to));
          if (!slide) break;
          to += d;
        }
      }
    }

    // рокировки
    if (!capturesOnly) {
      var home = side > 0 ? 7 : 0;
      var kSq = sq120(4, home);
      if (s.b[kSq] === side * K && !attacked(s, kSq, -side)) {
        var kBit = side > 0 ? 1 : 4, qBit = side > 0 ? 2 : 8;
        if ((s.castle & kBit) && !s.b[kSq + 1] && !s.b[kSq + 2] &&
            s.b[sq120(7, home)] === side * R &&
            !attacked(s, kSq + 1, -side) && !attacked(s, kSq + 2, -side)) {
          out.push(mv(kSq, kSq + 2, 0, "ock"));
        }
        if ((s.castle & qBit) && !s.b[kSq - 1] && !s.b[kSq - 2] && !s.b[kSq - 3] &&
            s.b[sq120(0, home)] === side * R &&
            !attacked(s, kSq - 1, -side) && !attacked(s, kSq - 2, -side)) {
          out.push(mv(kSq, kSq - 2, 0, "ocq"));
        }
      }
    }
    return out;
  }

  function mv(from, to, promo, flag) {
    return { from: from, to: to, promo: promo || 0, flag: flag || "" };
  }
  function push(out, from, to, promoting) {
    if (promoting) {
      // Недопревращение в жизни нужно раз в тысячу партий; даём выбор
      // только между ферзём и конём — остальное всегда хуже.
      out.push(mv(from, to, Q), mv(from, to, N));
    } else out.push(mv(from, to));
  }

  function make(s, m) {
    var piece = s.b[m.from];
    var a = Math.abs(piece);
    // Правило 50 ходов: счётчик обнуляют пешка и любое взятие
    s.half = (a === P || s.b[m.to] || m.flag === "ep") ? 0 : s.half + 1;
    s.b[m.to] = m.promo ? s.side * m.promo : piece;
    s.b[m.from] = EMPTY;

    if (m.flag === "ep") s.b[m.to + (s.side > 0 ? 16 : -16)] = EMPTY;
    if (m.flag === "ock") { s.b[m.to - 1] = s.b[m.to + 1]; s.b[m.to + 1] = EMPTY; }
    if (m.flag === "ocq") { s.b[m.to + 1] = s.b[m.to - 2]; s.b[m.to - 2] = EMPTY; }

    s.ep = m.flag === "double" ? (m.from + m.to) / 2 : -1;

    // права на рокировку теряются навсегда
    if (a === K) s.castle &= s.side > 0 ? ~3 : ~12;
    if (m.from === sq120(7, 7) || m.to === sq120(7, 7)) s.castle &= ~1;
    if (m.from === sq120(0, 7) || m.to === sq120(0, 7)) s.castle &= ~2;
    if (m.from === sq120(7, 0) || m.to === sq120(7, 0)) s.castle &= ~4;
    if (m.from === sq120(0, 0) || m.to === sq120(0, 0)) s.castle &= ~8;

    s.side = -s.side;
  }

  function legalMoves(s) {
    var all = genMoves(s), out = [];
    for (var i = 0; i < all.length; i++) {
      var c = cloneState(s);
      make(c, all[i]);
      if (!inCheck(c, -c.side)) out.push(all[i]);
    }
    return out;
  }

  /* ── Оценка ──────────────────────────────────────────────────────────── */
  function material(s) {
    var m = 0;
    for (var i = 0; i < 128; i++) {
      if (i & 0x88) continue;
      var p = s.b[i];
      if (p && Math.abs(p) !== K) m += VAL[Math.abs(p)];
    }
    return m;
  }

  function evaluate(s) {
    var score = 0, endgame = material(s) < 2600;
    for (var i = 0; i < 128; i++) {
      if (i & 0x88) continue;
      var p = s.b[i];
      if (!p) continue;
      var a = Math.abs(p), white = p > 0;
      var k = idx64(i);
      var pk = white ? k : (7 - rankOf(i)) * 8 + fileOf(i);
      var pst = (a === K && endgame) ? PST_KE[pk] : PST[a][pk];
      score += (VAL[a] + pst) * (white ? 1 : -1);
    }
    return score * s.side;                 // всегда с точки зрения того, чей ход
  }

  /* Добор взятий: считаем до «тихой» позиции, иначе на последней глубине
     движок радостно бьёт защищённую фигуру и не видит ответа. */
  function quiesce(s, alpha, beta, ctx) {
    ctx.nodes++;
    var stand = evaluate(s);
    if (stand >= beta) return beta;
    if (stand > alpha) alpha = stand;
    if (ctx.nodes > ctx.maxNodes) return alpha;

    var caps = genMoves(s, true);
    caps.sort(function (x, y) { return capScore(s, y) - capScore(s, x); });
    for (var i = 0; i < caps.length; i++) {
      var c = cloneState(s);
      make(c, caps[i]);
      if (inCheck(c, -c.side)) continue;
      var v = -quiesce(c, -beta, -alpha, ctx);
      if (v >= beta) return beta;
      if (v > alpha) alpha = v;
    }
    return alpha;
  }

  // Ценность жертвы минус ценность нападающего: бьём слабым сильное первым
  function capScore(s, m) {
    var victim = Math.abs(s.b[m.to]) || (m.flag === "ep" ? P : 0);
    var att = Math.abs(s.b[m.from]);
    return victim * 10 - att + (m.promo ? 800 : 0);
  }

  function search(s, depth, alpha, beta, ctx) {
    if (ctx.nodes > ctx.maxNodes || performance.now() > ctx.until) { ctx.stop = true; return evaluate(s); }
    if (depth <= 0) return quiesce(s, alpha, beta, ctx);
    ctx.nodes++;

    var moves = genMoves(s);
    moves.sort(function (x, y) { return capScore(s, y) - capScore(s, x); });

    var any = false, best = -1e9;
    for (var i = 0; i < moves.length; i++) {
      var c = cloneState(s);
      make(c, moves[i]);
      if (inCheck(c, -c.side)) continue;
      any = true;
      var v = -search(c, depth - 1, -beta, -alpha, ctx);
      if (v > best) best = v;
      if (v > alpha) alpha = v;
      if (alpha >= beta) break;
      if (ctx.stop) break;
    }
    if (!any) return inCheck(s, s.side) ? -30000 + (ctx.rootDepth - depth) : 0;
    return best;
  }

  /* Ищем ход с постепенным углублением: если время вышло на середине
     глубины, у нас уже есть готовый результат с предыдущей. */
  function bestMove(s, level) {
    var budget = [220, 600, 1400][level] || 600;
    var maxDepth = [2, 3, 5][level] || 3;
    var ctx = { nodes: 0, maxNodes: [12000, 60000, 260000][level] || 60000,
                until: performance.now() + budget, stop: false, rootDepth: 0 };

    var moves = legalMoves(s);
    if (!moves.length) return null;
    // Немного случайности на лёгком уровне, иначе партии одинаковые
    var noise = level === 0 ? 45 : level === 1 ? 12 : 0;

    var best = moves[0], bestVal = -1e9;
    for (var d = 1; d <= maxDepth; d++) {
      ctx.rootDepth = d;
      var localBest = null, localVal = -1e9;
      moves.sort(function (x, y) { return capScore(s, y) - capScore(s, x); });
      for (var i = 0; i < moves.length; i++) {
        var c = cloneState(s);
        make(c, moves[i]);
        var v = -search(c, d - 1, -1e9, 1e9, ctx);
        if (noise) v += Math.floor((Math.random() - 0.5) * noise * 2);
        if (v > localVal) { localVal = v; localBest = moves[i]; }
        if (ctx.stop) break;
      }
      if (localBest && (!ctx.stop || d === 1)) { best = localBest; bestVal = localVal; }
      if (ctx.stop || performance.now() > ctx.until) break;
    }
    return { move: best, score: bestVal, nodes: ctx.nodes };
  }

  /* ── Превью на карточке ─────────────────────────────────────────────── */
  function thumb(ctx, w, h, t) {
    var cell = Math.min(w, h) / 8;
    var ox = (w - cell * 8) / 2, oy = (h - cell * 8) / 2;
    ctx.fillStyle = "#05070d";
    ctx.fillRect(0, 0, w, h);
    for (var r = 0; r < 8; r++) {
      for (var c = 0; c < 8; c++) {
        ctx.fillStyle = (r + c) % 2 ? "#2a3646" : "#4d5f75";
        ctx.fillRect(ox + c * cell, oy + r * cell, cell, cell);
      }
    }
    var pieces = [[R, 0, 0], [N, 1, 0], [K, 4, 0], [Q, 3, 7], [K, 4, 7], [N, 6, 7]];
    var lift = Math.abs(Math.sin(t * 1.6)) * cell * 0.4;
    pieces.forEach(function (p, i) {
      var y = oy + p[2] * cell + (i === 2 ? -lift : 0);
      drawPiece(ctx, p[2] === 0 ? -p[0] : p[0], ox + p[1] * cell + cell * 0.1,
                y + cell * 0.1, cell * 0.8);
    });
  }

  /* ── Игра ────────────────────────────────────────────────────────────── */
  function start(root, api) {
    var SIZE = 480, CELL = SIZE / 8, PAD = 26;
    var W = SIZE + PAD * 2, H = SIZE + PAD * 2;

    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;" +
      "width:100%;max-height:100%;min-height:0";
    var hud = document.createElement("div");
    hud.style.cssText = "display:flex;gap:14px;flex-wrap:wrap;justify-content:center;flex:none;" +
      "font:700 .78rem " + api.font + ";letter-spacing:.06em;color:#8fa5b8";
    var canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    canvas.style.cssText = (api.touch
      ? "width:100%;height:auto;max-height:100%;"
      : "max-width:100%;max-height:100%;width:auto;height:auto;") +
      "min-height:0;object-fit:contain;border:1px solid rgba(45,226,255,.22);background:#05070d;" +
      "cursor:pointer";
    var tip = document.createElement("div");
    tip.style.cssText = "color:#4a6379;font-size:.66rem;letter-spacing:.1em;flex:none;text-align:center";
    tip.textContent = "ТЫКНИ ФИГУРУ, ПОТОМ КЛЕТКУ · ДВИЖОК СЧИТАЕТ ЗДЕСЬ ЖЕ, СЕРВЕР НЕ УЧАСТВУЕТ";
    wrap.append(hud, canvas, tip);
    root.appendChild(wrap);

    var ctx2 = canvas.getContext("2d");
    var raf = 0;

    var state, sel = -1, moves = [], hint = "", thinking = false;
    var level = 1, streak = 0, over = "", lastMove = null, flash = 0;
    var LEVELS = ["ЛЕГКО", "СРЕДНЕ", "СЛОЖНО"];

    function reset() {
      state = newGame();
      sel = -1; moves = []; over = ""; lastMove = null; thinking = false;
      hint = "твой ход, белые";
      hud_();
    }

    function hud_() {
      hud.innerHTML =
        '<span>УРОВЕНЬ <b style="color:#2de2ff">' + LEVELS[level] + "</b></span>" +
        '<span>ПОБЕД ПОДРЯД <b style="color:#ffd84a">' + streak + "</b></span>" +
        (api.top ? '<span>РЕКОРД <b style="color:#63f5ad">' + (api.top("chess") || 0) +
          "</b></span>" : "") +
        '<span style="color:#4a6379">' + hint + "</span>";
    }

    function finish(text, won) {
      over = text;
      if (won) {
        streak++;
        // В рейтинг идёт только серия на сложном: побеждать лёгкий движок
        // по кругу может кто угодно, и таблица тогда ничего не значит.
        if (level === 2) {
          api.best("chess", streak);
          api.record("chess", streak);
        }
      } else {
        streak = 0;
      }
      hint = text;
      hud_();
    }

    function afterMove() {
      var legal = legalMoves(state);
      if (!legal.length) {
        if (inCheck(state, state.side)) {
          finish(state.side > 0 ? "мат тебе - чёрные выиграли" : "мат! партия твоя",
                 state.side < 0);
        } else finish("пат - ничья", false);
        return false;
      }
      if (state.half >= 100) { finish("ничья по правилу 50 ходов", false); return false; }
      return true;
    }

    function doMove(m) {
      make(state, m);
      lastMove = m;
      flash = 0.4;
      api.audio.tone(m.promo ? 880 : 520, 0.05, { type: "square", volume: 0.07 });
      api.buzz(8);
    }

    function aiTurn() {
      thinking = true;
      hint = "думаю…";
      hud_();
      // Считаем в отдельном кадре: иначе браузер не успеет перерисовать
      // доску, и ход игрока будет выглядеть «залипшим».
      setTimeout(function () {
        var res = bestMove(state, level);
        thinking = false;
        if (!res) { afterMove(); return; }
        doMove(res.move);
        if (afterMove()) {
          hint = inCheck(state, state.side) ? "тебе шах" : "твой ход";
          hud_();
        }
      }, 30);
    }

    function onClick(e) {
      if (over || thinking || state.side < 0) return;
      var r = canvas.getBoundingClientRect();
      var x = (e.clientX - r.left) / r.width * W - PAD;
      var y = (e.clientY - r.top) / r.height * H - PAD;
      if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) return;
      var f = Math.floor(x / CELL), rr = Math.floor(y / CELL);
      var sq = sq120(f, rr);

      var hitMove = null;
      for (var i = 0; i < moves.length; i++) if (moves[i].to === sq) { hitMove = moves[i]; break; }
      if (hitMove) {
        // Превращение: если есть выбор, берём ферзя — конь остаётся
        // редким случаем, ради которого не стоит городить окно выбора.
        if (hitMove.promo) {
          for (var j = 0; j < moves.length; j++) {
            if (moves[j].to === sq && moves[j].from === hitMove.from && moves[j].promo === Q) {
              hitMove = moves[j]; break;
            }
          }
        }
        sel = -1; moves = [];
        doMove(hitMove);
        if (afterMove()) aiTurn();
        return;
      }
      if (state.b[sq] * state.side > 0) {
        sel = sq;
        moves = legalMoves(state).filter(function (m) { return m.from === sq; });
        api.audio.tone(700, 0.02, { type: "square", volume: 0.04 });
      } else { sel = -1; moves = []; }
    }
    canvas.addEventListener("click", onClick);

    function draw(now) {
      raf = requestAnimationFrame(draw);
      if (flash > 0) flash -= 0.016;

      ctx2.fillStyle = "#05070d";
      ctx2.fillRect(0, 0, W, H);

      // рамка с буквами и цифрами
      ctx2.font = 'bold 12px "Cascadia Code", Consolas, monospace';
      ctx2.fillStyle = "#4a6379";
      ctx2.textAlign = "center";
      for (var f = 0; f < 8; f++) {
        ctx2.fillText("abcdefgh".charAt(f), PAD + f * CELL + CELL / 2, H - 9);
        ctx2.fillText(String(8 - f), 13, PAD + f * CELL + CELL / 2 + 4);
      }
      ctx2.textAlign = "left";

      for (var r = 0; r < 8; r++) {
        for (var c = 0; c < 8; c++) {
          var sq = sq120(c, r);
          var px = PAD + c * CELL, py = PAD + r * CELL;
          ctx2.fillStyle = (r + c) % 2 ? "#26313f" : "#46586d";
          ctx2.fillRect(px, py, CELL, CELL);

          if (lastMove && (sq === lastMove.from || sq === lastMove.to)) {
            ctx2.fillStyle = "rgba(255,216,74,.22)";
            ctx2.fillRect(px, py, CELL, CELL);
          }
          if (sq === sel) {
            ctx2.fillStyle = "rgba(45,226,255,.32)";
            ctx2.fillRect(px, py, CELL, CELL);
          }
        }
      }

      // куда можно пойти
      moves.forEach(function (m) {
        var px = PAD + fileOf(m.to) * CELL, py = PAD + rankOf(m.to) * CELL;
        if (state.b[m.to] || m.flag === "ep") {
          ctx2.strokeStyle = "rgba(255,107,157,.9)";
          ctx2.lineWidth = 3;
          ctx2.strokeRect(px + 2, py + 2, CELL - 4, CELL - 4);
        } else {
          ctx2.fillStyle = "rgba(125,249,255,.55)";
          ctx2.beginPath();
          ctx2.arc(px + CELL / 2, py + CELL / 2, CELL * 0.14, 0, 7);
          ctx2.fill();
        }
      });

      // шах — красная рамка вокруг короля
      var ks = kingSq(state, state.side);
      if (ks >= 0 && !over && inCheck(state, state.side)) {
        ctx2.strokeStyle = "rgba(255,59,83," + (0.6 + Math.sin(now / 160) * 0.35) + ")";
        ctx2.lineWidth = 4;
        ctx2.strokeRect(PAD + fileOf(ks) * CELL + 2, PAD + rankOf(ks) * CELL + 2,
                        CELL - 4, CELL - 4);
      }

      for (var i = 0; i < 128; i++) {
        if (i & 0x88) continue;
        var p = state.b[i];
        if (!p) continue;
        drawPiece(ctx2, p, PAD + fileOf(i) * CELL + CELL * 0.06,
                  PAD + rankOf(i) * CELL + CELL * 0.06, CELL * 0.88);
      }

      if (thinking) {
        ctx2.fillStyle = "rgba(4,7,13,.55)";
        ctx2.fillRect(PAD, H / 2 - 24, SIZE, 48);
        ctx2.textAlign = "center";
        ctx2.fillStyle = "#2de2ff";
        ctx2.font = 'bold 20px "Cascadia Code", Consolas, monospace';
        var dots = ".".repeat(1 + Math.floor(now / 300) % 3);
        ctx2.fillText("ДУМАЮ" + dots, W / 2, H / 2 + 7);
        ctx2.textAlign = "left";
      }

      if (over) {
        ctx2.fillStyle = "rgba(4,7,13,.85)";
        ctx2.fillRect(PAD, H / 2 - 52, SIZE, 104);
        ctx2.textAlign = "center";
        ctx2.fillStyle = over.indexOf("твоя") >= 0 ? "#63f5ad" : "#ff6b9d";
        ctx2.font = 'bold 24px "Cascadia Code", Consolas, monospace';
        ctx2.fillText(over.toUpperCase(), W / 2, H / 2 - 8);
        ctx2.fillStyle = "#4a6379";
        ctx2.font = 'bold 13px "Cascadia Code", Consolas, monospace';
        ctx2.fillText("КНОПКА ПОВТОРА — НОВАЯ ПАРТИЯ", W / 2, H / 2 + 24);
        ctx2.textAlign = "left";
      }
    }

    function onKey(e) {
      if (e.key === "Enter") { reset(); e.preventDefault(); }
    }
    document.addEventListener("keydown", onKey);

    function buildDeck() {
      api.deck({
        extra: [
          { label: "УРОВЕНЬ: " + LEVELS[level], aria: "сменить уровень",
            down: function () {
              level = (level + 1) % 3;
              streak = 0;          // уровень сменили — серия начинается заново
              buildDeck();
              hud_();
            } },
        ],
        actions: [
          { icon: "replay", aria: "новая партия", label: "ЗАНОВО", color: "#ff3fa4",
            big: true, down: reset },
        ],
      });
    }
    buildDeck();

    reset();
    raf = requestAnimationFrame(draw);

    return {
      destroy: function () {
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKey);
      },
    };
  }

  window.VitazArcade.register({
    id: "chess",
    title: "ШАХМАТЫ",
    tagline: "Движок считает прямо в браузере — сервер отдаёт файл и больше " +
             "не участвует. Три уровня, рокировки, взятие на проходе и " +
             "превращение. В рейтинг идёт серия побед на сложном.",
    keys: "Мышь: фигуру, потом клетку · Enter — новая партия",
    keysTouch: "Тыкни фигуру, потом клетку",
    accent: "#5f9bff",
    thumb: thumb,
    start: start,
  });
})();
