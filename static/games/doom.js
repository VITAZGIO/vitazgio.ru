/* DOOM-подобный шутер на рейкастинге.
 *
 * Всё нарисовано с нуля кодом: текстуры стен, спрайты монстров, оружие, лица на
 * статус-панели и звуки. Ни одного файла ресурсов — ни своего, ни чужого; из
 * оригинальной игры не взято ничего, кроме жанра и раскладки интерфейса.
 *
 * Картинка считается в буфер 400x200 и растягивается на весь экран без
 * сглаживания: так и пиксель крупный, как положено, и рисовать быстро.
 */
(function () {
  "use strict";

  var VIEW_W = 400, VIEW_H = 200, BAR_H = 56;
  var SCREEN_W = VIEW_W, SCREEN_H = VIEW_H + BAR_H;
  var TEX = 64;
  var FOV = Math.PI / 3;

  /* ══ Цвета и мелкие помощники ═══════════════════════════════════════════ */
  function pack(r, g, b) {
    return (255 << 24) | ((b & 255) << 16) | ((g & 255) << 8) | (r & 255);
  }
  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }
  function rnd(a, b) { return a + Math.random() * (b - a); }

  /* ══ Текстуры стен ══════════════════════════════════════════════════════
     Каждая — Uint32Array 64x64. Генерируются один раз при первом запуске. */
  var textures = null;

  function makeTexture(fn) {
    var data = new Uint32Array(TEX * TEX);
    fn(function (x, y, r, g, b) {
      if (x < 0 || y < 0 || x >= TEX || y >= TEX) return;
      data[y * TEX + x] = pack(clamp(r | 0, 0, 255), clamp(g | 0, 0, 255), clamp(b | 0, 0, 255));
    });
    return data;
  }

  function buildTextures() {
    var t = {};

    // Кирпич — базовая стена уровня.
    t.brick = makeTexture(function (put) {
      for (var y = 0; y < TEX; y++) {
        for (var x = 0; x < TEX; x++) {
          var row = Math.floor(y / 16);
          var shift = (row % 2) * 16;
          var bx = (x + shift) % 32, by = y % 16;
          var mortar = bx < 2 || by < 2;
          var n = (Math.sin(x * 12.9898 + y * 78.233) * 43758.5453) % 1;
          n = (n < 0 ? -n : n) * 26;
          if (mortar) put(x, y, 46 + n * 0.4, 40 + n * 0.4, 38 + n * 0.4);
          else {
            var base = 116 + n;
            var light = by < 4 ? 18 : (by > 12 ? -18 : 0);
            put(x, y, base + light, base * 0.52 + light, base * 0.36 + light);
          }
        }
      }
    });

    // Техпанель — металл с заклёпками и полосой света.
    t.tech = makeTexture(function (put) {
      for (var y = 0; y < TEX; y++) {
        for (var x = 0; x < TEX; x++) {
          var seam = (x % 32 < 2) || (y % 32 < 2);
          var n = ((x * 7 + y * 13) % 11) * 2;
          var base = seam ? 54 : 92 + n;
          var vign = 1 - Math.abs((y % 32) - 16) / 42;
          put(x, y, base * vign, base * vign * 1.04, base * vign * 1.12);
        }
      }
      // заклёпки по углам панелей
      var spots = [[6, 6], [26, 6], [38, 6], [58, 6], [6, 26], [26, 26], [38, 26], [58, 26],
                   [6, 38], [26, 38], [38, 38], [58, 38], [6, 58], [26, 58], [38, 58], [58, 58]];
      spots.forEach(function (s) {
        for (var dy = -2; dy <= 2; dy++) {
          for (var dx = -2; dx <= 2; dx++) {
            if (dx * dx + dy * dy > 4) continue;
            var lit = (dx + dy) < 0 ? 60 : -30;
            put(s[0] + dx, s[1] + dy, 130 + lit, 136 + lit, 148 + lit);
          }
        }
      });
      // светящаяся полоса
      for (var x2 = 0; x2 < TEX; x2++) {
        for (var d = 0; d < 3; d++) {
          put(x2, 31 + d, 40, 190 - d * 40, 220 - d * 40);
        }
      }
    });

    // Адский камень — тёмно-зелёный мрамор с прожилками.
    t.marble = makeTexture(function (put) {
      for (var y = 0; y < TEX; y++) {
        for (var x = 0; x < TEX; x++) {
          var v = Math.sin(x * 0.31) * Math.cos(y * 0.19) + Math.sin((x + y) * 0.11);
          var n = ((Math.sin(x * 91.7 + y * 47.3) * 4375.55) % 1);
          n = (n < 0 ? -n : n) * 20;
          var base = 54 + v * 16 + n;
          put(x, y, base * 0.55, base, base * 0.62);
        }
      }
      // трещины
      for (var i = 0; i < 5; i++) {
        var cx = (i * 13 + 5) % TEX, cy = 0;
        while (cy < TEX) {
          put(cx, cy, 18, 26, 20);
          put(cx + 1, cy, 24, 34, 26);
          cx += Math.random() < 0.5 ? 1 : -1;
          cy++;
        }
      }
    });

    // Ржавый металл — для колонн и перемычек.
    t.metal = makeTexture(function (put) {
      for (var y = 0; y < TEX; y++) {
        for (var x = 0; x < TEX; x++) {
          var stripe = (x % 8 < 4) ? 12 : -12;
          var n = ((Math.sin(x * 27.1 + y * 13.7) * 2375.11) % 1);
          n = (n < 0 ? -n : n);
          var rust = n > 0.86 ? 1 : 0;
          var base = 96 + stripe + n * 18;
          if (rust) put(x, y, base * 0.92, base * 0.46, base * 0.24);
          else put(x, y, base * 0.86, base * 0.88, base * 0.9);
        }
      }
    });

    // Дверь — две створки с предупреждающими полосами.
    function doorTexture(rTint, gTint, bTint) {
      return makeTexture(function (put) {
        for (var y = 0; y < TEX; y++) {
          for (var x = 0; x < TEX; x++) {
            var center = Math.abs(x - 32);
            var seam = center < 2;
            var edge = x < 3 || x > 60;
            var base = seam ? 40 : (edge ? 70 : 118 - center * 0.5);
            var band = (y > 20 && y < 30) || (y > 38 && y < 44);
            if (band && !seam) {
              // косые полосы «не влезай»
              var s = ((x + y) % 12) < 6;
              put(x, y, s ? 190 : 40, s ? 150 : 40, s ? 30 : 40);
            } else {
              put(x, y, base * rTint, base * gTint, base * bTint);
            }
          }
        }
      });
    }
    t.door = doorTexture(1, 1.02, 1.08);
    t.doorRed = doorTexture(1.35, 0.6, 0.6);
    t.doorBlue = doorTexture(0.6, 0.75, 1.5);
    t.doorYellow = doorTexture(1.3, 1.2, 0.5);

    // Выход — панель с большим рычагом.
    t.exit = makeTexture(function (put) {
      for (var y = 0; y < TEX; y++) {
        for (var x = 0; x < TEX; x++) {
          var base = 78 + ((x * 5 + y * 3) % 9);
          put(x, y, base * 0.8, base, base * 0.85);
        }
      }
      for (var y2 = 14; y2 < 50; y2++) {
        for (var x2 = 20; x2 < 44; x2++) {
          var inner = x2 > 23 && x2 < 41 && y2 > 17 && y2 < 47;
          if (inner) {
            var glow = 210 - Math.abs(y2 - 32) * 3;
            put(x2, y2, glow, glow * 0.35, glow * 0.2);
          } else put(x2, y2, 40, 44, 48);
        }
      }
    });

    return t;
  }

  /* ══ Спрайты ════════════════════════════════════════════════════════════
     Рисуем обычным канвасом, потом забираем пиксели: так можно пользоваться
     дугами и градиентами, а движку отдать готовый массив для выборки. */
  function spriteFrom(w, h, draw) {
    var c = document.createElement("canvas");
    c.width = w; c.height = h;
    var g = c.getContext("2d");
    draw(g, w, h);
    var img = g.getImageData(0, 0, w, h);
    return { w: w, h: h, data: new Uint32Array(img.data.buffer.slice(0)) };
  }

  function outlineShape(g, path, fill, stroke) {
    g.fillStyle = fill;
    g.strokeStyle = stroke || "rgba(0,0,0,.75)";
    g.lineWidth = 2;
    path();
    g.fill();
    g.stroke();
  }

  // Сегмент конечности: сужающаяся «колбаса» от сустава к суставу.
  function limb(g, x1, y1, x2, y2, w1, w2, fill) {
    var ang = Math.atan2(y2 - y1, x2 - x1) + Math.PI / 2;
    var ax = Math.cos(ang), ay = Math.sin(ang);
    g.beginPath();
    g.moveTo(x1 + ax * w1, y1 + ay * w1);
    g.lineTo(x2 + ax * w2, y2 + ay * w2);
    g.lineTo(x2 - ax * w2, y2 - ay * w2);
    g.lineTo(x1 - ax * w1, y1 - ay * w1);
    g.closePath();
    g.fillStyle = fill;
    g.strokeStyle = "rgba(0,0,0,.8)";
    g.lineWidth = 2;
    g.fill();
    g.stroke();
  }

  // ── Бес: рогатая тварь, кидается огнём ─────────────────────────────────
  function drawImp(g, w, h, opt) {
    var t = opt.walk || 0;                       // 0..1 — фаза шага
    var swing = Math.sin(t * Math.PI * 2);       // -1..1
    var cx = w / 2, base = h - 3;
    g.clearRect(0, 0, w, h);

    var skin = opt.pain ? "#d97355" : "#9d4229";
    var skinLit = opt.pain ? "#f0a184" : "#c25f3c";
    var skinDark = opt.pain ? "#a04d33" : "#6b2916";
    var horn = "#d9cbb0";

    // ── ноги: обратный сустав, как у копытных ──
    [[-1, swing], [1, -swing]].forEach(function (pair) {
      var side = pair[0], ph = pair[1];
      var hipX = cx + side * 7, hipY = base - 26;
      var kneeX = hipX + side * 3 - ph * 3, kneeY = base - 16;
      var ankleX = hipX + ph * 6, ankleY = base - 7;
      limb(g, hipX, hipY, kneeX, kneeY, 6, 4.5, skinDark);
      limb(g, kneeX, kneeY, ankleX, ankleY, 4.5, 3, skinDark);
      // копыто
      g.fillStyle = "#2b1109";
      g.strokeStyle = "rgba(0,0,0,.8)";
      g.beginPath();
      g.ellipse(ankleX + ph * 1.5, base - 2, 5.5, 3.4, 0, 0, Math.PI * 2);
      g.fill(); g.stroke();
    });

    // ── торс: широкая грудь, узкая талия ──
    g.beginPath();
    g.moveTo(cx - 8, base - 24);
    g.quadraticCurveTo(cx - 13, base - 34, cx - 15, base - 44);
    g.quadraticCurveTo(cx - 12, base - 50, cx - 5, base - 50);
    g.lineTo(cx + 5, base - 50);
    g.quadraticCurveTo(cx + 12, base - 50, cx + 15, base - 44);
    g.quadraticCurveTo(cx + 13, base - 34, cx + 8, base - 24);
    g.closePath();
    var body = g.createLinearGradient(cx - 15, 0, cx + 15, 0);
    body.addColorStop(0, skinDark);
    body.addColorStop(0.35, skin);
    body.addColorStop(0.6, skinLit);
    body.addColorStop(1, skinDark);
    g.fillStyle = body;
    g.strokeStyle = "rgba(0,0,0,.8)"; g.lineWidth = 2;
    g.fill(); g.stroke();

    // грудные мышцы и рёбра
    g.strokeStyle = "rgba(60,18,8,.55)"; g.lineWidth = 1.4;
    g.beginPath(); g.moveTo(cx, base - 48); g.lineTo(cx, base - 38); g.stroke();
    g.beginPath();
    g.arc(cx - 6, base - 43, 5, -0.4, 1.6); g.stroke();
    g.beginPath();
    g.arc(cx + 6, base - 43, 5, 1.5, 3.5); g.stroke();
    for (var rib = 0; rib < 3; rib++) {
      g.strokeStyle = "rgba(60,18,8,.4)";
      g.beginPath();
      g.moveTo(cx - 9 + rib * 0.5, base - 34 + rib * 3.5);
      g.lineTo(cx + 9 - rib * 0.5, base - 34 + rib * 3.5);
      g.stroke();
    }

    // шипы на плечах
    [-1, 1].forEach(function (side) {
      g.beginPath();
      g.moveTo(cx + side * 11, base - 48);
      g.lineTo(cx + side * 17, base - 55);
      g.lineTo(cx + side * 13, base - 45);
      g.closePath();
      g.fillStyle = horn;
      g.strokeStyle = "rgba(0,0,0,.75)"; g.lineWidth = 1.5;
      g.fill(); g.stroke();
    });

    // ── руки ──
    [[-1, -swing], [1, swing]].forEach(function (pair) {
      var side = pair[0], ph = pair[1];
      var shX = cx + side * 12, shY = base - 46;
      var elbowX, elbowY, handX, handY;
      if (opt.attack) {                          // замах перед броском
        elbowX = cx + side * 20; elbowY = base - 50;
        handX = cx + side * 16; handY = base - 62;
      } else {
        elbowX = cx + side * 17; elbowY = base - 36 + ph * 2;
        handX = cx + side * 16 + ph * 4; handY = base - 24 + ph * 3;
      }
      limb(g, shX, shY, elbowX, elbowY, 6, 4.5, skin);
      limb(g, elbowX, elbowY, handX, handY, 4.5, 3.4, skinLit);
      // когти
      g.strokeStyle = "#efe3cc"; g.lineWidth = 2;
      g.lineCap = "round";
      for (var f = -1; f <= 1; f++) {
        var a = Math.atan2(handY - elbowY, handX - elbowX) + f * 0.45;
        g.beginPath();
        g.moveTo(handX, handY);
        g.lineTo(handX + Math.cos(a) * 6, handY + Math.sin(a) * 6);
        g.stroke();
      }
      g.lineCap = "butt";
    });

    // ── голова: череп с надбровьями и мордой ──
    var hy = base - 58;
    g.beginPath();
    g.moveTo(cx - 10, hy + 2);
    g.quadraticCurveTo(cx - 11, hy - 7, cx, hy - 8);
    g.quadraticCurveTo(cx + 11, hy - 7, cx + 10, hy + 2);
    g.quadraticCurveTo(cx + 8, hy + 9, cx, hy + 10);
    g.quadraticCurveTo(cx - 8, hy + 9, cx - 10, hy + 2);
    g.closePath();
    var headGrad = g.createLinearGradient(cx - 10, 0, cx + 10, 0);
    headGrad.addColorStop(0, skinDark);
    headGrad.addColorStop(0.45, skin);
    headGrad.addColorStop(1, skinLit);
    g.fillStyle = headGrad;
    g.strokeStyle = "rgba(0,0,0,.8)"; g.lineWidth = 2;
    g.fill(); g.stroke();

    // рога: толстые, загнуты назад
    [-1, 1].forEach(function (side) {
      g.beginPath();
      g.moveTo(cx + side * 7, hy - 4);
      g.quadraticCurveTo(cx + side * 17, hy - 10, cx + side * 16, hy - 21);
      g.quadraticCurveTo(cx + side * 13, hy - 13, cx + side * 4, hy - 7);
      g.closePath();
      g.fillStyle = horn;
      g.strokeStyle = "rgba(0,0,0,.8)"; g.lineWidth = 1.8;
      g.fill(); g.stroke();
      g.strokeStyle = "rgba(90,70,45,.6)"; g.lineWidth = 1;
      g.beginPath();
      g.moveTo(cx + side * 9, hy - 7);
      g.quadraticCurveTo(cx + side * 15, hy - 12, cx + side * 15, hy - 18);
      g.stroke();
    });

    // надбровье
    g.fillStyle = skinDark;
    g.beginPath();
    g.moveTo(cx - 10, hy - 1);
    g.quadraticCurveTo(cx, hy - 5, cx + 10, hy - 1);
    g.lineTo(cx + 9, hy + 2);
    g.quadraticCurveTo(cx, hy - 1, cx - 9, hy + 2);
    g.closePath();
    g.fill();

    // глаза
    g.fillStyle = opt.attack ? "#fff3b0" : "#ffb020";
    g.shadowColor = "#ff8000"; g.shadowBlur = 7;
    g.beginPath(); g.ellipse(cx - 4.5, hy + 2, 2.8, 2.1, -0.3, 0, Math.PI * 2); g.fill();
    g.beginPath(); g.ellipse(cx + 4.5, hy + 2, 2.8, 2.1, 0.3, 0, Math.PI * 2); g.fill();
    g.shadowBlur = 0;
    g.fillStyle = "#4a1500";
    g.fillRect(cx - 5.5, hy + 1.4, 2, 1.4);
    g.fillRect(cx + 3.5, hy + 1.4, 2, 1.4);

    // пасть с клыками
    var jaw = opt.attack ? 5 : 2.4;
    g.fillStyle = "#2a0a05";
    g.beginPath();
    g.ellipse(cx, hy + 7, 6, jaw, 0, 0, Math.PI * 2);
    g.fill();
    g.fillStyle = "#f2e6cd";
    for (var tooth = -2; tooth <= 2; tooth++) {
      g.beginPath();
      g.moveTo(cx + tooth * 2.4 - 1, hy + 7 - jaw);
      g.lineTo(cx + tooth * 2.4, hy + 7 - jaw + 2.4);
      g.lineTo(cx + tooth * 2.4 + 1, hy + 7 - jaw);
      g.closePath();
      g.fill();
      if (opt.attack) {
        g.beginPath();
        g.moveTo(cx + tooth * 2.4 - 1, hy + 7 + jaw);
        g.lineTo(cx + tooth * 2.4, hy + 7 + jaw - 2.2);
        g.lineTo(cx + tooth * 2.4 + 1, hy + 7 + jaw);
        g.closePath();
        g.fill();
      }
    }

    if (opt.attack) {                            // шар огня в лапах
      var fg = g.createRadialGradient(cx, base - 64, 1, cx, base - 64, 13);
      fg.addColorStop(0, "rgba(255,250,210,1)");
      fg.addColorStop(0.4, "rgba(255,170,40,.9)");
      fg.addColorStop(1, "rgba(255,60,0,0)");
      g.fillStyle = fg;
      g.beginPath(); g.arc(cx, base - 64, 13, 0, Math.PI * 2); g.fill();
    }
  }

  // ── Зомби-солдат с винтовкой ───────────────────────────────────────────
  function drawZombie(g, w, h, opt) {
    var t = opt.walk || 0;
    // Именно -1..1: ниже фаза ещё домножается на длину сегментов, и лишний
    // множитель разводил ноги в шпагат.
    var swing = Math.sin(t * Math.PI * 2);
    var cx = w / 2, base = h - 4;
    g.clearRect(0, 0, w, h);
    var cloth = opt.pain ? "#7f8f5c" : "#5c6b3f";
    var dark = "#3d4829";
    var skin = opt.pain ? "#d8b39a" : "#b9917a";

    // ноги: бедро и голень отдельными сегментами, шаг видно
    [[-1, swing], [1, -swing]].forEach(function (pair) {
      var side = pair[0], ph = pair[1];
      var hipX = cx + side * 5, hipY = base - 22;
      var kneeX = hipX + ph * 4, kneeY = base - 12;
      var footX = hipX + ph * 8, footY = base - 4;
      limb(g, hipX, hipY, kneeX, kneeY, 5, 4, dark);
      limb(g, kneeX, kneeY, footX, footY, 4, 3.2, dark);
      g.fillStyle = "#1a1e13";
      g.strokeStyle = "rgba(0,0,0,.8)"; g.lineWidth = 1.6;
      g.beginPath();
      g.ellipse(footX + ph * 1.5, base - 2, 5.5, 3, 0, 0, Math.PI * 2);
      g.fill(); g.stroke();
    });

    // торс с бронежилетом
    outlineShape(g, function () {
      g.beginPath();
      g.moveTo(cx - 11, base - 20);
      g.lineTo(cx - 12, base - 43);
      g.lineTo(cx + 12, base - 43);
      g.lineTo(cx + 11, base - 20);
      g.closePath();
    }, cloth);
    g.fillStyle = "rgba(0,0,0,.28)";
    g.fillRect(cx - 12, base - 34, 24, 5);
    g.fillStyle = "rgba(255,255,255,.1)";
    g.fillRect(cx - 8, base - 42, 16, 3);

    // руки и винтовка
    var gunUp = opt.attack ? 1 : 0;
    var handY = base - 34 + (gunUp ? -2 : swing * 1.6);
    outlineShape(g, function () {
      g.beginPath();
      g.rect(cx - 17, base - 41, 6, 16);
      g.closePath();
    }, cloth);
    outlineShape(g, function () {
      g.beginPath();
      g.rect(cx + 11, base - 41, 6, 16);
      g.closePath();
    }, cloth);
    g.fillStyle = "#22262b";
    g.fillRect(cx - 20, handY, 30, 4);
    g.fillRect(cx - 6, handY + 3, 6, 6);
    g.fillStyle = "#3b424b";
    g.fillRect(cx + 6, handY - 1, 8, 2);
    if (opt.attack) {
      var mg = g.createRadialGradient(cx + 14, handY + 2, 1, cx + 14, handY + 2, 9);
      mg.addColorStop(0, "rgba(255,250,210,.95)");
      mg.addColorStop(1, "rgba(255,160,20,0)");
      g.fillStyle = mg;
      g.beginPath(); g.arc(cx + 14, handY + 2, 9, 0, Math.PI * 2); g.fill();
    }

    // голова в каске
    outlineShape(g, function () {
      g.beginPath(); g.ellipse(cx, base - 50, 8, 8, 0, 0, Math.PI * 2); g.closePath();
    }, skin);
    outlineShape(g, function () {
      g.beginPath();
      g.ellipse(cx, base - 54, 10, 7, 0, Math.PI, Math.PI * 2);
      g.lineTo(cx + 10, base - 52);
      g.lineTo(cx - 10, base - 52);
      g.closePath();
    }, dark);
    g.fillStyle = "#2a1b16";
    g.fillRect(cx - 5, base - 50, 3, 2);
    g.fillRect(cx + 2, base - 50, 3, 2);
    g.fillStyle = "#5a2b22";
    g.fillRect(cx - 3, base - 45, 6, 1.6);
  }

  // ── Кадры смерти: тварь оседает, заваливается и растекается ────────────
  function drawCorpse(g, w, h, opt) {
    var p = opt.progress;              // 0..1
    var cx = w / 2, base = h - 3;
    g.clearRect(0, 0, w, h);

    var skin = opt.imp ? "#8b3a22" : "#54613a";
    var skinDark = opt.imp ? "#5c2312" : "#39422a";
    var flesh = opt.imp ? "#b8563a" : "#8a6a52";

    // лужа крови растекается раньше тела — так читается «его добили»
    var pool = 7 + p * 18;
    g.fillStyle = "rgba(112,10,10," + (0.45 + p * 0.45) + ")";
    g.beginPath();
    g.ellipse(cx, base - 2, pool, 2.5 + p * 5, 0, 0, Math.PI * 2);
    g.fill();
    g.fillStyle = "rgba(150,22,18,.55)";
    for (var s = 0; s < 8; s++) {
      var a = s * 2.4, r = pool * (0.6 + (s % 3) * 0.2);
      g.beginPath();
      g.arc(cx + Math.cos(a) * r, base - 3 - Math.sin(a) * r * 0.28,
            1.4 + (s % 3) * 0.7 * p, 0, Math.PI * 2);
      g.fill();
    }

    var lean = p * 1.25;               // заваливание набок, в радианах
    var drop = p * 20;

    g.save();
    g.translate(cx, base - 4);
    g.rotate(lean);
    g.translate(-cx, -(base - 4));

    // ноги подламываются
    [-1, 1].forEach(function (side) {
      limb(g, cx + side * 6, base - 22 + drop * 0.5, cx + side * (10 + p * 8),
           base - 8 + drop * 0.3, 5.5, 3.5, skinDark);
    });

    // торс оседает и распластывается
    g.beginPath();
    g.ellipse(cx, base - 26 + drop, 13 + p * 5, 15 - p * 6, 0, 0, Math.PI * 2);
    g.closePath();
    g.fillStyle = skin;
    g.strokeStyle = "rgba(0,0,0,.8)"; g.lineWidth = 2;
    g.fill(); g.stroke();
    // вскрытая рана
    if (p > 0.4) {
      g.fillStyle = "rgba(140,20,16,.85)";
      g.beginPath();
      g.ellipse(cx + 2, base - 26 + drop, 5 * p, 3.5 * p, 0.6, 0, Math.PI * 2);
      g.fill();
    }

    // руки раскинуты
    [-1, 1].forEach(function (side) {
      limb(g, cx + side * 10, base - 34 + drop, cx + side * (17 + p * 9),
           base - 24 + drop * 1.2, 5, 3, flesh);
    });

    // голова запрокинута
    var hy = base - 44 + drop * 1.5;
    g.beginPath();
    g.ellipse(cx - p * 8, hy, 9, 8 - p * 2, -lean * 0.5, 0, Math.PI * 2);
    g.closePath();
    g.fillStyle = flesh;
    g.strokeStyle = "rgba(0,0,0,.8)";
    g.fill(); g.stroke();
    if (opt.imp && p < 0.9) {                    // рога торчат даже у трупа
      g.fillStyle = "#cfc0a4";
      g.strokeStyle = "rgba(0,0,0,.7)"; g.lineWidth = 1.4;
      [-1, 1].forEach(function (side) {
        g.beginPath();
        g.moveTo(cx - p * 8 + side * 6, hy - 3);
        g.lineTo(cx - p * 8 + side * 13, hy - 9);
        g.lineTo(cx - p * 8 + side * 8, hy);
        g.closePath();
        g.fill(); g.stroke();
      });
    }
    // погасшие глаза
    g.fillStyle = "rgba(30,10,6,.9)";
    g.fillRect(cx - p * 8 - 4, hy - 1, 3, 2);
    g.fillRect(cx - p * 8 + 2, hy - 1, 3, 2);
    g.restore();
  }

  // ── Предметы ───────────────────────────────────────────────────────────
  function drawMedkit(g, w, h) {
    var cx = w / 2, base = h - 6;
    g.clearRect(0, 0, w, h);
    outlineShape(g, function () {
      g.beginPath(); g.rect(cx - 14, base - 20, 28, 20); g.closePath();
    }, "#e8e4dc");
    g.fillStyle = "rgba(0,0,0,.14)";
    g.fillRect(cx - 14, base - 6, 28, 6);
    g.fillStyle = "#d8342c";
    g.fillRect(cx - 3, base - 17, 6, 14);
    g.fillRect(cx - 9, base - 13, 18, 6);
    g.strokeStyle = "rgba(0,0,0,.5)"; g.lineWidth = 1;
    g.strokeRect(cx - 14, base - 20, 28, 20);
  }

  function drawArmor(g, w, h) {
    var cx = w / 2, base = h - 6;
    g.clearRect(0, 0, w, h);
    outlineShape(g, function () {
      g.beginPath();
      g.moveTo(cx, base - 26);
      g.lineTo(cx + 13, base - 20);
      g.lineTo(cx + 11, base - 4);
      g.lineTo(cx, base);
      g.lineTo(cx - 11, base - 4);
      g.lineTo(cx - 13, base - 20);
      g.closePath();
    }, "#2fa84a");
    g.fillStyle = "rgba(255,255,255,.28)";
    g.beginPath();
    g.moveTo(cx, base - 24); g.lineTo(cx - 10, base - 19);
    g.lineTo(cx - 9, base - 8); g.lineTo(cx, base - 12);
    g.closePath(); g.fill();
  }

  function drawAmmo(g, w, h, opt) {
    var cx = w / 2, base = h - 6;
    g.clearRect(0, 0, w, h);
    if (opt && opt.shells) {
      for (var i = -1; i <= 1; i++) {
        outlineShape(g, function () {
          g.beginPath(); g.rect(cx + i * 7 - 3, base - 16, 6, 16); g.closePath();
        }, "#b8362f");
        g.fillStyle = "#d9b45a";
        g.fillRect(cx + i * 7 - 3, base - 5, 6, 5);
      }
    } else {
      outlineShape(g, function () {
        g.beginPath(); g.rect(cx - 12, base - 13, 24, 13); g.closePath();
      }, "#6d6a58");
      g.fillStyle = "#c8b568";
      for (var j = 0; j < 5; j++) g.fillRect(cx - 10 + j * 4.4, base - 18, 3, 6);
      g.fillStyle = "rgba(0,0,0,.35)";
      g.fillRect(cx - 12, base - 6, 24, 3);
    }
  }

  function drawShotgunPickup(g, w, h) {
    var cx = w / 2, base = h - 8;
    g.clearRect(0, 0, w, h);
    g.fillStyle = "#3a2418";
    g.strokeStyle = "rgba(0,0,0,.7)"; g.lineWidth = 2;
    g.beginPath(); g.rect(cx - 16, base - 6, 16, 7); g.closePath();
    g.fill(); g.stroke();
    g.fillStyle = "#2c3238";
    g.beginPath(); g.rect(cx - 2, base - 7, 20, 6); g.closePath();
    g.fill(); g.stroke();
    g.fillStyle = "#565f68";
    g.fillRect(cx - 2, base - 2, 16, 3);
  }

  function drawKey(g, w, h, opt) {
    var cx = w / 2, base = h - 8;
    var color = opt.color;
    g.clearRect(0, 0, w, h);
    outlineShape(g, function () {
      g.beginPath(); g.rect(cx - 7, base - 18, 14, 18); g.closePath();
    }, color);
    g.fillStyle = "rgba(255,255,255,.45)";
    g.fillRect(cx - 5, base - 16, 10, 3);
    g.fillStyle = "rgba(0,0,0,.35)";
    g.fillRect(cx - 5, base - 8, 10, 2);
    g.fillRect(cx - 5, base - 5, 6, 2);
  }

  function drawBarrel(g, w, h) {
    var cx = w / 2, base = h - 4;
    g.clearRect(0, 0, w, h);
    var grad = g.createLinearGradient(cx - 14, 0, cx + 14, 0);
    grad.addColorStop(0, "#2e5c22");
    grad.addColorStop(0.4, "#67a53e");
    grad.addColorStop(1, "#24471b");
    outlineShape(g, function () {
      g.beginPath(); g.rect(cx - 13, base - 34, 26, 34); g.closePath();
    }, grad);
    g.fillStyle = "rgba(0,0,0,.35)";
    g.fillRect(cx - 13, base - 27, 26, 3);
    g.fillRect(cx - 13, base - 12, 26, 3);
    g.fillStyle = "#d8c93a";
    g.font = "bold 9px monospace";
    g.textAlign = "center";
    g.fillText("!", cx, base - 17);
  }

  function drawFireball(g, w, h) {
    var cx = w / 2, cy = h / 2;
    g.clearRect(0, 0, w, h);
    var grad = g.createRadialGradient(cx, cy, 1, cx, cy, w / 2);
    grad.addColorStop(0, "rgba(255,255,230,1)");
    grad.addColorStop(0.35, "rgba(255,190,60,.95)");
    grad.addColorStop(0.7, "rgba(240,90,20,.75)");
    grad.addColorStop(1, "rgba(160,20,0,0)");
    g.fillStyle = grad;
    g.beginPath(); g.arc(cx, cy, w / 2, 0, Math.PI * 2); g.fill();
  }

  function drawExplosion(g, w, h, opt) {
    var cx = w / 2, cy = h / 2;
    var p = opt.progress;
    g.clearRect(0, 0, w, h);
    var r = (0.25 + p * 0.75) * w / 2;
    var grad = g.createRadialGradient(cx, cy, r * 0.1, cx, cy, r);
    grad.addColorStop(0, "rgba(255,255,220," + (1 - p) + ")");
    grad.addColorStop(0.4, "rgba(255,170,40," + (0.9 - p * 0.7) + ")");
    grad.addColorStop(0.8, "rgba(180,50,10," + (0.7 - p * 0.6) + ")");
    grad.addColorStop(1, "rgba(60,20,10,0)");
    g.fillStyle = grad;
    g.beginPath(); g.arc(cx, cy, r, 0, Math.PI * 2); g.fill();
  }

  var sprites = null;

  function buildSprites() {
    var s = {};
    var SW = 56, SH = 72;
    // Фазы берём в четвертях: на 0 и 0.5 синус равен нулю, и оба кадра ходьбы
    // получались одинаковыми — тварь ехала по полу, не переставляя ног.
    var WALK_PHASES = [0.25, 0.5, 0.75, 1.0];
    s.impWalk = WALK_PHASES.map(function (ph) {
      return spriteFrom(SW, SH, function (g, w, h) { drawImp(g, w, h, { walk: ph }); });
    });
    s.impAttack = spriteFrom(SW, SH, function (g, w, h) { drawImp(g, w, h, { attack: true }); });
    s.impPain = spriteFrom(SW, SH, function (g, w, h) { drawImp(g, w, h, { pain: true }); });
    s.impDeath = [0.25, 0.55, 0.8, 1].map(function (p) {
      return spriteFrom(SW, SH, function (g, w, h) { drawCorpse(g, w, h, { progress: p, imp: true }); });
    });

    s.zomWalk = WALK_PHASES.map(function (ph) {
      return spriteFrom(SW, SH, function (g, w, h) { drawZombie(g, w, h, { walk: ph }); });
    });
    s.zomAttack = spriteFrom(SW, SH, function (g, w, h) { drawZombie(g, w, h, { attack: true }); });
    s.zomPain = spriteFrom(SW, SH, function (g, w, h) { drawZombie(g, w, h, { pain: true }); });
    s.zomDeath = [0.25, 0.55, 0.8, 1].map(function (p) {
      return spriteFrom(SW, SH, function (g, w, h) { drawCorpse(g, w, h, { progress: p }); });
    });

    s.medkit = spriteFrom(48, 48, drawMedkit);
    s.armor = spriteFrom(48, 48, drawArmor);
    s.ammo = spriteFrom(48, 48, function (g, w, h) { drawAmmo(g, w, h, {}); });
    s.shells = spriteFrom(48, 48, function (g, w, h) { drawAmmo(g, w, h, { shells: true }); });
    s.shotgun = spriteFrom(48, 48, drawShotgunPickup);
    s.barrel = spriteFrom(48, 56, drawBarrel);
    s.fireball = spriteFrom(24, 24, drawFireball);
    s.boom = [0.15, 0.4, 0.65, 0.9].map(function (p) {
      return spriteFrom(64, 64, function (g, w, h) { drawExplosion(g, w, h, { progress: p }); });
    });
    s.keyRed = spriteFrom(40, 40, function (g, w, h) { drawKey(g, w, h, { color: "#d63a3a" }); });
    s.keyBlue = spriteFrom(40, 40, function (g, w, h) { drawKey(g, w, h, { color: "#4472e8" }); });
    s.keyYellow = spriteFrom(40, 40, function (g, w, h) { drawKey(g, w, h, { color: "#e0c020" }); });
    return s;
  }

  /* ══ Уровни ═════════════════════════════════════════════════════════════
     # кирпич  = техпанель  M мрамор  I металл  D дверь  R/B/Y цветные двери
     X выход   . пол
     Вещи: p игрок  i бес  z зомби  h аптечка  a патроны  s дробовик
           e гильзы  v броня  r/b/y ключи  o бочка                        */
  var LEVELS = [
    {
      name: "ЗОНА 1 · АНГАР",
      sky: [26, 30, 42], floor: [46, 40, 34],
      map: [
        "################################",
        "#p.............#...............#",
        "#.....#...o....#...z......h....#",
        "#..h..D........D......#####....#",
        "#.....#...z....#......#...#..a.#",
        "################......#.i.#....#",
        "#=============#.......#####....#",
        "#=...........=#................#",
        "#=..s...i....=D....o.....z.....#",
        "#=...........=#................#",
        "#=====R========#####D###########",
        "#....#.........#...............#",
        "#.z..#...MMM...#....i.....v....#",
        "#....D...M.M...D...............#",
        "#..a.#...MMM...#......o....e...#",
        "#....#.........#...............#",
        "######.........#####...........#",
        "#....#....r....#...#.....i.....#",
        "#.h..#.........#.X.#...........#",
        "################################",
      ],
    },
    {
      name: "ЗОНА 2 · РЕАКТОР",
      sky: [34, 20, 22], floor: [40, 26, 24],
      map: [
        "##########################",
        "#p...#..........#........#",
        "#....#...z..z...#...i....#",
        "#.h..B....MM....B........#",
        "#....#....MM....#...o..a.#",
        "######..........###D######",
        "#===#####D#######.......=#",
        "#=..#...........#...z...=#",
        "#=..#..i....o...#.......=#",
        "#=..D......s....D...MM..=#",
        "#=..#...........#...MM..=#",
        "#=..#####...#####.......=#",
        "#=......#.b.#......i....=#",
        "#=..v...#...#...........=#",
        "#========#D#=============#",
        "#........#.#.............#",
        "#...i....D.D......z......#",
        "#........#.#....o........#",
        "#..e.....#Y#.........h...#",
        "##########.###############",
        "#........................#",
        "#..z...MMMMMMMMMM....i...#",
        "#......M........M........#",
        "#..a...M...X....M....v...#",
        "#......MMMMMMMMMM........#",
        "##########################",
      ],
    },
  ];

  var WALL_CHARS = {
    "#": "brick", "=": "tech", "M": "marble", "I": "metal", "X": "exit",
    "D": "door", "R": "doorRed", "B": "doorBlue", "Y": "doorYellow",
  };
  var THING_CHARS = "pizhasevrbyo";

  /* ══ Меню-превью ════════════════════════════════════════════════════════ */
  var thumbCache = null;
  function thumb(ctx, w, h, t) {
    if (!thumbCache) {
      thumbCache = document.createElement("canvas");
      thumbCache.width = 160; thumbCache.height = 80;
      var g = thumbCache.getContext("2d");
      // коридор в перспективе
      g.fillStyle = "#1a1116"; g.fillRect(0, 0, 160, 80);
      g.fillStyle = "#2b1d16"; g.fillRect(0, 44, 160, 36);
      for (var i = 0; i < 7; i++) {
        var k = i / 7, k2 = (i + 1) / 7;
        var y1 = 20 + k * 22, y2 = 20 + k2 * 22;
        var x1 = k * 56, x2 = k2 * 56;
        g.fillStyle = "rgb(" + (120 - i * 13) + "," + (62 - i * 7) + "," + (42 - i * 5) + ")";
        g.fillRect(x1, y1, x2 - x1, 80 - y1 * 2 + 20);
        g.fillRect(160 - x2, y1, x2 - x1, 80 - y1 * 2 + 20);
      }
      g.fillStyle = "#0d0a10"; g.fillRect(56, 42, 48, 22);
    }
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(thumbCache, 0, 0, w, h);
    // бес выходит из темноты
    var scale = 0.55 + 0.2 * Math.sin(t * 1.2);
    var sw = 70 * scale, sh = 90 * scale;
    if (!sprites) sprites = buildSprites();
    var frame = sprites.impWalk[Math.floor(t * 4) % 2];
    var tmp = document.createElement("canvas");
    tmp.width = frame.w; tmp.height = frame.h;
    var timg = tmp.getContext("2d").createImageData(frame.w, frame.h);
    timg.data.set(new Uint8ClampedArray(frame.data.buffer));
    tmp.getContext("2d").putImageData(timg, 0, 0);
    ctx.drawImage(tmp, w / 2 - sw / 2, h * 0.82 - sh, sw, sh);
    // ствол снизу
    ctx.fillStyle = "#2a2f36";
    ctx.fillRect(w / 2 - 9, h - 22, 18, 22);
    ctx.fillStyle = "#454d57";
    ctx.fillRect(w / 2 - 6, h - 20, 12, 6);
    ctx.imageSmoothingEnabled = true;
  }

  /* ══ Игра ═══════════════════════════════════════════════════════════════ */
  function start(root, api) {
    if (!textures) textures = buildTextures();
    if (!sprites) sprites = buildSprites();

    var canvas = document.createElement("canvas");
    canvas.width = SCREEN_W; canvas.height = SCREEN_H;
    canvas.style.cssText = "width:min(100%,1120px);height:auto;image-rendering:pixelated;" +
      "image-rendering:crisp-edges;background:#000;cursor:crosshair;max-height:calc(100vh - 110px)";
    var wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:8px;width:100%";
    var tip = document.createElement("div");
    tip.style.cssText = "color:#4a6379;font-size:.66rem;letter-spacing:.08em;text-align:center";
    tip.textContent = "WASD — движение · МЫШЬ или ← → — обзор · CTRL/ЛКМ — огонь · E — двери · " +
      "1-3 — оружие · TAB — карта · клик по экрану захватывает мышь";
    wrap.append(canvas, tip);
    root.appendChild(wrap);

    var ctx = canvas.getContext("2d", { alpha: false });
    var frame = ctx.createImageData(VIEW_W, VIEW_H);
    var frameBuf = new Uint32Array(frame.data.buffer);
    var zBuffer = new Float32Array(VIEW_W);

    var state = null;
    var raf = 0, lastTime = 0, running = true;

    /* ── Загрузка уровня ──────────────────────────────────────────────── */
    function loadLevel(index) {
      var level = LEVELS[index];
      var grid = [], things = [];
      for (var y = 0; y < level.map.length; y++) {
        var row = [];
        for (var x = 0; x < level.map[y].length; x++) {
          var ch = level.map[y][x];
          if (WALL_CHARS[ch]) {
            row.push({
              tex: WALL_CHARS[ch],
              door: ch === "D" || ch === "R" || ch === "B" || ch === "Y",
              key: ch === "R" ? "red" : ch === "B" ? "blue" : ch === "Y" ? "yellow" : null,
              exit: ch === "X",
              open: 0,
            });
          } else {
            row.push(null);
            if (THING_CHARS.indexOf(ch) >= 0) {
              things.push({ ch: ch, x: x + 0.5, y: y + 0.5 });
            }
          }
        }
        grid.push(row);
      }

      var player = { x: 1.5, y: 1.5, dir: 0, health: 100, armor: 0 };
      if (state && state.player) {          // переносим бойца между уровнями
        player.health = state.player.health;
        player.armor = state.armor;
      }
      var carried = state ? {
        weapons: state.weapons, ammo: state.ammo, weapon: state.weapon,
      } : null;

      var entities = [];
      things.forEach(function (t) {
        switch (t.ch) {
          case "p": player.x = t.x; player.y = t.y; break;
          case "i": entities.push(makeMonster("imp", t.x, t.y)); break;
          case "z": entities.push(makeMonster("zombie", t.x, t.y)); break;
          case "h": entities.push(makeItem("medkit", t.x, t.y)); break;
          case "a": entities.push(makeItem("ammo", t.x, t.y)); break;
          case "e": entities.push(makeItem("shells", t.x, t.y)); break;
          case "s": entities.push(makeItem("shotgun", t.x, t.y)); break;
          case "v": entities.push(makeItem("armor", t.x, t.y)); break;
          case "r": entities.push(makeItem("keyRed", t.x, t.y)); break;
          case "b": entities.push(makeItem("keyBlue", t.x, t.y)); break;
          case "y": entities.push(makeItem("keyYellow", t.x, t.y)); break;
          case "o": entities.push(makeBarrel(t.x, t.y)); break;
        }
      });

      state = {
        levelIndex: index,
        level: level,
        grid: grid,
        player: player,
        entities: entities,
        keys: { red: false, blue: false, yellow: false },
        armor: player.armor,
        weapons: carried ? carried.weapons : { pistol: true, shotgun: false, chaingun: false },
        ammo: carried ? carried.ammo : { bullets: 50, shells: 0 },
        weapon: carried ? carried.weapon : "pistol",
        fireCooldown: 0,
        weaponAnim: 0,
        bob: 0,
        damageFlash: 0,
        pickupFlash: 0,
        message: level.name,
        messageTime: 3000,
        kills: 0,
        totalMonsters: entities.filter(function (e) { return e.kind === "monster"; }).length,
        secretsFound: 0,
        showMap: false,
        dead: false,
        won: false,
        faceTimer: 0,
        faceMood: "normal",
        time: 0,
      };
      state.player.dir = pickStartAngle(player);
    }

    // Смотрим туда, где больше свободного места — иначе игрок стартует носом в стену.
    function pickStartAngle(p) {
      var best = 0, bestDist = -1;
      for (var a = 0; a < Math.PI * 2; a += Math.PI / 8) {
        var d = 0;
        while (d < 8 && !isWall(p.x + Math.cos(a) * d, p.y + Math.sin(a) * d)) d += 0.25;
        if (d > bestDist) { bestDist = d; best = a; }
      }
      return best;
    }

    function makeMonster(type, x, y) {
      var spec = type === "imp"
        ? { health: 60, speed: 1.5, damage: 12, range: 999, cooldown: 1500, ranged: true }
        : { health: 30, speed: 1.7, damage: 8, range: 999, cooldown: 1100, ranged: false };
      return {
        kind: "monster", type: type, x: x, y: y,
        health: spec.health, maxHealth: spec.health, spec: spec,
        state: "idle", stateTime: 0, walkPhase: Math.random(),
        attackTimer: rnd(300, 1200), painTimer: 0, deathFrame: 0,
        radius: 0.32, alive: true,
      };
    }
    function makeItem(type, x, y) {
      return { kind: "item", type: type, x: x, y: y, radius: 0.35, bobPhase: Math.random() * 6 };
    }
    function makeBarrel(x, y) {
      return { kind: "barrel", x: x, y: y, health: 20, radius: 0.3, alive: true, boomTime: 0 };
    }

    /* ── Карта ─────────────────────────────────────────────────────────── */
    function cellAt(x, y) {
      var gy = Math.floor(y), gx = Math.floor(x);
      if (gy < 0 || gy >= state.grid.length) return null;
      var row = state.grid[gy];
      if (gx < 0 || gx >= row.length) return null;
      return row[gx];
    }
    function isWall(x, y) {
      var c = cellAt(x, y);
      if (!c) return true;
      if (c.door) return c.open < 0.85;
      return true;
    }

    /* ── Звуки ─────────────────────────────────────────────────────────── */
    var snd = {
      pistol: function () {
        api.audio.noise(0.09, { volume: 0.2, freq: 2600, freqTo: 500, decay: 2.4 });
        api.audio.tone(200, 0.06, { type: "square", volume: 0.08, slideTo: 70 });
      },
      shotgun: function () {
        api.audio.noise(0.26, { volume: 0.3, freq: 1800, freqTo: 180, decay: 1.6 });
        api.audio.tone(110, 0.18, { type: "sawtooth", volume: 0.12, slideTo: 40 });
      },
      chaingun: function () {
        api.audio.noise(0.06, { volume: 0.16, freq: 3000, freqTo: 800, decay: 3 });
      },
      pain: function () {
        api.audio.tone(rnd(150, 220), 0.22, { type: "sawtooth", volume: 0.16, slideTo: 70 });
        api.audio.noise(0.12, { volume: 0.12, freq: 900, freqTo: 200 });
      },
      monsterPain: function () {
        api.audio.tone(rnd(260, 360), 0.16, { type: "square", volume: 0.11, slideTo: 120 });
      },
      monsterDie: function () {
        api.audio.tone(rnd(180, 260), 0.5, { type: "sawtooth", volume: 0.15, slideTo: 45 });
        api.audio.noise(0.4, { volume: 0.14, freq: 800, freqTo: 90, decay: 1.4 });
      },
      sight: function () {
        api.audio.tone(rnd(300, 420), 0.3, { type: "square", volume: 0.1, slideTo: 160 });
      },
      pickup: function () {
        api.audio.tone(660, 0.07, { type: "square", volume: 0.12 });
        setTimeout(function () { api.audio.tone(990, 0.09, { type: "square", volume: 0.11 }); }, 60);
      },
      door: function () {
        api.audio.noise(0.5, { volume: 0.1, freq: 320, freqTo: 90, decay: 1.1 });
      },
      locked: function () {
        api.audio.tone(140, 0.14, { type: "square", volume: 0.12 });
      },
      boom: function () {
        api.audio.noise(0.6, { volume: 0.34, freq: 1400, freqTo: 60, decay: 1.2 });
        api.audio.tone(80, 0.5, { type: "sawtooth", volume: 0.2, slideTo: 30 });
      },
      exit: function () {
        [523, 659, 784, 1046].forEach(function (f, i) {
          setTimeout(function () { api.audio.tone(f, 0.16, { type: "square", volume: 0.13 }); }, i * 110);
        });
      },
    };

    /* ── Ввод ──────────────────────────────────────────────────────────── */
    var keys = {};
    var mouseLocked = false;
    var mouseDX = 0, firing = false;

    function keyName(e) {
      var k = e.key;
      if (k.length === 1) {
        var map = { "ц": "w", "ф": "a", "ы": "s", "в": "d", "у": "e", "й": "q" };
        k = k.toLowerCase();
        if (map[k]) k = map[k];
      }
      return k;
    }
    function onKeyDown(e) {
      var k = keyName(e);
      keys[k] = true;
      if (k === "Tab") { state.showMap = !state.showMap; e.preventDefault(); }
      if (k === "e") { tryUse(); e.preventDefault(); }
      if (k === "1") switchWeapon("pistol");
      if (k === "2") switchWeapon("shotgun");
      if (k === "3") switchWeapon("chaingun");
      if (k === "Enter" && (state.dead || state.won)) restart();
      // Стреляем сразу по нажатию: короткий тык между кадрами иначе теряется,
      // а зажатая клавиша дальше отрабатывает в update().
      if (k === "Control" || k === " ") fire();
      if (["w", "a", "s", "d", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", " ", "Control"]
          .indexOf(k) >= 0) e.preventDefault();
    }
    function onKeyUp(e) { keys[keyName(e)] = false; }
    function onMouseDown(e) {
      if (e.button === 0) {
        firing = true;
        if (!mouseLocked && canvas.requestPointerLock) canvas.requestPointerLock();
      }
    }
    function onMouseUp() { firing = false; }
    function onMouseMove(e) { if (mouseLocked) mouseDX += e.movementX * 0.0022; }
    function onLockChange() { mouseLocked = document.pointerLockElement === canvas; }

    function switchWeapon(name) {
      if (!state.weapons[name] || state.weapon === name) return;
      state.weapon = name;
      state.weaponAnim = -1;         // -1..0 — подъём нового ствола
      api.audio.tone(300, 0.06, { type: "triangle", volume: 0.08 });
    }

    function tryUse() {
      var p = state.player;
      for (var d = 0.4; d <= 1.4; d += 0.25) {
        var tx = p.x + Math.cos(p.dir) * d, ty = p.y + Math.sin(p.dir) * d;
        var c = cellAt(tx, ty);
        if (!c) continue;
        if (c.exit) { finishLevel(); return; }
        if (c.door) {
          if (c.key && !state.keys[c.key]) {
            snd.locked();
            var names = { red: "красный", blue: "синий", yellow: "жёлтый" };
            say("Нужен " + names[c.key] + " ключ");
            return;
          }
          if (c.open < 1 && !c.opening) { c.opening = true; snd.door(); }
          return;
        }
      }
    }

    function say(text) { state.message = text; state.messageTime = 2200; }

    /* ── Стрельба ──────────────────────────────────────────────────────── */
    var WEAPONS = {
      pistol: { damage: 14, cooldown: 260, spread: 0.02, ammo: "bullets", perShot: 1, pellets: 1 },
      shotgun: { damage: 11, cooldown: 800, spread: 0.13, ammo: "shells", perShot: 1, pellets: 7 },
      chaingun: { damage: 11, cooldown: 105, spread: 0.055, ammo: "bullets", perShot: 1, pellets: 1 },
    };

    function fire() {
      var w = WEAPONS[state.weapon];
      if (state.fireCooldown > 0 || state.dead) return;
      if (state.ammo[w.ammo] < w.perShot) {
        api.audio.tone(120, 0.08, { type: "square", volume: 0.07 });
        state.fireCooldown = 300;
        // сами перекидываемся на то, из чего ещё есть чем стрелять
        if (state.weapon !== "pistol" && state.ammo.bullets > 0) switchWeapon("pistol");
        return;
      }
      state.ammo[w.ammo] -= w.perShot;
      state.fireCooldown = w.cooldown;
      state.weaponAnim = 1;
      state.muzzle = 1;
      if (state.weapon === "shotgun") snd.shotgun();
      else if (state.weapon === "chaingun") snd.chaingun();
      else snd.pistol();

      for (var i = 0; i < w.pellets; i++) {
        var angle = state.player.dir + (Math.random() - 0.5) * w.spread * 2;
        hitscan(angle, w.damage);
      }
      // выстрел слышно — дремлющие монстры просыпаются
      state.entities.forEach(function (e) {
        if (e.kind === "monster" && e.alive && e.state === "idle") {
          var dist = Math.hypot(e.x - state.player.x, e.y - state.player.y);
          if (dist < 12) { e.state = "chase"; }
        }
      });
    }

    function hitscan(angle, damage) {
      var p = state.player;
      var dx = Math.cos(angle), dy = Math.sin(angle);
      var step = 0.04, dist = 0;
      var x = p.x, y = p.y;
      while (dist < 24) {
        x += dx * step; y += dy * step; dist += step;
        if (isWall(x, y)) {
          spawnPuff(x - dx * 0.05, y - dy * 0.05);
          return;
        }
        for (var i = 0; i < state.entities.length; i++) {
          var e = state.entities[i];
          if ((e.kind !== "monster" && e.kind !== "barrel") || !e.alive) continue;
          if (Math.hypot(e.x - x, e.y - y) < e.radius) {
            damageEntity(e, damage);
            spawnPuff(x, y);
            return;
          }
        }
      }
    }

    function spawnPuff(x, y) {
      state.entities.push({
        kind: "effect", type: "puff", x: x, y: y, life: 140, maxLife: 140, radius: 0,
      });
    }

    function damageEntity(e, amount) {
      if (e.kind === "barrel") {
        e.health -= amount;
        if (e.health <= 0 && e.alive) explodeBarrel(e);
        return;
      }
      e.health -= amount;
      if (e.health <= 0) {
        e.alive = false;
        e.state = "dying";
        e.stateTime = 0;
        state.kills++;
        snd.monsterDie();
      } else {
        e.painTimer = 180;
        if (e.state === "idle") e.state = "chase";
        if (Math.random() < 0.5) snd.monsterPain();
      }
    }

    function explodeBarrel(barrel) {
      barrel.alive = false;
      barrel.boomTime = 1;
      snd.boom();
      state.entities.forEach(function (e) {
        if (e === barrel) return;
        var d = Math.hypot(e.x - barrel.x, e.y - barrel.y);
        if (d < 2.6) {
          if (e.kind === "monster" && e.alive) damageEntity(e, 80 - d * 20);
          else if (e.kind === "barrel" && e.alive) setTimeout(function () {
            if (e.alive) explodeBarrel(e);
          }, 120);
        }
      });
      var pd = Math.hypot(state.player.x - barrel.x, state.player.y - barrel.y);
      if (pd < 2.6) hurtPlayer(Math.round(60 - pd * 18));
    }

    function hurtPlayer(amount) {
      if (state.dead) return;
      var absorbed = Math.min(state.armor, Math.floor(amount / 3));
      state.armor -= absorbed;
      state.player.health -= (amount - absorbed);
      state.damageFlash = 1;
      state.faceMood = "pain";
      state.faceTimer = 500;
      snd.pain();
      if (state.player.health <= 0) {
        state.player.health = 0;
        state.dead = true;
        api.audio.tone(90, 1.1, { type: "sawtooth", volume: 0.2, slideTo: 30 });
      }
    }

    /* ── Обновление мира ──────────────────────────────────────────────── */
    function update(dt) {
      state.time += dt;
      var p = state.player;
      var sec = dt / 1000;

      if (state.messageTime > 0) state.messageTime -= dt;
      if (state.damageFlash > 0) state.damageFlash = Math.max(0, state.damageFlash - sec * 2.2);
      if (state.pickupFlash > 0) state.pickupFlash = Math.max(0, state.pickupFlash - sec * 3);
      if (state.fireCooldown > 0) state.fireCooldown -= dt;
      if (state.muzzle > 0) state.muzzle = Math.max(0, state.muzzle - sec * 9);
      if (state.faceTimer > 0) {
        state.faceTimer -= dt;
        if (state.faceTimer <= 0) state.faceMood = "normal";
      }
      if (state.weaponAnim > 0) state.weaponAnim = Math.max(0, state.weaponAnim - sec * 5);
      if (state.weaponAnim < 0) state.weaponAnim = Math.min(0, state.weaponAnim + sec * 5);

      // двери
      for (var gy = 0; gy < state.grid.length; gy++) {
        for (var gx = 0; gx < state.grid[gy].length; gx++) {
          var c = state.grid[gy][gx];
          if (c && c.opening && c.open < 1) {
            c.open = Math.min(1, c.open + sec * 1.1);
          }
        }
      }

      if (state.dead || state.won) return;

      /* движение игрока */
      var turn = 0;
      if (keys.ArrowLeft || keys.q) turn -= 2.6 * sec;
      if (keys.ArrowRight) turn += 2.6 * sec;
      p.dir += turn + mouseDX;
      mouseDX = 0;

      var run = keys.Shift ? 1.7 : 1;
      var speed = 3.1 * run * sec;
      var fx = 0, fy = 0;
      if (keys.w || keys.ArrowUp) { fx += Math.cos(p.dir); fy += Math.sin(p.dir); }
      if (keys.s || keys.ArrowDown) { fx -= Math.cos(p.dir); fy -= Math.sin(p.dir); }
      if (keys.a) { fx += Math.cos(p.dir - Math.PI / 2); fy += Math.sin(p.dir - Math.PI / 2); }
      if (keys.d) { fx += Math.cos(p.dir + Math.PI / 2); fy += Math.sin(p.dir + Math.PI / 2); }
      var len = Math.hypot(fx, fy);
      if (len > 0) {
        fx = fx / len * speed; fy = fy / len * speed;
        // по осям раздельно, чтобы вдоль стены можно было скользить
        if (!isWall(p.x + fx + Math.sign(fx) * 0.18, p.y)) p.x += fx;
        if (!isWall(p.x, p.y + fy + Math.sign(fy) * 0.18)) p.y += fy;
        state.bob += speed * 3.4;
      } else {
        state.bob += sec * 1.2;
      }

      if ((firing || keys.Control || keys[" "])) fire();

      /* сущности */
      for (var i = state.entities.length - 1; i >= 0; i--) {
        var e = state.entities[i];
        if (e.kind === "monster") updateMonster(e, dt, sec);
        else if (e.kind === "item") updateItem(e, i);
        else if (e.kind === "projectile") updateProjectile(e, sec, i);
        else if (e.kind === "effect") {
          e.life -= dt;
          if (e.life <= 0) state.entities.splice(i, 1);
        } else if (e.kind === "barrel" && !e.alive) {
          e.boomTime -= sec * 1.6;
          if (e.boomTime <= 0) state.entities.splice(i, 1);
        }
      }
    }

    function lineOfSight(ax, ay, bx, by) {
      var dx = bx - ax, dy = by - ay;
      var dist = Math.hypot(dx, dy);
      var steps = Math.ceil(dist / 0.12);
      for (var i = 1; i < steps; i++) {
        var t = i / steps;
        if (isWall(ax + dx * t, ay + dy * t)) return false;
      }
      return true;
    }

    function updateMonster(m, dt, sec) {
      var p = state.player;
      var dx = p.x - m.x, dy = p.y - m.y;
      var dist = Math.hypot(dx, dy);

      if (m.painTimer > 0) m.painTimer -= dt;

      if (!m.alive) {
        m.stateTime += dt;
        m.deathFrame = Math.min(3, Math.floor(m.stateTime / 110));
        return;
      }

      if (m.state === "idle") {
        if (dist < 11 && lineOfSight(m.x, m.y, p.x, p.y)) {
          m.state = "chase";
          if (Math.random() < 0.7) snd.sight();
        }
        return;
      }

      if (state.dead) return;
      var sees = lineOfSight(m.x, m.y, p.x, p.y);
      m.attackTimer -= dt;

      if (m.state === "attack") {
        m.stateTime += dt;
        if (m.stateTime > 260) { m.state = "chase"; }
        return;
      }

      if (sees && dist < 9 && m.attackTimer <= 0 && m.painTimer <= 0) {
        m.state = "attack";
        m.stateTime = 0;
        m.attackTimer = m.spec.cooldown * rnd(0.8, 1.4);
        if (m.spec.ranged) {
          var ang = Math.atan2(dy, dx);
          state.entities.push({
            kind: "projectile", x: m.x + Math.cos(ang) * 0.4, y: m.y + Math.sin(ang) * 0.4,
            vx: Math.cos(ang) * 4.4, vy: Math.sin(ang) * 4.4, damage: m.spec.damage,
            radius: 0.18, life: 4000,
          });
          api.audio.tone(320, 0.18, { type: "sawtooth", volume: 0.11, slideTo: 140 });
        } else {
          // зомби стреляет очередью с разбросом — на расстоянии часто мажет
          if (Math.random() < clamp(1.05 - dist * 0.07, 0.2, 0.8)) {
            hurtPlayer(m.spec.damage);
          }
          snd.pistol();
        }
        return;
      }

      // погоня: идём к игроку, слегка обходя стены
      if (m.painTimer > 0) return;
      var step = m.spec.speed * sec;
      var ang2 = Math.atan2(dy, dx);
      if (dist > 1.1) {
        var tries = [0, 0.5, -0.5, 1.1, -1.1];
        for (var k = 0; k < tries.length; k++) {
          var a = ang2 + tries[k];
          var nx = m.x + Math.cos(a) * step, ny = m.y + Math.sin(a) * step;
          if (!isWall(nx + Math.cos(a) * 0.25, ny + Math.sin(a) * 0.25)) {
            m.x = nx; m.y = ny;
            m.walkPhase = (m.walkPhase + step * 1.5) % 1;
            break;
          }
        }
      }
    }

    function updateProjectile(pr, sec, index) {
      pr.life -= sec * 1000;
      var nx = pr.x + pr.vx * sec, ny = pr.y + pr.vy * sec;
      if (isWall(nx, ny) || pr.life <= 0) {
        state.entities.splice(index, 1);
        state.entities.push({ kind: "effect", type: "boom", x: pr.x, y: pr.y,
                              life: 320, maxLife: 320, radius: 0 });
        api.audio.noise(0.2, { volume: 0.14, freq: 900, freqTo: 120 });
        return;
      }
      pr.x = nx; pr.y = ny;
      if (Math.hypot(pr.x - state.player.x, pr.y - state.player.y) < 0.45) {
        hurtPlayer(pr.damage);
        state.entities.splice(index, 1);
      }
    }

    function updateItem(it, index) {
      var p = state.player;
      if (Math.hypot(it.x - p.x, it.y - p.y) > 0.55) return;
      var taken = true;
      switch (it.type) {
        case "medkit":
          if (state.player.health >= 100) { taken = false; break; }
          state.player.health = Math.min(100, state.player.health + 25);
          say("Аптечка +25");
          break;
        case "armor":
          state.armor = Math.min(100, state.armor + 50);
          say("Броня +50");
          break;
        case "ammo":
          state.ammo.bullets = Math.min(300, state.ammo.bullets + 20);
          say("Патроны +20");
          break;
        case "shells":
          state.ammo.shells = Math.min(80, state.ammo.shells + 8);
          say("Гильзы +8");
          break;
        case "shotgun":
          state.weapons.shotgun = true;
          state.ammo.shells = Math.min(80, state.ammo.shells + 8);
          switchWeapon("shotgun");
          say("ДРОБОВИК!");
          break;
        case "keyRed": state.keys.red = true; say("Красный ключ"); break;
        case "keyBlue": state.keys.blue = true; say("Синий ключ"); break;
        case "keyYellow": state.keys.yellow = true; say("Жёлтый ключ"); break;
      }
      if (taken) {
        state.pickupFlash = 1;
        snd.pickup();
        state.entities.splice(index, 1);
      }
    }

    function finishLevel() {
      if (state.levelIndex + 1 < LEVELS.length) {
        snd.exit();
        var next = state.levelIndex + 1;
        loadLevel(next);
        // немного патронов на новый уровень, чтобы не начинать с пустыми руками
        state.ammo.bullets = Math.max(state.ammo.bullets, 30);
      } else {
        state.won = true;
        snd.exit();
        api.best("doom", state.kills);
      }
    }

    function restart() {
      state = null;
      loadLevel(0);
    }

    /* ══ Отрисовка мира ═════════════════════════════════════════════════ */
    function renderWorld() {
      var p = state.player;
      var lvl = state.level;
      var dirX = Math.cos(p.dir), dirY = Math.sin(p.dir);
      var planeLen = Math.tan(FOV / 2);
      var planeX = -dirY * planeLen, planeY = dirX * planeLen;
      var bobOffset = Math.sin(state.bob) * 2.2;
      var horizon = (VIEW_H / 2 + bobOffset) | 0;

      /* потолок и пол: рисуем построчно, цвет темнеет с расстоянием */
      for (var y = 0; y < VIEW_H; y++) {
        var isFloorRow = y > horizon;
        var base = isFloorRow ? lvl.floor : lvl.sky;
        var rowDist = isFloorRow
          ? (0.5 * VIEW_H) / (y - horizon)
          : (0.5 * VIEW_H) / (horizon - y);
        var shade = clamp(1.25 - rowDist * 0.16, 0.12, 1);
        // лёгкая полосатость, чтобы плоскость не выглядела заливкой
        var stripe = (y % 2 === 0) ? 1 : 0.94;
        var r = base[0] * shade * stripe, g = base[1] * shade * stripe, b = base[2] * shade * stripe;
        var color = pack(r, g, b);
        var off = y * VIEW_W;
        for (var x = 0; x < VIEW_W; x++) frameBuf[off + x] = color;
      }

      /* стены */
      for (var col = 0; col < VIEW_W; col++) {
        var cameraX = 2 * col / VIEW_W - 1;
        var rayX = dirX + planeX * cameraX;
        var rayY = dirY + planeY * cameraX;
        var mapX = Math.floor(p.x), mapY = Math.floor(p.y);
        var deltaX = Math.abs(1 / (rayX || 1e-9));
        var deltaY = Math.abs(1 / (rayY || 1e-9));
        var stepX, stepY, sideX, sideY;

        if (rayX < 0) { stepX = -1; sideX = (p.x - mapX) * deltaX; }
        else { stepX = 1; sideX = (mapX + 1 - p.x) * deltaX; }
        if (rayY < 0) { stepY = -1; sideY = (p.y - mapY) * deltaY; }
        else { stepY = 1; sideY = (mapY + 1 - p.y) * deltaY; }

        var hit = null, side = 0, guard = 0;
        while (guard++ < 128) {
          if (sideX < sideY) { sideX += deltaX; mapX += stepX; side = 0; }
          else { sideY += deltaY; mapY += stepY; side = 1; }
          if (mapY < 0 || mapY >= state.grid.length) break;
          var row = state.grid[mapY];
          if (mapX < 0 || mapX >= row.length) break;
          var cell = row[mapX];
          if (cell) {
            if (cell.door && cell.open >= 0.85) continue;   // открытая дверь не мешает
            hit = cell;
            break;
          }
        }
        if (!hit) { zBuffer[col] = 1e9; continue; }

        var perp = side === 0 ? (sideX - deltaX) : (sideY - deltaY);
        if (perp < 0.01) perp = 0.01;
        zBuffer[col] = perp;

        var lineH = Math.floor(VIEW_H / perp);
        var drawStart = Math.floor(horizon - lineH / 2);
        var drawEnd = drawStart + lineH;
        var clipStart = Math.max(0, drawStart);
        var clipEnd = Math.min(VIEW_H, drawEnd);

        var wallX = side === 0 ? p.y + perp * rayY : p.x + perp * rayX;
        wallX -= Math.floor(wallX);
        var texX = Math.floor(wallX * TEX);
        if ((side === 0 && rayX > 0) || (side === 1 && rayY < 0)) texX = TEX - texX - 1;
        // приоткрытая дверь уезжает в сторону
        if (hit.door && hit.open > 0) {
          texX = (texX + Math.floor(hit.open * TEX)) % TEX;
        }

        var tex = textures[hit.tex] || textures.brick;
        var lightSide = side === 1 ? 0.72 : 1;
        var fog = clamp(1.35 - perp * 0.13, 0.16, 1);
        var lit = lightSide * fog;
        // вспышка от выстрела подсвечивает ближние стены
        if (state.muzzle > 0) lit = Math.min(1.6, lit + state.muzzle * clamp(1.6 - perp * 0.35, 0, 1.1));

        var texStep = TEX / lineH;
        var texPos = (clipStart - horizon + lineH / 2) * texStep;
        for (var yy = clipStart; yy < clipEnd; yy++) {
          var texY = texPos & (TEX - 1);
          texPos += texStep;
          var c2 = tex[texY * TEX + texX];
          var rr = (c2 & 255) * lit;
          var gg = ((c2 >> 8) & 255) * lit;
          var bb = ((c2 >> 16) & 255) * lit;
          frameBuf[yy * VIEW_W + col] = pack(rr, gg, bb);
        }
      }

      /* спрайты — от дальних к ближним */
      var visible = [];
      state.entities.forEach(function (e) {
        var sprite = spriteFor(e);
        if (!sprite) return;
        var dx = e.x - p.x, dy = e.y - p.y;
        visible.push({ e: e, sprite: sprite, dist: dx * dx + dy * dy, dx: dx, dy: dy });
      });
      visible.sort(function (a, b) { return b.dist - a.dist; });

      var invDet = 1 / (planeX * dirY - dirX * planeY);
      visible.forEach(function (v) {
        var transX = invDet * (dirY * v.dx - dirX * v.dy);
        var transY = invDet * (-planeY * v.dx + planeX * v.dy);
        if (transY <= 0.15) return;

        var screenX = Math.floor((VIEW_W / 2) * (1 + transX / transY));
        var scale = v.e.kind === "item" || v.e.kind === "projectile" ? 0.6 : 1;
        var spriteH = Math.abs(Math.floor(VIEW_H / transY)) * scale;
        var spriteW = Math.floor(spriteH * (v.sprite.w / v.sprite.h));
        // предметы лежат на полу, монстры стоят
        var vOffset = v.e.kind === "projectile" ? -spriteH * 0.25 : 0;
        var startY = Math.floor(horizon + (VIEW_H / transY) / 2 - spriteH + vOffset);
        var startX = screenX - (spriteW >> 1);
        var fog2 = clamp(1.35 - transY * 0.13, 0.2, 1);
        var glow = (v.e.kind === "projectile" || (v.e.kind === "effect")) ? 1 : fog2;

        for (var sx = 0; sx < spriteW; sx++) {
          var px = startX + sx;
          if (px < 0 || px >= VIEW_W) continue;
          if (transY >= zBuffer[px]) continue;
          var texX2 = Math.floor(sx * v.sprite.w / spriteW);
          for (var sy = 0; sy < spriteH; sy++) {
            var py = startY + sy;
            if (py < 0 || py >= VIEW_H) continue;
            var texY2 = Math.floor(sy * v.sprite.h / spriteH);
            var c3 = v.sprite.data[texY2 * v.sprite.w + texX2];
            var alpha = (c3 >>> 24) & 255;
            if (alpha < 24) continue;
            var rr2 = (c3 & 255) * glow;
            var gg2 = ((c3 >> 8) & 255) * glow;
            var bb2 = ((c3 >> 16) & 255) * glow;
            if (alpha > 200) {
              frameBuf[py * VIEW_W + px] = pack(rr2, gg2, bb2);
            } else {
              var old = frameBuf[py * VIEW_W + px];
              var a = alpha / 255;
              frameBuf[py * VIEW_W + px] = pack(
                (old & 255) * (1 - a) + rr2 * a,
                ((old >> 8) & 255) * (1 - a) + gg2 * a,
                ((old >> 16) & 255) * (1 - a) + bb2 * a);
            }
          }
        }
      });

      ctx.putImageData(frame, 0, 0);
    }

    function spriteFor(e) {
      if (e.kind === "monster") {
        var set = e.type === "imp" ? sprites.impWalk : sprites.zomWalk;
        if (!e.alive) {
          return (e.type === "imp" ? sprites.impDeath : sprites.zomDeath)[e.deathFrame];
        }
        if (e.painTimer > 0) return e.type === "imp" ? sprites.impPain : sprites.zomPain;
        if (e.state === "attack") return e.type === "imp" ? sprites.impAttack : sprites.zomAttack;
        return set[Math.floor(e.walkPhase * set.length) % set.length];
      }
      if (e.kind === "item") return sprites[e.type];
      if (e.kind === "barrel") {
        if (e.alive) return sprites.barrel;
        var f = Math.min(3, Math.floor((1 - e.boomTime) * 4));
        return sprites.boom[clamp(f, 0, 3)];
      }
      if (e.kind === "projectile") return sprites.fireball;
      if (e.kind === "effect") {
        if (e.type === "boom") {
          return sprites.boom[clamp(Math.floor((1 - e.life / e.maxLife) * 4), 0, 3)];
        }
        return null;                   // облачко от пули не рисуем спрайтом
      }
      return null;
    }

    /* ══ Оружие в руках ═════════════════════════════════════════════════ */
    function drawWeapon() {
      var bobX = Math.sin(state.bob * 0.5) * 5;
      var bobY = Math.abs(Math.cos(state.bob * 0.5)) * 4;
      var recoil = state.weaponAnim > 0 ? state.weaponAnim * 12 : 0;
      var raise = state.weaponAnim < 0 ? -state.weaponAnim * 60 : 0;
      var cx = VIEW_W / 2 + bobX;
      var baseY = VIEW_H + bobY + recoil + raise;

      ctx.save();
      ctx.translate(cx, baseY);

      // Рука в перчатке — общая для всех стволов.
      function glove(gx, gy, gw, gh) {
        ctx.fillStyle = "#6d5136";
        ctx.fillRect(gx, gy, gw, gh);
        ctx.fillStyle = "#8a6743";
        ctx.fillRect(gx, gy, gw, 4);
        ctx.fillStyle = "#4a3524";
        ctx.fillRect(gx, gy + gh - 5, gw, 5);
        for (var f = 1; f < 4; f++) {          // складки на пальцах
          ctx.fillStyle = "rgba(40,28,18,.55)";
          ctx.fillRect(gx + 2, gy + 5 + f * 6, gw - 4, 2);
        }
      }

      if (state.weapon === "pistol") {
        // ствол
        ctx.fillStyle = "#20242a";
        ctx.fillRect(-9, -76, 18, 34);
        ctx.fillStyle = "#333a43";
        ctx.fillRect(-9, -76, 18, 5);
        ctx.fillStyle = "#12151a";
        ctx.fillRect(-4, -78, 8, 4);          // дуло
        // затвор и рамка
        ctx.fillStyle = "#2b3138";
        ctx.fillRect(-13, -46, 26, 20);
        ctx.fillStyle = "#454e59";
        ctx.fillRect(-13, -46, 26, 4);
        ctx.fillStyle = "#1a1e23";
        ctx.fillRect(-6, -30, 12, 12);        // скоба
        ctx.fillStyle = "#5c6672";
        ctx.fillRect(-2, -74, 4, 3);          // мушка
        glove(-26, -30, 20, 30);
        glove(6, -30, 20, 30);
      } else if (state.weapon === "shotgun") {
        // стволы
        ctx.fillStyle = "#1b1f24";
        ctx.fillRect(-11, -104, 22, 46);
        ctx.fillStyle = "#333a43";             // блик по левой кромке
        ctx.fillRect(-11, -104, 4, 46);
        ctx.fillStyle = "#0d1014";
        ctx.fillRect(-11, -104, 22, 4);        // срез дула
        ctx.fillStyle = "#454e59";
        ctx.fillRect(-2, -102, 4, 3);          // мушка
        // цевьё
        ctx.fillStyle = "#53341d";
        ctx.fillRect(-15, -66, 30, 22);
        ctx.fillStyle = "#6d4524";
        ctx.fillRect(-15, -66, 30, 5);
        ctx.fillStyle = "rgba(0,0,0,.3)";
        for (var rib = 0; rib < 4; rib++) ctx.fillRect(-15, -60 + rib * 5, 30, 2);
        // ствольная коробка
        ctx.fillStyle = "#2b3239";
        ctx.fillRect(-17, -46, 34, 26);
        ctx.fillStyle = "#454e59";
        ctx.fillRect(-17, -46, 34, 4);
        ctx.fillStyle = "#12151a";
        ctx.fillRect(-13, -30, 12, 10);        // окно выброса
        // приклад уходит вниз-вправо
        ctx.fillStyle = "#3a2418";
        ctx.fillRect(-4, -22, 26, 24);
        // руки: передняя на цевье, задняя на рукояти
        glove(-30, -64, 18, 26);
        glove(12, -26, 20, 28);
      } else {
        // вращающийся блок стволов
        for (var b = -2; b <= 2; b++) {
          var depth = Math.abs(b);
          ctx.fillStyle = depth === 0 ? "#3f4852" : (depth === 1 ? "#2f363f" : "#242a31");
          ctx.fillRect(b * 8 - 4, -100 + depth * 6, 8, 52 - depth * 5);
          ctx.fillStyle = "#0f1216";
          ctx.fillRect(b * 8 - 4, -100 + depth * 6, 8, 4);
        }
        // кожух и коробка
        ctx.fillStyle = "#1a1e23";
        ctx.fillRect(-22, -52, 44, 14);
        ctx.fillStyle = "#4a545f";
        ctx.fillRect(-22, -52, 44, 4);
        ctx.fillStyle = "#2b3239";
        ctx.fillRect(-18, -38, 36, 26);
        ctx.fillStyle = "#454e59";
        ctx.fillRect(-18, -38, 36, 4);
        // лента с патронами свисает вбок
        ctx.fillStyle = "#8a6a2a";
        ctx.fillRect(14, -16, 20, 8);
        ctx.fillStyle = "#c8a03a";
        for (var c = 0; c < 5; c++) ctx.fillRect(15 + c * 4, -15, 3, 6);
        glove(-32, -36, 18, 30);
        glove(10, -30, 20, 30);
      }

      if (state.muzzle > 0.25) {
        var grad = ctx.createRadialGradient(0, -62, 2, 0, -62, 34);
        grad.addColorStop(0, "rgba(255,250,200," + state.muzzle + ")");
        grad.addColorStop(0.45, "rgba(255,170,40," + state.muzzle * 0.7 + ")");
        grad.addColorStop(1, "rgba(255,80,0,0)");
        ctx.fillStyle = grad;
        ctx.beginPath(); ctx.arc(0, -62, 34, 0, Math.PI * 2); ctx.fill();
      }
      ctx.restore();
    }

    /* ══ Статус-панель ══════════════════════════════════════════════════ */
    var DIGITS = {
      "0": ["111", "101", "101", "101", "111"], "1": ["010", "110", "010", "010", "111"],
      "2": ["111", "001", "111", "100", "111"], "3": ["111", "001", "111", "001", "111"],
      "4": ["101", "101", "111", "001", "001"], "5": ["111", "100", "111", "001", "111"],
      "6": ["111", "100", "111", "101", "111"], "7": ["111", "001", "010", "010", "010"],
      "8": ["111", "101", "111", "101", "111"], "9": ["111", "101", "111", "001", "111"],
      "%": ["101", "001", "010", "100", "101"], "-": ["000", "000", "111", "000", "000"],
    };

    function bigNumber(text, x, y, scale, color) {
      ctx.fillStyle = color;
      var cursor = x;
      for (var i = 0; i < text.length; i++) {
        var glyph = DIGITS[text[i]];
        if (!glyph) { cursor += scale * 4; continue; }
        for (var r = 0; r < 5; r++) {
          for (var c = 0; c < 3; c++) {
            if (glyph[r][c] === "1") ctx.fillRect(cursor + c * scale, y + r * scale, scale, scale);
          }
        }
        cursor += scale * 4;
      }
      return cursor;
    }

    // Лицо бойца: чем меньше здоровья, тем хуже дела.
    function drawFace(x, y, size) {
      var hp = state.player.health;
      var g = ctx;
      var skin = hp > 60 ? "#c98d63" : hp > 30 ? "#bd7e56" : "#a96a48";
      g.fillStyle = "#1a1410";
      g.fillRect(x, y, size, size);
      // волосы
      g.fillStyle = "#5b3a20";
      g.fillRect(x + 3, y + 2, size - 6, 7);
      // лицо
      g.fillStyle = skin;
      g.fillRect(x + 4, y + 6, size - 8, size - 10);
      // глаза — смотрят в сторону поворота
      var look = Math.round(Math.sin(state.time / 900) * 1.4);
      g.fillStyle = "#ffffff";
      g.fillRect(x + 7 + look, y + 12, 4, 3);
      g.fillRect(x + size - 11 + look, y + 12, 4, 3);
      g.fillStyle = "#1a1a2a";
      g.fillRect(x + 8 + look, y + 13, 2, 2);
      g.fillRect(x + size - 10 + look, y + 13, 2, 2);
      // брови: злее при низком здоровье
      g.fillStyle = "#3a2412";
      var brow = hp > 60 ? 0 : 1;
      g.fillRect(x + 6, y + 10 - brow, 6, 2);
      g.fillRect(x + size - 12, y + 10 - brow, 6, 2);
      // рот
      g.fillStyle = "#5a2020";
      if (state.dead) {
        g.fillStyle = "#7a1010";
        g.fillRect(x + 6, y + 18, size - 12, 5);
      } else if (state.faceMood === "pain") {
        g.fillRect(x + 7, y + 19, size - 14, 4);
      } else if (hp > 70) {
        g.fillRect(x + 8, y + 20, size - 16, 2);
      } else {
        g.fillRect(x + 8, y + 21, size - 16, 2);
      }
      // кровь по мере урона
      if (hp < 70) {
        g.fillStyle = "rgba(150,20,16,.85)";
        g.fillRect(x + 6, y + 8, 2, 6 + (70 - hp) / 8);
        if (hp < 40) g.fillRect(x + size - 9, y + 12, 2, 5);
        if (hp < 20) g.fillRect(x + 11, y + 16, 3, 7);
      }
    }

    function drawBar() {
      var y = VIEW_H;
      var grad = ctx.createLinearGradient(0, y, 0, y + BAR_H);
      grad.addColorStop(0, "#4a4238");
      grad.addColorStop(0.1, "#3a342c");
      grad.addColorStop(1, "#221f1a");
      ctx.fillStyle = grad;
      ctx.fillRect(0, y, SCREEN_W, BAR_H);
      ctx.fillStyle = "rgba(0,0,0,.4)";
      ctx.fillRect(0, y, SCREEN_W, 2);

      function slot(x, w, label) {
        ctx.fillStyle = "rgba(0,0,0,.32)";
        ctx.fillRect(x, y + 6, w, BAR_H - 12);
        ctx.strokeStyle = "rgba(255,255,255,.07)";
        ctx.strokeRect(x + 0.5, y + 6.5, w - 1, BAR_H - 13);
        ctx.fillStyle = "#8a7f6c";
        ctx.font = 'bold 7px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "center";
        ctx.fillText(label, x + w / 2, y + BAR_H - 7);
      }

      var w = WEAPONS[state.weapon];
      slot(6, 62, "ПАТРОНЫ");
      bigNumber(String(state.ammo[w.ammo]), 16, y + 14, 4, "#ff2b2b");

      slot(74, 74, "ЗДОРОВЬЕ");
      bigNumber(state.player.health + "%", 82, y + 14, 4, "#ff2b2b");

      // ARMS — какие стволы уже есть
      slot(154, 62, "ОРУЖИЕ");
      var owned = [["1", true], ["2", state.weapons.shotgun], ["3", state.weapons.chaingun]];
      var ax = 162;
      owned.forEach(function (o) {
        var active = (o[0] === "1" && state.weapon === "pistol") ||
                     (o[0] === "2" && state.weapon === "shotgun") ||
                     (o[0] === "3" && state.weapon === "chaingun");
        bigNumber(o[0], ax, y + 16, 3, o[1] ? (active ? "#ffd84a" : "#ff2b2b") : "#5c5346");
        ax += 18;
      });

      slot(222, 44, "ЛИЦО");
      drawFace(230, y + 10, 28);

      slot(272, 62, "БРОНЯ");
      bigNumber(state.armor + "%", 280, y + 14, 4, "#3ad14e");

      slot(340, 54, "КЛЮЧИ");
      var keyColors = [["red", "#d63a3a"], ["blue", "#4472e8"], ["yellow", "#e0c020"]];
      keyColors.forEach(function (k, i) {
        var kx = 350, ky = y + 11 + i * 12;
        ctx.fillStyle = state.keys[k[0]] ? k[1] : "rgba(255,255,255,.07)";
        ctx.fillRect(kx, ky, 26, 8);
        if (state.keys[k[0]]) {
          ctx.fillStyle = "rgba(255,255,255,.4)";
          ctx.fillRect(kx, ky, 26, 2);
        }
      });
    }

    /* ══ Карта на Tab ═══════════════════════════════════════════════════ */
    function drawAutomap() {
      var cell = Math.min(
        Math.floor(VIEW_W / state.grid[0].length),
        Math.floor(VIEW_H / state.grid.length)) || 4;
      var ox = (VIEW_W - state.grid[0].length * cell) / 2;
      var oy = (VIEW_H - state.grid.length * cell) / 2;
      ctx.fillStyle = "rgba(4,6,11,.985)";
      ctx.fillRect(0, 0, VIEW_W, VIEW_H);
      for (var y = 0; y < state.grid.length; y++) {
        for (var x = 0; x < state.grid[y].length; x++) {
          var c = state.grid[y][x];
          if (!c) continue;
          ctx.fillStyle = c.exit ? "#ffd84a"
            : c.key ? ({ red: "#d63a3a", blue: "#4472e8", yellow: "#e0c020" })[c.key]
            : c.door ? "#8a6a3a" : "#2f5f73";
          ctx.fillRect(ox + x * cell, oy + y * cell, cell - 1, cell - 1);
        }
      }
      state.entities.forEach(function (e) {
        if (e.kind === "monster" && e.alive) ctx.fillStyle = "#ff4040";
        else if (e.kind === "item") ctx.fillStyle = "#40ff90";
        else return;
        ctx.fillRect(ox + e.x * cell - 1, oy + e.y * cell - 1, 3, 3);
      });
      var p = state.player;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(ox + p.x * cell, oy + p.y * cell);
      ctx.lineTo(ox + (p.x + Math.cos(p.dir) * 1.6) * cell, oy + (p.y + Math.sin(p.dir) * 1.6) * cell);
      ctx.stroke();
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(ox + p.x * cell - 2, oy + p.y * cell - 2, 4, 4);

      ctx.fillStyle = "#8fa5b8";
      ctx.font = 'bold 9px "Cascadia Code", Consolas, monospace';
      ctx.textAlign = "left";
      ctx.fillText(state.level.name + "   УБИТО: " + state.kills + "/" + state.totalMonsters,
                   8, 14);
    }

    /* ══ Кадр целиком ═══════════════════════════════════════════════════ */
    function render() {
      renderWorld();
      if (state.showMap) drawAutomap();
      else drawWeapon();

      // вспышки
      if (state.damageFlash > 0) {
        ctx.fillStyle = "rgba(180,10,10," + state.damageFlash * 0.42 + ")";
        ctx.fillRect(0, 0, VIEW_W, VIEW_H);
      }
      if (state.pickupFlash > 0) {
        ctx.fillStyle = "rgba(230,200,90," + state.pickupFlash * 0.22 + ")";
        ctx.fillRect(0, 0, VIEW_W, VIEW_H);
      }

      // прицел
      if (!state.showMap && !state.dead) {
        ctx.strokeStyle = "rgba(255,255,255,.55)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(VIEW_W / 2 - 5, VIEW_H / 2); ctx.lineTo(VIEW_W / 2 - 2, VIEW_H / 2);
        ctx.moveTo(VIEW_W / 2 + 2, VIEW_H / 2); ctx.lineTo(VIEW_W / 2 + 5, VIEW_H / 2);
        ctx.moveTo(VIEW_W / 2, VIEW_H / 2 - 5); ctx.lineTo(VIEW_W / 2, VIEW_H / 2 - 2);
        ctx.moveTo(VIEW_W / 2, VIEW_H / 2 + 2); ctx.lineTo(VIEW_W / 2, VIEW_H / 2 + 5);
        ctx.stroke();
      }

      if (state.messageTime > 0) {
        ctx.fillStyle = "rgba(255,240,190," + clamp(state.messageTime / 500, 0, 1) + ")";
        ctx.font = 'bold 11px "Cascadia Code", Consolas, monospace';
        ctx.textAlign = "left";
        ctx.fillText(state.message, 8, 16);
      }

      drawBar();

      if (state.dead || state.won) {
        ctx.fillStyle = state.won ? "rgba(10,20,14,.86)" : "rgba(40,4,4,.72)";
        ctx.fillRect(0, 0, SCREEN_W, SCREEN_H);
        ctx.textAlign = "center";
        ctx.fillStyle = state.won ? "#63f5ad" : "#ff4040";
        ctx.font = 'bold 26px "Cascadia Code", Consolas, monospace';
        ctx.fillText(state.won ? "ЗОНА ЗАЧИЩЕНА" : "ВЫ ПОГИБЛИ", SCREEN_W / 2, SCREEN_H / 2 - 8);
        ctx.fillStyle = "#dfeffa";
        ctx.font = 'bold 11px "Cascadia Code", Consolas, monospace';
        ctx.fillText("Убито: " + state.kills + " / " + state.totalMonsters,
                     SCREEN_W / 2, SCREEN_H / 2 + 14);
        ctx.fillStyle = "#8fa5b8";
        ctx.fillText("ENTER — сначала    ESCAPE — в меню", SCREEN_W / 2, SCREEN_H / 2 + 34);
      }
    }

    function loop(now) {
      if (!running) return;
      raf = requestAnimationFrame(loop);
      var dt = Math.min(50, now - lastTime || 16);
      lastTime = now;
      update(dt);
      render();
    }

    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("keyup", onKeyUp);
    canvas.addEventListener("mousedown", onMouseDown);
    document.addEventListener("mouseup", onMouseUp);
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("pointerlockchange", onLockChange);
    canvas.addEventListener("contextmenu", function (e) { e.preventDefault(); });

    loadLevel(0);
    lastTime = performance.now();
    raf = requestAnimationFrame(loop);

    return {
      destroy: function () {
        running = false;
        cancelAnimationFrame(raf);
        document.removeEventListener("keydown", onKeyDown);
        document.removeEventListener("keyup", onKeyUp);
        canvas.removeEventListener("mousedown", onMouseDown);
        document.removeEventListener("mouseup", onMouseUp);
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("pointerlockchange", onLockChange);
        if (document.pointerLockElement === canvas && document.exitPointerLock) {
          document.exitPointerLock();
        }
      },
    };
  }

  window.VitazArcade.register({
    id: "doom",
    title: "DOOM",
    tagline: "Шутер на рейкастинге: два уровня, ключи и двери, бесы с огнём, зомби с винтовками, " +
      "взрывающиеся бочки и три ствола. Текстуры и спрайты нарисованы кодом.",
    keys: "WASD · мышь — обзор · Ctrl — огонь · E — двери · Tab — карта",
    accent: "#ff3b30",
    thumb: thumb,
    start: start,
  });
})();
