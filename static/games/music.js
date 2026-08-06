/* Музыка аркады: шестнадцать коротких зацикленных тем в духе 8 бит.
 *
 * Никаких файлов: всё считается на лету из нотной записи. Трек весит
 * несколько строк текста вместо мегабайта mp3, грузится мгновенно и
 * зацикливается без щелчка на стыке.
 *
 * Запись. Такт — шестнадцать шагов, шаг это шестнадцатая. Пишем ноты
 * буквами с номером октавы, между ними:
 *     .   держать предыдущую
 *     -   тишина
 *     |   черта такта, на звук не влияет — только чтобы глазом читалось
 * Ударные своим алфавитом: k бочка, s малый, h закрытый хай-хэт,
 * H открытый, - пауза.
 *
 * Три голоса, как в приставке: ведущий (квадрат), бас (треугольник) и
 * шум под ударные. Четвёртого канала нет намеренно — с ним теряется та
 * самая жестяная простота, ради которой всё и затевалось.
 */
(function () {
  "use strict";

  var STEPS = 16;                       // шагов в такте
  var NOTE = { c: 0, d: 2, e: 4, f: 5, g: 7, a: 9, b: 11 };

  /* Имя ноты в частоту. «c4» — до первой октавы, 261.63 Гц. */
  function freqOf(name) {
    var m = /^([a-g])([#s]?)(-?\d)$/.exec(name);
    if (!m) return 0;
    var semis = NOTE[m[1]] + (m[2] ? 1 : 0) + (parseInt(m[3], 10) + 1) * 12;
    return 440 * Math.pow(2, (semis - 69) / 12);
  }

  /* Строку записи — в массив шагов. Каждый шаг: имя ноты, "." или null. */
  function parse(line) {
    var out = [];
    (line || "").split(/\s+/).forEach(function (tok) {
      if (!tok || tok === "|") return;
      out.push(tok === "-" ? null : tok);
    });
    return out;
  }

  /* ── Ударные рисунки ─────────────────────────────────────────────── */
  var D = {
    ровно:   "k - h - s - h - k - h - s - h -",
    быстро:  "k - h h s - h h k h h h s - h h",
    марш:    "k k h - s - h - k k h - s - h H",
    вальс:   "k - - h - - s - - h - - k - - h",
    гонка:   "k h k h s h k h k h k h s h k H",
    тихо:    "k - - - s - - - k - - - s - - h",
    сбивка:  "k - h - s - h h k - h - s s s H",
    пусто:   "- - - - - - - - - - - - - - - -",
  };

  /* ── Темы ────────────────────────────────────────────────────────────
     Порядок важен только для списка; по играм их раскидывает MUSIC_FOR
     в arcade.js — поменять привязку это одна строка. */
  var TRACKS = [
    { name: "Ангар", bpm: 132, drum: D.ровно,
      lead: "c5 - e5 - g5 - e5 - c5 - g4 - a4 - b4 - | c5 - e5 - a5 - g5 - e5 - c5 - d5 - e5 -",
      bass: "c3 . . . c3 . . . g2 . . . g2 . . . | a2 . . . a2 . . . f2 . . . g2 . . ." },

    { name: "Погоня", bpm: 156, drum: D.гонка,
      lead: "e5 e5 - g5 a5 - g5 e5 d5 - e5 - c5 - - - | e5 e5 - g5 c6 - b5 a5 g5 - e5 - g5 - - -",
      bass: "a2 a2 - a2 e2 e2 - e2 f2 f2 - f2 g2 g2 - g2 | a2 a2 - a2 e2 e2 - e2 f2 f2 g2 g2 a2 - - -" },

    { name: "Ночной двор", bpm: 96, drum: D.тихо,
      lead: "a4 - c5 - e5 - . - d5 - c5 - b4 - - - | a4 - c5 - e5 - g5 - f5 - e5 - d5 - c5 -",
      bass: "a2 . . . . . . . f2 . . . . . . . | d2 . . . . . . . e2 . . . e2 . . ." },

    { name: "Кирпичи", bpm: 144, drum: D.быстро,
      lead: "g4 - g4 - a4 - b4 - c5 - b4 - a4 - g4 - | g4 - b4 - d5 - c5 - b4 - a4 - g4 - d4 -",
      bass: "g2 - g2 - g2 - g2 - c3 - c3 - c3 - c3 - | d3 - d3 - d3 - d3 - g2 - g2 - g2 - g2 -" },

    { name: "Стальной цех", bpm: 126, drum: D.марш,
      lead: "d5 - - d5 - f5 - d5 c5 - - c5 - a4 - - | d5 - - d5 - f5 - a5 g5 - f5 - d5 - - -",
      bass: "d2 . . . a2 . . . as2 . . . a2 . . . | d2 . . . a2 . . . g2 . . . a2 . . ." },

    { name: "Лабиринт", bpm: 118, drum: D.ровно,
      lead: "e4 - a4 - b4 - c5 - b4 - a4 - e4 - - - | e4 - a4 - c5 - d5 - c5 - b4 - a4 - - -",
      bass: "a2 . . . e2 . . . f2 . . . e2 . . . | a2 . . . e2 . . . g2 . . . a2 . . ." },

    { name: "Пружина", bpm: 168, drum: D.гонка,
      lead: "c5 g4 c5 g4 ds5 g4 ds5 g4 f5 g4 f5 g4 ds5 - c5 - | c5 g4 c5 g4 gs5 g4 gs5 g4 as5 - gs5 - f5 - ds5 -",
      bass: "c2 c2 - c2 c2 c2 - c2 f2 f2 - f2 f2 f2 - f2 | gs2 gs2 - gs2 gs2 - as2 - c3 c3 - c3 c3 - - -" },

    { name: "Дозор", bpm: 108, drum: D.вальс,
      lead: "f4 - a4 - c5 - a4 - g4 - as4 - d5 - as4 - | f4 - a4 - c5 - f5 - e5 - d5 - c5 - a4 -",
      bass: "f2 . . . . . . . g2 . . . . . . . | f2 . . . . . . . c3 . . . c3 . . ." },

    { name: "Жёлоб", bpm: 138, drum: D.сбивка,
      lead: "b4 - - a4 - g4 - - a4 - b4 - d5 - - - | b4 - - d5 - e5 - - d5 - b4 - a4 - g4 -",
      bass: "e2 - e2 - e2 - e2 - g2 - g2 - g2 - g2 - | a2 - a2 - a2 - a2 - b2 - b2 - e2 - - -" },

    { name: "Тревога", bpm: 150, drum: D.марш,
      lead: "d5 d5 - as4 - d5 - as4 c5 c5 - a4 - c5 - a4 | as4 as4 - f4 - as4 - d5 c5 - as4 - a4 - - -",
      bass: "d2 d2 d2 - d2 d2 d2 - c2 c2 c2 - c2 c2 c2 - | as1 as1 as1 - as1 as1 - - a1 a1 - - a1 - - -" },

    { name: "Синий лёд", bpm: 100, drum: D.тихо,
      lead: "g5 - - - e5 - - - c5 - d5 - e5 - - - | g5 - - - a5 - - - g5 - e5 - d5 - c5 -",
      bass: "c3 . . . . . . . a2 . . . . . . . | f2 . . . . . . . g2 . . . . . . ." },

    { name: "Шестерёнки", bpm: 128, drum: D.быстро,
      lead: "a4 b4 c5 - a4 b4 c5 - d5 - c5 - b4 - a4 - | a4 b4 c5 - e5 d5 c5 - b4 - a4 - gs4 - - -",
      bass: "a2 - a2 a2 - a2 - a2 e2 - e2 e2 - e2 - e2 | f2 - f2 f2 - f2 - f2 e2 - e2 - a2 - - -" },

    { name: "Праздник", bpm: 146, drum: D.сбивка,
      lead: "c5 - e5 g5 - a5 g5 - e5 - c5 - g4 - - - | c5 - e5 g5 - c6 b5 - g5 - e5 - c5 - - -",
      bass: "c3 - g2 - c3 - g2 - f2 - c3 - f2 - c3 - | g2 - d3 - g2 - d3 - c3 - g2 - c3 - - -" },

    { name: "Тёмный трюм", bpm: 92, drum: D.тихо,
      lead: "d4 - - - f4 - - - a4 - - - g4 - f4 - | d4 - - - as4 - - - a4 - - - f4 - - -",
      bass: "d2 . . . . . . . d2 . . . . . . . | as1 . . . . . . . a1 . . . . . . ." },

    { name: "Финал", bpm: 160, drum: D.гонка,
      lead: "c5 e5 g5 c6 - g5 e5 c5 d5 f5 a5 d6 - a5 f5 d5 | e5 g5 b5 e6 - b5 g5 e5 c6 - b5 - a5 - g5 -",
      bass: "c3 - c3 - g2 - g2 - d3 - d3 - a2 - a2 - | e3 - e3 - b2 - b2 - c3 - g2 - c3 - - -" },

    { name: "Титры", bpm: 88, drum: D.пусто,
      lead: "c5 - - e5 - - g5 - - e5 - - c5 - - - | a4 - - c5 - - e5 - - d5 - - c5 - - -",
      bass: "c3 . . . . . . . g2 . . . . . . . | a2 . . . . . . . f2 . . . g2 . . ." },
  ];

  /* ── Проигрыватель ───────────────────────────────────────────────── */
  var player = {
    muted: false,
    index: -1,
    ctx: null,
    gain: null,
    timer: 0,
    step: 0,
    nextTime: 0,
    track: null,
    parsed: null,

    list: function () {
      return TRACKS.map(function (t) { return { name: t.name, bpm: t.bpm }; });
    },

    count: function () { return TRACKS.length; },

    /* Включить тему по номеру. Тот же номер второй раз — ничего не делаем,
       иначе при каждом обращении музыка начиналась бы заново. */
    play: function (index, audio) {
      if (index == null || index < 0) return this.stop();
      index = index % TRACKS.length;
      if (this.index === index && this.timer) return;
      this.stop();
      var ctx = audio && audio.ensure ? audio.ensure() : null;
      if (!ctx) return;
      this.ctx = ctx;
      this.index = index;
      this.track = TRACKS[index];
      this.parsed = {
        lead: parse(this.track.lead),
        bass: parse(this.track.bass),
        drum: parse(this.track.drum),
      };
      this.gain = ctx.createGain();
      this.gain.gain.value = this.muted ? 0 : 0.5;
      this.gain.connect(ctx.destination);
      this.step = 0;
      this.nextTime = ctx.currentTime + 0.06;
      var self = this;
      // Планируем ноты с запасом вперёд: setInterval в браузере плавает
      // на десятки миллисекунд, и по нему ритм разъезжается на слух.
      this.timer = setInterval(function () { self._fill(); }, 25);
      this._fill();
    },

    stop: function () {
      if (this.timer) clearInterval(this.timer);
      this.timer = 0;
      this.index = -1;
      if (this.gain) {
        try {
          var g = this.gain, t = this.ctx.currentTime;
          g.gain.setValueAtTime(g.gain.value, t);
          g.gain.linearRampToValueAtTime(0, t + 0.08);
          setTimeout(function () { try { g.disconnect(); } catch (e) {} }, 200);
        } catch (e) {}
      }
      this.gain = null;
    },

    setMuted: function (on) {
      this.muted = !!on;
      if (this.gain) {
        var t = this.ctx.currentTime;
        this.gain.gain.setValueAtTime(this.gain.gain.value, t);
        this.gain.gain.linearRampToValueAtTime(this.muted ? 0 : 0.5, t + 0.05);
      }
    },

    _fill: function () {
      if (!this.ctx || !this.track) return;
      var spb = 60 / this.track.bpm / 4;          // длительность шестнадцатой
      while (this.nextTime < this.ctx.currentTime + 0.25) {
        this._playStep(this.step, this.nextTime, spb);
        this.nextTime += spb;
        this.step++;
      }
    },

    _voice: function (name, at, dur, type, vol, slide) {
      var f = freqOf(name);
      if (!f) return;
      var ctx = this.ctx;
      var osc = ctx.createOscillator();
      var g = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(f, at);
      if (slide) osc.frequency.exponentialRampToValueAtTime(f * slide, at + dur);
      // Короткая атака и спад: без них на стыке нот слышен щелчок
      g.gain.setValueAtTime(0.0001, at);
      g.gain.exponentialRampToValueAtTime(vol, at + 0.008);
      g.gain.exponentialRampToValueAtTime(0.0001, at + dur);
      osc.connect(g).connect(this.gain);
      osc.start(at);
      osc.stop(at + dur + 0.02);
    },

    _drum: function (kind, at) {
      var ctx = this.ctx;
      if (kind === "k") {                          // бочка — скользящий тон вниз
        var o = ctx.createOscillator(), g = ctx.createGain();
        o.type = "sine";
        o.frequency.setValueAtTime(150, at);
        o.frequency.exponentialRampToValueAtTime(45, at + 0.11);
        g.gain.setValueAtTime(0.5, at);
        g.gain.exponentialRampToValueAtTime(0.0001, at + 0.13);
        o.connect(g).connect(this.gain);
        o.start(at); o.stop(at + 0.15);
        return;
      }
      var dur = kind === "s" ? 0.13 : kind === "H" ? 0.11 : 0.035;
      var frames = Math.max(1, Math.floor(ctx.sampleRate * dur));
      var buf = ctx.createBuffer(1, frames, ctx.sampleRate);
      var d = buf.getChannelData(0);
      for (var i = 0; i < frames; i++) {
        d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / frames, kind === "s" ? 2 : 3);
      }
      var src = ctx.createBufferSource();
      src.buffer = buf;
      var f = ctx.createBiquadFilter();
      f.type = kind === "s" ? "bandpass" : "highpass";
      f.frequency.value = kind === "s" ? 1900 : 7000;
      var g2 = ctx.createGain();
      g2.gain.value = kind === "s" ? 0.32 : 0.16;
      src.connect(f).connect(g2).connect(this.gain);
      src.start(at);
    },

    _playStep: function (step, at, spb) {
      var p = this.parsed;
      function pick(arr) { return arr.length ? arr[step % arr.length] : null; }

      var lead = pick(p.lead);
      if (lead && lead !== ".") {
        // Держим ноту, пока идут точки, — так мелодия не рубится на куски
        var hold = 1, arr = p.lead;
        while (arr[(step + hold) % arr.length] === ".") hold++;
        this._voice(lead, at, spb * hold * 0.92, "square", 0.16);
      }
      var bass = pick(p.bass);
      if (bass && bass !== ".") {
        var bh = 1, ba = p.bass;
        while (ba[(step + bh) % ba.length] === ".") bh++;
        this._voice(bass, at, spb * bh * 0.9, "triangle", 0.26);
      }
      var dr = pick(p.drum);
      if (dr && dr !== ".") this._drum(dr, at);
    },
  };

  window.VitazMusic = player;
})();
