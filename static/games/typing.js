/* Тренажёр слепой печати в духе «Стамины».
 *
 * Работает как классический тренажёр: пока не нажмёшь правильную клавишу,
 * текст не двигается. Опечатка считается и подсвечивается, но откатывать
 * ничего не надо — так вырабатывается привычка не тыкать наугад.
 *
 * На экране можно включить клавиатуру: клавиши раскрашены по пальцам
 * (у каждого свой цвет), следующая нужная мигает, а нужный палец подписан
 * снизу. На телефоне клавиатура включена всегда и работает как ввод —
 * физической-то нет.
 *
 * В рейтинг уходит чистая скорость: знаков в минуту за вычетом опечаток.
 * Считается только на длинных текстах — на разминке из десяти символов
 * любая цифра была бы враньём.
 */
(function () {
  "use strict";

  /* ── Пальцы ──────────────────────────────────────────────────────────── */
  var FINGERS = {
    L5: { name: "левый мизинец",      color: "#ff6b9d" },
    L4: { name: "левый безымянный",   color: "#ffb35c" },
    L3: { name: "левый средний",      color: "#ffd84a" },
    L2: { name: "левый указательный", color: "#63f5ad" },
    R2: { name: "правый указательный", color: "#2de2ff" },
    R3: { name: "правый средний",     color: "#5f9bff" },
    R4: { name: "правый безымянный",  color: "#b57cff" },
    R5: { name: "правый мизинец",     color: "#ff5cc8" },
    TH: { name: "большой палец",      color: "#8fa5b8" },
  };

  /* Раскладка по физическим клавишам. Для каждой — что она даёт в двух
     раскладках без Shift и с ним, каким пальцем жать и во сколько единиц
     ширины. Русская ЙЦУКЕН ложится на те же самые клавиши. */
  function K(f, w, en, En, ru, Ru) {
    return { f: f, w: w || 1, en: en, En: En == null ? (en || "").toUpperCase() : En,
             ru: ru, Ru: Ru == null ? (ru || "").toUpperCase() : Ru };
  }
  function SP(f, w, label) { return { f: f, w: w, label: label, dead: true }; }

  var ROWS = [
    [K("L5", 1, "`", "~", "ё"), K("L5", 1, "1", "!", "1", "!"),
     K("L4", 1, "2", "@", "2", '"'), K("L3", 1, "3", "#", "3", "№"),
     K("L2", 1, "4", "$", "4", ";"), K("L2", 1, "5", "%", "5", "%"),
     K("R2", 1, "6", "^", "6", ":"), K("R2", 1, "7", "&", "7", "?"),
     K("R3", 1, "8", "*", "8", "*"), K("R4", 1, "9", "(", "9", "("),
     K("R5", 1, "0", ")", "0", ")"), K("R5", 1, "-", "_", "-", "_"),
     K("R5", 1, "=", "+", "=", "+"), SP("R5", 2, "⌫")],

    [SP("L5", 1.5, "Tab"), K("L5", 1, "q", null, "й"), K("L4", 1, "w", null, "ц"),
     K("L3", 1, "e", null, "у"), K("L2", 1, "r", null, "к"), K("L2", 1, "t", null, "е"),
     K("R2", 1, "y", null, "н"), K("R2", 1, "u", null, "г"), K("R3", 1, "i", null, "ш"),
     K("R4", 1, "o", null, "щ"), K("R5", 1, "p", null, "з"), K("R5", 1, "[", "{", "х"),
     K("R5", 1, "]", "}", "ъ"), K("R5", 1.5, "\\", "|", "\\", "/")],

    [SP("L5", 1.8, "Caps"), K("L5", 1, "a", null, "ф"), K("L4", 1, "s", null, "ы"),
     K("L3", 1, "d", null, "в"), K("L2", 1, "f", null, "а"), K("L2", 1, "g", null, "п"),
     K("R2", 1, "h", null, "р"), K("R2", 1, "j", null, "о"), K("R3", 1, "k", null, "л"),
     K("R4", 1, "l", null, "д"), K("R5", 1, ";", ":", "ж"), K("R5", 1, "'", '"', "э"),
     SP("R5", 2.2, "Enter")],

    [SP("L5", 2.4, "Shift"), K("L5", 1, "z", null, "я"), K("L4", 1, "x", null, "ч"),
     K("L3", 1, "c", null, "с"), K("L2", 1, "v", null, "м"), K("L2", 1, "b", null, "и"),
     K("R2", 1, "n", null, "т"), K("R2", 1, "m", null, "ь"), K("R3", 1, ",", "<", "б"),
     K("R4", 1, ".", ">", "ю"), K("R5", 1, "/", "?", ".", ","),
     SP("R5", 2.6, "Shift")],

    [SP("TH", 3, "Ctrl  Alt"), K("TH", 8, " ", " ", " ", " "), SP("TH", 3, "Alt  Ctrl")],
  ];

  /* ── Тексты ──────────────────────────────────────────────────────────────
     rank: true — текст длинный, результат по нему уходит в общий рейтинг.
     Разминки в рейтинг не идут: на двадцати символах любая скорость случайна. */
  var TEXTS = {
    ru: [
      { title: "Разминка · основной ряд",
        body: "фыва олдж фыва олдж ффф ыыы ввв ааа ооо ллл ддд жжж " +
              "фыв олд ава ало дом лов вол лад вода лоза жаба фара" },
      { title: "Разминка · верхний ряд",
        body: "йцук енгш щзхъ ййй ццц ууу ккк еее ннн ггг шшш " +
              "куку неуч цунк щенок гуще шёпот зной ключ шкура" },
      { title: "Разминка · нижний ряд",
        body: "ячсм итьб ююю яяя ччч ссс ммм иии ттт ььь ббб " +
              "мясо часы сито тьма быт мичман смятие часть" },
      { title: "Разминка · цифры и знаки",
        body: "1234 5678 90-= 12 34 56 78 90 ; % : ? * ( ) " +
              "1 января, 2 февраля; 3 марта: 4 апреля? 5 мая!" },

      { title: "Пушкин · У лукоморья",
        body: "У лукоморья дуб зелёный; златая цепь на дубе том: " +
              "и днём и ночью кот учёный всё ходит по цепи кругом; " +
              "идёт направо - песнь заводит, налево - сказку говорит." },
      { title: "Пушкин · Евгений Онегин", rank: true,
        body: "Мой дядя самых честных правил, когда не в шутку занемог, " +
              "он уважать себя заставил и лучше выдумать не мог. " +
              "Его пример другим наука; но, боже мой, какая скука " +
              "с больным сидеть и день и ночь, не отходя ни шагу прочь! " +
              "Какое низкое коварство полуживого забавлять, ему подушки поправлять, " +
              "печально подносить лекарство, вздыхать и думать про себя: " +
              "когда же чёрт возьмёт тебя!" },

      { title: "Серверная", rank: true,
        body: "В серверной всегда одна и та же погода. Гудят вентиляторы, " +
              "мигают зелёные лампы, и по стойке ползёт тёплый воздух. " +
              "Здесь не бывает вечера: свет одинаковый и в полдень, и в три " +
              "часа ночи. Человек, который сюда заходит, первым делом смотрит " +
              "не на экран, а на ряд индикаторов - по ним видно всё сразу. " +
              "Зелёный значит, что можно идти пить чай. Жёлтый значит, что чай " +
              "придётся пить быстро. Красный значит, что чая сегодня не будет. " +
              "Опытный человек умеет отличать шум исправной машины от шума " +
              "машины, которая держится из последних сил. Это как со старым " +
              "автомобилем: сначала ты слышишь новый стук, а потом уже " +
              "понимаешь, что он значит." },

      { title: "Ночной поезд", rank: true,
        body: "Поезд шёл всю ночь, и всю ночь за окном тянулась одна и та же " +
              "чернота, изредка проколотая жёлтым огоньком. Иногда огоньков " +
              "становилось много, они выстраивались в улицу, и было понятно, " +
              "что это город; потом улица обрывалась, и снова начиналось поле. " +
              "В вагоне пахло чаем и разогретым металлом. Кто-то не спал и " +
              "переворачивал страницу раз в две минуты - страница шуршала " +
              "громче, чем колёса. На верхней полке спал человек, который " +
              "садился ещё днём и с тех пор ни разу не проснулся. Проводница " +
              "прошла по коридору, придерживая стаканы, и стаканы всё равно " +
              "звякнули. К утру чернота за окном стала синей, потом серой, " +
              "и в ней проявились деревья - сначала как пятна, потом как " +
              "деревья. Стало видно, что всю ночь рядом с поездом шёл лес." },

      { title: "Кот и распорядок", rank: true,
        body: "У кота был твёрдый распорядок дня, и человек в этом распорядке " +
              "занимал скромное место. В шесть утра кот проверял, жив ли " +
              "человек, и делал это громко. В семь он спал на клавиатуре, " +
              "потому что клавиатура тёплая и потому что человек тогда " +
              "перестаёт смотреть в экран. В полдень кот сидел на подоконнике " +
              "и следил за птицами с видом инспектора, который всё записывает. " +
              "Вечером наступало главное: кот ложился ровно посередине " +
              "прохода, там, где ходят чаще всего, и лежал с достоинством. " +
              "Обойти его было можно, но каждый раз получалось, что это " +
              "человек уступил дорогу, а не кот выбрал неудачное место. " +
              "Ночью кот работал: бегал по коридору, ронял мелкие предметы " +
              "и проверял, все ли двери закрыты. К утру отчёт был готов, " +
              "и всё начиналось сначала." },
    ],

    en: [
      { title: "Warm-up · home row",
        body: "asdf jkl; asdf jkl; aaa sss ddd fff jjj kkk lll " +
              "dad sad lad fall glass flask salad" },
      { title: "Warm-up · pangrams",
        body: "the quick brown fox jumps over the lazy dog. " +
              "pack my box with five dozen liquor jugs. " +
              "how vexingly quick daft zebras jump!" },

      { title: "Carroll · Alice in Wonderland", rank: true,
        body: "Alice was beginning to get very tired of sitting by her sister " +
              "on the bank, and of having nothing to do: once or twice she had " +
              "peeped into the book her sister was reading, but it had no " +
              "pictures or conversations in it, and what is the use of a book, " +
              "thought Alice, without pictures or conversations?" },

      { title: "The workshop", rank: true,
        body: "The workshop smelled of oil and warm dust. Along the far wall " +
              "stood a row of drawers, each one labelled in handwriting that " +
              "had faded to the colour of weak tea. Nobody remembered who had " +
              "written the labels, and nobody dared to change them, because " +
              "the old man could find any screw in the building in under ten " +
              "seconds and nobody wanted to be the one who broke that. " +
              "He worked slowly, which is a different thing from working " +
              "badly. He would pick up a part, turn it over twice, and put it " +
              "down again in a place that looked random and never was. " +
              "When something finally clicked into position, he did not smile; " +
              "he simply reached for the next part, as if the machine had " +
              "agreed with him all along and the matter had never been " +
              "in doubt." },

      { title: "The lighthouse", rank: true,
        body: "From the cliff the sea looked patient, which is the most " +
              "dishonest thing about it. All afternoon the water moved in long " +
              "slow lines, and the gulls hung above the rocks without seeming " +
              "to work at all. Then the wind turned, and within an hour the " +
              "same water was throwing itself at the stones hard enough to " +
              "shake the handrail. The keeper had seen it a thousand times " +
              "and still stopped to watch. He said the trick was never to " +
              "trust a calm sea in the middle of the day, and never to trust " +
              "yourself for knowing better. The light came on at dusk, swung " +
              "once around the bay, and went on doing it whether anyone was " +
              "out there or not." },
    ],
  };

  /* Приводим текст к тому, что реально набирается с клавиатуры: длинные тире,
     «ёлочки» и многоточие одной клавишей не наберёшь. */
  function normalize(s) {
    return s.replace(/[—–]/g, "-")
            .replace(/[«»“”„]/g, '"')
            .replace(/[‘’]/g, "'")
            .replace(/…/g, "...")
            .replace(/ /g, " ");
  }

  /* ── Превью на карточке ─────────────────────────────────────────────── */
  function thumb(ctx, w, h, t) {
    ctx.fillStyle = "#06090f";
    ctx.fillRect(0, 0, w, h);
    var line = "слепая печать без ошибок";
    var shown = Math.floor((t * 7) % (line.length + 12));
    ctx.font = 'bold 18px "Cascadia Code", Consolas, monospace';
    ctx.textBaseline = "middle";
    ctx.fillStyle = "#2de2ff";
    ctx.fillText(line.slice(0, shown), 18, 40);
    ctx.fillStyle = "#33465a";
    ctx.fillText(line.slice(shown), 18 + ctx.measureText(line.slice(0, shown)).width, 40);
    if (Math.floor(t * 3) % 2) {
      ctx.fillStyle = "#ffd84a";
      ctx.fillRect(18 + ctx.measureText(line.slice(0, shown)).width, 30, 2, 20);
    }
    // ряд клавиш внизу, подсвечивается «нажатая»
    var keys = 12, kw = (w - 36) / keys;
    for (var i = 0; i < keys; i++) {
      var on = i === Math.floor(t * 7) % keys;
      ctx.fillStyle = on ? "#2de2ff" : "#182231";
      ctx.fillRect(18 + i * kw + 2, h - 52, kw - 4, kw - 4 > 26 ? 26 : kw - 4);
    }
    ctx.fillStyle = "#182231";
    ctx.fillRect(18 + kw * 2, h - 22, (w - 36) - kw * 4, 12);
  }

  /* ── Игра ────────────────────────────────────────────────────────────── */
  function start(root, api) {
    var lang = "ru";
    var textIndex = 4;
    var showKb = true;
    var shiftOn = false;

    var text = "", pos = 0, errors = 0, strokes = 0;
    var startedAt = 0, finishedAt = 0, wrongAt = -1;
    var timer = 0;

    var css = document.createElement("style");
    css.textContent = [
      ".tp{display:flex;flex-direction:column;gap:8px;width:100%;max-width:1020px;",
      "max-height:100%;min-height:0;font-family:" + api.font + "}",
      ".tp-bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;flex:none}",
      ".tp-bar select,.tp-bar button,.tp-bar label{font:700 .68rem " + api.font + ";",
      "letter-spacing:.06em;color:#bfe6f5;border:1px solid rgba(45,226,255,.28);",
      "background:rgba(45,226,255,.06);padding:6px 10px;cursor:pointer;border-radius:0}",
      ".tp-bar select{max-width:min(46vw,300px)}",
      ".tp-bar button.on{color:#04060b;background:#2de2ff;border-color:#2de2ff}",
      ".tp-bar label{display:flex;align-items:center;gap:6px;user-select:none}",
      ".tp-bar input[type=checkbox]{accent-color:#2de2ff;width:14px;height:14px;margin:0}",
      ".tp-stats{display:flex;flex-wrap:wrap;gap:14px;flex:none;font:700 .72rem " + api.font + ";",
      "letter-spacing:.06em;color:#4a6379}",
      ".tp-stats b{color:#eaf6ff;font-size:.86rem}",
      ".tp-stats .accent b{color:#63f5ad}",
      ".tp-text{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;",
      "touch-action:pan-y;padding:14px 16px;border:1px solid rgba(45,226,255,.2);",
      "background:rgba(6,10,17,.86);font-size:clamp(15px,2.1vw,20px);line-height:1.9;",
      "letter-spacing:.02em;word-break:break-word}",
      ".tp-text i{font-style:normal;color:#33465a}",
      ".tp-text i.ok{color:#63f5ad}",
      ".tp-text i.bad{color:#ff6b9d;background:rgba(255,107,157,.18)}",
      ".tp-text i.cur{color:#04060b;background:#ffd84a;border-radius:2px}",
      ".tp-text i.cur.miss{background:#ff6b9d;color:#fff;animation:tpShake .16s}",
      "@keyframes tpShake{0%,100%{transform:translateX(0)}33%{transform:translateX(-3px)}",
      "66%{transform:translateX(3px)}}",
      /* клавиатура */
      ".tp-kb{flex:none;display:flex;flex-direction:column;gap:3px;align-items:center;",
      "padding:8px;border:1px solid rgba(255,255,255,.07);background:rgba(10,14,22,.7)}",
      ".tp-kr{display:flex;gap:3px;width:100%;justify-content:center}",
      ".tp-key{--kc:#8fa5b8;position:relative;display:grid;place-items:center;",
      "height:clamp(22px,4.4vw,38px);border-radius:4px;font:700 clamp(9px,1.5vw,13px) " + api.font + ";",
      "color:#cfe2ee;border:1px solid rgba(255,255,255,.08);",
      "background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(0,0,0,.25));",
      "box-shadow:inset 0 -2px 0 rgba(0,0,0,.35);user-select:none;overflow:hidden}",
      ".tp-key::after{content:'';position:absolute;inset:auto 0 0 0;height:3px;",
      "background:var(--kc);opacity:.55}",
      ".tp-key.dead{color:#4a6379;font-size:clamp(8px,1.2vw,10px)}",
      ".tp-key.next{color:#04060b;background:var(--kc);border-color:#fff;",
      "box-shadow:0 0 0 2px var(--kc),0 0 14px var(--kc)}",
      ".tp-key.hold{background:rgba(255,255,255,.16);border-color:#eaf6ff}",
      ".tp-kb .tp-hint{font:700 .64rem " + api.font + ";letter-spacing:.1em;color:#4a6379;",
      "margin-top:2px;text-align:center}",
      ".tp-kb .tp-hint b{color:#eaf6ff}",
      /* итог */
      ".tp-done{flex:none;padding:12px 14px;border:1px solid rgba(99,245,173,.4);",
      "background:rgba(10,26,20,.9);font:700 .78rem " + api.font + ";color:#eaf6ff;",
      "letter-spacing:.04em;line-height:1.7}",
      ".tp-done s{display:block;color:#63f5ad;font-size:1.05rem;text-decoration:none;",
      "margin-bottom:4px}",
      ".tp-warn{flex:none;color:#ffb35c;font:700 .7rem " + api.font + ";letter-spacing:.06em}",
    ].join("");

    var wrap = document.createElement("div");
    wrap.className = "tp";
    wrap.innerHTML =
      '<div class="tp-bar">' +
        '<button type="button" data-lang="ru">РУС</button>' +
        '<button type="button" data-lang="en">ENG</button>' +
        '<select data-pick></select>' +
        '<label><input type="checkbox" data-kb checked>клавиатура</label>' +
        '<button type="button" data-again>Заново</button>' +
      '</div>' +
      '<div class="tp-stats">' +
        '<span>ВРЕМЯ <b data-t>0:00</b></span>' +
        '<span>СКОРОСТЬ <b data-cpm>0</b> зн/мин</span>' +
        '<span class="accent">ЧИСТАЯ <b data-net>0</b> зн/мин</span>' +
        '<span>ОШИБКИ <b data-err>0</b></span>' +
        '<span>ТОЧНОСТЬ <b data-acc>100</b>%</span>' +
      '</div>' +
      '<div class="tp-warn" hidden></div>' +
      '<div class="tp-text"></div>' +
      '<div class="tp-done" hidden></div>' +
      '<div class="tp-kb"></div>';
    root.appendChild(css);
    root.appendChild(wrap);

    var elText = wrap.querySelector(".tp-text");
    var elKb = wrap.querySelector(".tp-kb");
    var elDone = wrap.querySelector(".tp-done");
    var elWarn = wrap.querySelector(".tp-warn");
    var elPick = wrap.querySelector("[data-pick]");
    var elKbBox = wrap.querySelector("[data-kb]");
    var stats = {
      t: wrap.querySelector("[data-t]"), cpm: wrap.querySelector("[data-cpm]"),
      net: wrap.querySelector("[data-net]"), err: wrap.querySelector("[data-err]"),
      acc: wrap.querySelector("[data-acc]"),
    };

    // На телефоне физической клавиатуры нет — экранная становится вводом,
    // выключать её нельзя.
    if (api.touch) { elKbBox.checked = true; elKbBox.disabled = true; }

    /* ── Раскладка: char -> клавиша ──────────────────────────────────── */
    var keyEls = [];          // { def, el }
    var byChar = {};          // символ -> { def, el, shift }

    function buildKeyboard() {
      elKb.innerHTML = "";
      keyEls = [];
      byChar = {};
      ROWS.forEach(function (row) {
        var r = document.createElement("div");
        r.className = "tp-kr";
        row.forEach(function (def) {
          var el = document.createElement("div");
          el.className = "tp-key" + (def.dead ? " dead" : "");
          el.style.flex = def.w + " 0 0";
          el.style.setProperty("--kc", FINGERS[def.f].color);
          if (def.dead) {
            el.textContent = def.label || "";
          } else {
            var base = lang === "ru" ? def.ru : def.en;
            var up = lang === "ru" ? def.Ru : def.En;
            el.textContent = base === " " ? "пробел" : (shiftOn ? up : base);
            if (base) { byChar[base] = { el: el, def: def, shift: false }; }
            if (up && up !== base) { byChar[up] = { el: el, def: def, shift: true }; }
          }
          if (!def.dead || def.label === "Shift") {
            el.addEventListener("pointerdown", function (e) {
              e.preventDefault();
              onScreenKey(def);
            });
          }
          keyEls.push({ def: def, el: el });
          r.appendChild(el);
        });
        elKb.appendChild(r);
      });
      var hint = document.createElement("div");
      hint.className = "tp-hint";
      elKb.appendChild(hint);
      elKb.hintEl = hint;
    }

    function onScreenKey(def) {
      if (def.dead) {
        if (def.label === "Shift") { shiftOn = !shiftOn; buildKeyboard(); paintKeyboard(); }
        return;
      }
      var base = lang === "ru" ? def.ru : def.en;
      var up = lang === "ru" ? def.Ru : def.En;
      var ch = shiftOn && up ? up : base;
      if (shiftOn) { shiftOn = false; buildKeyboard(); }
      type(ch);
    }

    /* Подсветка нужной клавиши и подпись пальца. */
    function paintKeyboard() {
      keyEls.forEach(function (k) { k.el.classList.remove("next", "hold"); });
      if (!elKb.hintEl) return;
      if (pos >= text.length) { elKb.hintEl.innerHTML = "&nbsp;"; return; }
      var ch = text[pos];
      var hit = byChar[ch];
      if (!hit) { elKb.hintEl.innerHTML = "&nbsp;"; return; }
      hit.el.classList.add("next");
      var finger = FINGERS[hit.def.f];
      var label = ch === " " ? "пробел" : ch;
      if (hit.shift) {
        // Shift жмётся мизинцем противоположной руки — иначе рука уезжает.
        var wantLeft = hit.def.f.charAt(0) === "R";
        keyEls.forEach(function (k) {
          if (k.def.label === "Shift" &&
              (wantLeft ? k.def.f === "L5" : k.def.f === "R5")) k.el.classList.add("hold");
        });
        label = "Shift + " + label;
      }
      elKb.hintEl.innerHTML = "<b>" + escapeHtml(label) + "</b> &middot; " + finger.name;
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }

    /* ── Текст ───────────────────────────────────────────────────────── */
    function fillPicker() {
      elPick.innerHTML = TEXTS[lang].map(function (t, i) {
        return '<option value="' + i + '">' + escapeHtml(t.title) +
               (t.rank ? " ★" : "") + "</option>";
      }).join("");
      elPick.value = String(textIndex);
    }

    function paintText() {
      var html = "";
      for (var i = 0; i < text.length; i++) {
        var cls = i < pos ? "ok" : (i === pos ? "cur" + (wrongAt === pos ? " miss" : "") : "");
        var ch = text[i];
        html += '<i class="' + cls + '">' +
                (ch === " " ? (i === pos ? "&nbsp;" : " ") : escapeHtml(ch)) + "</i>";
      }
      elText.innerHTML = html;
      var cur = elText.querySelector(".cur");
      if (cur && cur.scrollIntoView) {
        var top = cur.offsetTop - elText.clientHeight / 2;
        elText.scrollTop = Math.max(0, top);
      }
    }

    function paintStats() {
      var now = finishedAt || (startedAt ? performance.now() : 0);
      var secs = startedAt ? (now - startedAt) / 1000 : 0;
      var mins = secs / 60;
      stats.t.textContent = Math.floor(secs / 60) + ":" +
        (Math.floor(secs % 60) < 10 ? "0" : "") + Math.floor(secs % 60);
      var cpm = mins > 0 ? Math.round(pos / mins) : 0;
      stats.cpm.textContent = cpm;
      stats.net.textContent = mins > 0 ? Math.max(0, Math.round((pos - errors) / mins)) : 0;
      stats.err.textContent = errors;
      stats.acc.textContent = strokes ? Math.round((strokes - errors) / strokes * 100) : 100;
    }

    function netCpm() {
      if (!startedAt || !finishedAt) return 0;
      var mins = (finishedAt - startedAt) / 60000;
      return mins > 0 ? Math.max(0, Math.round((pos - errors) / mins)) : 0;
    }

    function reset() {
      var item = TEXTS[lang][textIndex] || TEXTS[lang][0];
      text = normalize(item.body);
      pos = 0; errors = 0; strokes = 0;
      startedAt = 0; finishedAt = 0; wrongAt = -1;
      shiftOn = false;
      elDone.hidden = true;
      elWarn.hidden = true;
      buildKeyboard();
      paintText();
      paintKeyboard();
      paintStats();
    }

    function finish() {
      finishedAt = performance.now();
      paintStats();
      var item = TEXTS[lang][textIndex] || {};
      var speed = netCpm();
      api.audio.tone(660, 0.12, { type: "square", volume: 0.12 });
      setTimeout(function () { api.audio.tone(990, 0.2, { type: "square", volume: 0.1 }); }, 130);
      api.buzz([40, 50, 90]);

      var acc = strokes ? Math.round((strokes - errors) / strokes * 100) : 100;
      elDone.hidden = false;
      elDone.innerHTML =
        "<s>ГОТОВО - " + speed + " зн/мин чистыми</s>" +
        "знаков: " + text.length + " &middot; ошибок: " + errors +
        " &middot; точность: " + acc + "%<br>" +
        (item.rank
          ? "результат уходит в общий рейтинг"
          : "разминка в рейтинг не идёт - выбери текст со звёздочкой");
      if (item.rank && speed > 0 && api.record) {
        api.best("typing", speed);
        api.record("typing", speed);
      }
    }

    /* Один введённый символ. Пока не попал - текст стоит на месте. */
    function type(ch) {
      if (!ch || pos >= text.length) return;
      if (!startedAt) startedAt = performance.now();
      strokes++;
      if (ch === text[pos]) {
        pos++;
        wrongAt = -1;
        api.audio.tone(1100, 0.02, { type: "square", volume: 0.04 });
        if (pos >= text.length) { paintText(); paintKeyboard(); finish(); return; }
      } else {
        errors++;
        wrongAt = pos;
        api.buzz(12);
        api.audio.tone(160, 0.07, { type: "sawtooth", volume: 0.09 });
      }
      paintText();
      paintKeyboard();
      paintStats();
    }

    /* Раскладка системы должна совпадать с выбранным языком, иначе клавиши
       дают не те буквы. Ловим это и говорим прямо, а не молчим. */
    function checkLayout(ch) {
      var cyr = /[а-яёА-ЯЁ]/.test(ch);
      var lat = /[a-zA-Z]/.test(ch);
      if (lang === "ru" && lat) return "Похоже, раскладка английская - переключи на русскую";
      if (lang === "en" && cyr) return "Похоже, раскладка русская - переключи на английскую";
      return "";
    }

    function onKey(e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "Backspace") { e.preventDefault(); return; }   // откат не нужен
      if (e.key.length !== 1) return;
      e.preventDefault();
      e.stopPropagation();
      var warn = checkLayout(e.key);
      elWarn.hidden = !warn;
      elWarn.textContent = warn;
      if (warn) return;
      type(e.key);
    }

    /* ── Панель и настройки ──────────────────────────────────────────── */
    wrap.querySelectorAll("[data-lang]").forEach(function (b) {
      b.addEventListener("click", function () {
        lang = b.dataset.lang;
        textIndex = lang === "ru" ? 4 : 1;
        wrap.querySelectorAll("[data-lang]").forEach(function (o) {
          o.classList.toggle("on", o.dataset.lang === lang);
        });
        fillPicker();
        reset();
      });
    });
    wrap.querySelector('[data-lang="ru"]').classList.add("on");

    elPick.addEventListener("change", function () {
      textIndex = parseInt(elPick.value, 10) || 0;
      reset();
    });
    elKbBox.addEventListener("change", function () {
      showKb = elKbBox.checked;
      elKb.hidden = !showKb;
    });
    wrap.querySelector("[data-again]").addEventListener("click", reset);

    api.deck({});
    document.addEventListener("keydown", onKey, true);
    timer = setInterval(function () { if (startedAt && !finishedAt) paintStats(); }, 250);

    fillPicker();
    reset();

    return {
      destroy: function () {
        clearInterval(timer);
        document.removeEventListener("keydown", onKey, true);
        css.remove();
      },
    };
  }

  window.VitazArcade.register({
    id: "typing",
    title: "ПЕЧАТЬ",
    tagline: "Тренажёр слепой печати: русский и английский, экранная клавиатура " +
             "с разбивкой по пальцам, скорость, ошибки и точность.",
    keys: "Просто печатай · пока не попал в нужную клавишу, текст не двинется",
    keysTouch: "Печатай по экранной клавиатуре",
    accent: "#63f5ad",
    thumb: thumb,
    start: start,
  });
})();
