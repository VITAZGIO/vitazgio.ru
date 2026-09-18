# ai.py — «Нейронки» /neuro + /ai, и страница /claude

## Нейронки /neuro + /ai — чаты через OpenRouter

**Точки входа:** `/neuro` (три вкладки в iframe), `/ai?m=<модель>`,
API `/api/ai/state`, `/api/ai/chat*`, `/api/ai/folder*`,
`/api/ai/chat/<id>/regenerate`, `/api/ai/img/<img_id>`.

`/neuro` — три вкладки, каждая грузит `/ai?m=<модель>`: **MiniMax**
(`minimax/minimax-m3:free`, розовый, умеет фото), **NVIDIA**
(`nvidia/nemotron-3-ultra-550b-a55b:free`, зелёный), **Claude** (оранжевый).
Модель зашита в `/neuro`. Если модель вкладки ответила ошибкой, сервер
перебирает список живых бесплатных (каталог `/api/v1/models`, цена 0,
обновляется раз в 15 мин).

Функционал `/ai`: папки чатов, переименование, перенос, закрепление,
поиск по заголовкам. Подтверждения/ввод — свои карточки (`uiConfirm`/
`uiPrompt`/`uiToast`). Фото (до `AI_IMG_COUNT_MAX`=6, выбор ИЛИ вставка из
буфера), PDF (до 8 МБ, `pypdf`, до 6000 симв., подкладывается в контекст
на КАЖДОМ следующем ходе). Размышления (reasoning) у MiniMax/Nemotron —
отдельное поле `delta.reasoning`, кнопка «Копировать» их не тянет (только
`out.dataset.raw`, куда пишутся исключительно куски `delta.content`).

**Инварианты (нельзя ломать):**
- Аватарка бота — по модели, которая **реально ответила на конкретное
  сообщение** (`m.model` в `data/aichat.json`), не по текущей вкладке.
- Кнопка **Стоп** — `AbortController`, сервер ловит обрыв как
  `GeneratorExit` в `finally` у `_ai_run_stream` и досохраняет частичный
  ответ. Реплика юзера сохраняется СРАЗУ (до ответа), лимит не съедает
  написанное.
- Автозаголовок (`_ai_smart_title`) долетает первым кадром SSE
  (`{"title": ...}`).
- Цвета — `color-mix(in srgb, var(--ac) N%, transparent)`, не хардкод.

**Настройка (.env):** `OPENROUTER_KEY` обязателен, `OPENROUTER_MODEL`/
`OPENROUTER_VISION_MODEL`/`OPENROUTER_URL` — опционально.

**Тесты:** `scratchpad/aitest.js`, `aifeat*.js`, `aiimg2.js`/`aiimg3.js`,
`batch2.js`/`batch3.js`, `reason.js`; фейковый OpenRouter —
`scratchpad/fakeor.py` (слово `stopme` — медленный ответ для теста «Стоп»).

Не доделано: выбор модели прямо со страницы, редактирование своей реплики.

## Страница /claude

`/claude` и `/api/claude/state` здесь — тонкая обёртка (проверка
`claude_ready()`, отдача шаблона). Сам канал (WebSocket `/ws/claude` → SSH
→ tmux) реализован в `blueprints/remote.py` — подробности, инварианты и
настройка (`CLAUDE_HOST`/`CLAUDE_DIR`/`CLAUDE_BIN`) в `remote.md`.
