# notebook.py — блокнот (/notebook)

**Назначение:** личные заметки страницами, с возможностью приложить PDF.
Сюда же попадают ответы нейронки по кнопке «В блокнот» на `/ai`.

**Точки входа:** `/notebook`, `/api/notebook` (чтение всего),
`/api/notebook/page` (+ PATCH/DELETE по `<pid>`),
`/api/notebook/entry` (+ PATCH/DELETE по `<eid>`),
`POST /api/notebook/entry/<eid>/pdf`, `GET /notebook/pdf/<eid>`.

**Где данные:** `data/notebook.json` (`NOTEBOOK_PATH`, атомарная запись)
и вложенные PDF в `data/notebook/` (`NOTEBOOK_DIR`).

**Гейт:** `login_required` на всём.

**Инварианты:**
- фича **владеет своим состоянием сама** (`notebook_data`/`notebook_lock`
  на модульном уровне) — `app.py` и `blueprints/ai.py` читают их
  импортом ОТСЮДА, а не наоборот;
- имя присланного файла не становится путём на диске — только
  `safe_filename` из `core.storage`; ссылки чистятся `clean_url`;
- кнопка «В блокнот» на `/ai` зовёт `/api/notebook/entry` — менять
  формат записи, не посмотрев на `ai.py`, нельзя.

**Тест перед правкой:** `pytest tests/test_notebook.py -q`.
