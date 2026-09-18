"""core/storage.py — общая инфраструктура хранения (задача 34).

`DATA_DIR` и атомарная запись JSON нужны почти каждой фиче на сайте —
раньше `DATA_DIR` жил в `app.py`, и любой новый модуль получал его только
через фабрику-аргумент. Здесь единственный источник: и `app.py`, и
`core/auth.py`, и со временем сами blueprints импортируют его отсюда
напрямую.

Модуль обычный, выполняется при импорте (создаёт `data/`, если её нет) —
как и предписывает «жёсткое ограничение» в docs/structure-plan.md:
`app.py` не фабрика, и core/* тоже не фабрики.
"""

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = os.path.join(str(REPO_ROOT), "data")
os.makedirs(DATA_DIR, exist_ok=True)


def atomic_write_json(path, data, *, ensure_ascii=False):
    """Пишет `data` в `path` атомарно: во временный файл рядом, потом
    `os.replace`. Читатель никогда не увидит недописанный JSON, даже если
    процесс упадёт посреди записи — `os.replace` на одной файловой системе
    неделим. Ошибки (диск полон, нет прав) сама не глотает — как раньше,
    решает вызывающий (один код ловил `OSError` и молчал, другой — нет;
    это сохранено на стороне вызовов, не здесь).
    """
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=ensure_ascii)
    os.replace(tmp, path)
