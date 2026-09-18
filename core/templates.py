"""core/templates.py — чтение HTML/JS страниц (задача 34).

Страницы — обычные текстовые файлы в `templates/`, НЕ Jinja2 (см.
CLAUDE.md, «Как добавлять новую фичу/страницу»): подстановки — через
`.replace()`/`.format()` уже в самом blueprint'е. `template()` — раньше
жила в `app.py` как `_template`, единственная точка чтения.
"""

from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def template(name):
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")
