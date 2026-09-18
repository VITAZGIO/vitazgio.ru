"""Сторож размера CLAUDE.md.

Правило «CLAUDE.md ≤ 25 КБ» уже один раз держалось только на дисциплине и
не удержалось: 2026-09-04 файл урезали до 20 КБ, а за следующие две недели
он вырос до 72 КБ — описания свежих фич дописывали прямо в него вместо
blueprints/<name>.md (задача 31, см. docs/structure-plan.md). Порог здесь
взят с запасом (30 КБ, а не 25) — так тест падает раньше, чем файл успеет
разрастись до состояния, требующего отдельной уборочной задачи.
"""

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
LIMIT_BYTES = 30 * 1024

HELP = (
    "CLAUDE.md весит {size} байт — больше {limit_kb} КБ. "
    "Не дописывать сюда описание фичи — оно живёт в blueprints/<name>.md "
    "рядом с кодом. Хроника решений и переделок («пробовали X, откатили, "
    "вот почему») — в docs/history.md. См. раздел «Дисциплина "
    "документации» в самом CLAUDE.md — куда что писать и три правила, "
    "которые важнее остальных."
)


def test_claude_md_size_guarded():
    size = (REPO / "CLAUDE.md").stat().st_size
    assert size <= LIMIT_BYTES, HELP.format(
        size=size, limit_kb=LIMIT_BYTES // 1024,
    )


def test_routes_inventory_matches_code():
    """Опись роутов (задача 33) — генерируется, а не ведётся руками.

    Файл дважды расходился с кодом, когда его правили вручную (см.
    docs/routes-inventory.md — стояло 143, а в коде было 153; ещё раньше
    123 вместо 127 — забыли @sock.route). Теперь `docs/routes-inventory.md`
    — прямой вывод `scripts/gen_routes.py`; этот тест перегенерирует опись
    в память и сверяет с закоммиченным файлом, чтобы забытый прогон
    генератора не прошёл незамеченным мимо ревью.
    """
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from scripts.gen_routes import generate

    expected = generate()
    actual = (REPO / "docs" / "routes-inventory.md").read_text(encoding="utf-8")
    assert actual == expected, (
        "docs/routes-inventory.md разошёлся с кодом — запусти "
        "`python3 scripts/gen_routes.py` и закоммить результат."
    )
