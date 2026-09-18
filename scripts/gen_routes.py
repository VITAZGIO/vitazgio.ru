"""Генератор `docs/routes-inventory.md` — целиком из кода (задача 33).

Опись роутов раньше вели руками и она дважды разошлась с кодом: один раз
забыли 4 вебсокет-роута (`@sock.route`, не `@app.*`), второй раз — само
число в шапке подправили отдельно от таблиц, и оно снова разошлось со
следующей правкой (`docs/routes-inventory.md` помнит оба случая). Этот
скрипт устраняет причину, а не подчищает следствие: и число роутов, и
содержимое таблиц — прямой результат `app.url_map.iter_rules()`, тут
нечему расходиться с кодом, потому что тут больше нет ничего, что было бы
написано «на память».

Группировка — по blueprint'у (по имени, под которым он передан в
`Blueprint(...)`), а не по прежним тематическим разделам («cabinet»,
«websockets/remote access» и т.п.): та группировка была ручной классификацией
и сама была источником расхождений. Колонка Guards — decorator'ы, реально
навешанные на функцию (второй проход — по AST исходников, тоже код, а не
память); там, где проверка доступа сделана внутри функции (вебсокеты,
живое соединение и т.п.), декоратора нет и колонка пустая — это не значит,
что доступа нет, подробности — в `blueprints/<name>.md` рядом с кодом.

Запуск: `python3 scripts/gen_routes.py` — перезаписывает
`docs/routes-inventory.md`. `tests/test_docs.py` зовёт `generate()` и
сверяет результат с файлом в репозитории.
"""

import ast
import base64
import hashlib
import importlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "docs" / "routes-inventory.md"

# Флаги-регистраторы роута: `@x.get(...)`, `@x.post(...)`, ..., `@x.route(...)`
# (сюда же попадает `@sock.route(...)`, у него тот же формат вызова).
_ROUTE_ATTRS = {"get", "post", "put", "patch", "delete", "route"}


def _sandbox_env():
    """Одноразовое окружение, только чтобы `app.py` не упал `SystemExit`
    при импорте (см. `_password_secret` в app.py). К значениям из
    настоящего `.env` отношения не имеет — тот же приём, что и в
    `tests/conftest.py`."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", b"gen-routes", salt, 600_000)
    return {
        "CABINET_PASSWORD_SALT": base64.b64encode(salt).decode(),
        "CABINET_PASSWORD_HASH": base64.b64encode(digest).decode(),
        "VITAZGIO_SESSION_SECRET": "gen-routes-secret",
        "SERVERS_PASSWORD": "gen-routes-servers",
        "SSH_GATE_PASSWORD_PREFIX": "gen-routes-console-",
        "PHONE_AGENT_TOKEN": "gen-routes-agent-token",
        "PHONE_FILES_USER": "gen-routes-phone-user",
        "PHONE_FILES_PASSWORD": "gen-routes-phone-password",
        "OPENROUTER_KEY": "gen-routes-key",
    }


def _collect_rules():
    """Импортирует `app.py` в одноразовой копии во временной папке и
    возвращает `[(url, [методы], endpoint), ...]`.

    Копия — по той же причине, что в тестах: `app.py` не фабрика, при
    импорте сам заводит `data/`/`drop_data/` рядом с собой, и незачем
    трогать этим настоящий репозиторий ради описи роутов.
    """
    with tempfile.TemporaryDirectory(prefix="gen-routes-") as tmp:
        work = Path(tmp)
        # core/ — с задачи 34: app.py импортирует core.auth/core.storage/
        # core.templates, а core.storage считает DATA_DIR от своего
        # расположения на диске. Без копии сюда копия app.py находила бы
        # настоящий core/ репозитория через sys.path (тот же урок, что и в
        # tests/conftest.py).
        for name in ("app.py", "blueprints", "templates", "static", "core"):
            src = REPO_ROOT / name
            dst = work / name
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy2(src, dst)

        env = _sandbox_env()
        backup = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        sys.path.insert(0, str(work))
        stale_prefixes = ("blueprints", "core.")
        cached = {
            m: sys.modules.pop(m)
            for m in list(sys.modules)
            if m == "app" or m == "core" or m.startswith(stale_prefixes)
        }
        try:
            module = importlib.import_module("app")
            rules = [
                (
                    rule.rule,
                    sorted(rule.methods - {"HEAD", "OPTIONS"}),
                    rule.endpoint,
                )
                for rule in module.app.url_map.iter_rules()
                if rule.endpoint != "static"
            ]
        finally:
            sys.path.remove(str(work))
            for m in [
                m for m in list(sys.modules)
                if m == "app" or m == "core" or m.startswith(stale_prefixes)
            ]:
                del sys.modules[m]
            sys.modules.update(cached)
            for k, v in backup.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    return rules


def _is_route_decorator(dec):
    return (
        isinstance(dec, ast.Call)
        and isinstance(dec.func, ast.Attribute)
        and dec.func.attr in _ROUTE_ATTRS
    )


def _decorator_name(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ast.unparse(node)


def _guards_by_function(source_path):
    """`{имя_функции: [guard, ...]}` для функций с роут-декоратором в файле.

    Guard — любой декоратор на той же функции, кроме самой регистрации
    роута. Не пытается угадать проверки, сделанные внутри тела функции —
    те не «в коде декоратора», их место в `blueprints/<name>.md`.
    """
    if not source_path.exists():
        return {}
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_route_decorator(d) for d in node.decorator_list):
            continue
        result[node.name] = [
            _decorator_name(d) for d in node.decorator_list
            if not _is_route_decorator(d)
        ]
    return result


def _group_of(endpoint):
    """Blueprint даёт эндпоинту префикс `<имя>.<функция>`; без префикса —
    роут объявлен прямо в `app.py`."""
    return endpoint.split(".", 1)[0] if "." in endpoint else "app.py"


def _source_file(group):
    if group == "app.py":
        return REPO_ROOT / "app.py"
    return REPO_ROOT / "blueprints" / f"{group}.py"


def generate():
    """Строит содержимое `docs/routes-inventory.md` строкой."""
    rules = _collect_rules()

    groups = {}
    guard_cache = {}
    for url, methods, endpoint in rules:
        group = _group_of(endpoint)
        fn_name = endpoint.rsplit(".", 1)[-1]
        if group not in guard_cache:
            guard_cache[group] = _guards_by_function(_source_file(group))
        guards = guard_cache[group].get(fn_name, [])
        groups.setdefault(group, []).append((url, ", ".join(methods), fn_name, guards))

    total = len(rules)
    unique = len({url for url, _, _ in rules})

    lines = [
        "# Опись роутов",
        "",
        "Генерируется скриптом `scripts/gen_routes.py` — не редактировать "
        "руками, правки потеряются при следующем запуске. Расхождение с "
        "кодом ловит `tests/test_docs.py`.",
        "",
        f"Роутов: **{total}** (без `static`). Уникальных адресов: **{unique}** "
        "— один URL под несколько HTTP-методов даёт несколько роутов на",
        "один адрес, это не расхождение.",
        "",
        "Группировка — по blueprint'у (по имени, переданному в `Blueprint(...)`),"
        " `app.py` — роуты без blueprint'а. Guards — decorator'ы, реально"
        " навешанные на функцию; пустая колонка не значит «без проверки» — где"
        " гейт сделан внутри функции (вебсокеты, живые SSH/SFTP-соединения и"
        " т.п.), подробности в `blueprints/<name>.md` рядом с кодом.",
        "",
    ]

    order = ["app.py"] + sorted(g for g in groups if g != "app.py")
    for group in order:
        rows = sorted(groups[group])
        lines.append(f"## {group}")
        lines.append("")
        lines.append("| URL | Метод | Функция | Guards |")
        lines.append("| --- | --- | --- | --- |")
        for url, methods, fn_name, guards in rows:
            guard_text = " + ".join(guards) if guards else "-"
            lines.append(f"| `{url}` | {methods} | `{fn_name}` | {guard_text} |")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def main():
    OUTPUT.write_text(generate(), encoding="utf-8")
    print(f"Записано: {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
