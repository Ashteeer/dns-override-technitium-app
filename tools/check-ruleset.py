#!/usr/bin/env python3
"""Проверка файла ruleset.dat и отладка сопоставления доменов.

Формат: ../docs/ruleset-format.md
Семантика поиска: ../docs/rule-matching.md

Использование:
    python3 tools/check-ruleset.py                                  # config-examples/ruleset.dat
    python3 tools/check-ruleset.py /etc/dns-override/ruleset.dat
    python3 tools/check-ruleset.py <файл> --query test.google.com www.example.org

Проверяет: сигнатуру, схему заголовка, count, sha256, порядок сортировки,
дубликаты (rdomain, scope), диапазон targetIndex, формат доменов, ссылку defaultTarget.

--query повторяет алгоритм поиска приложения и показывает, какое правило победило.

Зависимости: pip install jsonschema   (без него проверка схемы заголовка пропускается)
Код возврата: 0 — ок, 1 — есть ошибки.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILE = ROOT / "config-examples" / "ruleset.dat"
HEADER_SCHEMA = ROOT / "docs" / "schema" / "ruleset-header.schema.json"

MAGIC = b"!DNSOVR1"
LINE_RE = re.compile(rb"^([WA])([OP])(0|[1-9][0-9]*) ([a-z0-9.-]{1,253})$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

MAX_LINE = 512


class Ruleset:
    def __init__(self, header: dict, lines: list[bytes]):
        self.header = header
        self.lines = lines                                    # отсортированное тело
        self.keys = [ln.partition(b" ")[2] for ln in lines]  # rdomain для бинарного поиска


def parse(path: Path) -> tuple[Ruleset | None, list[str]]:
    errors: list[str] = []
    raw = path.read_bytes()

    nl = raw.find(b"\n")
    if nl < 0:
        return None, ["файл не содержит ни одной строки"]

    head_line, body = raw[:nl], raw[nl + 1:]

    if not head_line.startswith(MAGIC + b" "):
        return None, [f"неверная сигнатура: ожидалось {MAGIC.decode()}, получено {head_line[:16]!r}"]

    try:
        header = json.loads(head_line[len(MAGIC) + 1:].decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"заголовок не разбирается как JSON: {exc}"]
    if not isinstance(header, dict):
        return None, ["заголовок должен быть JSON-объектом"]

    if body and not body.endswith(b"\n"):
        errors.append("тело не заканчивается переводом строки")

    lines = body.split(b"\n")[:-1] if body else []

    actual_sha = hashlib.sha256(body).hexdigest()
    if header.get("sha256") != actual_sha:
        errors.append(f"sha256 не совпал: в заголовке {header.get('sha256')}, фактический {actual_sha}")
    if header.get("count") != len(lines):
        errors.append(f"count не совпал: в заголовке {header.get('count')}, строк в теле {len(lines)}")

    return Ruleset(header, lines), errors


def check_header_schema(header: dict) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print("  INFO  jsonschema не установлен — проверка схемы заголовка пропущена")
        return []
    with HEADER_SCHEMA.open(encoding="utf-8") as fh:
        validator = Draft202012Validator(json.load(fh))
    out = []
    for err in sorted(validator.iter_errors(header), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in err.path) or "<header>"
        out.append(f"заголовок: {where}: {err.message}")
    return out


def check_policy(header: dict) -> list[str]:
    version = header.get("version")
    if type(version) is not int or version not in (1, 2):
        return [f"неподдерживаемая версия {version!r}"]
    if version == 1:
        return ["policy требует version=2"] if "policy" in header else []
    policy = header.get("policy")
    if not isinstance(policy, dict):
        return ["policy должен быть объектом"]
    errors = []
    for key in ("allowDomains", "protectedZones", "allowNetworks", "patterns"):
        items = policy.get(key, [])
        if not isinstance(items, list):
            errors.append(f"policy.{key}: ожидался массив")
            continue
        for item in items:
            if key == "patterns":
                if not isinstance(item, dict):
                    errors.append("policy.patterns: ожидался объект")
                    continue
                index = item.get("targetIndex")
                action = item.get("action")
                value = item.get("value")
                if (
                    type(index) is not int or not 0 <= index < len(header.get("targets", []))
                    or action not in ("override", "passthru", "allowlist")
                    or (action != "override" and index != 0)
                    or item.get("kind") not in ("substring", "regexp")
                    or not isinstance(value, str) or not 0 < len(value) <= 1024
                    or not value.isascii() or not value.isprintable()
                ):
                    errors.append(f"policy.patterns: некорректное правило {item!r}")
            elif not isinstance(item, str):
                errors.append(f"policy.{key}: ожидалась строка")
            elif key == "allowNetworks":
                try:
                    if "/" not in item or "%" in item:
                        raise ValueError(item)
                    ipaddress.ip_network(item)
                except ValueError:
                    errors.append(f"policy.{key}: некорректная сеть {item!r}")
            else:
                domain = item.removeprefix("@") if key == "allowDomains" else item
                if len(domain) > 253 or any(not LABEL_RE.fullmatch(label) for label in domain.split(".")):
                    errors.append(f"policy.{key}: некорректный домен {item!r}")
    return errors


def check_body(rs: Ruleset) -> list[str]:
    errors: list[str] = []
    targets = rs.header.get("targets", [])
    engine = rs.header.get("engine", {})

    if engine.get("defaultAction") == "override":
        names = {t.get("name") for t in targets}
        if engine.get("defaultTarget") not in names:
            errors.append(f"заголовок: defaultTarget '{engine.get('defaultTarget')}' отсутствует в targets")

    seen: dict[tuple[bytes, bytes], int] = {}
    prev_key = b""
    prev_scope = b""

    for i, line in enumerate(rs.lines, start=2):        # нумерация строк файла с 1, тело с 2
        if len(line) > MAX_LINE:
            errors.append(f"строка {i}: длина {len(line)} > {MAX_LINE}")
            continue
        m = LINE_RE.match(line)
        if not m:
            errors.append(f"строка {i}: не соответствует формату <W|A><O|P><idx> <rdomain>: {line[:80]!r}")
            continue

        scope, action, idx_raw, rdomain = m.group(1), m.group(2), m.group(3), m.group(4)
        idx = int(idx_raw)

        if action == b"O" and not (0 <= idx < len(targets)):
            errors.append(f"строка {i}: targetIndex {idx} вне диапазона targets[0..{len(targets) - 1}]")
        if action == b"P" and idx != 0:
            errors.append(f"строка {i}: при action=P targetIndex должен быть 0, получено {idx}")

        dom = rdomain.decode("ascii")
        if dom.startswith(".") or dom.endswith(".") or ".." in dom:
            errors.append(f"строка {i}: некорректный rdomain '{dom}'")
        else:
            for label in dom.split("."):
                if not LABEL_RE.match(label):
                    errors.append(f"строка {i}: некорректная метка '{label}' в '{dom}'")
                    break

        key = (rdomain, scope)
        if key in seen:
            errors.append(f"строка {i}: дубль ({dom}, {scope.decode()}), уже был в строке {seen[key]}")
        seen[key] = i

        if rdomain < prev_key:
            errors.append(f"строка {i}: нарушен порядок сортировки: '{dom}' после '{prev_key.decode()}'")
        elif rdomain == prev_key and prev_scope == b"W" and scope == b"A":
            errors.append(f"строка {i}: при одинаковом rdomain '{dom}' запись A должна идти перед W")
        prev_key, prev_scope = rdomain, scope

    return errors


def lookup(rs: Ruleset, qname: str) -> tuple[str, str | None, str]:
    """Повторяет алгоритм приложения. Возвращает (action, target_name, объяснение)."""
    import bisect

    engine = rs.header.get("engine", {})
    default = engine.get("defaultAction", "passthru")
    q = qname.strip(".").lower().encode("idna").decode("ascii") if any(ord(c) > 127 for c in qname) else qname.strip(".").lower()
    labels = q.split(".")
    policy = rs.header.get("policy", {})
    suffixes = {".".join(labels[i:]) for i in range(len(labels))}
    approved = set(policy.get("allowDomains", []))
    if "@" + q in approved or suffixes & approved:
        return "passthru", None, "белый список доменов"
    protected = len(labels) < 2 or suffixes.intersection(policy.get("protectedZones", []))
    patterns = policy.get("patterns", [])

    def match_patterns(allowlist: bool):
        for rule in patterns:
            if (rule["action"] == "allowlist") != allowlist:
                continue
            if rule["kind"] == "regexp":
                try:
                    import regex
                except ImportError:
                    return "unknown", None, "для проверки regexp установите regex"
                try:
                    if not regex.search(rule["value"], q, regex.ASCII, timeout=0.01):
                        continue
                except (TimeoutError, regex.error):
                    return "unknown", None, "не удалось проверить regexp"
            elif rule["value"] not in q:
                continue
            action = "passthru" if allowlist else rule["action"]
            target = rs.header["targets"][rule["targetIndex"]]["name"] if action == "override" else None
            return action, target, "шаблон GeoSite"
        return None

    def with_ip(action: str, target: str | None, reason: str):
        if action == "override" and policy.get("allowNetworks"):
            reason += " — белый список IP проверяется по реальному DNS-ответу"
        return action, target, reason

    found = match_patterns(allowlist=True)
    if found:
        return found
    rq = labels[::-1]

    for d in range(len(rq), 0, -1):
        key = ".".join(rq[:d]).encode("ascii")
        lo = bisect.bisect_left(rs.keys, key)
        hits = []
        while lo < len(rs.keys) and rs.keys[lo] == key:
            hits.append(rs.lines[lo])
            lo += 1
        if not hits:
            continue
        exact = d == len(rq)
        for line in hits:                                    # A лежит раньше W — apex выигрывает
            scope = line[0:1]
            if scope == b"A" and not exact:
                continue
            action = "override" if line[1:2] == b"O" else "passthru"
            idx = int(line[2:line.index(b" ")])
            name = rs.header["targets"][idx]["name"] if action == "override" else None
            matched = ".".join(reversed(key.decode().split(".")))
            kind = "apex" if scope == b"A" else "wildcard"
            return with_ip(action, name, f"правило {kind} на '{matched}'")
    found = None if protected else match_patterns(allowlist=False)
    if found:
        return with_ip(*found)
    return with_ip(default, engine.get("defaultTarget"), "правил не найдено — defaultAction")


def main() -> int:
    args = [a for a in sys.argv[1:]]
    queries: list[str] = []
    if "--query" in args:
        i = args.index("--query")
        queries = args[i + 1:]
        args = args[:i]
    path = Path(args[0]) if args else DEFAULT_FILE

    if not path.is_file():
        sys.exit(f"файл не найден: {path}")

    print(f"проверяю {path}  ({path.stat().st_size} байт)")
    rs, errors = parse(path)
    if rs is None:
        for e in errors:
            print(f"  ERROR {e}")
        return 1

    errors += check_header_schema(rs.header)
    errors += check_policy(rs.header)
    errors += check_body(rs)

    for e in errors[:50]:
        print(f"  ERROR {e}")
    if len(errors) > 50:
        print(f"  … ещё {len(errors) - 50} ошибок")

    if errors:
        print(f"\nошибок: {len(errors)}")
        return 1

    h = rs.header
    print(f"  revision {h['revision']}, правил {h['count']}, targets {len(h['targets'])}, "
          f"defaultAction {h['engine']['defaultAction']}")
    print("\nфайл корректен")

    if queries:
        print("\nпроверка запросов:")
        for q in queries:
            action, target, why = lookup(rs, q)
            suffix = f" → target '{target}'" if target else ""
            print(f"  {q:32} {action}{suffix}   ({why})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
