#!/usr/bin/env python3
"""Static checks for the message catalogs of php2shell_host.py and php2shell_remote.py.

  - every language has the same keys, and per key the same str.format placeholders
  - every key the code asks for exists, gets all its placeholders, and every catalog key is used
  - en/ja contain no Hangul; t("loc.default") contains no colon (pending_restart relies on it)

Usage: python lab/check_i18n.py   (exit 0 = clean)
"""

import ast
import os
import re
import string
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
HANGUL = re.compile("[㄰-㆏가-힣]")


def literal(tree: ast.Module, name: str):
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else (node.targets[0] if isinstance(node, ast.Assign) else None)
        if isinstance(target, ast.Name) and target.id == name:
            if isinstance(node.value, ast.Dict) and name == "LOG_PATTERNS":
                return [k.value for k in node.value.keys]
            return ast.literal_eval(node.value)
    return None


def fields(text: str):
    return sorted(f for _, f, _, _ in string.Formatter().parse(text) if f is not None)


def check(path: str) -> list:
    errors = []
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    cat = literal(tree, "MESSAGES")
    ko = cat["ko"]
    for lang in ("en", "ja"):
        other = cat.get(lang, {})
        for k in sorted(set(ko) ^ set(other)):
            errors.append(f"{lang}: key {'missing' if k in ko else 'extra'}: {k}")
        for k in sorted(set(ko) & set(other)):
            try:
                if fields(ko[k]) != fields(other[k]):
                    errors.append(f"{lang}: placeholders differ: {k}: {fields(ko[k])} vs {fields(other[k])}")
            except ValueError as exc:
                errors.append(f"{lang}: bad format string {k}: {exc}")
            if HANGUL.search(other[k]):
                errors.append(f"{lang}: Hangul left in {k}")
    for k, v in ko.items():
        try:
            fields(v)
        except ValueError as exc:
            errors.append(f"ko: bad format string {k}: {exc}")
    for lang in cat:
        if ":" in cat[lang].get("loc.default", "") or "：" in cat[lang].get("loc.default", ""):
            errors.append(f"{lang}: loc.default must not contain a colon")

    # Keys used by the code: t("key") literals, key strings stored in tables (OPS_GUIDE),
    # and t("prefix." + code) families expanded over their code tables.
    msg_node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                    and getattr(n.target if isinstance(n, ast.AnnAssign) else n.targets[0], "id", "") == "MESSAGES")
    used, prefixes = set(), set()
    for node in ast.walk(tree):
        if node is msg_node:
            continue
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "t" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant):
                used.add(arg.value)
                if arg.value not in ko:
                    errors.append(f"line {node.lineno}: unknown key {arg.value!r}")
                elif not any(k.arg is None for k in node.keywords):
                    missing = set(fields(ko[arg.value])) - {k.arg for k in node.keywords}
                    if missing:
                        errors.append(f"line {node.lineno}: t({arg.value!r}) lacks {sorted(missing)}")
            elif isinstance(arg, ast.BinOp) and isinstance(arg.left, ast.Constant):
                prefixes.add(arg.left.value)
            elif not isinstance(arg, ast.Name):  # names iterate key tables, checked below
                errors.append(f"line {node.lineno}: t() key is not a literal or 'prefix.' + code")
    table_keys = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and n.value in ko and not (msg_node.lineno <= n.lineno <= msg_node.end_lineno)}
    used |= table_keys
    for title, items in literal(tree, "OPS_GUIDE") or []:
        for k in (title,) + tuple(items):
            if k not in ko:
                errors.append(f"OPS_GUIDE: unknown key {k!r}")
    families = {"verdict.": literal(tree, "VERDICTS"), "html.crit.": literal(tree, "VERDICTS"),
                "prio.": literal(tree, "PRIORITIES"), "log.": literal(tree, "LOG_PATTERNS")}
    for p in sorted(prefixes):
        codes = families.get(p)
        if codes is None:
            errors.append(f"dynamic key prefix without a code table: {p!r}")
            continue
        for c in codes:
            used.add(p + c)
            if p + c not in ko:
                errors.append(f"unknown key {p + c!r}")
            elif fields(ko[p + c]):
                errors.append(f"dynamic key {p + c!r} must not take placeholders")
    for k in sorted(set(ko) - used):
        errors.append(f"unused key {k}")
    return errors


def main() -> int:
    failed = False
    for name in ("php2shell_host.py", "php2shell_remote.py"):
        errors = check(os.path.join(ROOT, name))
        print(f"{name}: {'OK' if not errors else f'{len(errors)} problem(s)'}")
        for e in errors:
            print("  " + e)
        failed |= bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
