#!/usr/bin/env python3
"""Fail if the package uses anything newer than the Python version it advertises.

    python3 scripts/check_python_floor.py

`requires-python = ">=3.9"` in `pyproject.toml` is a promise made to `pip`, which enforces it
by refusing to install on older interpreters — and by *allowing* the install on 3.9, where the
code then fails at import or, worse, at the first call to whatever construct is too new. The
promise is only as good as something that checks it, and the natural check (run the suite on
3.9) covers what the tests exercise, not what a rarely-taken branch reaches.

So this reads the floor out of `pyproject.toml` and scans for constructs above it. The list is
deliberately short: it holds the things this codebase has actually reached for, not a general
model of Python's history, because a check nobody can extend correctly is a check that gets
deleted. Adding an entry is one tuple.
"""
from __future__ import annotations

import ast
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "kit"))

from secaudit_core.taint import code_view                             # noqa: E402

PACKAGE = os.path.join(REPO, "kit")
PYPROJECT = os.path.join(REPO, "kit", "pyproject.toml")

# (minimum version, needle, what to do instead). Needles are matched against `taint.code_view`
# — comments and string-literal contents blanked, offsets preserved — for a reason this check
# learned the hard way: matching raw text flags the *fix*, because the comment explaining why
# a construct was avoided has to name the construct. A gate that fires on the correct code is
# a gate someone deletes. Same view the code-shape detectors use, for the same reason.
TEXT_RULES: list[tuple[tuple[int, int], str, str]] = [
    ((3, 11), "ExceptionGroup", "use a list of exceptions"),
    ((3, 11), "tomllib", "the repo parses its own TOML; there is no dependency to add"),
    ((3, 10), "sys.stdlib_module_names", "keep an explicit list, or gate on the version"),
    ((3, 9), "itertools.pairwise", "zip(x, x[1:])"),
]

AST_RULES: list[tuple[tuple[int, int], type, str]] = [
    ((3, 10), ast.Match, "if/elif chain"),
]

# (minimum version, called-attribute name, keyword name, what to do instead). A keyword
# argument is not findable by text search: `filter="data"` has a string literal inside it, so
# the blanked view sees `filter="    "` and misses it, while the raw view hits the comment that
# explains the workaround. Both failure modes are real — the first left this gate passing on
# known-bad code, the second left it failing on the fix — and neither survives asking the parse
# tree what keywords a call actually has.
KEYWORD_RULES: list[tuple[tuple[int, int], str, str, str]] = [
    ((3, 12), "extract", "filter",
     "feature-detect with `hasattr(tarfile, 'data_filter')` — backported unevenly across 3.9"),
    ((3, 12), "extractall", "filter",
     "feature-detect with `hasattr(tarfile, 'data_filter')` — backported unevenly across 3.9"),
]


def declared_floor() -> tuple[int, int]:
    with open(PYPROJECT, encoding="utf-8") as f:
        text = f.read()
    found = re.search(r'requires-python\s*=\s*"[^"]*?(\d+)\.(\d+)', text)
    if not found:
        raise SystemExit("FAIL — kit/pyproject.toml has no parseable requires-python floor.")
    return (int(found.group(1)), int(found.group(2)))


def sources() -> list[str]:
    out = []
    for root, dirs, files in os.walk(PACKAGE):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "tests")]
        out += [os.path.join(root, f) for f in files if f.endswith(".py")]
    return sorted(out)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    floor = declared_floor()
    problems: list[str] = []

    for path in sources():
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        with open(path, encoding="utf-8") as f:
            text = f.read()

        scannable = code_view(text, path) or text

        for needs, needle, instead in TEXT_RULES:
            if needs > floor and needle in scannable:
                line = scannable[: scannable.index(needle)].count("\n") + 1
                problems.append(
                    f"{rel}:{line} uses `{needle}` (Python {needs[0]}.{needs[1]}+) but the "
                    f"package advertises >={floor[0]}.{floor[1]} — {instead}")

        try:
            tree = ast.parse(text)
        except SyntaxError as e:                # unparseable on THIS interpreter, never mind 3.9
            problems.append(f"{rel}:{e.lineno} does not parse: {e.msg}")
            continue

        # Annotations only exist at runtime without `from __future__ import annotations`, and
        # `X | Y` in one is a 3.9 TypeError. Every module that carries annotations needs it.
        has_future = any(
            isinstance(n, ast.ImportFrom) and n.module == "__future__"
            and any(a.name == "annotations" for a in n.names) for n in tree.body)
        annotated = any(isinstance(n, (ast.AnnAssign, ast.arg)) and getattr(n, "annotation", None)
                        for n in ast.walk(tree)) or any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.returns
            for n in ast.walk(tree))
        if annotated and not has_future and floor < (3, 10):
            problems.append(
                f"{rel} carries annotations without `from __future__ import annotations`; "
                f"`X | Y` in one is a TypeError on {floor[0]}.{floor[1]}")

        for needs, node_type, instead in AST_RULES:
            if needs <= floor:
                continue
            for node in ast.walk(tree):
                if isinstance(node, node_type):
                    problems.append(
                        f"{rel}:{node.lineno} uses {node_type.__name__} (Python "
                        f"{needs[0]}.{needs[1]}+) — use {instead}")

        for needs, method, keyword, instead in KEYWORD_RULES:
            if needs <= floor:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func.attr if isinstance(node.func, ast.Attribute) else \
                    getattr(node.func, "id", "")
                if called != method:
                    continue
                # `**extra` is how a call passes the keyword only where it exists, which is the
                # fix — so only a keyword spelled out at the call site counts.
                if any(kw.arg == keyword for kw in node.keywords):
                    problems.append(
                        f"{rel}:{node.lineno} passes `{keyword}=` to `{method}()` (Python "
                        f"{needs[0]}.{needs[1]}+) but the package advertises "
                        f">={floor[0]}.{floor[1]} — {instead}")

    if problems:
        print(f"FAIL — code above the advertised Python floor ({floor[0]}.{floor[1]}):")
        print("\n".join("  - " + p for p in problems))
        return 1

    print(f"Python floor OK — {len(sources())} module(s) stay within "
          f">={floor[0]}.{floor[1]} as advertised in kit/pyproject.toml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
