"""CSV formula injection — an export that puts what a user typed into a spreadsheet cell.

29 labels on the external corpus, none found, and no rule of any kind: the pattern pack had no
detector for CWE-1236 and neither did the taint tier. That is the shape this project's two
largest recall gains have both had — not a rule that misses, a class nothing looks at — so it is
the first one this round takes.

The bug is not the export and not the data. It is that a spreadsheet reads a cell beginning with
`=`, `+`, `-` or `@` as a formula, so a field the application let a user type — a ticket subject,
an employee display name, a matter title — becomes code when a colleague opens the file. The
application is not attacked; its staff are.

So the rule is a relation, the same shape as the rest of this package: **a function produces CSV,
a row in it carries a value the code did not write as a literal, and nothing anywhere in the
module neutralises a leading formula character.** All three parts matter. Without the first it
matches any list of lists; without the second it fires on the header row, which is the one row
that is always safe; without the third it reports the codebases that got this right.

Two ways a row is produced, because the corpus writes it both ways and one of them writes no CSV
at all in the function that owns the data:

* `writer.writerow([t.subject, ...])` — 27 of the 29.
* `rows.append([t.title, ...])` handed to a helper that does the writing — the other two. The
  data and the `csv.writer` are in different functions, and the helper is shared, so the export
  function is where the finding belongs.

**Neutralisation is read generously and file-wide**, for the reason the whole package states: a
rule reporting the ABSENCE of something has to be sure of the absence, and a helper called
`_csv_safe` two functions up is still a fix. The markers are deliberately narrow words rather
than `escape` on its own — `django.utils.html.escape` is imported into view modules for HTML and
means nothing about spreadsheets, and treating it as evidence would silence the rule on exactly
the files it is for.

What it does **not** decide is whether the value can actually reach a keyboard. A CSV of
machine-generated identifiers is reported the same as one of free-text titles; the fix
(prefix-neutralise on the way out) is the same either way, which is why this is a MEDIUM finding
and not a HIGH one.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _dotted, _evidence, EXTS, module_functions

# The characters a spreadsheet reads as the start of a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@")

# A file that has nothing to do with CSV is not asked any of the questions below.
_CSV_FILE_SIGNALS = ("csv", "text/csv", ".csv")

# Names that mean somebody already thought about this. Narrow on purpose — see the docstring.
_NEUTRALISER_MARKERS = (
    "csv_safe", "safe_csv", "csv_escape", "escape_csv", "sanitize_cell", "sanitise_cell",
    "sanitize_csv", "sanitise_csv", "neutralis", "neutraliz", "formula", "defus",
    "escape_cell", "safe_cell", "strip_formula", "csv_inject",
)

_ROW_WRITERS = ("writerow", "writerows")


def _dynamic(node: ast.AST) -> bool:
    """Whether a row element is a value rather than a literal the developer typed.

    A header row is every export's first row and is the one row that cannot carry input, so a
    rule that ignored this would report every export twice and both times at the wrong line.
    """
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_dynamic(e) for e in node.elts)
    return True


def _dynamic_row(call: ast.Call) -> bool:
    """Whether this call writes a row holding at least one non-literal element."""
    if not call.args:
        return False
    arg = call.args[0]
    if isinstance(arg, (ast.List, ast.Tuple)):
        return any(_dynamic(e) for e in arg.elts)
    if isinstance(arg, ast.Dict):
        return any(_dynamic(v) for v in arg.values)
    # `writerows(qs.values_list(...))` and friends — a generator of rows, all of it data.
    return isinstance(arg, (ast.Name, ast.Attribute, ast.Call, ast.GeneratorExp, ast.ListComp))


def _names_and_strings(node: ast.AST) -> list[str]:
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value.lower())
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            out.extend((a.asname or a.name).lower() for a in child.names)
    return out


def _neutralises(tree: ast.AST) -> bool:
    """Whether anything in this module defuses a leading formula character."""
    for name in _names_and_strings(tree):
        if any(m in name for m in _NEUTRALISER_MARKERS):
            return True
    # `if value.startswith(("=", "+", "-", "@"))` — the check written out rather than named.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _dotted(node.func).rsplit(".", 1)[-1] not in ("startswith", "lstrip", "strip"):
            continue
        for arg in node.args:
            elts = arg.elts if isinstance(arg, (ast.Tuple, ast.List)) else [arg]
            values = [e.value for e in elts
                      if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if any(v and v[0] in _FORMULA_PREFIXES for v in values):
                return True
    return False


def _writes_csv(func: AnyFunc) -> bool:
    """Whether this function is the one producing a CSV document."""
    return any("csv" in n for n in _names_and_strings(func))


def _row_lines(func: AnyFunc) -> list[int]:
    """Lines in this function where a row of data is produced, in source order."""
    direct: list[int] = []
    collected: list[int] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
        if tail in _ROW_WRITERS and _dynamic_row(node):
            direct.append(node.lineno)
        elif tail == "append" and len(node.args) == 1 and _dynamic_row(node):
            # `rows.append([...])` only counts when this function is the CSV one: a list of
            # lists is otherwise the most ordinary thing in Python.
            collected.append(node.lineno)
    return sorted(direct) if direct else sorted(collected)


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    lowered = text.lower()
    if not any(s in lowered for s in _CSV_FILE_SIGNALS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if _neutralises(tree):
        return []

    lines = text.splitlines()
    for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
        if not _writes_csv(func):
            continue
        rows = _row_lines(func)
        if not rows:
            continue
        line = rows[0]
        return [Finding(
            detector_id="CSVINJ-PY-EXPORT",
            title="CSV export writes application data into a cell without neutralising a "
                  "leading formula character",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            cwe="CWE-1236", owasp="A03",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` writes values into a CSV that a spreadsheet will open, and "
                f"nothing in this module neutralises a cell beginning with "
                f"{', '.join(_FORMULA_PREFIXES)}. Prefix any cell starting with one of those "
                f"characters with an apostrophe (or a tab) before writing it, in one helper "
                f"every export calls — the reader of the file is the person attacked here, "
                f"not this application.",
            source="structural", verdict=Verdict.UNVERIFIED)]
    return []


def limitations() -> list[str]:
    return [
        "CSV export analysis reports one export per file: a function producing CSV whose rows "
        "carry non-literal values, where nothing in the module neutralises a leading =, +, - or "
        "@. It does not decide whether those values are reachable by a user — a CSV of "
        "machine-generated identifiers reads the same as one of free-text titles — and it goes "
        "silent for the whole file when any neutralising helper is present, including one that "
        "the offending export does not call.",
    ]
