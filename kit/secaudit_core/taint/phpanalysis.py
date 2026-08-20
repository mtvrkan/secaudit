"""PHP taint — the one hop between a superglobal and the thing that uses it.

`detectors.py` already reports a superglobal sitting *inside* a dangerous call, and that pays
for itself: six rules, +392 labelled files on CVEfixes, zero matched lines across 990,000 lines
of maintained PHP. What it cannot see is the shape PHP code is actually written in, which is one
assignment long:

    $id = $_GET['id'];
    …
    $rows = $db->query("SELECT * FROM users WHERE id = $id");

Measured on the 6,268 unsealed labelled PHP files in `eval/cvefixes/`: **+257 files, PHP recall
0.1187 → 0.1597**, against **0 matched lines in `laravel/framework`, 0 in Symfony's HTTP layer
and 34 in phpMyAdmin's 325,732**. That last comparison is the point of this module rather than a
wider regex: SQL built by string interpolation, reported without asking where the value came
from, was measured at **1,225 lines inside Laravel alone** and rejected for it. The same sink
with a taint requirement in front of it is silent there.

**Why this is a separate front end and not a third branch of `taint/__init__.py`.** That module
is a summary-based interprocedural engine: it reduces each function to what its parameters reach,
resolves calls by name, and iterates over the import graph. PHP would need a fourth notion of
what a function is, and every mistake in it would land inside the code path that produces the
published Python and JavaScript figures. This is deliberately *less* than that engine — one
assignment hop, inside one file — and it says so in its own `limitations()` rather than
borrowing the depth claim of a tier it does not implement.

**What it does not do**, in the order a reader will hit it:

* **One file.** A value read in `index.php` and used in `db.php` is two findings or none;
  `include` is not followed. PHP's include graph is computed at runtime from strings this
  analysis is not allowed to evaluate.
* **One hop of propagation.** `$b = $a . '-x'` carries taint from `$a`; `$c = $b` after that
  does not. A second round was measured and added 4 files against 11 more matched lines in
  phpMyAdmin — the wrong side of the trade for a bound this file can state exactly.
* **No function boundaries at all.** A superglobal assigned at the top of a file taints that
  name for the whole file, including inside functions that shadow it with a parameter. This
  errs toward reporting, and it is why every path here is MEDIUM confidence rather than HIGH:
  the source is certain, the *reach* is not.
* **A sanitizer clears the assignment, not the value.** `$id = intval($_GET['id'])` is clean;
  `$id = $_GET['id']; $id = intval($id);` is not seen as cleaned, because that would need the
  ordering this pass does not track.
"""
from __future__ import annotations

import re

from ..schema import Severity
from .model import Sink, TaintPath

# The four superglobals a caller controls. `$_SERVER` is deliberately absent: most of it is set
# by the server, and the entries an attacker does control (`HTTP_REFERER`, `HTTP_USER_AGENT`)
# were measured to add 6 labelled files against 41 more matched lines in maintained PHP.
_SUPERGLOBAL = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)"

# `$id = $_GET['id']`, `$name = trim($_POST['name'])`. The subscript is required for the reason
# `SEC-PHP-XSS-ECHO` requires it: `isset($_GET)` is a test, not a read.
_ASSIGN = re.compile(rf"\$([A-Za-z_]\w*)\s*=\s*[^;\n]*{_SUPERGLOBAL}\s*\[")

# One further hop, anchored at the start of a statement so `global $a, $b;` and a comparison
# inside a condition are not read as assignments.
_PROPAGATE = re.compile(r"^\s*\$([A-Za-z_]\w*)\s*=\s*([^;\n]*)")

# Calls that make a value safe for at least one of the sinks below. Deliberately coarse — this
# clears the assignment entirely rather than per sink, because a value somebody ran through
# `intval` or `htmlspecialchars` is a value somebody thought about, and the sink rules in
# `detectors.py` still report it if the superglobal reaches them directly.
_SANITISED = re.compile(
    r"\b(?:intval|floatval|boolval|abs|count|htmlspecialchars|htmlentities|strip_tags|"
    r"mysqli_real_escape_string|pg_escape_string|pg_escape_literal|preg_quote|filter_var|"
    r"is_numeric|is_int|urlencode|rawurlencode|basename|md5|sha1|hash|password_hash)\s*\(",
    re.I)

# A query, not the word SELECT. `__('Select one…')` is a translated label and it was reported as
# SQL until this asked for the clause that makes a statement a statement — worth 33 of
# phpMyAdmin's 67 matched lines, at a cost of 21 labelled files.
_SQL = re.compile(r"SELECT\b[^;\n]{0,200}\bFROM\b|INSERT\s+INTO\b"
                  r"|UPDATE\b[^;\n]{0,200}\bSET\b|DELETE\s+FROM\b", re.I)

_SINKS: tuple[tuple[re.Pattern, Sink], ...] = (
    (_SQL,
     Sink("TAINT-PHP-SQLI", "SQL injection — a request value reaches a query", "CWE-89", "A03",
          Severity.CRITICAL,
          "Bind the value: `$stmt = $pdo->prepare('… WHERE id = ?'); $stmt->execute([$id]);`. "
          "Interpolating it into the statement text is injection however the variable is named.")),
    (re.compile(r"\b(?:include|include_once|require|require_once)\b"),
     Sink("TAINT-PHP-LFI", "File inclusion — a request value chooses which file runs",
          "CWE-98", "A03", Severity.CRITICAL,
          "Map the value through an allowlist of known filenames. A caller who chooses the "
          "included file chooses the code that runs.")),
    (re.compile(r"(?<![\w>:$])(?<!function )(?:system|exec|shell_exec|passthru|popen|proc_open)"
                r"\s*\("),
     Sink("TAINT-PHP-CMDI", "Command injection — a request value reaches a shell", "CWE-78",
          "A03", Severity.CRITICAL,
          "Pass arguments as an array with `proc_open`, or validate against an allowlist. "
          "`escapeshellarg` is a last resort and is easy to get wrong across platforms.")),
    (re.compile(r"\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|"
                r"move_uploaded_file|scandir|opendir)\s*\("),
     Sink("TAINT-PHP-PATH", "Path traversal — a request value reaches a filesystem call",
          "CWE-22", "A01", Severity.HIGH,
          "Resolve with `realpath()` and check the result still starts with the directory you "
          "meant. `../` is a valid path component and PHP will follow it.")),
    (re.compile(r"\bheader\s*\("),
     Sink("TAINT-PHP-HEADER", "Open redirect / header injection from a request value",
          "CWE-601", "A01", Severity.MEDIUM,
          "Compare the target against an allowlist of paths you own before redirecting. A "
          "newline in the value ends the header and starts a response you did not write.")),
    (re.compile(r"(?:\becho\b|\bprint\b|<\?=)"),
     Sink("TAINT-PHP-XSS", "XSS — a request value is printed without escaping", "CWE-79", "A03",
          Severity.HIGH,
          "Escape at the point of output: `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`, or "
          "render through a template engine that escapes by default. PHP escapes nothing.")),
)

EXTS: tuple[str, ...] = (".php", ".phtml")


def analyze(path: str, text: str) -> list[TaintPath]:
    """Every superglobal-derived value that reaches a sink in this file.

    Returns `TaintPath`s so the engine's existing ranking, dedupe and corroboration apply
    unchanged — a PHP path outranks the pattern match at the same line exactly as a Python one
    does, and the two collapse into one finding rather than two.
    """
    if not path.lower().endswith(EXTS):
        return []
    lines = text.split("\n")

    # Pass 1: names bound directly from a superglobal, and where.
    origin: dict[str, tuple[int, str]] = {}
    for number, line in enumerate(lines, 1):
        if len(line) > 2000 or _SANITISED.search(line):
            continue
        for match in _ASSIGN.finditer(line):
            origin.setdefault(match.group(1), (number, line.strip()[:200]))
    if not origin:
        return []

    # Pass 2: one hop of propagation — `$sql = "… $id"`, `$target = $dir . '/' . $name`.
    for line in lines:
        if len(line) > 2000:
            continue
        propagated = _PROPAGATE.match(line)
        if not propagated or propagated.group(1) in origin:
            continue
        name, rhs = propagated.group(1), propagated.group(2)
        if _SANITISED.search(rhs):
            continue
        for tainted, (source_line, evidence) in list(origin.items()):
            if re.search(rf"\${re.escape(tainted)}\b", rhs):
                origin[name] = (source_line, evidence)
                break

    uses = re.compile(r"\$(" + "|".join(re.escape(n) for n in sorted(origin)) + r")\b")
    out: list[TaintPath] = []
    for number, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        used = uses.search(line)
        if not used or _ASSIGN.search(line):     # the assignment itself is not the sink
            continue
        for pattern, sink in _SINKS:
            if not pattern.search(line):
                continue
            source_line, evidence = origin[used.group(1)]
            out.append(TaintPath(
                sink=sink, file=path, line=number,
                source=f"${used.group(1)} (from a superglobal)", source_line=source_line,
                # "parameter" rather than "request", and the difference is load-bearing: it is
                # what makes these paths MEDIUM confidence in `engine`, which is the honest
                # reading of an analysis with no function boundaries. See the module docstring.
                source_kind="parameter",
                steps=[(source_line, evidence)], evidence=line.strip()[:200]))
            break
    return out


def limitations() -> list[str]:
    """Printed in every scan that runs this, beside the other tiers' bounds."""
    return [
        "PHP taint follows a superglobal through ONE assignment inside ONE file — "
        "`$id = $_GET['id']` then `$id` in a query, an include, a shell call, a filesystem "
        "call, a header or an echo. It does not cross `include`, does not follow a second "
        "assignment, and has no notion of function boundaries, so a name is tainted for the "
        "whole file once it is bound. Every path is MEDIUM confidence for that reason: the "
        "source is certain and the reach is not.",
    ]
