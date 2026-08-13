"""Structural analyses — the questions that are about a handler, not about a line.

A pattern pack reads one line at a time and a taint engine follows one value. Both are blind to
a whole category of real vulnerability whose evidence is a *relation between parts of a handler*:
who the caller is versus which row was selected, whether anything bounds how often a credential
can be tested, whether a check stands between reading an upload and writing it, whether the
caller or the developer chose which fields get written.

Each rule here answers one of those and shares one model of what a handler is (`routes.py`).
That sharing is the point: `_route_of` decides which frameworks are recognised at all, and four
private copies of it would give four different answers to "is this a route" inside one report.

Every rule follows the same two disciplines, learned the expensive way on the external corpus:

* **Evidence is resolved through the module, not just the handler.** Gates, limiters and
  validators get factored into helpers, and a rule that only looked at the handler body reports
  precisely the codebases that did that refactoring properly. Calls *and* bare references are
  followed, because dependency injection passes a function by name and never calls it.
* **An unresolvable reference counts as evidence.** Every rule here reports the ABSENCE of
  something, so it errs toward silence. The alternative — reporting whenever a check cannot be
  proven present — was measured and produced 48 false positives on one shape alone.
"""
from __future__ import annotations

from ..schema import Finding
from . import authz, js, massassign, ratelimit, upload
from .routes import EXTS as PY_EXTS, LANGS as PY_LANGS, is_production_source

__all__ = ["EXTS", "LANGS", "analyze_file", "analyze_files", "limitations"]

_RULES = (authz, ratelimit, upload, massassign)

# Python and JavaScript do not share a call path, only a vocabulary. The Python rules are written
# against `ast` nodes and produce the published RealVuln figure; threading a second, parserless
# front end through them would put every JavaScript mistake inside that measured path. `js.py`
# answers the same four questions separately and says in its own `limitations()` that it is the
# unmeasured half.
LANGS: dict[str, dict] = {**PY_LANGS, **js.JS_LANGS}
EXTS: tuple[str, ...] = PY_EXTS + js.JS_EXTS


def analyze_file(rel: str, text: str) -> list[Finding]:
    # Scoped to production sources on purpose — see `routes.is_production_source`. Every rule
    # here reports something a deployed handler fails to do, and a test module is not one.
    if not is_production_source(rel):
        return []
    if rel.lower().endswith(js.JS_EXTS):
        return js.analyze_file(rel, text)
    return [f for rule in _RULES for f in rule.analyze_file(rel, text)]


def analyze_files(files: dict[str, str]) -> list[Finding]:
    return [f for rel, text in sorted(files.items()) for f in analyze_file(rel, text)]


def limitations() -> list[str]:
    """Every rule's own bounds, in one list, printed in every scan that runs them."""
    langs = ", ".join(sorted(LANGS))
    out = [f"Structural analysis ({langs} only) decides four questions about a request handler "
           f"that no single line carries: whether a handler that knows its caller ignores them "
           f"when selecting a row, whether a state-changing handler establishes a caller at all, "
           f"whether a credential-testing endpoint bounds attempts, whether an upload is checked "
           f"before it is written, and whether the caller chooses which fields get written. "
           f"Evidence is followed through functions defined in the same module; a helper "
           f"imported from elsewhere is not followed, and the handler is left unreported rather "
           f"than assumed unprotected."]
    for rule in _RULES:
        out.extend(rule.limitations())
    out.extend(js.limitations())
    return out
