"""What the response says about the server — CWE-209 and CWE-215.

83 labels between them, 68 of them missed, and both are one relation: **something that describes
the server's internals reaches the body of a response.** Not a log, not a template it renders for
an operator — the payload a caller gets back.

    except Exception as exc:
        return JSONResponse({"detail": str(exc), "kind": exc.__class__.__name__}, status_code=500)

    return {"trace": True, "module": os.environ.get("APP_ENV"), "base": str(BASE_EXPORT_DIR)}

The first is CWE-209. A stack trace or an exception message is written for whoever is debugging,
and it names table columns, file paths, library versions and sometimes the query that failed —
the reconnaissance an attacker would otherwise have to guess at. The second is CWE-215: the same
disclosure done deliberately, by a diagnostics endpoint that returns environment variables and
deployment paths to anyone who asks.

The rule is narrow in the way the rest of this package is narrow. It is not "an exception was
handled" and not "the environment was read" — both are ordinary. It is that the *value flows
into what is returned*, which is decidable from one function: the exception name bound by the
`except` clause, or an environment read, appearing inside a `return` or inside the argument of a
response constructor.

**A rendered template is not a response body here.** Passing a message to a template gives the
template the choice, and Django's own error pages are a deployment setting rather than a code
one; reporting those would put this rule in the middle of every reasonable error handler. What
is reported is a payload the handler builds itself.

What it does not decide is whether the disclosure matters. `str(exc)` on a ValueError the
handler raised itself, with a message it wrote, is reported the same as a database driver's
error text. The fix — return a correlation id and log the detail server-side — is the same for
both, and a handler cannot tell you at rest which exceptions will arrive at runtime.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _dotted, _evidence, EXTS, is_web_module, module_functions

# Response constructors whose first argument is the body the caller receives.
_RESPONSE_CALLS = ("jsonresponse", "httpresponse", "response", "jsonify", "make_response",
                   "httpresponsebadrequest", "httpresponseserverError", "plaintextresponse",
                   "orjsonresponse", "ujsonresponse", "json_response", "abort")

# Reads that describe the deployment rather than the request.
_INTERNALS = ("os.environ", "os.getenv", "environ.get", "sys.path", "sys.version",
              "platform.platform", "platform.node", "platform.uname", "settings.",
              "current_app.config", "app.config", "os.getcwd", "__file__", "locals",
              "globals", "vars", "traceback.format_exc", "traceback.format_exception",
              "traceback.print_exc", "sys.exc_info")

# Names that are almost always a deployment path when they appear in a payload.
_PATH_NAMES = ("base_dir", "basedir", "base_export_dir", "root_dir", "media_root", "static_root",
               "upload_dir", "storage_dir", "export_dir", "tmp_dir", "log_path")


def _response_payloads(func: AnyFunc) -> list[ast.expr]:
    """The expressions this function hands back to the caller."""
    out: list[ast.expr] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is not None:
            out.append(node.value)
        elif isinstance(node, ast.Call):
            tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
            if tail in _RESPONSE_CALLS and node.args:
                out.append(node.args[0])
    return out


def _dotted_names(node: ast.AST) -> list[str]:
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Call):
            dotted = _dotted(child.func)
            if dotted:
                out.append(dotted.lower())
    return out


def _exception_names(func: AnyFunc) -> set[str]:
    """Names bound by an `except ... as e` clause, plus the traceback module."""
    names: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def _leaks_exception(payload: ast.expr, caught: set[str]) -> bool:
    """Whether the caught exception's own TEXT reaches the payload.

    Narrower than "the exception appears somewhere in the body", which was measured first and
    was too generous: `{"kind": exc.__class__.__name__}` names the class and discloses nothing a
    status code does not already imply, while `str(exc)` hands over whatever the failing layer
    wrote. The distinction is what the value carries, so the test is on the accessor.
    """
    if any("traceback.format" in n or "traceback.print" in n for n in _dotted_names(payload)):
        return True
    if not caught:
        return False
    for node in ast.walk(payload):
        # `str(exc)`, `repr(exc)`, `"".join(exc.args)`
        if isinstance(node, ast.Call):
            tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
            if tail in ("str", "repr", "format") and any(
                    isinstance(a, ast.Name) and a.id in caught for a in node.args):
                return True
        # `exc.args`, `exc.message`, `exc.detail`, `exc.msg`
        if isinstance(node, ast.Attribute) and node.attr in ("args", "message", "detail", "msg"):
            if isinstance(node.value, ast.Name) and node.value.id in caught:
                return True
        # `f"failed: {exc}"` — the conversion is implicit and the text still goes out.
        if isinstance(node, ast.FormattedValue) and isinstance(node.value, ast.Name) \
                and node.value.id in caught:
            return True
        # `{"detail": exc}` — handed straight to a serializer, which will stringify it. The
        # exception has to appear on its OWN: `exc.__class__.__name__` reaches the same Name
        # through `ast.walk` and carries only the class, which is what the docstring above
        # promises to leave alone. Written as an explicit set because the walk gives no parent.
        if isinstance(node, ast.Name) and node.id in caught \
                and id(node) not in _reached_through(payload):
            return True
    return False


def _reached_through(payload: ast.AST) -> set[int]:
    """Name nodes that are the base of an attribute access or an argument to a call.

    Both are cases where the *expression around* the name decides what goes out — an attribute
    picks one field off the exception, a call is handled by the accessor tests above — so the
    bare-name rule must not fire on either. Identity is by `id()` because AST nodes are not
    hashable in a way that distinguishes two structurally equal names.
    """
    out: set[int] = set()
    for node in ast.walk(payload):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            out.add(id(node.value))
        elif isinstance(node, ast.Call):
            out.update(id(a) for a in node.args if isinstance(a, ast.Name))
    return out


def _leaks_internals(payload: ast.expr) -> bool:
    names = _dotted_names(payload)
    if any(any(marker in n for marker in _INTERNALS) for n in names):
        return True
    return any(n in _PATH_NAMES or n.rsplit(".", 1)[-1] in _PATH_NAMES for n in names)


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if not is_web_module(tree, text):
        return []

    lines = text.splitlines()
    findings: list[Finding] = []
    for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
        payloads = _response_payloads(func)
        if not payloads:
            continue
        caught = _exception_names(func)
        exception_leaks = [p for p in payloads if _leaks_exception(p, caught)]
        internal_leaks = [p for p in payloads if _leaks_internals(p)]

        if exception_leaks:
            line = min(p.lineno for p in exception_leaks)
            findings.append(Finding(
                detector_id="EXPOSE-PY-EXCEPTION",
                title="Exception detail returned to the caller",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                cwe="CWE-209", owasp="A05",
                file=rel, line=line,
                evidence=_evidence(lines, line),
                fix=f"`{func.name}` puts the caught exception into the response body, so "
                    f"whoever triggered the error reads whatever the failing layer wrote — "
                    f"table names, file paths, driver versions. Return a generic message and a "
                    f"correlation id, and log the exception with that id server-side.",
                source="structural", verdict=Verdict.UNVERIFIED))
        elif internal_leaks:
            line = min(p.lineno for p in internal_leaks)
            findings.append(Finding(
                detector_id="EXPOSE-PY-INTERNALS",
                title="Environment or deployment detail returned to the caller",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                cwe="CWE-215", owasp="A05",
                file=rel, line=line,
                evidence=_evidence(lines, line),
                fix=f"`{func.name}` returns environment values, settings or server paths in the "
                    f"response body. A diagnostics endpoint belongs behind the same "
                    f"authorization as an admin action at minimum, and the values it reports "
                    f"should be a fixed allowlist rather than whatever the environment holds.",
                source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Response-exposure analysis reports a caught exception or an environment/settings/path "
        "value reaching a response body the handler builds itself. A value passed to a template "
        "is not reported — the template decides what it renders — and neither is a framework "
        "debug page, which is a deployment setting rather than a line of code. It cannot tell a "
        "harmless exception message from a revealing one, because which exceptions arrive is a "
        "runtime fact.",
    ]
