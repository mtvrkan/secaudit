"""Missing rate limiting on the routes where its absence is the vulnerability.

99 labels in the external corpus name a missing rate limit and the engine found none of them.
Reading the labelled code showed why the class is decidable at all: the flaw is not "this
endpoint is slow to protect", it is that a **credential-testing** endpoint — login, register,
password reset, token issuance, OTP — accepts unlimited attempts. CWE-307 is precisely
"improper restriction of excessive authentication attempts", and that is a property of a
handler, not of a line.

**The rule is deliberately narrow, and the narrowness is the whole design.** Almost every route
in almost every application has no rate limiter, so a rule that reported "route without a
limiter" would report the entire codebase and be switched off within a day. This one fires only
where the *credential* is the resource being tested: the path or the handler name has to name an
authentication action, and the handler has to actually consult a credential store. A rate limit
missing from `/api/reports` is a capacity question for the team that owns it. A rate limit
missing from `/api/auth/login` is how the account gets taken.

Evidence for a limiter is resolved the same way authorization evidence is — through decorators,
dependency injection, module-local helpers, and any limiter registered on the app or router at
module level, because a limiter installed as middleware protects handlers that never mention it.
An unresolvable call is treated as a possible limiter: this rule reports the ABSENCE of one.
"""
from __future__ import annotations

import ast
import re

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import (AnyFunc, Route, _decorator_name, _dotted, _evidence, EXTS,
                     module_functions, routes_in)

# Path or handler-name markers for an action that tests a credential. `logout` is deliberately
# absent — it consumes a session the caller already holds, so unlimited attempts prove nothing.
_AUTH_ACTION_MARKERS = (
    "login", "signin", "sign-in", "sign_in", "authenticate", "auth/token", "/token",
    "register", "signup", "sign-up", "sign_up", "reset-password", "reset_password",
    "password-reset", "password_reset", "forgot-password", "forgot_password", "forgot",
    "otp", "2fa", "mfa", "verify-code", "verify_code", "resend", "magic-link", "magic_link",
    "change-password", "change_password", "session",
)

# Names that mean a limiter is in play, whether decorator, dependency or middleware.
_LIMITER_MARKERS = (
    "limiter", "ratelimit", "rate_limit", "throttle", "throttling", "slowapi",
    "flask_limiter", "flask-limiter", "django_ratelimit", "ratelimiter", "leakybucket",
    "tokenbucket", "brakeman", "cooldown", "backoff", "captcha",
)

# Names for the *count* of attempts, and for a lockout keyed on it. These are deliberately NOT
# in `_LIMITER_MARKERS`, because the name alone does not say which side of the problem the code
# is on: `attempts_for(ip) > 5` is a bound and `db.record_attempt(email)` is a handler writing
# down the break-in it is failing to stop. `attempt` used to be a plain marker and matched both,
# so a login that carefully logged every failed password silenced itself. What separates them is
# not the name but what is done with the value — see `_bounds_attempts`.
_ATTEMPT_MARKERS = ("attempt", "lockout", "lock_out", "locked_out", "lock-out", "locked-out",
                    "cooldown_until", "blocked_until", "banned_until")


def _bounds_attempts(node: ast.AST) -> bool:
    """Whether an attempt count is being *compared against something* rather than merely kept.

    A limiter is a decision, so it shows up as a condition: `if attempts_for(ip) > 5`,
    `if too_many_attempts(email)`, `if user.lockout_until > now()`. Counting attempts without
    ever testing the count is bookkeeping, and bookkeeping is what the endpoints this rule
    reports tend to have instead of a limit.
    """
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp, ast.While, ast.Assert)):
            tests: list[ast.AST] = [child.test]
        elif isinstance(child, ast.Compare):
            tests = [child]
        else:
            continue
        for test in tests:
            if any(any(m in name for m in _ATTEMPT_MARKERS) for name in _names_in(test)):
                return True
    return False

# What makes a handler a credential-testing one rather than merely a route whose name matches.
_CREDENTIAL_MARKERS = (
    "password", "passwd", "credential", "authenticate", "check_password", "verify_password",
    "check_hash", "verify_hash", "bcrypt", "argon", "pbkdf2", "scrypt", "hashpw",
    "otp", "token", "secret", "login", "session",
)


def _names_in(node: ast.AST) -> list[str]:
    """Every dotted name and attribute mentioned anywhere under `node`, lowercased."""
    out = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value.lower())
    return out


def _mentions_limiter(node: ast.AST) -> bool:
    return any(any(m in name for m in _LIMITER_MARKERS) for name in _names_in(node))


def _module_has_limiter(tree: ast.AST) -> bool:
    """A limiter registered on the app, the router or as middleware at module level.

    Checked before any handler is judged, because this is the shape that protects a handler
    which never mentions a limiter itself — `app.add_middleware(RateLimitMiddleware)` a hundred
    lines above the route. Missing it would report an application that is correctly protected.

    Only **module-level** statements count, and that word is doing real work. This walked the
    entire tree once, so any call anywhere that mentioned a limiter marker silenced every route
    in the file. Three shapes fell out of that, all of them false negatives on the exact code
    this rule exists to find:

      * a handler calling `db.record_attempt(email)` — `attempt` is a limiter marker, and
        recording failed attempts is what an unprotected login does *instead* of limiting them;
      * an unrelated route logging the string `"... attempt"`, because a call's whole subtree
        was searched, string constants included;
      * one route carrying `@limiter.limit("5/minute")` silencing an unlimited `admin-login`
        beside it — a per-route decorator on ONE route is not a module-level registration, and
        "some endpoints are limited, one was forgotten" is the realistic form of this bug.

    A limiter genuinely installed for the whole module is an import, a module-level assignment
    or call, or a decorator/middleware registration — never a call buried inside one handler.
    A handler that limits itself is still recognised, by `_limiter_evidence`, per handler.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
            if any(any(m in (n or "").lower() for m in _LIMITER_MARKERS) for n in names):
                return True
    # Statements written at module level, plus the bodies of any `if`/`try`/`with` wrapper they
    # are nested in — app setup is routinely guarded by `if not TESTING:` or a settings check,
    # and that is still module-level registration. Function and class bodies are not descended
    # into: that is the boundary the tree walk used to cross.
    pending = list(getattr(tree, "body", []))
    while pending:
        stmt = pending.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for wrapper in ("body", "orelse", "finalbody"):
            pending += getattr(stmt, wrapper, []) or []
        for handler in getattr(stmt, "handlers", []) or []:
            pending += handler.body
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and _mentions_limiter(node):
                return True
    return False


def _limiter_evidence(func: AnyFunc, decorators: list[str],
                      functions: dict[str, AnyFunc], seen: set[str] | None = None) -> bool:
    """Whether anything in or reachable from this handler limits attempts.

    `seen` accumulates across the traversal, not down each branch — this is a reachability
    question, and a per-path visited set enumerates paths rather than nodes, which is
    exponential. See `structural/js.py:_resolved` for the measurement that found it.
    """
    if seen is None:
        seen = set()
    if any(any(m in d.lower() for m in (*_LIMITER_MARKERS, *_ATTEMPT_MARKERS))
           for d in decorators):
        return True
    if _mentions_limiter(func) or _bounds_attempts(func):
        return True
    for node in ast.walk(func):
        name = ""
        if isinstance(node, ast.Call):
            name = _dotted(node.func).rsplit(".", 1)[-1]
        elif isinstance(node, ast.Name):
            name = node.id
        callee = functions.get(name)
        if callee is None or name in seen or callee is func:
            continue
        seen.add(name)
        if _limiter_evidence(callee, [_decorator_name(d) for d in callee.decorator_list],
                             functions, seen):
            return True
    return False


def _is_auth_action(route: Route) -> bool:
    haystack = f"{route.path.lower()} {route.func.name.lower()}"
    return any(marker in haystack for marker in _AUTH_ACTION_MARKERS)


def _touches_a_credential(func: AnyFunc, functions: dict[str, AnyFunc]) -> bool:
    """Whether the handler actually consults a credential, directly or through a helper.

    The name test alone is not enough: a `GET /session` that returns the current user's profile
    matches `session` and tests no credential at all. Requiring the handler to reach something
    that looks like a password, hash, token or OTP check is what keeps this rule on the
    endpoints where unlimited attempts are the bug.
    """
    names = _names_in(func)
    if any(any(m in n for m in _CREDENTIAL_MARKERS) for n in names):
        return True
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        callee = functions.get(_dotted(node.func).rsplit(".", 1)[-1])
        if callee is not None and callee is not func:
            if any(any(m in n for m in _CREDENTIAL_MARKERS) for n in _names_in(callee)):
                return True
    return False


# --------------------------------------------------------------- the framework's own login

# Django ships the credential-testing endpoints most projects use, and a project that uses them
# writes no handler at all: `path("accounts/login/", auth_views.LoginView.as_view())` is the
# whole login. Every rule above reads a function — its decorators, its body, its helpers — so on
# this shape there is nothing to read, and the rule stayed silent on eighteen labelled cases of
# exactly the flaw it exists to find. The absence is not a threshold to tune; it is a question
# nobody asked of a route with no function behind it.
#
# Two classes, and the exclusions carry as much of the design as the inclusions:
#
#   * `LoginView` — a password guessed at unlimited speed, by an anonymous caller.
#   * `PasswordResetView` — a reset email sent at unlimited speed to any address a caller names,
#     which is both an abuse channel and an account-existence oracle.
#
# `PasswordChangeView` is NOT here: it requires a session the attacker must already hold, so
# unlimited attempts prove nothing they did not already have. Neither is
# `PasswordResetConfirmView`: the value it tests is an HMAC Django generated, not a secret a
# person chose, and guessing it is not a rate problem. `LogoutView` and the three `*DoneView`
# pages test nothing at all.
_FRAMEWORK_CREDENTIAL_VIEWS = ("LoginView", "PasswordResetView")

_URLCONF_REGISTRARS = ("path", "re_path", "url")

# Project-wide evidence that attempts are bounded somewhere. This is deliberately a different
# and *narrower* vocabulary than `_LIMITER_MARKERS`: that list is read inside one module, where
# `cooldown` and `backoff` are about the thing at hand, and this one is read across every file
# in the project, where a retry `backoff` in an unrelated HTTP client would silence the login.
# What stays are the names that only ever mean this: the generic throttle vocabulary, a lockout,
# and the second Django brute-force package.
#
# The boundary is letters rather than `\b`, because `_` is how a Django setting spells a space:
# `\bratelimit\b` does not match `django_ratelimit` and `\blockout\b` does not match
# `AXES_LOCKOUT_TEMPLATE`, which are two of the most common ways a project says it is defended.
# A word that merely contains one — `throttlebury` — still does not, since a letter on either
# side is what is excluded.
_PROJECT_LIMITER_MARKERS = ("ratelimit", "rate_limit", "throttle", "throttling",
                            "defender", "captcha", "lockout", "brute_force", "bruteforce")

_PROJECT_LIMITER_RE = re.compile(
    r"(?<![A-Za-z])(?:" + "|".join(_PROJECT_LIMITER_MARKERS) + r")(?![A-Za-z])", re.IGNORECASE)

# `axes` is the first Django brute-force package and the only marker here that is also an
# ordinary English word — a plotting helper, a settings key, a variable in any file that draws a
# chart. Read as a bare token it would let an unrelated module silence the login, so it counts
# only in the four shapes that mean the package: an installed-app or middleware string, a
# settings prefix, a dependency line, or its own module path.
_AXES_RE = re.compile(r"""['"]axes['"]|(?<![A-Za-z])AXES_|django-axes|(?<![A-Za-z])axes\.""")


def _django_auth_view_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    """The names in this module that reach `django.contrib.auth.views`.

    Returned as (module aliases, class names) — `from django.contrib.auth import views as
    auth_views` gives the first, `from django.contrib.auth.views import LoginView` the second.
    A project's own class called `LoginView` is therefore not matched, which is the point: this
    rule knows what the *framework's* views do and nothing about anybody else's.
    """
    modules: set[str] = set()
    classes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "django.contrib.auth.views":
                classes |= {a.asname or a.name for a in node.names}
            elif mod == "django.contrib.auth":
                modules |= {a.asname or a.name for a in node.names if a.name == "views"}
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "django.contrib.auth.views" and a.asname:
                    modules.add(a.asname)
    return modules, classes


def _registered_credential_view(call: ast.Call, modules: set[str],
                                classes: set[str]) -> str | None:
    """The framework credential view this `path(...)` mounts, if it mounts one."""
    if _dotted(call.func).rsplit(".", 1)[-1] not in _URLCONF_REGISTRARS:
        return None
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        if not isinstance(arg, ast.Call):
            continue
        dotted = _dotted(arg.func)
        if not dotted.endswith(".as_view"):
            continue
        receiver = dotted[: -len(".as_view")]
        head, _, tail = receiver.rpartition(".")
        if tail not in _FRAMEWORK_CREDENTIAL_VIEWS:
            continue
        if (head and head in modules) or (not head and tail in classes):
            return tail
    return None


def _project_bounds_attempts(files: dict[str, str]) -> bool:
    """Whether anything anywhere in the project bounds authentication attempts.

    Project-wide rather than per-module because that is where the answer lives: `django-axes` is
    an entry in `INSTALLED_APPS` and a middleware line in `settings.py`, and the URL conf that
    wires the login never mentions it. A rule reading only the URL conf would report every
    correctly-defended Django project there is.

    Read across the project's Python sources and generously — this rule reports the ABSENCE of a
    limiter, so an ambiguous mention counts as evidence and buys silence.

    A dependency manifest is deliberately not consulted, and not only because the scan does not
    read one: `django-axes` in `requirements.txt` defends nothing until it is in `INSTALLED_APPS`
    or `MIDDLEWARE`, and both of those are Python. An installed limiter always leaves a mark in
    the sources; a listed one that never does is a dependency, not a defence.
    """
    for rel, text in files.items():
        if rel.lower().endswith(".py"):
            if _PROJECT_LIMITER_RE.search(text) or _AXES_RE.search(text):
                return True
    return False


def analyze_project(files: dict[str, str]) -> list[Finding]:
    """The credential endpoints a project mounts without writing them."""
    urlconfs: list[tuple[str, str, ast.AST]] = []
    for rel, text in sorted(files.items()):
        if not rel.lower().endswith(EXTS) or "urlpatterns" not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            continue
        urlconfs.append((rel, text, tree))
    if not urlconfs:
        return []
    if _project_bounds_attempts(files):
        return []

    findings: list[Finding] = []
    for rel, text, conf in urlconfs:
        modules, classes = _django_auth_view_names(conf)
        if not modules and not classes:
            continue
        lines = text.splitlines()
        for node in ast.walk(conf):
            if not isinstance(node, ast.Call):
                continue
            view = _registered_credential_view(node, modules, classes)
            if view is None:
                continue
            findings.append(Finding(
                detector_id="RATELIMIT-PY-AUTHVIEW",
                title="Framework authentication route accepts unlimited attempts "
                      "(no rate limit)",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                cwe="CWE-307", owasp="A07",
                file=rel, line=node.lineno,
                evidence=_evidence(lines, node.lineno),
                fix=f"This route mounts Django's own `{view}`, so there is no handler in this "
                    f"project to carry a limiter — and nothing anywhere in it bounds "
                    f"authentication attempts: no `django-axes`, no `django-ratelimit`, no "
                    f"throttling middleware, no lockout. Install a brute-force defence at the "
                    f"project level (per account AND per source address) or wrap the view.",
                source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if _module_has_limiter(tree):
        return []

    lines = text.splitlines()
    functions = module_functions(tree)
    findings: list[Finding] = []

    for route, func in routes_in(tree):
        if not route.state_changing or not _is_auth_action(route):
            continue
        if not _touches_a_credential(func, functions):
            continue
        if _limiter_evidence(func, route.decorators, functions):
            continue
        findings.append(Finding(
            detector_id="RATELIMIT-PY-AUTH",
            title="Authentication endpoint accepts unlimited attempts (no rate limit)",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            cwe="CWE-307", owasp="A07",
            file=rel, line=route.line,
            evidence=_evidence(lines, route.line),
            fix=f"`{func.name}` tests a credential and nothing bounds how often it can be "
                f"called — not a decorator, not a dependency, not middleware on this module. "
                f"Add a per-identifier limit (attempts per account AND per source address, so "
                f"neither a single account nor a single client can be hammered), and prefer a "
                f"progressive delay or lockout over a flat cap.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Rate-limit analysis reports only credential-testing endpoints (login, registration, "
        "password reset, token and OTP issuance) that reach a credential check with no limiter "
        "in the handler, its decorators, its module-local helpers, or registered on the app. "
        "A missing limit on any other endpoint is a capacity decision this does not make, and "
        "a limiter enforced outside the application — at a gateway, a WAF or a reverse proxy — "
        "is invisible here and will read as missing.",
        "A login the project does not write is read separately, and only in one shape: Django's "
        "own `LoginView` or `PasswordResetView` mounted in a URL conf, in a project where "
        "nothing at all names a limiter. Two neighbouring shapes are NOT reported and are "
        "genuine misses rather than decisions — `include('django.contrib.auth.urls')`, which "
        "mounts the same login through a module this analysis does not open, and a class-based "
        "view the project wrote itself, whose body no rule here reads.",
    ]
