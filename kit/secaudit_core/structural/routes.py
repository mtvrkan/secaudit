"""Shared machinery for the structural analyses: what a request handler *is*.

Route detection, the authenticated-principal model, and the request-reading helpers were all
written for the authorization rules and then needed verbatim by the rate-limit, upload and
mass-assignment rules — the four questions differ, the notion of "a handler and what it can
see" does not. Keeping one copy is not just tidiness: `_route_of` encodes which frameworks are
recognised at all, and four drifting copies of that would mean four different answers to
"is this a route" in one report.
"""
from __future__ import annotations

import ast
from typing import Union

# `ast.walk` yields both flavours of function and every framework in scope defines async
# handlers, so the two are the same thing everywhere below.
AnyFunc = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# The languages every structural analysis claims, in the shape `gen_language_matrix.py` reads.
# Derived from here and nowhere else — the language matrix once said "single file" for months
# because the scope was a literal in the generator rather than a fact in the engine.
LANGS: dict[str, dict] = {
    "Python": {"exts": (".py",), "frontend": "stdlib `ast` parse",
               "resolves": "module-local helper calls and references"},
}
EXTS: tuple[str, ...] = tuple(ext for spec in LANGS.values() for ext in spec["exts"])


def _evidence(lines: list[str], line: int) -> str:
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


# Path fragments that mean a file is not code serving traffic. Every rule in this package
# describes something a *deployed handler* fails to do, so a test module, a fixture, a migration
# or a one-off script is out of scope by construction — not merely noisy. (The detector pack
# still scans these files: a committed secret in a test is a real secret. That is a different
# question from "this endpoint has no rate limit".)
_NON_PRODUCTION = ("/tests/", "/test/", "test_", "_test.py", "tests.py", "test.py",
                   "conftest.py", "/migrations/",
                   "/fixtures/", "/scripts/", "/examples/", "/samples/", "/benchmarks/")


def is_production_source(rel: str) -> bool:
    normalised = "/" + rel.replace("\\", "/").lstrip("/")
    tail = normalised.rsplit("/", 1)[-1]
    return not (any(m in normalised for m in _NON_PRODUCTION if m.startswith("/"))
                or any(tail.startswith(m) or tail.endswith(m)
                       for m in _NON_PRODUCTION if not m.startswith("/")))


def module_functions(tree: ast.AST) -> dict[str, AnyFunc]:
    """Every function defined in the module, by name.

    Built once per file and handed to each rule: resolving a gate, a limiter or a validator
    through a helper is the difference between a rule that works and one that reports the
    codebases which factored that helper out.
    """
    return {node.name: node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def routes_in(tree: ast.AST) -> list[tuple[Route, AnyFunc]]:
    """Every mounted handler in the module, paired with its function node."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            route = _route_of(node)
            if route is not None:
                out.append((route, node))
    return out

# --------------------------------------------------------------------------- route detection

# Decorator attributes that mount a function as an HTTP route. Flask/Blueprint use `.route`
# with a `methods=` kwarg; FastAPI/APIRouter and Bottle name the verb directly.
_VERB_DECORATORS = {"get", "post", "put", "delete", "patch", "head", "options"}
_STATE_CHANGING = {"post", "put", "delete", "patch"}

# Paths that are unauthenticated by design. Reporting "missing authentication" on the login
# route is the single most obvious way for this rule to lose a reader's trust, and no amount of
# recall is worth it.
_PUBLIC_PATH_MARKERS = (
    "login", "signin", "sign-in", "register", "signup", "sign-up", "token", "auth/",
    "authenticate", "forgot", "reset-password", "password-reset", "health", "healthz",
    "ping", "status", "metrics", "docs", "openapi", "static", "favicon", "robots",
    "webhook",  # a webhook authenticates by signature, which this module does not model
    "/", "index", "home", "public",
)


def _decorator_name(node: ast.AST) -> str:
    """The dotted name of a decorator, without its call arguments.

    `@app.route("/x")` -> `app.route`; `@login_required` -> `login_required`;
    `@router.get("/x")` -> `router.get`.
    """
    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _string_args(node: ast.Call) -> list[str]:
    return [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]


class Route:
    """A function that answers HTTP requests, plus what its decorators asserted about it."""

    __slots__ = ("decorators", "func", "line", "methods", "path")

    def __init__(self, func: AnyFunc, path: str, methods: set[str],
                 decorators: list[str]) -> None:
        self.func = func
        self.path = path
        self.methods = methods
        self.decorators = decorators
        self.line = func.lineno

    @property
    def state_changing(self) -> bool:
        return bool(self.methods & _STATE_CHANGING)

    @property
    def public_by_design(self) -> bool:
        path = self.path.lower()
        name = self.func.name.lower()
        if path in ("", "/"):
            return True
        return any(m in path or m in name for m in _PUBLIC_PATH_MARKERS if m != "/")


def _route_of(func: AnyFunc) -> Route | None:
    """The Route this function is mounted as, or None if it is not a handler.

    Django's function views have no decorator at all — they are recognised by taking `request`
    as the first parameter, which is the framework's own convention and the only signal there
    is. Their methods are unknown, so they are treated as not state-changing unless the body
    says otherwise; `_django_methods` recovers that from `request.method` comparisons.
    """
    decorators = [_decorator_name(d) for d in func.decorator_list]
    path, methods = "", set()
    mounted = False

    for dec in func.decorator_list:
        name = _decorator_name(dec)
        tail = name.rsplit(".", 1)[-1]
        if not isinstance(dec, ast.Call):
            continue
        if tail == "route":
            mounted = True
            args = _string_args(dec)
            path = args[0] if args else path
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods |= {e.value.lower() for e in kw.value.elts
                                if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        elif tail in _VERB_DECORATORS and "." in name:
            mounted = True
            methods.add(tail)
            args = _string_args(dec)
            path = args[0] if args else path
        elif tail == "api_view":                       # Django REST Framework
            mounted = True
            for arg in dec.args:
                if isinstance(arg, (ast.List, ast.Tuple)):
                    methods |= {e.value.lower() for e in arg.elts
                                if isinstance(e, ast.Constant) and isinstance(e.value, str)}

    if mounted:
        # A Flask route with no `methods=` serves GET only — that is the framework default,
        # not an unknown, and treating it as unknown would silence the state-changing rule.
        return Route(func, path, methods or {"get"}, decorators)

    args = [a.arg for a in func.args.args]
    if args and args[0] in ("request",) and not _is_method(func):
        return Route(func, "", _django_methods(func), decorators)
    if len(args) > 1 and args[0] == "self" and func.name.lower() in _VERB_DECORATORS:
        return Route(func, "", {func.name.lower()}, decorators)   # class-based view
    return None


def _is_method(func: AnyFunc) -> bool:
    args = [a.arg for a in func.args.args]
    return bool(args) and args[0] in ("self", "cls")


def _django_methods(func: AnyFunc) -> set[str]:
    """Verbs a Django function view handles, read from `request.method == "POST"` tests."""
    methods = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Compare) and _dotted(node.left).endswith("request.method"):
            methods |= {c.value.lower() for c in node.comparators
                        if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    return methods


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# --------------------------------------------------------------------- authorization evidence

# Decorator suffixes that assert the caller was authenticated or authorized.
_AUTH_DECORATORS = (
    "login_required", "token_required", "auth_required", "authenticated", "requires_auth",
    "jwt_required", "jwt_optional", "admin_required", "staff_member_required",
    "permission_required", "permission_classes", "authentication_classes", "requires_login",
    "protected", "authorize", "authorized", "roles_required", "role_required",
    "has_permission", "check_permission", "verify_token", "require_api_key", "require_auth",
)

# Names that ARE the authenticated principal once they appear in scope.
_PRINCIPAL_NAMES = (
    "current_user", "currentuser", "request.user", "g.user", "self.request.user",
    "current_identity", "auth_user", "logged_in_user", "request.state.user",
)

# Calls that produce the principal, or that reject the request outright.
_PRINCIPAL_CALLS = (
    "get_current_user", "get_jwt_identity", "get_current_active_user", "verify_jwt",
    "decode_token", "get_user_from_token", "authenticate", "check_auth", "verify_token",
)
_REJECTION_CALLS = ("abort", "permissiondenied", "httpexception", "forbidden", "unauthorized")

# Session keys that carry identity. `session["cart"]` does not authenticate anybody, so the
# key has to look like one — otherwise every session-using handler reads as authorized.
_IDENTITY_SESSION_KEYS = ("user", "user_id", "uid", "username", "account", "identity",
                          "logged_in", "is_admin", "role")


def _has_auth_decorator(decorators: list[str]) -> bool:
    return any(d.rsplit(".", 1)[-1].lower().endswith(_AUTH_DECORATORS)
               or d.rsplit(".", 1)[-1].lower() in _AUTH_DECORATORS
               for d in decorators)


def _principal_names_in_scope(func: AnyFunc) -> set[str]:
    """Local names that hold the authenticated principal inside this handler.

    Includes the parameter a decorator injects (`def update(current_user)`), which is how
    Flask's `@token_required` convention passes identity, and any local bound from a principal
    call or attribute (`user = get_jwt_identity()`).
    """
    names = {a.arg for a in func.args.args if a.arg.lower() in ("current_user", "user",
                                                                "current_identity", "auth_user")}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            value = node.value
            dotted = _dotted(value.func).lower() if isinstance(value, ast.Call) else ""
            tail = dotted.rsplit(".", 1)[-1]
            attr = _dotted(value).lower()
            if tail in _PRINCIPAL_CALLS or attr in _PRINCIPAL_NAMES:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return names


def _auth_evidence(func: AnyFunc, decorators: list[str],
                   functions: dict[str, AnyFunc], seen: frozenset[str] = frozenset(),
                   ) -> bool:
    """Whether anything in or reachable from this handler establishes who the caller is.

    Resolved through module-local calls, which is what the benchmark's 42 traps require: their
    handlers carry no auth decorator and call a helper that compares a header to an environment
    token. Depth is bounded by `seen`; recursion through a cycle returns False rather than
    hanging, and an unresolved call is treated as evidence — see `_calls_unresolved`.
    """
    if _has_auth_decorator(decorators):
        return True

    for node in ast.walk(func):
        # A reference to the principal, or a call that produces or checks it.
        if isinstance(node, (ast.Attribute, ast.Name)):
            if _dotted(node).lower() in _PRINCIPAL_NAMES:
                return True
        if isinstance(node, ast.Call):
            tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
            if tail in _PRINCIPAL_CALLS or tail in _REJECTION_CALLS:
                return True
        # `session["user_id"]` / `session.get("user_id")` — identity keys only.
        if isinstance(node, ast.Subscript) and _dotted(node.value).lower().endswith("session"):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if any(k in key.value.lower() for k in _IDENTITY_SESSION_KEYS):
                    return True
        if isinstance(node, ast.Call) and _dotted(node.func).lower().endswith("session.get"):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(k in arg.value.lower() for k in _IDENTITY_SESSION_KEYS):
                        return True
        # Raising 401/403 is an authorization decision however it is spelled.
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("status_code", "status", "code") and isinstance(kw.value, ast.Constant):
                    if kw.value.value in (401, 403):
                        return True
            for arg in node.args:
                if isinstance(arg, ast.Constant) and arg.value in (401, 403):
                    return True

    # Follow every module-local function this handler *reaches*. This is the trap guard, and
    # "reaches" has to be wider than "calls": a framework gate is as often injected as invoked.
    # FastAPI writes it `gate: None = Depends(_wrk_gate)` — the gate is an argument to Depends,
    # sitting in the parameter defaults, and is never called in the body at all. Following only
    # `ast.Call` callees walked straight past it and reported every handler in the file. So any
    # reference by name to a function defined in this module is followed, whether it is being
    # called, injected, or listed in `dependencies=[...]`.
    for node in ast.walk(func):
        name = ""
        if isinstance(node, ast.Call):
            name = _dotted(node.func).rsplit(".", 1)[-1]
        elif isinstance(node, ast.Name):
            name = node.id
        callee = functions.get(name)
        if callee is None or name in seen or callee is func:
            continue
        if _auth_evidence(callee, [_decorator_name(d) for d in callee.decorator_list],
                          functions, seen | {name}):
            return True
    return False


# ------------------------------------------------------------------- request-supplied ids

# Where a handler reads an identifier the caller chose. Path parameters count: in FastAPI and
# Flask they arrive as function arguments, which is why the parameter list is consulted too.
_REQUEST_READERS = (
    "request.args", "request.form", "request.json", "request.values", "request.data",
    "request.get_json", "request.query_params", "request.path_params", "request.POST",
    "request.GET", "request.body", "self.request.query_params", "data.get", "payload.get",
    "body.get", "params.get",
)

_ID_HINTS = ("id", "uid", "uuid", "pk", "key", "account", "order", "user", "customer",
             "invoice", "document", "file", "record", "ticket", "profile")

# Data operations — where an identifier turns into a row.
_DATA_CALLS = ("get", "filter", "filter_by", "get_or_404", "first", "one", "one_or_none",
               "all", "find", "find_one", "find_by_id", "query", "execute", "select",
               "delete", "update", "save", "get_object_or_404", "fetchone", "fetchall")
_DATA_RECEIVERS = ("query", "objects", "session", "db", "cursor", "conn", "connection",
                   "collection", "table", "repo", "repository", "model")


def _is_request_read(node: ast.AST) -> bool:
    """Whether this expression reads something the caller sent.

    Written as three explicit cases rather than one chained expression: the chained form mixed
    `or` with `and` and, because `and` binds tighter, evaluated as `startswith(...) or
    (endswith(...) and "request" in low)` — which is not what the reader (or the author) took
    it to mean. The linter caught it before the corpus did.
    """
    dotted = _dotted(node.func if isinstance(node, ast.Call) else node)
    if not dotted:
        return False
    low = dotted.lower()
    if low.startswith("request."):
        return True
    if any(low.startswith(reader.lower()) for reader in _REQUEST_READERS):
        return True
    # `x.json.get`, `body.get` on something already named for the request.
    tails = {reader.lower().rsplit(".", 1)[-1] for reader in _REQUEST_READERS}
    return "request" in low and any(low.endswith("." + tail) for tail in tails)


def _request_id_names(route: Route) -> set[str]:
    """Locals bound to a caller-chosen identifier, plus path parameters that look like ids."""
    func = route.func
    names = {a.arg for a in func.args.args
             if a.arg not in ("self", "request", "current_user", "user")
             and any(h in a.arg.lower() for h in _ID_HINTS)}
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        reads_request = False
        if isinstance(value, ast.Call) and _is_request_read(value):
            reads_request = True
            for arg in value.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    reads_request = any(h in arg.value.lower() for h in _ID_HINTS)
        elif isinstance(value, ast.Subscript) and _is_request_read(value.value):
            key = value.slice
            reads_request = (isinstance(key, ast.Constant) and isinstance(key.value, str)
                             and any(h in key.value.lower() for h in _ID_HINTS))
        if reads_request:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _reads_request_inline(call: ast.Call) -> bool:
    """Whether an argument of this call reads a caller-supplied identifier directly.

    Keyed on the same id-shaped key names `_request_id_names` uses, so an inline
    `request.args.get("order_id")` and a `oid = request.args.get("order_id")` two lines up are
    judged the same way — rather than the second being a bug and the first being invisible.
    """
    for arg in list(call.args) + [k.value for k in call.keywords]:
        for node in ast.walk(arg):
            if isinstance(node, ast.Call) and _is_request_read(node):
                for inner in node.args:
                    if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                        if any(h in inner.value.lower() for h in _ID_HINTS):
                            return True
            if isinstance(node, ast.Subscript) and _is_request_read(node.value):
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if any(h in key.value.lower() for h in _ID_HINTS):
                        return True
    return False


def _mentions(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


def _data_operations(func: AnyFunc) -> list[ast.Call]:
    """Calls that read or write persistent state, by method name plus a receiver that looks
    like a data access object. The receiver requirement is what keeps a bare `get(...)` or
    `update(...)` — ordinary dictionary and object methods — out of the result."""
    out = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        if "." not in dotted:
            if dotted.lower() in ("get_object_or_404",):
                out.append(node)
            continue
        receiver, _, method = dotted.rpartition(".")
        if method.lower() not in _DATA_CALLS:
            continue
        low = receiver.lower()
        if any(r in low for r in _DATA_RECEIVERS) or low.endswith("objects") or "." in receiver:
            out.append(node)
    return out


def _reads_request(func: AnyFunc) -> bool:
    """Whether the handler consumes anything the caller sent — body, form, query or headers."""
    for node in ast.walk(func):
        target = node.func if isinstance(node, ast.Call) else node
        if isinstance(target, (ast.Attribute, ast.Name)):
            if _dotted(target).lower().startswith("request."):
                return True
    return False


def _principal_constrains(call: ast.Call, principals: set[str], func: AnyFunc,
                          functions: dict[str, AnyFunc]) -> bool:
    """Whether the principal takes part in constraining this data operation.

    Checked on the whole enclosing statement chain rather than the call node alone, because
    `Order.query.filter_by(id=oid).filter_by(user_id=current_user.id)` and
    `if order.user_id != current_user.id: abort(403)` are both correct and neither puts the
    principal inside the first call.
    """
    if _mentions(call, principals):
        return True
    for node in ast.walk(func):
        # A comparison mentioning the principal is an ownership check, wherever it sits.
        if isinstance(node, ast.Compare) and _mentions(node, principals):
            return True
        # And so is handing the principal to a helper. `dispute = db.get(Dispute, dispute_id)`
        # followed by `_require_view(current_user, dispute)` is the *correct* fetch-then-authorize
        # idiom, and it was the single largest source of false positives here — 48 of them,
        # nearly all this one shape. The check does not have to be inline to exist; a call that
        # receives the principal is a check delegated, exactly as an auth gate reached through a
        # helper is authentication delegated. Missing this made the rule punish the codebases
        # that had factored their authorization out properly.
        if isinstance(node, ast.Call) and _receives(node, principals):
            return True
    return False


def _receives(call: ast.Call, principals: set[str]) -> bool:
    """Whether the principal is handed to this call, positionally or by keyword.

    Any such call silences the rule. That is deliberately generous, and the generosity was
    measured rather than assumed: a refinement that counted only calls *looking* like checks —
    by name, or by containing a comparison — was run against the corpus and recovered none of
    the true positives the conservative reading loses, while adding nine false ones. A rule
    that reports the ABSENCE of a check has to be sure of the absence, so it takes the reading
    that reports less.
    """
    return (any(_mentions(a, principals) for a in call.args)
            or any(_mentions(k.value, principals) for k in call.keywords))


