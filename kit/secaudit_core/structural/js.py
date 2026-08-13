"""The same four handler questions, asked of JavaScript and TypeScript.

`routes.py` answers them with `ast`. There is no parser here, so this module answers them with
the same brace-aware scanning the JS taint front end uses, and the difference in confidence is
real: what a Python rule *knows* about a handler, this one *recognises*. Every rule below is
therefore written to err toward silence, which is the discipline the Python rules arrived at the
expensive way — all five report the ABSENCE of something, and a rule that reports an absence has
to be sure of it.

**Why a separate module rather than a second front end under `routes.py`.** The four Python
rules are written against `ast` nodes from top to bottom; threading a second node type through
them would put every JavaScript mistake inside the code path that produces the published
RealVuln figure. Python's behaviour is measured and JavaScript's is not, so they do not share a
call path. What they share is the vocabulary — the same detector families, the same finding
shape, the same "an unresolved reference counts as evidence" rule.

**What a route is here.** A mount with a *string literal path* and at least one more argument:
`app.post('/users', requireAuth, createUser)`. The string-path anchor is what keeps `map.get(k)`
and `cache.delete(key)` out, and it is the single most important precision decision in the file.
Alongside that: NestJS method decorators, Next.js App Router `export function GET`, and Next.js
Pages API default exports, each recognised only in a file whose path says that is what it is.

**The bound worth stating before any of the rules.** The whole mount call is treated as the
handler — middleware arguments included. That is deliberate: middleware is exactly where a
JavaScript app puts its auth and its rate limiting, so reading it is the point. It does mean an
inline handler and its own middleware are not told apart, which can only ever *silence* a rule,
never fire one.

**This is unmeasured against any external corpus.** RealVuln v1 is Python-only, so there is no
number here comparable to the Python side's. What is asserted is a regression floor: the shapes
in `kit/tests/test_structural.py` are found, and the shipped secure fixture stays silent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schema import Confidence, Finding, Severity, Verdict
from ..taint.lexical import code_view, split_args
from .routes import _evidence, is_production_source

JS_LANGS: dict[str, dict] = {
    "JavaScript": {"exts": (".js", ".jsx", ".mjs", ".cjs"),
                   "frontend": "brace-aware route scanner",
                   "resolves": "module-local helper functions and mount middleware",
                   "analyses": ("authorization", "rate limit", "upload", "mass assignment")},
    "TypeScript": {"exts": (".ts", ".tsx", ".mts", ".cts"),
                   "frontend": "brace-aware route scanner",
                   "resolves": "module-local helper functions and mount middleware",
                   "analyses": ("authorization", "rate limit", "upload", "mass assignment")},
}
JS_EXTS: tuple[str, ...] = tuple(e for spec in JS_LANGS.values() for e in spec["exts"])

# Path shapes that mean a file is not code serving traffic, in the conventions JavaScript uses.
# `routes.is_production_source` covers the language-neutral ones; these are additional, and are
# kept here rather than added there so nothing in this module can change how a `.py` file is
# classified — that classification is inside the measured RealVuln path.
_JS_NON_PRODUCTION = (".test.", ".spec.", ".stories.", ".e2e.", ".cy.", ".mock.", ".d.ts",
                      "/__tests__/", "/__mocks__/", "/cypress/", "/e2e/", "/.next/",
                      "/coverage/", "/storybook/", ".config.")

_STATE_CHANGING = ("post", "put", "patch", "delete")

# A mounted route: a receiver, an HTTP verb, and a STRING LITERAL path. The string path is the
# precision anchor — without it `store.get(key)` and `queue.delete(id)` are routes.
_MOUNT = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all|head|options)\s*\(\s*"
    r"(['\"`])([^'\"`]*)\3\s*,")

# NestJS — the verb is the decorator and the path is optional.
_NEST = re.compile(r"@(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:(['\"`])([^'\"`]*)\2)?")
# Next.js App Router — a named export per verb, only in a `route.*` file.
_NEXT_ROUTE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(")
# Next.js Pages API — one default-exported handler for every verb.
_NEXT_PAGES = re.compile(r"export\s+default\s+(?:async\s+)?function\s*([A-Za-z_$][\w$]*)?\s*\(")

# Named functions whose body can be delimited, so evidence can be followed into a helper.
_FUNC_FORMS = (
    re.compile(r"(?:^|[^.\w$])(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?(?:function\s*\*?\s*)?\("),
    re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?[A-Za-z_$][\w$]*\s*=>"),
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")

# Paths and handler names that are unauthenticated by design. Reporting "missing authentication"
# on the login route is the fastest way for this rule to lose a reader, and no recall is worth it.
_PUBLIC = ("login", "signin", "sign-in", "register", "signup", "sign-up", "token", "auth/",
           "authenticate", "forgot", "reset", "health", "healthz", "ping", "status", "metrics",
           "docs", "openapi", "static", "public", "favicon", "robots", "webhook", "callback",
           "contact", "subscribe", "newsletter")

# Evidence that the caller was established. Middleware names count: in this ecosystem that is
# where authentication usually lives, and a handler protected by `requireAuth` in its own mount
# never mentions authentication in its body.
_AUTH_MARKERS = (
    "req.user", "request.user", "req.auth", "ctx.state.user", "res.locals.user",
    "req.session.user", "req.session.userid", "session.user", "currentuser", "current_user",
    "getserversession", "getsession", "auth()", "verifytoken", "verifyjwt", "jwt.verify",
    "requireauth", "require_auth", "ensureauth", "ensureloggedin", "isauthenticated",
    "authenticate", "authguard", "useguards", "passport", "checkauth", "requirelogin",
    "protect", "authorize", "authorized", "permit", "haspermission", "checkpermission",
    "requirerole", "requireadmin", "isadmin", "adminonly", "withauth", "clerk", "nextauth",
)
_REJECTION = ("401", "403", "unauthorized", "forbidden")

# Where a caller-chosen identifier is read.
_REQUEST_ID_READ = re.compile(
    r"\b(?:req|request|ctx)\s*\.\s*(?:params|query|body|args|payload)\s*(?:\.\s*|\[\s*['\"`])"
    r"([A-Za-z_$][\w$]*)", re.I)
_ID_HINTS = ("id", "uid", "uuid", "pk", "key", "slug", "account", "order", "user", "customer",
             "invoice", "document", "file", "record", "ticket", "profile", "owner")

# Data operations — where an identifier becomes a row.
_DATA_CALL = re.compile(
    r"\b(?:findbyid|findone|findbyidandupdate|findbyidanddelete|findbyidandremove|findunique|"
    r"findfirst|deleteone|updateone|getbyid|fetchbyid|query|execute|findall|destroy|"
    r"aggregate|scan)\s*\(", re.I)
_ORM_HINT = re.compile(r"\b(?:prisma|db|knex|sequelize|mongoose|model|repo|repository|"
                       r"collection|table|conn|connection|pool|client)\b", re.I)

# Rate limiting.
_AUTH_ACTION = ("login", "signin", "sign-in", "authenticate", "session", "token", "otp",
                "verify", "password", "reset", "forgot", "2fa", "mfa", "register", "signup")
_CREDENTIAL_CHECK = re.compile(
    r"\b(?:bcrypt|argon2|scrypt|pbkdf2|comparesync|compare|checkpassword|verifypassword|"
    r"validatepassword|signin|authenticate|comparepassword|passwordmatch|matchpassword)\b", re.I)
# Two alternatives, and the second one is why this is not a single case-insensitive list.
# `\blimiter\b` does not match `loginLimiter`, which is what the middleware is actually called in
# this ecosystem — so the rule fired on every correctly limited route. Dropping the boundary
# instead makes `delimiter` read as a rate limiter, which silences the rule on code that has no
# limit at all. So: whole words case-insensitively, plus a camel hump that must be a real capital.
_LIMITER = re.compile(
    r"(?i:\b(?:ratelimit|rate_limit|rate-limit|ratelimiter|expressratelimit|expressbrute|"
    r"slowdown|throttler?|bottleneck|limiter|leakybucket|tokenbucket)\b)"
    r"|(?<=[a-z0-9])(?:Limiter|Throttle|RateLimit|Brute)\b")
_ATTEMPT_BOUND = re.compile(
    r"\battempts?\b[^\n;]{0,80}?(?:[<>]=?|>=|===?|\.length\s*[<>]|exceed|over|max|limit)", re.I)

# Uploads.
_UPLOAD_READ = re.compile(
    r"\b(?:req|request|ctx)\s*\.\s*(?:file|files)\b|\bmulter\b|\bformidable\b|\bbusboy\b|"
    r"\bmultipart\b|\bformdata\s*\.\s*get\b|\bbodyparser\s*\.\s*raw\b", re.I)
_WRITE = re.compile(
    r"\b(?:writefile|writefilesync|createwritestream|copyfile|rename|mv|putobject|upload|"
    r"uploadfile|save|persist|store|pipe)\s*\(", re.I)
# Substring, not whole word, and deliberately so: `validateUpload`, `allowedTypes` and
# `checkFileType` are all the same evidence, and a trailing `\b` sees none of them. Erring
# generous is right for every silencing pattern in this file — each one is asked "is a check
# present", and a rule that reports the ABSENCE of a check has to be sure of the absence.
_UPLOAD_VALIDATION = re.compile(
    r"(?:allowed|allowlist|whitelist|permitted|mimetype|mime_type|mimetypes|"
    r"contenttype|content_type|filefilter|extname|magic|filetype|sniff|imagesize|maxsize|"
    r"max_size|limits|filesize|sizelimit|sharp|imagemagick|validatefile|checkfile|isimage|"
    r"validate|sanitiz)", re.I)

# Mass assignment.
_BODY_WHOLESALE = re.compile(
    r"(?:\b(?:create|createmany|insert|update|updateone|updatemany|findbyidandupdate|save|set|"
    r"build|bulkcreate|upsert)\s*\(\s*(?:\{\s*\.\.\.\s*)?(?:req|request|ctx)\s*\.\s*body\b)"
    r"|(?:\bnew\s+[A-Z][\w$]*\s*\(\s*(?:req|request|ctx)\s*\.\s*body\b)"
    r"|(?:\bobject\s*\.\s*assign\s*\([^,)]+,\s*(?:req|request|ctx)\s*\.\s*body\b)"
    r"|(?:\bdata\s*:\s*(?:req|request|ctx)\s*\.\s*body\b)", re.I)
# Substring for the same reason as `_UPLOAD_VALIDATION`. The most generic tokens a previous
# draft carried — `only`, `fields`, `select` — are gone: they appear in ordinary code that
# allowlists nothing, and every one of them silences a real finding.
_ALLOWLIST = re.compile(
    r"(?:pick|omit|allowlist|whitelist|permitted|sanitiz|sanitis|schema|zod|joi\b|yup|valibot|"
    r"superstruct|ajv|classvalidator|class-validator|validate|safeparse|dto|plainto)", re.I)
# There is deliberately no exemption for `const { name, email } = req.body` here. It looked
# obviously right — destructuring the body to named fields IS the idiomatic allowlist — and it
# was both dead and wrong. Dead, because a handler that destructures and then writes the named
# fields never matches `_BODY_WHOLESALE` in the first place, so the exemption decided nothing.
# Wrong, because the one case it did decide is this:
#
#     const { email, name } = req.body;          // narrows nothing on its own
#     await prisma.user.create({ data: req.body });   // the whole body still reaches the write
#
# which is mass assignment, and the exemption silenced it. Same shape as the Python rate-limit
# rule treating a limiter anywhere in the file as protection everywhere in it: evidence has to
# be about the operation being judged, not merely present nearby. Found by mutation — removing
# the exemption changed no test, which is what a branch that decides nothing looks like.


@dataclass(frozen=True)
class _Route:
    """A mounted handler and the lines that make it up."""
    path: str
    method: str
    name: str
    line: int
    start: int
    end: int

    @property
    def state_changing(self) -> bool:
        return self.method in _STATE_CHANGING

    @property
    def public_by_design(self) -> bool:
        hay = f"{self.path} {self.name}".lower()
        return any(marker in hay for marker in _PUBLIC)


def is_production_js(rel: str) -> bool:
    lowered = "/" + rel.replace("\\", "/").lstrip("/").lower()
    return is_production_source(rel) and not any(m in lowered for m in _JS_NON_PRODUCTION)


def _block_end(lines: list[str], start: int, col: int, opener: str = "{", closer: str = "}") -> int:
    """Line of the delimiter matching the one at (start, col). Called on a string-blanked view,
    so a brace or paren inside a literal cannot move the boundary."""
    depth = 0
    for lineno in range(start, len(lines) + 1):
        text = lines[lineno - 1]
        for ch in (text[col:] if lineno == start else text):
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return lineno
    return len(lines)


def _functions(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Module-local named functions, by name, as (first line, last line).

    Used to follow evidence into a helper: an app that factors `requireAuth` or `validateUpload`
    out is the app these rules must not report, and a rule that reads only the mount would report
    exactly those.
    """
    out: dict[str, tuple[int, int]] = {}
    for lineno, line in enumerate(lines, start=1):
        for pattern in _FUNC_FORMS:
            m = pattern.search(line)
            if not m:
                continue
            brace = line.find("{", m.end() - 1)
            if brace == -1:
                continue
            out.setdefault(m.group(1), (lineno, _block_end(lines, lineno, brace)))
            break
    return out


def _text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])


def _resolved(body: str, lines: list[str], functions: dict[str, tuple[int, int]],
              pattern: re.Pattern[str], seen: frozenset[str] = frozenset()) -> bool:
    """Whether `pattern` matches the handler, or anything module-local it names.

    Bare references are followed, not only calls: `app.post('/x', requireAuth, handler)` never
    calls `requireAuth`, and `@UseGuards(AuthGuard)` never calls the guard either. Following only
    call sites would report every route in both idioms.
    """
    if pattern.search(body):
        return True
    for name in set(_IDENT.findall(body)):
        span = functions.get(name)
        if span is None or name in seen:
            continue
        if _resolved(_text(lines, *span), lines, functions, pattern, seen | {name}):
            return True
    return False


def _literal_at(raw: list[str], lineno: int, pattern: re.Pattern[str], group: int) -> str:
    """Re-read a string literal from the ORIGINAL line.

    Routes are *found* on the blanked view, because a mount written inside a comment or a
    template string is not a mount. But `code_view` blanks the contents of every string literal,
    which is exactly where the path lives — so `'/auth/login'` arrives as `'           '` and the
    route has no path at all. Every rule that reads the path then reads nothing: login stops
    looking public, an auth endpoint stops naming an auth action, and the file silently loses
    two of its five rules. Found on the view, read from the source: the view decides *whether*
    there is a mount here, the raw line says what it mounts.
    """
    if not 0 < lineno <= len(raw):
        return ""
    m = pattern.search(raw[lineno - 1])
    return (m.group(group) or "") if m else ""


def _decorator_block_start(lines: list[str], lineno: int) -> int:
    """The first line of the contiguous decorator stack above `lineno`.

    `@UseGuards(AuthGuard)` sits on the line above `@Post(':id/cancel')`, so a span starting at
    the verb decorator excludes the guard and reports every guarded NestJS route in the file.
    """
    start = lineno
    while start > 1 and re.match(r"\s*@[A-Za-z_$]", lines[start - 2]):
        start -= 1
    return start


def _routes(lines: list[str], raw: list[str], rel: str) -> list[_Route]:
    """Every mounted handler in the file."""
    found: list[_Route] = []
    lowered = rel.replace("\\", "/").lower()

    for lineno, line in enumerate(lines, start=1):
        for m in _MOUNT.finditer(line):
            verb = m.group(2).lower()
            paren = line.find("(", m.end(2) - 1)
            if paren == -1:
                continue
            end = _block_end(lines, lineno, paren, "(", ")")
            path = _literal_at(raw, lineno, _MOUNT, 4)
            # The handler and its middleware, as written after the path. Identifier arguments
            # are names this rule can resolve; an inline function is not one, and falls back to
            # the path for the "what is this endpoint called" question.
            call = line[paren + 1:] + "\n" + "\n".join(lines[lineno:end])
            names = [a.strip() for a in split_args(call) if _IDENT.fullmatch(a.strip())]
            # `all` mounts every verb; treated as state-changing so the auth rule can see it.
            found.append(_Route(path, "post" if verb == "all" else verb,
                                " ".join(names) or path, lineno, lineno, end))

        for m in _NEST.finditer(line):
            verb = m.group(1).lower()
            path = _literal_at(raw, lineno, _NEST, 3)
            for probe in range(lineno, min(lineno + 6, len(lines)) + 1):
                brace = lines[probe - 1].find("{")
                if brace != -1:
                    start = _decorator_block_start(lines, lineno)
                    found.append(_Route(path, "post" if verb == "all" else verb, path,
                                        lineno, start, _block_end(lines, probe, brace)))
                    break

        if lowered.rsplit("/", 1)[-1].startswith("route."):
            route_m = _NEXT_ROUTE.search(line)
            if route_m:
                brace = line.find("{", route_m.end() - 1)
                start_line, brace_col = lineno, brace
                if brace == -1:
                    for probe in range(lineno + 1, min(lineno + 4, len(lines)) + 1):
                        brace_col = lines[probe - 1].find("{")
                        if brace_col != -1:
                            start_line = probe
                            break
                if brace_col != -1:
                    found.append(_Route(lowered, route_m.group(1).lower(), route_m.group(1),
                                        lineno, lineno,
                                        _block_end(lines, start_line, brace_col)))

        if "/pages/api/" in lowered or "/api/" in lowered:
            pages_m = _NEXT_PAGES.search(line)
            if pages_m:
                brace = line.find("{", pages_m.end() - 1)
                if brace != -1:
                    # Verb unknown — a Pages API handler serves them all. Reported as
                    # state-changing only where the body actually branches on a write method.
                    # Read from the RAW span, not the view: the verb is a string literal, and
                    # `code_view` blanks it, so `req.method === 'DELETE'` arrives as
                    # `req.method === '      '` and every Pages API handler reads as a GET.
                    # Second instance of the same trap as the route path — anything this module
                    # needs *out of* a literal has to come from the source, and only the
                    # decision that a construct is code comes from the view.
                    end = _block_end(lines, lineno, brace)
                    writes = re.search(r"method\s*===?\s*['\"`](POST|PUT|PATCH|DELETE)",
                                       _text(raw, lineno, end), re.I)
                    found.append(_Route(lowered, (writes.group(1).lower() if writes else "get"),
                                        pages_m.group(1) or "handler", lineno, lineno, end))
    return found


def _has_auth(body: str, lines: list[str], functions: dict[str, tuple[int, int]]) -> bool:
    low = body.lower()
    if any(marker in low for marker in _AUTH_MARKERS):
        return True
    if any(re.search(rf"\b{re.escape(word)}\b", low) for word in _REJECTION):
        return True
    return _resolved(body, lines, functions,
                     re.compile("|".join(re.escape(m) for m in _AUTH_MARKERS), re.I))


def _finding(rel: str, line: int, raw: list[str], detector: str, title: str,
             cwe: str, owasp: str, fix: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(detector_id=detector, title=title, severity=severity,
                   confidence=Confidence.MEDIUM, cwe=cwe, owasp=owasp, file=rel, line=line,
                   evidence=_evidence(raw, line), fix=fix,
                   source="structural", verdict=Verdict.UNVERIFIED)


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(JS_EXTS) or not is_production_js(rel):
        return []
    view = code_view(text, rel)
    if view is None:
        return []
    lines = view.splitlines()
    raw = text.splitlines()
    if not lines:
        return []

    functions = _functions(lines)
    routes = _routes(lines, raw, rel)
    if not routes:
        return []

    # A limiter installed on the app at module scope protects handlers that never mention it.
    # Module scope means module scope: a `use` inside a function body is that function's, and
    # the Python rule learned the cost of not making that distinction.
    module_level = "\n".join(
        line for line in lines
        if line[:1] not in (" ", "\t") or re.match(r"\s*(?:import|const|let|var|require)\b", line))
    app_wide_limiter = bool(_LIMITER.search(module_level))

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(finding: Finding) -> None:
        key = (finding.detector_id, finding.line)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for route in routes:
        body = _text(lines, route.start, route.end)
        low = body.lower()
        authed = _has_auth(body, lines, functions)

        # 1. A state-changing endpoint that never establishes who is calling.
        if route.state_changing and not route.public_by_design and not authed:
            add(_finding(
                rel, route.line, raw, "AUTHZ-JS-NOAUTH",
                "Missing authentication on a state-changing endpoint",
                "CWE-306", "A01",
                f"`{route.method.upper()} {route.path}` changes state and nothing in the mount, "
                f"the handler, or any module-local helper it names establishes who the caller "
                f"is — no auth middleware, no `req.user`, no session read, and no 401/403 path. "
                f"Put an authentication middleware on this route (or its router) and authorize "
                f"the action against the caller it produces."))

        # 2. The handler knows its caller and then selects a row by an id the caller chose.
        ids = {m.group(1) for m in _REQUEST_ID_READ.finditer(body)
               if any(h in m.group(1).lower() for h in _ID_HINTS)}
        if authed and ids and _DATA_CALL.search(body) and _ORM_HINT.search(body):
            # The principal has to be absent from the constraint, not merely from the call: an
            # ownership check written as a comparison, or delegated to a helper that receives the
            # principal, is the correct idiom and the largest false-positive shape there is.
            principal = re.search(
                r"(?:req|request|ctx)\s*\.\s*(?:user|auth|session)\b[^\n]{0,120}?"
                r"(?:[=!]==?|\.id\b|\.sub\b|userid|owner|\bwhere\b|,)", body, re.I)
            if not principal:
                add(_finding(
                    rel, route.line, raw, "AUTHZ-JS-IDOR",
                    "Broken access control — object looked up by a caller-supplied id "
                    "without an ownership check",
                    "CWE-284", "A01",
                    f"`{route.method.upper()} {route.path}` establishes the caller and then "
                    f"selects a record by an identifier the caller supplied "
                    f"({', '.join(sorted(ids))}), without the caller taking part in the "
                    f"constraint. Scope the query by the authenticated principal, or compare "
                    f"ownership on the loaded record and reject before returning it."))

        # 3. A credential-testing endpoint that bounds nothing.
        names_auth_action = any(a in f"{route.path} {route.name}".lower() for a in _AUTH_ACTION)
        if names_auth_action and _CREDENTIAL_CHECK.search(body):
            limited = (app_wide_limiter or _LIMITER.search(body)
                       or _ATTEMPT_BOUND.search(body)
                       or _resolved(body, lines, functions, _LIMITER))
            if not limited:
                add(_finding(
                    rel, route.line, raw, "RATELIMIT-JS-AUTH",
                    "Authentication endpoint accepts unlimited attempts (no rate limit)",
                    "CWE-307", "A07",
                    f"`{route.method.upper()} {route.path}` tests a credential and nothing "
                    f"bounds how often it can be tested — no limiter on the route, on the "
                    f"router, or at module scope, and no attempt count compared against a "
                    f"maximum. Add a per-identifier and per-IP limit, and lock or delay after "
                    f"repeated failures.",
                    severity=Severity.MEDIUM))

        # 4. An upload read and written with nothing deciding what it is.
        if _UPLOAD_READ.search(body) and _WRITE.search(body):
            if not (_UPLOAD_VALIDATION.search(body)
                    or _resolved(body, lines, functions, _UPLOAD_VALIDATION)):
                add(_finding(
                    rel, route.line, raw, "UPLOAD-JS-UNRESTRICTED",
                    "Uploaded file is written without deciding what kind of file it is",
                    "CWE-434", "A04",
                    f"`{route.method.upper()} {route.path}` reads an uploaded file and writes "
                    f"it, and nothing between the two narrows what is acceptable — no extension "
                    f"or MIME allowlist, no content sniff, no size bound. Validate against an "
                    f"allowlist AND the sniffed type, cap the size, and store under a name the "
                    f"server generates."))

        # 5. The caller chooses which fields get written.
        if _BODY_WHOLESALE.search(body):
            if not (_ALLOWLIST.search(low) or _resolved(body, lines, functions, _ALLOWLIST)):
                add(_finding(
                    rel, route.line, raw, "MASSASSIGN-JS",
                    "Mass assignment — the caller chooses which fields are written",
                    "CWE-915", "A08",
                    f"`{route.method.upper()} {route.path}` hands the request body straight to a "
                    f"write, so any field the model accepts can be set by the caller — including "
                    f"`role`, `isAdmin`, `balance` or a foreign key. Pick the fields the endpoint "
                    f"means to accept, or validate the body against a schema that rejects "
                    f"unknown keys."))

    return findings


def limitations() -> list[str]:
    return [
        "JavaScript/TypeScript structural analysis recognises a route by a mount carrying a "
        "string literal path (`app.post('/x', ...)`), a NestJS method decorator, or a Next.js "
        "route/Pages-API export. A router assembled dynamically, a path held in a constant, or a "
        "framework not in that list is not recognised, and its handlers are not analysed at all.",
        "It has no parser. The whole mount call is read as the handler, so an inline handler and "
        "its own middleware are not told apart — which can only silence a rule, never fire one — "
        "and evidence is followed only into named functions defined in the same file.",
        "Unlike the Python rules, none of these is measured against an external corpus: RealVuln "
        "v1 is Python-only. What is asserted is that the shapes in the test suite are found and "
        "that the shipped secure fixture stays silent.",
    ]
