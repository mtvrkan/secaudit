"""The same handler questions, asked of JavaScript and TypeScript.

`routes.py` answers them with `ast`. There is no parser here, so this module answers them with
the same brace-aware scanning the JS taint front end uses, and the difference in confidence is
real: what a Python rule *knows* about a handler, this one *recognises*. Every rule below is
therefore written to err toward silence, which is the discipline the Python rules arrived at the
expensive way — most of them report the ABSENCE of something, and a rule that reports an absence
has to be sure of it. Three later ones report a PRESENCE instead — internals in a response body,
a branch decided by a header, two failure messages that differ — and those are held to the
opposite discipline: the evidence has to be on the line, not merely missing from it.

**Why a separate module rather than a second front end under `routes.py`.** The Python rules
are written against `ast` nodes from top to bottom; threading a second node type through
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

from ..langs import JS_EXTS as _JS_ONLY, TS_EXTS as _TS_ONLY
from ..schema import Confidence, Finding, Severity, Verdict
from ..taint.lexical import code_view, split_args
from .routes import _evidence, is_production_source

JS_LANGS: dict[str, dict] = {
    "JavaScript": {"exts": _JS_ONLY,
                   "frontend": "brace-aware route scanner",
                   "resolves": "module-local helper functions and mount middleware",
                   "analyses": ("authorization", "rate limit", "upload", "mass assignment",
                                "response exposure", "client-trusted decision",
                                "account enumeration")},
    "TypeScript": {"exts": _TS_ONLY,
                   "frontend": "brace-aware route scanner",
                   "resolves": "module-local helper functions and mount middleware",
                   "analyses": ("authorization", "rate limit", "upload", "mass assignment",
                                "response exposure", "client-trusted decision",
                                "account enumeration")},
}
JS_EXTS: tuple[str, ...] = tuple(e for spec in JS_LANGS.values() for e in spec["exts"])

# Path shapes that mean a file is not code serving traffic, in the conventions JavaScript uses.
# `routes.is_production_source` covers the language-neutral ones; these are additional, and are
# kept here rather than added there so nothing in this module can change how a `.py` file is
# classified — that classification is inside the measured RealVuln path.
_JS_NON_PRODUCTION = (".test.", ".spec.", ".stories.", ".e2e.", ".cy.", ".mock.", ".d.ts",
                      "/__tests__/", "/__mocks__/", "/cypress/", "/e2e/", "/.next/",
                      "/coverage/", "/storybook/", ".config.",
                      # Ember's HTTP mock server. `mirage/config/posts.js` mounts
                      # `server.post('/posts', …)` with no authentication because it IS the
                      # fake backend a test talks to — 26 findings in one project, every one
                      # of them a report about a fixture.
                      "/mirage/")

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

# Words that open a block and are not a function, for the method-shorthand form below. Without
# this list `if (ok) {` is a function called `if` — which is not merely wrong, it is a *span*, and
# a wrong span is what decides which writes a rule believes are inside which body.
_NOT_A_METHOD = frozenset({
    "if", "for", "while", "switch", "catch", "with", "do", "else", "try", "finally",
    "function", "return", "typeof", "new", "delete", "void", "await", "yield", "in", "of",
    "case", "default", "class", "extends", "import", "export", "constructor",
})

# Named functions whose body can be delimited, so evidence can be followed into a helper.
# Each entry is (pattern, ends_at_arrow): the second says whether the match ends after `=>`
# rather than after the `(` that opens the parameter list, which is what `_body_opens_at` needs
# to know to walk out of the parentheses.
_FUNC_FORMS = (
    # `(?:\*\s*)?` rather than `\*?\s*`: the optional star between two `\s*` is what makes the
    # pair splittable, and this engine's own ReDoS criterion flagged it on the day that criterion
    # landed. Verified to match identically on 7 MB of real JavaScript.
    (re.compile(r"(?:^|[^.\w$])(?:async\s+)?function\s*(?:\*\s*)?([A-Za-z_$][\w$]*)\s*\("), False),
    (re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                r"(?:async\s+)?(?:function\s*(?:\*\s*)?)?\("), False),
    (re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                r"(?:async\s+)?[A-Za-z_$][\w$]*\s*=>"), True),
    # An assignment to a property, and the chains it comes in:
    #     module.exports = function reduceObject(target, source) {
    #     exports.merge = (target, source) => {
    #     const assign = module.exports = (target, ...args) => {
    # Named by the last identifier before the parameter list, or by the property written to.
    # These are how a single-function npm module is written, which is most of this corpus.
    #
    # The leading `NAME =` is optional and appears at most once, rather than repeated. Written
    # first as `(?:[A-Za-z_$][\w$]*\s*=\s*)*` — a quantifier over a group that itself repeats,
    # which is star height two, which is catastrophic backtracking. This repository's own ReDoS
    # analysis reported it in the dogfood gate within minutes of it being written, at High, on
    # the same day the analysis learned to read the shape. Kept as a comment because a rule
    # catching its author is the only evidence that a rule works.
    (re.compile(r"(?:^|[^.\w$])(?:[A-Za-z_$][\w$]*\s*=\s*)?"
                r"(?:[A-Za-z_$][\w$]*\.){1,4}([A-Za-z_$][\w$]*)\s*=\s*"
                r"(?:async\s+)?function[\s*]*(?:[A-Za-z_$][\w$]*)?\s*\("), False),
    (re.compile(r"(?:^|[^.\w$])(?:[A-Za-z_$][\w$]*\s*=\s*)?"
                r"(?:[A-Za-z_$][\w$]*\.){1,4}([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\("), False),
    # A method in an object literal or a class body — `merge: function (a, b) {`, `set(o, k) {`.
    # The shorthand shares its shape with `if (…) {`, so the name is filtered by `_NOT_A_METHOD`;
    # getting that wrong would not just add a function, it would give every rule a body span that
    # belongs to a control-flow block.
    (re.compile(r"(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?function[\s*]*\("), False),
    (re.compile(r"^\s*(?:static\s+)?(?:async\s+)?(?:\*\s*)?([A-Za-z_$][\w$]*)\s*\("), False),
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

# The naming convention the list above cannot enumerate: a project's own auth middleware, named
# for what it guards. `mw.authAdminApi`, `authUser`, `requireAuth`, `adminAuth`, `authMiddleware`
# — 220 occurrences of one such name in Ghost alone, and every route carrying it was reported as
# unauthenticated until this existed. Found the day the noise floor grew a real Express
# application; before that the corpus held an HTTP framework, an HTTP client, a date library and
# a promise library, none of which mounts a route, so the rule had never met its subject.
#
# Matched on the RAW casing, and that is the precision: `auth` followed by a capital is a
# camelCase compound about authentication, while `author`, `authoring` and `authority` continue
# in lower case and do not match. `authUrl` and `authConfig` do match and are not middleware —
# accepted deliberately, because this rule reports the ABSENCE of a control and the package's
# rule for that is to read evidence generously. A handler that mentions an auth anything is not
# a handler nobody thought about.
_AUTH_NAMING = re.compile(r"\bauth[A-Z]\w*|\b\w+Auth\b|\bAuth\w*(?:Middleware|Guard)\b")

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


# ---- The three questions the Python side answered and this one did not ----------------------
#
# `structural/` decides eleven questions about a handler and six of them had a Python front end
# and no JavaScript one, which is the same asymmetry `langs.py` exists to end one level down.
# Three land here; the other three are in ROADMAP.md with the reason they are harder, and the
# split is by *shape* rather than by importance: these three are decided by what a handler
# returns and what it compares, which a brace-scanner can read.
#
# **None of this is measured against an external corpus, and unlike the four rules above that is
# not merely a bound — it is the reason to distrust these three more.** RealVuln is Python;
# SecBench.js has five classes and none is one of these; and CVEfixes' JavaScript labels for
# CWE-209 and CWE-400 are deleted `import` lines and `package.json` version fields, which is a
# label set that cannot tell a rule from a coin flip. So what is asserted here is exactly what
# `limitations()` says: the shapes in the test suite are found, the secure fixture stays silent,
# and the noise floor says what they cost on 1.37M lines of maintained code. Nothing more.

# What a response body says about the server. `err.stack` is the whole of CWE-209 in Express,
# and `process.env` in a payload is CWE-215 — a diagnostics endpoint answering everyone.
_INTERNALS_IN_RESPONSE = re.compile(
    r"(?:res|reply|ctx|response)\s*\.\s*(?:json|send|status\s*\([^)]*\)\s*\.\s*(?:json|send))"
    r"\s*\([^;\n]{0,300}?"
    r"(?:\b(?:err|error|e|exc|ex)\s*\.\s*(?:stack|message|sqlMessage|sql|code|errno|detail)"
    r"|\bprocess\s*\.\s*env\b|\b__dirname\b|\b__filename\b|\bprocess\s*\.\s*(?:cwd|version)\b)",
    re.I)
# `throw` and `next(err)` hand the object to a framework error handler, which is where the
# decision about what a client sees belongs. Only a body this handler builds itself is reported.
_ERROR_HANDLED_ELSEWHERE = re.compile(r"\bnext\s*\(\s*(?:err|error|e)\b", re.I)

# A decision made from something the caller sends. The header list is what makes this decidable:
# comparing `content-type` to a constant is correct code, and comparing `x-user-role` to
# `'admin'` is an access control decision made by the attacker.
_CLIENT_DECISION = re.compile(
    r"\bif\s*\([^)\n]{0,200}?(?:req|request|ctx)\s*\.\s*(?:headers|cookies|query)\s*"
    r"(?:\.\s*([\w$-]+)|\[\s*['\"]([^'\"]+)['\"]\s*\])[^)\n]{0,120}?[=!]==?", re.I)
_TRANSPORT_HEADERS = (
    "content-type", "contenttype", "accept", "accept-encoding", "accept-language", "user-agent",
    "useragent", "x-requested-with", "referer", "referrer", "origin", "host", "connection",
    "cache-control", "if-none-match", "if-modified-since", "range", "content-length", "upgrade",
    "sec-fetch", "dnt", "te", "expect", "authorization", "cookie",
)
# Evidence the value was authenticated before it was believed. `authorization` is in the list
# above for the same reason: a bearer token compared after `jwt.verify` is the correct idiom.
_VERIFIED = re.compile(r"\b(?:verify|jwt|jsonwebtoken|hmac|createhmac|timingsafeequal|unsign|"
                       r"signed|decodetoken|validatetoken|passport)\b", re.I)

# Two failure messages in one credential flow that name different halves of the credential.
_IDENTITY_NOUN = ("user", "username", "email", "e-mail", "account", "handle", "login", "member")
_CREDENTIAL_NOUN = ("password", "passcode", "passphrase", "pin", "otp", "credential", "secret",
                    "one-time", "security code")
_ABSENCE = ("not exist", "doesn't exist", "does not exist", "unknown", "no such", "not found",
            "no account", "not registered", "unregistered", "not recognised", "not recognized")
_INVALIDITY = ("incorrect", "invalid", "wrong", "mismatch", "does not match", "not match",
               "failed", "denied")
_MESSAGE_LITERAL = re.compile(r"['\"`]([^'\"`\n]{6,120})['\"`]")


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


def _body_opens_at(lines: list[str], lineno: int, col: int,
                   inside_parens: bool) -> tuple[int, int] | None:
    """Where the `{` that opens this function's body is, or None if there isn't one.

    Two things this replaces a `line.find("{")` with, both of which were losing whole functions:

    * **The parameter list can contain braces.** `function unflatten(obj = {}) {` — the first `{`
      on the line is the default value, and a block that opens and closes inside the parentheses
      makes the function one line long. Every rule then reads an empty body and reports nothing.
    * **The brace does not have to be on the same line.** `function reduceObject(a, b)` with the
      brace on the next line is ordinary formatting, and a TypeScript return type
      (`function f(x): Promise<void> {`) pushes it further along.

    So: walk out of the parameter list by counting parentheses, then take the first `{`. A `;`
    at depth zero means there is no body — a TypeScript overload signature or an interface
    member — and gets None rather than the next function's brace. Three lines of lookahead,
    because beyond that the thing being read is no longer a header.
    """
    depth = 1 if inside_parens else 0
    for offset in range(4):
        if lineno + offset > len(lines):
            return None
        text = lines[lineno + offset - 1]
        for index in range(col if offset == 0 else 0, len(text)):
            ch = text[index]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth <= 0:
                if ch == "{":
                    return lineno + offset, index
                if ch == ";":
                    return None
    return None


def _functions(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Module-local named functions, by name, as (first line, last line).

    Used to follow evidence into a helper: an app that factors `requireAuth` or `validateUpload`
    out is the app these rules must not report, and a rule that reads only the mount would report
    exactly those. Every structural analysis on JavaScript is scoped by this — a function it
    cannot delimit is a function none of them look inside — which is why the shapes it misses are
    worth more than any single rule. Measured on SecBench.js's prototype-pollution class,
    **35 of 113 labelled misses were sinks in a function this could not see**, across four shapes
    that are all ordinary JavaScript: a default parameter value, a brace on the next line, an
    export assignment (`module.exports = function name(…)`), and a method in an object literal or
    a class.
    """
    out: dict[str, tuple[int, int]] = {}
    for lineno, line in enumerate(lines, start=1):
        for pattern, arrow in _FUNC_FORMS:
            m = pattern.search(line)
            if not m:
                continue
            name = next((g for g in m.groups() if g), "")
            if not name or name in _NOT_A_METHOD:
                continue
            opened = _body_opens_at(lines, lineno, m.end(), not arrow)
            if opened is None:
                continue
            brace_line, brace_col = opened
            out.setdefault(name, (lineno, _block_end(lines, brace_line, brace_col)))
            break
    return out


def _text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])


def _resolved(body: str, lines: list[str], functions: dict[str, tuple[int, int]],
              pattern: re.Pattern[str]) -> bool:
    """Whether `pattern` matches the handler, or anything module-local it names.

    Bare references are followed, not only calls: `app.post('/x', requireAuth, handler)` never
    calls `requireAuth`, and `@UseGuards(AuthGuard)` never calls the guard either. Following only
    call sites would report every route in both idioms.

    A helper is marked visited **globally, not per path**. The question this answers is
    reachability — does anything this handler can reach match the pattern — and a second arrival
    at a helper already visited cannot change that answer. Carrying the visited set down each
    branch instead, which is what this did, enumerates every distinct path through the call graph,
    and that is exponential in a file whose helpers reference each other freely. It was not a
    theoretical cost: on `materialize.js` (366 KB, 10k lines) the analysis ran in 0.12s over the
    first 6,750 lines and had not finished ten minutes later over the first 7,000, so a Tier-0
    scan of any repository vendoring a bundle that size hung instead of completing. Iterative
    rather than recursive for the same reason — the node-visiting form is bounded by the number
    of helpers, which is exactly the depth that would overflow the stack.
    """
    if pattern.search(body):
        return True
    seen: set[str] = set()
    pending = [body]
    while pending:
        for name in set(_IDENT.findall(pending.pop())):
            span = functions.get(name)
            if span is None or name in seen:
                continue
            seen.add(name)
            text = _text(lines, *span)
            if pattern.search(text):
                return True
            pending.append(text)
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


# A call whose RESULT is used is not a route registration. `app.post('/x', handler)` is a
# statement and its return value is discarded; `await api.post('/x', body)` is an expression whose
# value is the response. These are the contexts that consume a value.
_CONSUMING_WORDS = frozenset({"await", "return", "yield", "typeof", "void"})
_CONSUMING_CHARS = "=(,[?:&|+>"


def _value_is_consumed(lines: list[str], lineno: int, start: int, end: int) -> bool:
    """Whether this call's value is used, which is what separates a client call from a mount.

    `_MOUNT` looks for a receiver, an HTTP verb and a string-literal path, and a browser's HTTP
    client is written exactly that way: `api.post('/tickets', body)` is indistinguishable from
    `app.post('/tickets', handler)` by shape alone. It cost 147 false positives and zero true
    positives on RealVuln — every one of them in a React `frontend/src/` tree, where the rule
    reported the *caller* of an endpoint for not authenticating it.

    The distinction that is actually about the bug is what happens to the return value. Express,
    Fastify, Koa and Hono all discard it; a client call's value is the response, so it is
    awaited, returned, assigned, collected into an array, or chained. Deliberately not a list of
    client library names — `axios` and `api` were the two receivers in the corpus, and a rule
    that names them is one rename away from silence.
    """
    before = lines[lineno - 1][:start].rstrip()
    if not before:
        # The call opens the line, so the expression it belongs to — if any — ends the previous
        # one. `export const createReply = (id, data) =>\n  api.post(...)` is the same client
        # call as the single-line form and has to read the same way; a mount never continues a
        # dangling operator, because there is nothing for it to continue.
        probe = lineno - 1
        while probe > 0 and not lines[probe - 1].strip():
            probe -= 1
        before = lines[probe - 1].rstrip() if probe > 0 else ""
    if before:
        word = re.search(r"[A-Za-z_$][\w$]*$", before)
        if word and word.group(0) in _CONSUMING_WORDS:
            return True
        if before[-1] in _CONSUMING_CHARS:
            return True
    tail = lines[end - 1].rstrip()
    return tail.endswith((",", "]")) or ").then(" in tail or ").catch(" in tail


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
            if _value_is_consumed(lines, lineno, m.start(), end):
                continue
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
    if _AUTH_NAMING.search(body):
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

        # 6. The response describes the server.
        if _INTERNALS_IN_RESPONSE.search(body) and not _ERROR_HANDLED_ELSEWHERE.search(body):
            add(_finding(
                rel, route.line, raw, "EXPOSE-JS-INTERNALS",
                "Response body carries server internals",
                "CWE-209", "A09",
                f"`{route.method.upper()} {route.path}` builds a response body out of something "
                f"that describes the server — a stack trace, a driver's error text, an "
                f"environment value or a deployment path. That is the reconnaissance an attacker "
                f"would otherwise have to guess at: table columns, file paths, library versions, "
                f"sometimes the failing query with its values still in it. Return a message and "
                f"a correlation id, and log the detail server-side.",
                severity=Severity.MEDIUM))

        # 7. A branch decided by something the caller sent. Read from the RAW text, not the
        # blanked view: `req.headers['x-user-role']` names the header inside a string literal,
        # and `code_view` blanks literal contents — so on the view every header is the same
        # header and the transport-header exemption below could never fire. Found by the
        # fixture that asserts content negotiation is ordinary code, which is what that fixture
        # is for.
        for match in _CLIENT_DECISION.finditer(_text(raw, route.start, route.end)):
            header = (match.group(1) or match.group(2) or "").lower()
            if any(h in header for h in _TRANSPORT_HEADERS) or _VERIFIED.search(body):
                continue
            add(_finding(
                rel, route.line, raw, "TRUST-JS-CLIENT-DECISION",
                "Access decision made from a value the caller sends",
                "CWE-807", "A01",
                f"`{route.method.upper()} {route.path}` branches on `{header}`, which the caller "
                f"chooses and can set to anything. Nothing in the handler verifies it — no "
                f"signature check, no token decode, no session lookup — so the check is a "
                f"suggestion the client is free to ignore. Decide from the authenticated "
                f"principal, or verify the value cryptographically before believing it.",
                severity=Severity.HIGH))

        # 8. A failure message that says which half of the credential was wrong.
        if any(a in f"{route.path} {route.name}".lower() for a in _AUTH_ACTION):
            absence = invalidity = ""
            for message in _MESSAGE_LITERAL.finditer(_text(raw, route.start, route.end)):
                text_low = message.group(1).lower()
                names_identity = any(n in text_low for n in _IDENTITY_NOUN)
                names_credential = any(n in text_low for n in _CREDENTIAL_NOUN)
                if names_identity and any(a in text_low for a in _ABSENCE):
                    absence = message.group(1)
                elif names_credential and any(i in text_low for i in _INVALIDITY):
                    invalidity = message.group(1)
            if absence and invalidity:
                add(_finding(
                    rel, route.line, raw, "ENUM-JS-CREDENTIAL",
                    "Failure message says which half of the credential was wrong",
                    "CWE-204", "A07",
                    f"`{route.method.upper()} {route.path}` answers a missing account and a "
                    f"wrong password differently — \"{absence}\" against \"{invalidity}\" — so "
                    f"the form becomes a query interface for whether an address is registered. "
                    f"That is the reconnaissance step before credential stuffing and the whole "
                    f"attack against a password reset. Return one message and one status for "
                    f"both, and keep the difference in the log.",
                    severity=Severity.MEDIUM))

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
        "The response-exposure, client-trusted-decision and account-enumeration rules were added "
        "with that bound measured rather than assumed: across four corpora they moved no figure "
        "at all. They fire — 15 findings on CVEfixes, none of which landed on a labelled hunk — "
        "and they are silent across 1,372,511 lines of maintained code, which holds no Express "
        "application for them to read. Treat them as unmeasured in the strongest sense: nothing "
        "outside this repository's own fixtures has ever agreed or disagreed with them.",
    ]
