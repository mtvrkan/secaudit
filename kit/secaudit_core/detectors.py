"""Built-in deterministic detector pack (Tier 0, zero external dependencies).

Each detector is a regex sink-matcher with an optional `suppress_if` control-marker: if the
control regex is present in the same file, the finding is cleared (the safe pattern is in
place). This is a small, honest subset of what a full SAST engine (semgrep) does — the kit
uses installed scanners when present (see engine.py) and falls back to this pack when not, so
it always produces a report.

HIGH-confidence detectors match unambiguous sinks and should never fire on correct code —
they are what the precision measurement checks. MEDIUM detectors are leads that want triage;
that triage is exactly what the optional LLM tier adds. `maps_to` ties a detector to a golden
-set id (V1–V20) for the eval harness only; it has no runtime effect.

Honest bound: regex detectors are crude. On the shipped fixtures (which they were tuned
against) recall/precision are high; on arbitrary real code both are lower. This tier is the
reproducible floor, not a guarantee — the LLM tier and real scanners raise the ceiling.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .langs import JSTS_EXTS, PHP_EXTS, TEMPLATE_EXTS
from .schema import Severity, Confidence


@dataclass(frozen=True)
class Detector:
    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    confidence: Confidence
    exts: tuple[str, ...]          # file extensions, or ("Dockerfile",) for the special name
    pattern: str
    fix: str
    maps_to: str = ""
    suppress_if: str = ""          # if this regex is found in the file, clear the finding
    suppress_line_if: str = ""     # if this regex is found on the MATCHED LINE, drop that match
                                   # and keep the rest. The file-scoped `suppress_if` above is
                                   # the pack's blunt instrument, and its bluntness is measured:
                                   # for `SEC-JS-HTML-CONCAT` an escaper on the same line as the
                                   # concatenation genuinely answers the question, and
                                   # suppressing on it costs **3 labelled files at line scope
                                   # against 27 at file scope** — because a module that escapes
                                   # four values and forgets the fifth is the shape the bug comes
                                   # in, not an exotic case. That rule therefore shipped with no
                                   # suppressor at all, and the noise floor said what that cost
                                   # as soon as it grew a project that builds DOM: 260 findings
                                   # in one checkout. A per-line scope is the thing that was
                                   # missing, so it is a field rather than a regex trick inside
                                   # one pattern.
    requires_in_file: str = ""     # if this regex is NOT found in the file, clear the finding —
                                   # a file-level precondition, the mirror of `suppress_if`.
                                   # `suppress_if` says "a control is present, so this is fixed";
                                   # this says "this is not the kind of file the rule is about".
                                   # The case it exists for: `hostPath:` inside this repository's
                                   # own exported Semgrep pack is a quoted pattern in a rule
                                   # definition, not a volume mount in a manifest — and the
                                   # `literal=False` view cannot decide that, because YAML has no
                                   # lexical shape this engine models (blanking its scalars would
                                   # also blank the VALUE half of `privileged: true`). A rule that
                                   # only makes sense inside one file format should say so.
    once_per_file: bool = False    # report the first match only.
                                   # For a rule whose subject is the FILE rather than the line:
                                   # a settings module missing `SESSION_COOKIE_SECURE` is one
                                   # omission with one fix, and the pattern that finds it matches
                                   # every cookie line the module *did* harden — so the default
                                   # per-match behaviour reports the same problem three times.
                                   # Measured cost of not having this: on the external corpus the
                                   # settings rule emitted 45 findings for 19 labels, and the
                                   # benchmark's scorer counts a second finding on an
                                   # already-matched label as a false positive, exactly as a
                                   # reader would.
    about_committed_text: bool = False
                                   # Does this rule describe TEXT that is present in the file, or
                                   # BEHAVIOUR the shipped application performs? The two answer
                                   # differently in a test, a fixture, a migration or a seed
                                   # script, and getting them confused is where a large share of
                                   # this pack's false positives lived.
                                   #
                                   # Behaviour (the default): a test that calls `os.remove` on its
                                   # own temp file, disables TLS verification against a local stub,
                                   # or hashes with MD5 to check a fixture is not the application
                                   # doing any of those things. `structural/routes.py` wrote this
                                   # reasoning down for its own rules from the start — "every rule
                                   # in this package describes something a *deployed handler*
                                   # fails to do" — and it is just as true here. Measured across
                                   # 62 external repositories: **0 true positives and 22 false
                                   # ones** sat in non-production paths.
                                   #
                                   # Committed text (`True`): a credential is in the repository
                                   # whatever directory it is in. `git log` does not care that the
                                   # file was a test, and neither does anyone who clones it. So
                                   # every shape-based secret rule sets this and keeps scanning
                                   # everything — which is the case the older, coarser version of
                                   # this decision existed to protect, and it survives intact.
                                   #
                                   # `SEC-SECRET-GENERIC` is the deliberate exception among the
                                   # secret rules: it guesses from a *keyword* rather than from a
                                   # credential's shape, and scored **0 TP / 104 FP** in test
                                   # paths. It is behaviour-scoped for that reason, stated here
                                   # rather than left to be rediscovered.
    superseded_by: tuple[str, ...] = ()
                                   # Detector ids that say the same thing about the same line
                                   # more precisely. When one of them also fired there, this
                                   # finding is dropped.
                                   #
                                   # The pack had no way to express this and it showed: widening
                                   # `SEC-SECRET-GENERIC` to accept a suffixed name
                                   # (`ACCESS_TOKEN_SALT`) also made it match the name
                                   # `SEC-PY-SECRET-KEY-LITERAL` already owns, so every
                                   # `SECRET_KEY = "<literal>"` in a `.py` file produced two
                                   # findings — measured on the noise floor as 10 of the 12 lines
                                   # that widening added. The cross-tool dedupe in
                                   # `engine._dedupe` could not collapse them because it groups
                                   # by CWE and the two rules carry different ones (CWE-798 and
                                   # CWE-321), which is correct: they ARE different classes. This
                                   # says something the CWE cannot — that one rule is the other's
                                   # coarse approximation.
    mask: bool = False             # redact the evidence line (secret detectors never print values)
    case_sensitive: bool = False   # token-shape secrets (AKIA…, ghp_…) encode a fixed case — a
                                   # case-insensitive match would widen them into false positives
    literal: bool = True           # does this pattern legitimately match INSIDE a string literal
                                   # or comment? Secrets, SQL fragments and quoted header names
                                   # do; a code-shape rule like `eval(` does not, and matching
                                   # one inside a literal is a false positive — `"eval": Sink(…)`
                                   # in a rule catalog is not a call to eval. Detectors marked
                                   # False are scanned against `taint.code_view`, which blanks
                                   # comments and literal contents while preserving offsets.
                                   # Defaults to True so a new detector is never silently
                                   # narrowed; opt into the stricter view deliberately.

    def regex(self) -> re.Pattern:
        flags = re.M if self.case_sensitive else re.I | re.M
        return re.compile(self.pattern, flags)

    def suppressor(self) -> re.Pattern | None:
        return re.compile(self.suppress_if, re.I | re.M) if self.suppress_if else None

    def line_suppressor(self) -> re.Pattern | None:
        return re.compile(self.suppress_line_if, re.I) if self.suppress_line_if else None

    def precondition(self) -> re.Pattern | None:
        return re.compile(self.requires_in_file, re.I | re.M) if self.requires_in_file else None


S, C = Severity, Confidence

# Secret patterns are language-agnostic — scan every text-ish source file plus Dockerfiles.
_SECRET_EXTS = (*JSTS_EXTS, ".py", ".go", ".rb", *PHP_EXTS, ".java", ".cs", ".json",
                ".yaml", ".yml", ".env", ".txt", ".tf", "Dockerfile")

# "This YAML declares a workload." The three top-level keys that separate a manifest from every
# other thing shipped as `.yaml`: `apiVersion`/`kind` for Kubernetes, Helm and Kustomize,
# `services` for Compose. Anchored to the start of a line so the word inside a quoted scalar —
# which is exactly how it appears in a SAST rule pack — does not satisfy it.
_MANIFEST = r"^\s*(?:apiVersion|kind|services)\s*:"

DETECTORS: list[Detector] = [
    # ---- JavaScript / TypeScript ----
    Detector("SEC-JS-SQLI", "SQL injection via string concatenation", "CWE-89", "A03",
             S.CRITICAL, C.HIGH, JSTS_EXTS,
             # Require an actual SQL statement shape (SELECT…FROM / UPDATE…SET / DELETE FROM /
             # INSERT INTO) followed by string concatenation — so the ordinary method name
             # `.update(...)` does not read as the SQL keyword UPDATE.
             r"(?:SELECT\b[^;\n]*\bFROM\b|INSERT\s+INTO\b|UPDATE\b[^;\n]*\bSET\b|DELETE\s+FROM\b)"
             r"[^;\n]*['\"]\s*\+",
             "Use parameterized queries / prepared statements; never concatenate input into SQL.",
             maps_to="V1"),
    Detector("SEC-JS-CMDI", "OS command injection (exec with concatenated input)", "CWE-78", "A03",
             S.CRITICAL, C.HIGH, JSTS_EXTS,
             r"\bexec\b\s*\(\s*['\"][^)]*\+",
             "Use execFile/spawn with an argument array (no shell) and validate input.",
             maps_to="V2"),
    Detector("SEC-JS-MD5", "Weak password hashing (MD5)", "CWE-327", "A02",
             S.HIGH, C.HIGH, JSTS_EXTS,
             r"createHash\(\s*['\"]md5['\"]",
             "Use a memory-hard KDF (argon2id / bcrypt / scrypt) with a per-password salt.",
             maps_to="V4"),
    Detector("SEC-SECRET-AWS", "Hardcoded AWS access key id", "CWE-798", "A07",
             S.HIGH, C.HIGH, (*JSTS_EXTS, ".py", ".json", ".env", ".txt", "Dockerfile"),
             r"AKIA[0-9A-Z]{16}",
             "Remove the secret from source, rotate it, and load from a secret manager / env.",
             maps_to="V5", mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-JS-CORS", "Permissive CORS reflecting Origin", "CWE-942", "A05",
             S.MEDIUM, C.HIGH, JSTS_EXTS,
             r"Access-Control-Allow-Origin['\"]?\s*,\s*req\.headers\.origin",
             "Reflect only an explicit origin allowlist; never echo the request Origin with credentials.",
             maps_to="V6"),
    Detector("SEC-JS-SSRF", "Possible SSRF (server fetch of user-supplied URL)", "CWE-918", "A10",
             S.HIGH, C.MEDIUM, JSTS_EXTS,
             r"\.get\(\s*req\.(?:query|params|body)",
             "Allowlist the destination host and block private / link-local ranges.",
             maps_to="V7"),
    Detector("SEC-JS-XSS", "Improper output handling → XSS (unsanitized markdown to innerHTML)",
             "CWE-79", "A03", S.HIGH, C.HIGH, JSTS_EXTS,
             r"innerHTML\s*=\s*marked\.parse",
             "Sanitize rendered HTML with DOMPurify before assignment (or use textContent).",
             maps_to="V8"),
    Detector("SEC-JS-JWT-NONE", "Broken JWT verification (alg:none accepted)", "CWE-347", "A07",
             S.HIGH, C.HIGH, JSTS_EXTS,
             r"alg\s*===?\s*['\"]none['\"]",
             "Pin the algorithm server-side, verify the signature, and check exp/aud.",
             maps_to="V10"),
    Detector("SEC-JS-OPENREDIR", "Open redirect (user-controlled Location)", "CWE-601", "A01",
             S.MEDIUM, C.HIGH, JSTS_EXTS,
             r"Location['\"]?\s*:\s*req\.query",
             "Redirect only to an allowlist of relative paths.",
             maps_to="V11"),
    Detector("SEC-JS-PATHTRAV", "Path traversal (user input in filesystem path)", "CWE-22", "A01",
             S.HIGH, C.MEDIUM, JSTS_EXTS,
             r"path\.(?:join|resolve)\([^)]*req\.(?:query|params|body)",
             "Resolve then verify the result stays within an allowed base directory.",
             maps_to="V12", suppress_if=r"\.startsWith\(\s*\w*(?:ROOT|BASE|DIR)"),
    Detector("SEC-JS-MASSASSIGN", "Mass assignment (whole request body copied to model)",
             "CWE-915", "A08", S.HIGH, C.HIGH, JSTS_EXTS,
             r"Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)",
             "Copy only an explicit field allowlist; never bind the raw body.",
             maps_to="V13"),
    # SEC-JS-PROTO was here and is deliberately gone, not renamed. It matched `for (… in …)` —
    # the most ordinary loop in the language — and on 594 real npm packages that produced 950
    # findings and 9 of the 185 labelled prototype-pollution bugs, the worst ratio anything in
    # this pack has ever measured. The defect is not the loop, it is the write inside it, and a
    # write is decided by facts about the whole function: where the key came from, and whether
    # anything refuses `__proto__`. That is `structural/protopollution.py`, and its detector id
    # is `PROTO-JS-WRITE`. `maps_to="V14"` moved with it.
    Detector("SEC-JS-EVAL", "Insecure deserialization / code injection (eval)", "CWE-95", "A03",
             S.CRITICAL, C.HIGH, JSTS_EXTS,
             r"\beval\s*\(",
             "Never eval untrusted input; parse data with JSON.parse.",
             maps_to="V15"),
    Detector("SEC-JS-SSTI", "Server-side template injection (dynamic Function)", "CWE-94", "A03",
             S.HIGH, C.HIGH, JSTS_EXTS,
             r"new\s+Function\s*\(",
             "Pass user data as template context; never compile it as code.",
             maps_to="V16"),
    # ---- Python ----
    Detector("SEC-PY-XXE", "XXE (XML external entity resolution enabled)", "CWE-611", "A05",
             S.HIGH, C.HIGH, (".py",),
             r"resolve_entities\s*=\s*True",
             "Disable entities/DTD/network (defusedxml or resolve_entities=False).",
             maps_to="V17"),
    # `verify=False` is the requests spelling and was the only one here. The standard library
    # has three more, and 29 of the external corpus's misses are one of them — an unverified
    # SSL context handed to urlopen. Same bug, same CWE, same fix, so it widens the rule rather
    # than adding an id: a reader who greps for "TLS verification" should find one answer.
    Detector("SEC-PY-TLS", "Disabled TLS certificate verification", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".py",),
             r"verify\s*=\s*False"
             r"|ssl\._create_unverified_context\s*\("
             r"|_create_default_https_context\s*=\s*ssl\._create_unverified_context"
             r"|verify_mode\s*=\s*(?:ssl\.)?CERT_NONE"
             r"|check_hostname\s*=\s*False",
             "Keep certificate verification on; trust the proper CA bundle.",
             maps_to="V18"),
    Detector("SEC-PY-CMDI", "OS command injection (subprocess shell=True)", "CWE-78", "A03",
             S.HIGH, C.HIGH, (".py",),
             r"subprocess\.\w+\([^)]*shell\s*=\s*True",
             "Use an argument list without shell=True and validate input.",
             maps_to="V19"),
    Detector("SEC-PY-PICKLE", "Insecure deserialization (pickle.loads on untrusted data)",
             "CWE-502", "A08", S.CRITICAL, C.HIGH, (".py",),
             r"pickle\.loads\s*\(",
             "Use a safe format (JSON with a schema); never unpickle untrusted bytes.",
             maps_to="V20"),
    # ---- Container / IaC ----
    Detector("SEC-DOCKER-LATEST", "Unpinned base image (:latest)", "CWE-1104", "A06",
             S.MEDIUM, C.HIGH, ("Dockerfile",),
             r"^FROM\s+\S+:latest\b",
             "Pin the base image by version and ideally by @sha256 digest.",
             maps_to="V9"),
    Detector("SEC-DOCKER-ENVSECRET", "Secret baked into image ENV", "CWE-798", "A05",
             S.HIGH, C.HIGH, ("Dockerfile",),
             r"^ENV\s+\w*(?:TOKEN|SECRET|KEY|PASSWORD)\w*\s*=",
             "Inject secrets at runtime (--env / mounted file); never bake them into the image.",
             maps_to="V9", mask=True),
    # The same bug one file over. `ENV` in a Dockerfile had a rule from the beginning; the Compose
    # `environment:` list, which is where the value usually actually lives, had none — and a
    # committed compose file is as public as a committed Dockerfile. `(?!\$)` keeps the correct
    # form out: `- SECRET_KEY=${SECRET_KEY}` is an interpolation, which is the fix, not the bug.
    Detector("SEC-COMPOSE-ENVSECRET", "Secret written into a Compose environment entry",
             "CWE-798", "A05", S.HIGH, C.HIGH, (".yml", ".yaml"),
             r"^\s*-\s*\w*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)\w*\s*=\s*"
             r"(?![\s$])(?![^\n]*<[^\n]*>)\S+",
             "Reference the value instead of writing it: `- SECRET_KEY=${SECRET_KEY}` with the "
             "real value in an untracked `.env`, or a secrets mount.",
             mask=True, about_committed_text=True),

    # ---- Secret patterns (multi-file) ----
    Detector("SEC-SECRET-GH", "Hardcoded GitHub token", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
             "Revoke the token, rotate it, and load from a secret manager.", mask=True,
             case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-SLACK", "Hardcoded Slack token", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
             "Revoke the token and move it to a secret manager.",
             mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-OPENAI", "Hardcoded OpenAI-style API key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bsk-[A-Za-z0-9]{32,}\b",
             "Revoke the key, rotate it, and load from the environment / a secret manager.",
             mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-PRIVKEY", "Private key committed to source", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
             "Remove the key from source, rotate it, and purge it from git history.",
             mask=True, about_committed_text=True),
    Detector("SEC-SECRET-GENERIC", "Possible hardcoded credential", "CWE-798", "A07", S.MEDIUM, C.MEDIUM,
             _SECRET_EXTS,
             # The value must not be a placeholder. An interpolation (`'{password}'`,
             # `"${pw}"`), a format slot (`"%s"`) or an angle-bracket stand-in (`"<your-key>"`)
             # is a shape that says "a secret goes here", which is the opposite of a secret
             # being here — the clearest instance being an f-string SQL query that merely
             # contains the word.
             #
             # `\w*` after the keyword is what lets `ACCESS_TOKEN_SALT = "..."` match. The rule
             # used to require the keyword to sit immediately against the `=`, so every
             # credential whose name carried a suffix — the salt, the seed, the pepper, the
             # `_v2` — read as a different word and went unreported. The bytes/raw prefix is the
             # same omission one level down: `SECRET = b"..."` is a credential and `b` is not
             # part of the value.
             r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)\w*\s*[:=]\s*"
             r"(?:[bBrRuU]{1,2})?"
             r"['\"](?![^'\"\n]*[{}$])(?![^'\"\n]*%[sd])(?![^'\"\n]*<[^'\"\n]*>)"
             r"[^'\"\n]{8,}['\"]",
             "If real, rotate it and load from env / a secret manager (ignore obvious placeholders).",
             mask=True,
             # The keyword rule is the coarse approximation of every rule that knows the shape
             # of the credential it is looking at. Where one of those fired on the same line,
             # this one adds a second report of the same fact — measured, not assumed: 10 of the
             # 12 noise-floor lines the keyword widening added were already reported by the
             # signing-key rule.
             superseded_by=("SEC-PY-SECRET-KEY-LITERAL", "SEC-PY-SECRET-KEY-FALLBACK",
                            "SEC-SECRET-JWT", "SEC-SECRET-AWS", "SEC-SECRET-GOOGLE",
                            "SEC-SECRET-STRIPE", "SEC-SECRET-SLACK", "SEC-SECRET-GITHUB",
                            "SEC-SECRET-PRIVATE-KEY", "SEC-SECRET-DB-URL")),

    # ---- JavaScript / TypeScript (extra) ----
    Detector("SEC-JS-SHA1", "Weak hash (SHA-1)", "CWE-327", "A02", S.MEDIUM, C.MEDIUM, JSTS_EXTS,
             r"createHash\(\s*['\"]sha1['\"]", "Use SHA-256+ (or a KDF for passwords)."),
    Detector("SEC-JS-RANDOM", "Insecure randomness for security value", "CWE-338", "A02",
             S.MEDIUM, C.MEDIUM, JSTS_EXTS, r"Math\.random\s*\(",
             "Use crypto.randomBytes / crypto.getRandomValues for tokens, ids, salts."),

    # ---- Python (extra) ----
    # JavaScript, PHP, Java and C# each had a SQL-concatenation rule from the beginning. Python
    # — the one language the published external number is measured on — had none, and relied
    # entirely on the taint tier, which needs a path rooted in `request.*`. Most of the missed
    # labels are a handler that takes the value as an ordinary function parameter and builds the
    # statement from it, so there is no request root to find and the whole class went unreported
    # by both tiers at once.
    Detector("SEC-PY-SQLI-CONCAT", "SQL built by string concatenation or interpolation",
             "CWE-89", "A03", S.HIGH, C.MEDIUM, (".py",),
             # The statement shape comes first, exactly as in the JavaScript rule: without it,
             # `.update(` and the word `set` make every ORM call a SQL statement. Then one of the
             # four ways Python builds a string.
             #
             # The `%` branch carries the distinction the whole rule turns on. `execute("… WHERE
             # id = %s", (uid,))` is a **bind placeholder** and is the correct, safe form;
             # `execute("… WHERE id = %s" % uid)` is injection. They differ only in whether the
             # `%` is an operator applied *after* the closing quote, which is what
             # `['\"]\s*%\s*[({\w]` requires and a naive `%s` search would report as a bug.
             r"^[^#\n]*(?:SELECT\b[^;\n]*\bFROM\b|INSERT\s+INTO\b|UPDATE\b[^;\n]*\bSET\b"
             r"|DELETE\s+FROM\b)"
             r"(?:[^;\n]*['\"]\s*(?:\+|%\s*[({\w]|\.\s*format\s*\()"
             r"|[^;\n]*\{[^}{\n]*\}[^;\n]*['\"])",
             "Pass the value as a bind parameter — `cursor.execute(sql, (value,))`, or the ORM's "
             "own parameter form. Every string-building route into a query is the same bug: an "
             "f-string, `%`, `.format()` and `+` differ only in spelling.",
             maps_to="V1"),
    Detector("SEC-PY-YAML", "Unsafe YAML load", "CWE-20", "A08", S.HIGH, C.HIGH, (".py",),
             r"yaml\.load\s*\(", "Use yaml.safe_load (or Loader=SafeLoader).",
             suppress_if=r"SafeLoader"),
    Detector("SEC-PY-OSSYSTEM", "OS command execution (os.system)", "CWE-78", "A03", S.HIGH, C.HIGH,
             (".py",), r"os\.system\s*\(", "Use subprocess with an argument list; validate input."),
    Detector("SEC-PY-EVAL", "Dynamic code execution (eval/exec)", "CWE-95", "A03", S.HIGH, C.HIGH,
             (".py",), r"\b(?:eval|exec)\s*\(", "Never eval/exec untrusted input."),
    Detector("SEC-PY-MD5", "Weak hash (MD5/SHA-1)", "CWE-327", "A02", S.MEDIUM, C.MEDIUM, (".py",),
             r"hashlib\.(?:md5|sha1)\s*\(", "Use SHA-256+ or a password KDF (argon2/bcrypt/scrypt)."),
    # Four spellings of one switch, and they cannot all live in one rule — which is a fact about
    # this engine rather than about Flask. Code-shape rules are matched against `code_view`,
    # where the CONTENTS of every string literal are blanked, so `app.config['DEBUG']` arrives as
    # `app.config['     ']` and a pattern naming the key inside the brackets is dead text. The
    # three spellings below survive blanking because none of them puts the word in a literal.
    Detector("SEC-PY-DEBUG", "Debug mode enabled", "CWE-489", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"(?:DEBUG\s*=\s*True|\.debug\s*=\s*True"
             r"|\.run\([^)]*debug\s*=\s*True|config\.update\([^)]*DEBUG\s*=\s*True)",
             "Disable debug in production; never expose the interactive debugger."),
    # And the fourth, which needs the raw text for the reason above. `literal=True` is the same
    # flag the secret rules use, and it carries the same cost: the raw text still has comments in
    # it, so a commented-out switch would match. `suppress_line_if` drops those — the line is the
    # right scope here, since one commented line says nothing about the next.
    Detector("SEC-PY-DEBUG-CONFIG", "Debug mode enabled through the config mapping",
             "CWE-489", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"config\[\s*['\"]DEBUG['\"]\s*\]\s*=\s*True",
             "Disable debug in production; never expose the interactive debugger.",
             literal=True, suppress_line_if=r"^\s*#"),
    # A settings module that defaults debug ON is the same exposure with a switch in front of
    # it: `DEBUG = env_bool("DJANGO_DEBUG", True)` ships debug to every deployment that forgot
    # the variable, which is the deployment that needed it off. The plain `DEBUG = True` above
    # does not match this shape.
    Detector("SEC-PY-DEBUG-DEFAULT", "Debug mode defaults to on when the env var is unset",
             "CWE-16", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"^\s*DEBUG\s*=\s*\w+\([^)]*(?:,\s*(?:True|['\"](?:1|true|yes|on)['\"])\s*\)"
             r"|[^)]*['\"](?:1|true)['\"]\s*\)\s*==\s*['\"](?:1|true)['\"])",
             "Default to False and opt in: `DEBUG = os.environ.get('DJANGO_DEBUG') == '1'`."),
    Detector("SEC-PY-ALLOWED-HOSTS", "ALLOWED_HOSTS accepts any Host header",
             "CWE-16", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"^\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]",
             "List the hostnames you serve. `['*']` enables Host-header injection, cache "
             "poisoning and password-reset poisoning."),
    # The literal is the whole finding: a fallback secret ships in the source, so every
    # deployment that does not set the variable signs its sessions with a key that is public.
    Detector("SEC-PY-SECRET-KEY-FALLBACK",
             "Signing key falls back to a literal committed in the source",
             "CWE-321", "A02", S.HIGH, C.HIGH, (".py",),
             r"^\s*(?:SECRET_KEY|JWT_SECRET\w*|\w*_SECRET_KEY)\s*=\s*(?:os\.)?(?:environ\.get|getenv)"
             r"\s*\(\s*[^)]*,\s*['\"][^'\"]{8,}['\"]",
             "Fail closed when the variable is missing rather than falling back: a committed "
             "default key is a published key.", mask=True),
    # The rule above catches the *fallback* — `os.environ.get("SECRET_KEY", "dev-key")` — and
    # for the whole life of that rule the simpler case sat next to it uncaught: the key written
    # straight into the file, with no environment lookup to fall back from. It is the single
    # largest labelled shape in the external benchmark's credential class, and the pack scored
    # 6 of 52 on that class while owning a rule that reads the same variable name. Two lessons
    # already in this repository's ledger, both of them again: check the *source* shapes before
    # adding sinks, and a rule that handles the elaborate version of a bug is not evidence that
    # the plain version is handled.
    Detector("SEC-PY-SECRET-KEY-LITERAL",
             "Signing key written into the source as a literal",
             "CWE-798", "A02", S.HIGH, C.HIGH, (".py",),
             # Three shapes, one bug: the Django module constant, the Flask attribute, and the
             # Flask config-dict entry. `(?!=)` keeps a comparison (`if SECRET_KEY == "..."`)
             # out — that reads a key, it does not set one.
             #
             # The floor used to be 8 characters, inherited from the fallback rule, and it was
             # wrong here. Two labelled credentials in the external corpus are four and six
             # characters long, and both sat under it: a short signing key is a *worse* key than
             # a long one, not a non-key, and length is the one property a published key does not
             # need. Only the empty string is excluded now — an unset key is a framework
             # misconfiguration with its own finding, not something anyone can forge with.
             #
             # Cost of relaxing it, found by the dogfood gate on the commit that relaxed it: this
             # rule reads raw text, comments included, so the four-character example that used to
             # sit in this very comment became a High finding against the engine's own source.
             # Deliberately not silenced with a ceiling entry — prose that demonstrates a short
             # key really does look exactly like a short key, and the honest fix is to describe
             # the shape instead of writing one down.
             r"(?:^\s*(?:\w*SECRET_KEY|JWT_SECRET\w*|\w*SIGNING_KEY)\s*=\s*(?!=)"
             r"|\.\s*secret_key\s*=\s*(?!=)"
             r"|\bconfig\s*\[\s*['\"](?:\w*SECRET_KEY|JWT_SECRET\w*|\w*SIGNING_KEY)['\"]\s*\]"
             r"\s*=\s*(?!=))"
             r"\s*(?:b|r|rb|br)?['\"][^'\"]+['\"]",
             "Load the key from the environment or a secret manager and fail closed when it is "
             "absent. A key in the repository is a key every fork, clone and CI log has — "
             "rotate it, do not just move it.", mask=True),
    # Cookie flags. Suppressed when the call already names the flags, so a correct call is not
    # reported — that suppression is per-file, which is the pack's coarse-grained trade-off.
    Detector("SEC-PY-COOKIE-FLAGS", "Cookie set without Secure/HttpOnly",
             "CWE-1004", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"\.set_cookie\s*\((?:[^()]|\([^()]*\))*\)",
             "Set `httponly=True, secure=True, samesite='Lax'` — without HttpOnly the cookie is "
             "readable by any script the page ends up running.",
             suppress_if=r"set_cookie\s*\((?:[^()]|\([^()]*\))*httponly\s*=\s*True"),
    # The Secure half, which the HttpOnly rule above was hiding. Its suppression fires on
    # `httponly=True` — so a call that sets HttpOnly and never Secure was read as a fixed cookie
    # and reported nothing at all. Those are different flags against different attacks: HttpOnly
    # keeps script from reading the cookie, Secure keeps the network from seeing it. Measured on
    # the external corpus before this was added: 10 labels that no rule reached, against 4
    # findings in no labelled region and zero hits on a labelled trap.
    Detector("SEC-PY-COOKIE-NO-SECURE", "Cookie set without the Secure attribute",
             "CWE-614", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"\.set_cookie\s*\((?:[^()]|\([^()]*\))*\)",
             "Add `secure=True` so the cookie is never sent over plain HTTP. It is a separate "
             "flag from HttpOnly and a separate attack: one stops a script reading the cookie, "
             "the other stops the network doing it.",
             suppress_if=r"set_cookie\s*\((?:[^()]|\([^()]*\))*secure\s*=\s*True",
             once_per_file=True),
    # The same omission in a Django settings module, where cookie behaviour is configured rather
    # than called. The shape that makes this decidable is *selective* hardening: a file that
    # deliberately sets HttpOnly or SameSite has thought about cookie security, so the absence of
    # the Secure flag beside them is an omission rather than a file that simply never mentions
    # cookies. A settings module that configures none of them is not reported, and one that sets
    # `SESSION_COOKIE_SECURE = False` still is — the suppression asks for `True`.
    Detector("SEC-PY-COOKIE-SETTINGS-NO-SECURE",
             "Session cookie hardened without the Secure attribute",
             "CWE-614", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"^\s*(?:SESSION|CSRF)_COOKIE_(?:HTTPONLY|SAMESITE)\s*=",
             "Set `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True`. The module "
             "already hardens these cookies in other ways, so the missing flag reads as an "
             "oversight rather than a deployment choice.",
             suppress_if=r"(?:SESSION|CSRF)_COOKIE_SECURE\s*=\s*True", once_per_file=True),
    # Randomness for security material. `random` is a Mersenne Twister: observe enough output
    # and the rest is predictable, which is exactly the property a token must not have. Bound
    # to security-shaped names on purpose — `random.choice` picking a demo colour is fine, and
    # a rule that says otherwise gets muted.
    Detector("SEC-PY-WEAK-PRNG", "Security material generated with a non-cryptographic PRNG",
             "CWE-330", "A02", S.HIGH, C.MEDIUM, (".py",),
             r"^\s*\w*(?:key|token|secret|nonce|otp|code|session|salt|iv|password|passwd|pin|"
             r"verifier|challenge)\w*\s*=\s*[^=\n]*\brandom\s*\.\s*"
             r"(?:random|randint|randrange|choice|choices|sample|getrandbits|shuffle|uniform)\s*\(",
             "Use `secrets` (or `os.urandom`): `secrets.token_urlsafe(32)`."),
    Detector("SEC-PY-CSRF-EXEMPT", "CSRF protection switched off",
             "CWE-352", "A01", S.MEDIUM, C.HIGH, (".py",),
             # CSRF is a defence against a *state-changing* request the user did not intend, so
             # an exemption on a handler the framework has already restricted to GET/HEAD is not
             # a hole — it is the correct annotation on a read-only endpoint, and one of these
             # repositories says so in a comment right beside it. Measured: 11 of the rule's 19
             # false positives on the external corpus were exactly this, and none of its true
             # positives. The lookahead is bounded to the next three lines rather than written
             # with a nested quantifier, because an unbounded one over a decorator stack is a
             # ReDoS — and this repository ships a detector for that.
             r"@csrf_exempt\b(?![^\n]*\n(?:[^\n]*\n){0,2}?[^\n]*@(?:require_safe\b|require_GET\b"
             r"|require_http_methods\s*\(\s*\[\s*['\"](?:GET|HEAD)))"
             r"|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False"
             r"|\bcsrf\.exempt\b",
             "Keep CSRF protection on for any state-changing route; use a token, not an "
             "exemption."),
    # CSRF middleware commented out of the MIDDLEWARE list. This one must read the RAW text and
    # never `code_view`: the whole finding IS a comment, and the code view exists to blank those.
    # A rule that describes disabled-by-commenting-out is the one case where the comment is the
    # evidence.
    Detector("SEC-PY-CSRF-MIDDLEWARE-OFF", "CSRF middleware commented out of the middleware list",
             "CWE-352", "A01", S.HIGH, C.HIGH, (".py",),
             r"^\s*#\s*['\"][\w.]*Csrf\w*Middleware['\"]",
             "Re-enable `django.middleware.csrf.CsrfViewMiddleware`. Commenting it out disables "
             "CSRF for every view at once, which is strictly wider than any per-view exemption."),
    # Security headers. Only the unambiguous downgrades are here, and the boundary is worth
    # stating: `X-XSS-Protection: 0` is labelled a misconfiguration by the external corpus and is
    # NOT a rule in this pack, because the OWASP Secure Headers Project recommends exactly that
    # value — the header is deprecated and its filter was itself an XSS vector. Two corpus labels
    # were left on the table rather than ship a rule that fires on correct modern code.
    #
    # `max-age=0` is different in kind: it withdraws an HSTS pin the browser already holds, which
    # is a downgrade to plaintext whatever the year.
    Detector("SEC-PY-HSTS-DISABLED", "HSTS withdrawn (Strict-Transport-Security: max-age=0)",
             "CWE-319", "A02", S.MEDIUM, C.HIGH, (".py",),
             r"['\"]Strict-Transport-Security['\"][^\n]{0,20}['\"]\s*max-age\s*=\s*0\b",
             "Serve a real `max-age` (a year, once you are confident) and keep it. Emitting "
             "`max-age=0` tells browsers that already pinned you to stop, which re-opens the "
             "plaintext downgrade the pin existed to close."),
    Detector("SEC-PY-CSP-WEAK", "Content-Security-Policy that permits inline script or any origin",
             "CWE-693", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             # The header name, then the value within the same call. `unsafe-inline` re-permits
             # exactly the injected `<script>` a CSP is deployed to stop, and `default-src *`
             # permits every origin, so a policy carrying either is a policy in name only.
             r"['\"]Content-Security-Policy['\"][^\n]{0,40}"
             r"['\"][^'\"\n]*(?:unsafe-inline|unsafe-eval|default-src\s+\*)",
             "Drop `unsafe-inline`/`unsafe-eval` and name your origins. If inline script is "
             "genuinely required, allow it by nonce or hash, not by category."),
    # Autoescaping, both halves. The explicit `autoescape=False` is unambiguous. The second rule
    # is the default-off case: raw Jinja2 `Environment(...)` does not escape unless you ask, which
    # its own documentation says and which Flask hides by overriding it — so a file that builds an
    # Environment by hand and never mentions autoescape renders every variable unescaped.
    Detector("SEC-PY-AUTOESCAPE-OFF", "Template autoescaping switched off in code",
             "CWE-79", "A03", S.HIGH, C.MEDIUM, (".py",),
             r"\bautoescape\s*=\s*False\b",
             "Set `autoescape=True` (or `select_autoescape()`) and mark the few genuinely "
             "trusted values individually. Escaping off at the environment covers every "
             "template the environment ever loads.", maps_to="V8"),
    Detector("SEC-PY-JINJA-ENV-DEFAULT", "Jinja2 Environment built without autoescaping",
             "CWE-79", "A03", S.MEDIUM, C.MEDIUM, (".py",),
             # Bound on three sides: the file must actually be using Jinja2, any mention of
             # autoescape anywhere in it clears the finding, and the match must be a *call*
             # rather than a class statement. That last one is not hypothetical — the first
             # measured run of this rule reported `class Environment(BaseEnvironment):` in
             # Flask's own `templating.py`, which is a declaration of the type, not a
             # construction of one, and Flask is the library that turns autoescaping on.
             r"(?<!class )\bEnvironment\s*\(",
             "Pass `autoescape=select_autoescape()`. Jinja2 defaults autoescaping OFF — Flask "
             "turns it on for you, a hand-built Environment does not, and the difference is "
             "invisible until a variable carries markup.",
             requires_in_file=r"\bjinja2\b", suppress_if=r"autoescape", maps_to="V8"),
    # Debug as a config-dict entry (Tornado, and anything else that takes a settings mapping).
    # Reads the raw text on purpose: the key is a string literal, which `code_view` blanks, so
    # the existing `SEC-PY-DEBUG` — which is code-shaped and matches `DEBUG = True` — structurally
    # cannot see this spelling.
    Detector("SEC-PY-DEBUG-DICT", "Debug mode enabled in a settings mapping",
             "CWE-489", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"['\"]debug['\"]\s*:\s*True\b",
             "Disable debug in production. A debug handler renders tracebacks, local variables "
             "and often a live interpreter to whoever triggered the error."),
    # A signing key passed straight into the call rather than assigned to a name first. The
    # name-based rules above cannot see this shape at all, and it is the spelling every JWT
    # tutorial uses.
    Detector("SEC-PY-CRED-LITERAL-ARG", "Signing key passed to the call as a literal",
             "CWE-798", "A02", S.HIGH, C.HIGH, (".py",),
             r"\bjwt\s*\.\s*(?:encode|decode)\s*\([^)\n]*,\s*['\"][^'\"\n]+['\"]"
             r"|\bFernet\s*\(\s*['\"][^'\"\n]+['\"]"
             r"|\bnew\s+HMAC\s*\(\s*['\"][^'\"\n]+['\"]",
             "Load the key from the environment or a secret manager. A literal here signs and "
             "verifies with a key every reader of the repository can forge tokens with.",
             mask=True),
    # SQL statement tracing wired to stdout. Every statement the application runs — with its bound
    # values, so the password reset token and the session id included — goes to the process log.
    Detector("SEC-PY-SQL-TRACE", "Every SQL statement, with its values, written to the log",
             "CWE-532", "A09", S.MEDIUM, C.HIGH, (".py",),
             r"\.set_trace_callback\s*\(\s*(?:print|sys\s*\.\s*std\w+\s*\.\s*write)"
             r"|\bcreate_engine\s*\([^)\n]*\becho\s*=\s*True",
             "Remove the trace callback, or route it to a logger that redacts bound parameters. "
             "Statement tracing prints the values, which is where the credentials are."),
    # The round-3 lesson, one language over: ask which function this is, not what it is called.
    # `md5(...)` bare is only the hash when the file imported it as one, and this is the spelling
    # a password check actually uses.
    Detector("SEC-PY-MD5-IMPORTED", "Weak hash (MD5/SHA-1) called through a bare import",
             "CWE-327", "A02", S.MEDIUM, C.MEDIUM, (".py",),
             r"(?<![.\w])(?:md5|sha1)\s*\(",
             "Use SHA-256+ for digests and a password KDF (argon2/bcrypt/scrypt) for passwords. "
             "An MD5 of a password is a lookup, not a hash.",
             requires_in_file=r"from\s+hashlib\s+import[^\n]*\b(?:md5|sha1)\b"),

    # ---- Go ----
    Detector("SEC-GO-TLS", "Disabled TLS verification (InsecureSkipVerify)", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".go",), r"InsecureSkipVerify:\s*true",
             "Keep certificate verification on; trust the proper CA bundle."),
    Detector("SEC-GO-SQL", "Possible SQL injection (Sprintf into SQL)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".go",),
             r"fmt\.Sprintf\([^)]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
             "Use parameterized queries (database/sql placeholders)."),
    Detector("SEC-GO-EXEC", "OS command execution (exec.Command)", "CWE-78", "A03",
             S.MEDIUM, C.MEDIUM, (".go",), r"exec\.Command\(",
             "Validate arguments; never pass user input to a shell."),

    # ---- Rust ----
    # Rust's memory safety is enforced by the compiler, so the classes worth a rule are the
    # ones where the code opts *out* of it, plus the panic paths that turn a request into a
    # denial of service. Deliberately three narrow rules rather than a broad pack: a language
    # where most of the usual sinks cannot exist deserves rules about what is actually left.
    Detector("SEC-RS-UNSAFE", "`unsafe` block without a safety comment", "CWE-758", "A04",
             S.MEDIUM, C.MEDIUM, (".rs",), r"^\s*unsafe\s*\{",
             "Document the invariants that make this block sound in a `// SAFETY:` comment "
             "directly above it, or replace it with a safe abstraction.",
             suppress_if=r"//\s*SAFETY:"),
    Detector("SEC-RS-TRANSMUTE", "`mem::transmute` reinterprets bytes with no checks",
             "CWE-704", "A04", S.HIGH, C.MEDIUM, (".rs",), r"\bmem::transmute\b|\btransmute::<",
             "Prefer a checked conversion (`TryFrom`, `from_le_bytes`, `bytemuck`); transmute "
             "assumes a layout the compiler does not verify."),
    Detector("SEC-RS-CMDI", "Shell command built with a shell interpreter", "CWE-78", "A03",
             S.MEDIUM, C.MEDIUM, (".rs",),
             r"Command::new\(\s*\"(?:sh|bash|cmd|powershell)\"|\.arg\(\s*\"-c\"",
             "Invoke the program directly with `Command::new(prog).arg(value)`; a `-c` string "
             "re-introduces shell metacharacter injection that Rust otherwise avoids."),

    # ---- Java ----
    Detector("SEC-JAVA-DESER", "Insecure deserialization (ObjectInputStream)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".java",), r"\bObjectInputStream\b",
             "Avoid Java native deserialization of untrusted data; use a safe format."),
    Detector("SEC-JAVA-EXEC", "OS command execution (Runtime.exec)", "CWE-78", "A03",
             S.HIGH, C.HIGH, (".java",), r"Runtime\.getRuntime\(\)\.exec",
             "Use ProcessBuilder with an argument list; validate input."),
    Detector("SEC-JAVA-SQL", "Possible SQL injection (concatenated query)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".java",), r"executeQuery\([^)]*\+",
             "Use PreparedStatement with bind parameters."),

    # ---- PHP ----
    # `(?<![\w>:$])` is the whole difference between a language construct and a method that
    # happens to share its name, and it was worth 104 matched lines on one repository.
    # `$redis->eval(...)` is Redis' Lua evaluator, `Process::exec(...)` is a class method,
    # `$this->system(...)` is somebody's helper — none of them is PHP's `eval`. Measured on the
    # noise floor the day it grew a PHP half: **125 matched lines in `laravel/framework` before
    # this and 21 after**, against a cost of 8 labelled files out of 167 on CVEfixes.
    # `(?<!function )` drops the declaration for the same reason — `function exec(` is where a
    # method with this name is *defined*, and a definition is not a call.
    Detector("SEC-PHP-EXEC", "Command/code execution sink", "CWE-78", "A03", S.HIGH, C.HIGH,
             PHP_EXTS,
             r"(?<![\w>:$])(?<!function )(?:system|exec|shell_exec|passthru|eval)\s*\(",
             "Avoid these on untrusted input; use safe APIs and validation."),
    # The same two exclusions, plus the one control PHP actually ships for this:
    # `unserialize($x, ['allowed_classes' => false])` cannot construct an object, so it cannot
    # reach a magic method, which is the whole of PHP object injection. Written as a lookahead
    # rather than a `suppress_if` deliberately — suppression in this pack is per FILE, and a
    # class that calls `unserialize` safely in one method and unsafely in another is the
    # ordinary case, not the exotic one.
    #
    # Confidence is MEDIUM rather than HIGH, and the demotion is the honest reading of what this
    # rule can see: a sink, and no source. Requiring a request-shaped argument was measured and
    # rejected — it takes 74 labelled files to 15, because real PHP object injection usually
    # arrives through a cookie or a session read three functions earlier. What remains is 114
    # matched lines in Laravel, cache and queue paths where the framework serialises its own
    # state, and that number is published rather than tuned away: the fix for it is a PHP taint
    # tier, not a narrower regex.
    Detector("SEC-PHP-UNSER", "Insecure deserialization (unserialize)", "CWE-502", "A08",
             S.HIGH, C.MEDIUM, PHP_EXTS,
             r"(?<![\w>:$])(?<!function )unserialize\s*\("
             r"(?!(?:[^()\n]|\([^()\n]*\))*allowed_classes)",
             "Never unserialize untrusted data; use JSON. If the call has to stay, pass "
             "`['allowed_classes' => false]` so no object can be constructed."),
    Detector("SEC-PHP-SQLI", "SQL injection (superglobal in query)", "CWE-89", "A03",
             S.HIGH, C.HIGH, PHP_EXTS,
             r"mysqli_query\([^)]*\$_(?:GET|POST|REQUEST)",
             "Use prepared statements (mysqli/PDO bind parameters)."),

    # ---- PHP, the superglobal rules ----
    #
    # PHP is 64% of the labels in `eval/cvefixes/` and scored 3.4% there, the worst of the four
    # languages this engine covers, with three rules against it. What makes the gap closable
    # without a taint tier is a property of the language rather than a trick: **the source is
    # spelled in the sink**. `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` are superglobals — no
    # import, no binding, no parameter to resolve — so a rule that sees one inside a dangerous
    # call has seen the whole path, which is exactly what Python and JavaScript need a taint
    # engine for.
    #
    # Every rule below was measured on both sides before it was written. On the 6,268 unsealed
    # labelled PHP files: **+240, +79, +7, +37 and +29 files** respectively. On 664,722 lines of
    # maintained PHP — Laravel, Symfony's HTTP layer, Guzzle, PHPMailer — **all five together
    # match zero lines.** That is the shape a rule should have, and it is why the two candidates
    # that did NOT have it were dropped rather than shipped with a caveat:
    #
    # * **SQL built by interpolation** (`"SELECT … WHERE id=$id"`, `'…' . $id`) would have been
    #   the biggest single win here — **+1,100 labelled files, recall 3.7% → 21.3%** — and it
    #   matches **1,225 lines in `laravel/framework` alone**, because a query builder's own
    #   source is full of SQL fragments with variables in them. A rule that fires 1,225 times on
    #   the framework everybody uses is a rule nobody keeps switched on. It needs the taint tier
    #   PHP does not have yet, and it is in `ROADMAP.md` as that.
    # * **A shell sink with a superglobal argument** was already covered: 0 new files, because
    #   `SEC-PHP-EXEC` above reports the same lines.
    Detector("SEC-PHP-XSS-ECHO", "Superglobal echoed into the page without escaping",
             "CWE-79", "A03", S.HIGH, C.HIGH, PHP_EXTS,
             # `echo $_GET['q']`, `print $_POST['name']`, `<?= $_REQUEST['id'] ?>`. PHP does not
             # escape anything on the way out — there is no autoescaping to fail — so a
             # superglobal reaching `echo` is reflected XSS with nothing in between. The rule
             # asks for the subscript (`$_GET[`) so that `isset($_GET)` and `count($_POST)` in
             # the same statement do not read as output.
             r"(?:\becho\b|\bprint\b|<\?=)[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[",
             "Escape at the point of output: `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`, or "
             "render through a template engine that escapes by default. PHP escapes nothing on "
             "its own, so an unescaped superglobal in `echo` is reflected XSS.",
             maps_to="V8"),
    Detector("SEC-PHP-XSS-SHORTECHO", "Value printed by the short-echo tag with nothing escaping it",
             "CWE-79", "A03", S.MEDIUM, C.MEDIUM, PHP_EXTS,
             # `<?= $name ?>`, `<?= $row['title'] ?>`, `<?= $user->email ?>` — a template
             # printing a value, in a language that escapes nothing. The rule takes only the
             # shape with **no call in it**, and that is the whole precision decision: allowing a
             # call would read `<?= $this->escape($x) ?>` and `<?= $fmt->render($y) ?>` as bugs,
             # and there is no way to tell those from `<?= $obj->rawHtml() ?>` in one line.
             # Measured: the permissive form reaches **560** unsealed labelled files and this one
             # **240**, so the narrowing costs 320 files and is still the right call — the ones it
             # keeps are the ones where nothing could have escaped the value, because nothing ran.
             #
             # Severity and confidence are both MEDIUM: the sink is certain and the source is not.
             # Where a superglobal is the thing being printed, `SEC-PHP-XSS-ECHO` above says so at
             # HIGH.
             r"<\?=\s*\$[A-Za-z_]\w*(?:\s*(?:->|::)\s*\w+|\s*\[[^\]\n]*\])*\s*(?:;|\?>)",
             "Escape at the tag: `<?= htmlspecialchars($v, ENT_QUOTES, 'UTF-8') ?>`, or move the "
             "page to a template engine that escapes by default. Nothing in PHP escapes this "
             "value on its own, and every string on the page reached it from somewhere.",
             maps_to="V8"),
    Detector("SEC-PHP-SQLI-SUPERGLOBAL", "Superglobal passed straight into a query call",
             "CWE-89", "A03", S.CRITICAL, C.HIGH, PHP_EXTS,
             # Wider than `SEC-PHP-SQLI` above, which names `mysqli_query` and nothing else:
             # this covers PDO (`->query`, `->exec`, `->prepare`), any wrapper that kept those
             # names, and the procedural spellings. `prepare` is in the list on purpose — a
             # prepared statement whose *text* is built from a superglobal is not parameterised,
             # it is the same injection with an extra call.
             r"(?:query|exec|prepare|db_query|pg_query|sqlite_query)\s*\([^)\n]*"
             r"\$_(?:GET|POST|REQUEST|COOKIE)",
             "Bind the value instead of pasting it: `$stmt = $pdo->prepare('… WHERE id = ?'); "
             "$stmt->execute([$id]);`. A superglobal inside the query TEXT is injection even "
             "when the call is named `prepare`.",
             maps_to="V1"),
    Detector("SEC-PHP-LFI", "File included from a request value", "CWE-98", "A03",
             S.CRITICAL, C.HIGH, PHP_EXTS,
             r"\b(?:include|include_once|require|require_once)\b[^;\n]*"
             r"\$_(?:GET|POST|REQUEST|COOKIE)",
             "Never build an include path from a request. Map the value through an allowlist of "
             "known filenames; a caller who chooses the file chooses the code that runs.",
             maps_to="V12"),
    Detector("SEC-PHP-PATHTRAV", "Filesystem call on a request-supplied path", "CWE-22", "A01",
             S.HIGH, C.HIGH, PHP_EXTS,
             r"\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|"
             r"move_uploaded_file|scandir|opendir)\s*\([^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)",
             "Resolve with `realpath()` and check the result still starts with the directory you "
             "meant, or map the request value through an allowlist. `../` is a valid path "
             "component and PHP will follow it.",
             maps_to="V12"),
    Detector("SEC-PHP-HEADER-INJECT", "Response header built from a request value",
             "CWE-601", "A01", S.MEDIUM, C.HIGH, PHP_EXTS,
             # Two bugs share this shape: `header("Location: " . $_GET['next'])` is an open
             # redirect, and a value carrying CRLF splits the response into a second one.
             r"\bheader\s*\([^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)",
             "Validate before redirecting: compare the target against an allowlist of paths you "
             "own, and never pass a request value into a header unfiltered — a newline in it "
             "ends the header and starts a response you did not write.",
             maps_to="V6"),

    # ---- Ruby ----
    Detector("SEC-RB-MARSHAL", "Insecure deserialization (Marshal.load)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".rb",), r"Marshal\.load",
             "Never Marshal.load untrusted data; use JSON."),
    Detector("SEC-RB-EVAL", "Dynamic code execution (eval)", "CWE-95", "A03", S.HIGH, C.HIGH, (".rb",),
             r"\beval\s*\(", "Never eval untrusted input."),

    # ---- C# ----
    Detector("SEC-CS-DESER", "Insecure deserialization (BinaryFormatter)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".cs",), r"\bBinaryFormatter\b",
             "BinaryFormatter is unsafe and removed in modern .NET; use a safe serializer."),
    Detector("SEC-CS-SQL", "Possible SQL injection (concatenated SqlCommand)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".cs",), r"SqlCommand\([^)]*\+",
             "Use parameterized queries (SqlParameter)."),

    # ---- Container / IaC (extra) ----
    Detector("SEC-DOCKER-CURLSH", "Remote script piped to a shell in RUN", "CWE-494", "A08",
             S.HIGH, C.HIGH, ("Dockerfile",), r"RUN[^\n]*\bcurl\b[^\n]*\|\s*(?:sh|bash)\b",
             "Download, verify a checksum/signature, then execute — never pipe curl to a shell."),
    Detector("SEC-DOCKER-USERROOT", "Container explicitly runs as root", "CWE-250", "A05",
             S.MEDIUM, C.MEDIUM, ("Dockerfile",), r"^USER\s+root\b",
             "Run as a non-root user."),
    Detector("SEC-TF-OPENINGRESS", "Security group open to the world", "CWE-284", "A01",
             S.MEDIUM, C.MEDIUM, (".tf",), r"cidr_blocks\s*=\s*\[?\s*['\"]0\.0\.0\.0/0",
             "Restrict ingress to known CIDRs; avoid 0.0.0.0/0 on sensitive ports."),
    Detector("SEC-TF-PUBLICACL", "Public-read storage ACL", "CWE-732", "A01",
             S.MEDIUM, C.MEDIUM, (".tf",), r"acl\s*=\s*['\"]public-read",
             "Keep buckets private; use signed URLs / explicit policies."),
    Detector("SEC-TF-IAM-WILDCARD", "Over-broad IAM policy (Action/Resource \"*\")", "CWE-732", "A01",
             S.MEDIUM, C.MEDIUM, (".tf", ".json", ".yaml", ".yml"),
             r"['\"](?:Action|Resource)['\"]\s*[:=]\s*['\"]\*['\"]",
             "Scope IAM actions and resources to the minimum needed."),
    Detector("SEC-TF-UNENCRYPTED", "Storage encryption disabled", "CWE-311", "A02",
             S.MEDIUM, C.MEDIUM, (".tf",), r"(?:storage_encrypted|encrypted)\s*=\s*false",
             "Enable encryption at rest."),
    Detector("SEC-TF-PUBLICDB", "Database publicly accessible", "CWE-284", "A01",
             S.HIGH, C.MEDIUM, (".tf",), r"publicly_accessible\s*=\s*true",
             "Keep managed databases in private subnets; never expose them publicly."),

    # ---- Kubernetes ----
    # Every rule here carries `_MANIFEST`: `.yaml` is not a language, it is a container format,
    # and these four patterns are only about a workload manifest. Without the precondition they
    # fire on any YAML that happens to contain the word — including this repository's own
    # exported Semgrep pack, where `hostPath:` appears as the quoted pattern of the rule that
    # looks for it. `docker-compose.yml` is kept in scope on purpose (`services:`): it is the
    # only file the Docker detectors, which key on the name `Dockerfile`, cannot see.
    Detector("SEC-K8S-PRIVILEGED", "Privileged container", "CWE-250", "A05", S.HIGH, C.HIGH,
             (".yaml", ".yml"), r"privileged:\s*true",
             "Drop privileged; use least-privilege securityContext + capability drops.",
             requires_in_file=_MANIFEST),
    Detector("SEC-K8S-PRIVESC", "Privilege escalation allowed", "CWE-250", "A05", S.MEDIUM, C.MEDIUM,
             (".yaml", ".yml"), r"allowPrivilegeEscalation:\s*true",
             "Set allowPrivilegeEscalation: false.", requires_in_file=_MANIFEST),
    Detector("SEC-K8S-HOSTPATH", "hostPath volume mount", "CWE-552", "A05", S.MEDIUM, C.MEDIUM,
             (".yaml", ".yml"), r"hostPath:", "Avoid hostPath; use PVCs / restricted volumes.",
             requires_in_file=_MANIFEST),
    Detector("SEC-K8S-HOSTNET", "Host network / PID namespace shared", "CWE-668", "A05",
             S.MEDIUM, C.MEDIUM, (".yaml", ".yml"), r"host(?:Network|PID|IPC):\s*true",
             "Do not share the host network/PID/IPC namespaces.", requires_in_file=_MANIFEST),

    # ---- Web / config (cross-language) ----
    Detector("SEC-CORS-WILDCARD", "CORS allows any origin (*)", "CWE-942", "A05", S.MEDIUM, C.MEDIUM,
             (*JSTS_EXTS, ".py", ".go", ".java", ".rb", *PHP_EXTS),
             r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]",
             "Use an explicit origin allowlist, especially with credentials."),
    Detector("SEC-COOKIE-INSECURE", "Cookie without Secure/HttpOnly", "CWE-1004", "A05",
             S.MEDIUM, C.MEDIUM, (*JSTS_EXTS, ".py"),
             r"(?:secure|httpOnly)\s*[:=]\s*false",
             "Set Secure + HttpOnly (+ SameSite) on session cookies."),

    # The wildcard rule above reads a literal `*`. Reflection is the other half of the same bug
    # and the one a codebase actually writes: read the caller's Origin, write it straight back,
    # and every origin is allowed while the header looks like an allowlist. `SEC-JS-CORS` had
    # this for JavaScript only; 36 of the external corpus's misses are the Python spelling, which
    # is the lever this project has now hit three times — a rule that exists for one language
    # and not for the one the number is measured on.
    Detector("SEC-PY-CORS-REFLECT", "CORS origin reflected back from the request",
             "CWE-942", "A05", S.HIGH, C.MEDIUM, (".py",),
             r"Access-Control-Allow-Origin['\"]\s*(?:\]\s*=|,)\s*(?!['\"])[\w.\[\]()]",
             "Compare the Origin against an explicit allowlist and echo it only on a match; "
             "reflecting it makes Access-Control-Allow-Credentials trust every site."),
    # A header set to a value that turns the protection off. Deliberately not "this header is
    # missing" — absence is a property of a deployment, not of a line, and the corpus labels the
    # line that assigns the off value: a zero, an empty policy, an allow-anything framing value.
    # Written that way rather than shown, because this rule cannot use the code view — the header
    # name it keys on is always inside a string literal — so an example in a comment would be a
    # finding in this file, and the dogfood gate is right to say so.
    Detector("SEC-HEADER-DISABLED", "Browser security header explicitly disabled",
             "CWE-1021", "A05", S.MEDIUM, C.MEDIUM, (*JSTS_EXTS, ".py"),
             r"['\"](?:X-Frame-Options|X-XSS-Protection|Content-Security-Policy"
             r"|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy)['\"]\s*"
             r"(?:\]\s*=|[:,])\s*['\"](?:0|ALLOWALL|ALLOW-FROM \*|)['\"]",
             "Remove the override and let the header do its job: DENY or SAMEORIGIN for framing, "
             "a real Content-Security-Policy, nosniff for content type."),

    # ---- Secrets (more providers) ----
    Detector("SEC-SECRET-GOOGLE", "Hardcoded Google API key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bAIza[0-9A-Za-z_\-]{35}\b",
             "Revoke and rotate the key; restrict it; load from a secret manager.", mask=True,
             case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-STRIPE", "Hardcoded Stripe secret key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bsk_live_[0-9A-Za-z]{20,}\b",
             "Revoke and rotate immediately; load from a secret manager.", mask=True,
             case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-JWT", "JWT / bearer token in source", "CWE-798", "A07", S.MEDIUM, C.MEDIUM,
             _SECRET_EXTS, r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
             "Do not commit tokens; issue them at runtime and store server-side.", mask=True,
             case_sensitive=True, about_committed_text=True),

    # ---- Mobile: Android (Kotlin / Java) ----
    Detector("SEC-ANDROID-JSIF", "WebView addJavascriptInterface (RCE surface)", "CWE-749", "A05",
             S.HIGH, C.HIGH, (".java", ".kt"), r"addJavascriptInterface\s*\(",
             "Avoid it on untrusted content; require API 17+ and @JavascriptInterface, or drop it."),
    Detector("SEC-ANDROID-WORLDPERM", "World-readable/writable file mode", "CWE-732", "A04",
             S.HIGH, C.HIGH, (".java", ".kt"), r"MODE_WORLD_(?:READABLE|WRITEABLE)",
             "Use MODE_PRIVATE; share via a FileProvider/content URI."),
    Detector("SEC-ANDROID-WEBVIEW-JS", "WebView JavaScript enabled", "CWE-749", "A05",
             S.MEDIUM, C.MEDIUM, (".java", ".kt"), r"setJavaScriptEnabled\s*\(\s*true\s*\)",
             "Enable JS only when required and only for trusted content."),

    # ---- Mobile: iOS (Swift) / Flutter (Dart) ----
    Detector("SEC-IOS-ATS", "App Transport Security disabled", "CWE-319", "A02", S.HIGH, C.HIGH,
             (".plist", ".xml", ".swift"), r"NSAllowsArbitraryLoads",
             "Keep ATS on; allow-list specific domains instead of disabling it globally."),
    Detector("SEC-DART-BADCERT", "Flutter accepts any TLS certificate", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".dart",), r"badCertificateCallback\s*=",
             "Never return true for all certs; pin or validate properly."),

    # ---- AI / LLM / agentic security (2025-2026) ----
    # LLM Top 10:2025 + the emerging Agentic-Apps / MCP risk classes. Regex-detectable
    # surfaces only; deeper prompt-injection / excessive-agency analysis is the LLM tier's job.
    Detector("SEC-AI-LANGCHAIN-DANGER", "LangChain dangerous execution explicitly enabled",
             "CWE-94", "A05", S.HIGH, C.HIGH, (".py", *JSTS_EXTS),
             r"allow_dangerous_(?:code|requests|deserialization|tools)\s*=\s*True",
             "Do not enable dangerous execution on untrusted input; sandbox the agent and gate tools."),
    Detector("SEC-AI-PYREPL", "Agent code-execution tool (Python REPL) exposed", "CWE-94", "A05",
             S.MEDIUM, C.MEDIUM, (".py",), r"\bPython(?:Ast)?REPLTool\b",
             "Arbitrary-code tools give an LLM RCE; remove, or run in an isolated sandbox with no secrets."),
    Detector("SEC-AI-SHELL-TOOL", "Agent shell/terminal tool exposed to the model", "CWE-78", "A05",
             S.MEDIUM, C.MEDIUM, (".py",),
             r"\bShellTool\b|load_tools\(\s*\[[^\]]*['\"](?:terminal|shell)['\"]",
             "Giving an LLM a shell is excessive agency; drop it or constrain to an allowlisted command set."),
    Detector("SEC-AI-LLM-EXEC", "LLM/completion output flows into a code-exec sink", "CWE-94", "A05",
             S.HIGH, C.MEDIUM, (".py",),
             r"(?:eval|exec)\(\s*\w*(?:response|completion|message|output|result|llm|answer)\w*",
             "Never execute model output; treat it as untrusted data and validate/parse it."),

    # ---- Secrets: modern token formats (2025-2026 provider shapes) ----
    Detector("SEC-SECRET-ANTHROPIC", "Hardcoded Anthropic API key", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
             "Revoke and rotate the key; load it from the environment / a secret manager.",
             mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-GH-PAT", "Hardcoded GitHub fine-grained PAT", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bgithub_pat_[0-9A-Za-z_]{22,}\b",
             "Revoke the token in GitHub settings, rotate it, and load from a secret manager.",
             mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-HF", "Hardcoded Hugging Face token", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bhf_[A-Za-z0-9]{34,}\b",
             "Revoke and rotate the token; load it from the environment / a secret manager.",
             mask=True, case_sensitive=True, about_committed_text=True),
    Detector("SEC-SECRET-NPM", "Hardcoded npm access token", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bnpm_[A-Za-z0-9]{36}\b",
             "Revoke the token (npm token revoke), rotate it, and store it in CI secrets.",
             mask=True, case_sensitive=True, about_committed_text=True),

    # ---- Software supply chain / CI (2025-2026) ----
    # The A03:2025 "Software Supply Chain Failures" surface — mutable-tag CI compromise
    # (the tj-actions/changed-files CVE-2025-30066 class) and install-script execution.
    Detector("SEC-CI-MUTABLE-ACTION", "GitHub Action pinned to a mutable branch ref",
             "CWE-1357", "A03", S.HIGH, C.HIGH, (".yml", ".yaml"),
             # Two branch shapes, because only catching the first missed the one this
             # repository's own release workflow reached for. A bare branch name
             # (`@main`, `@develop`), and any ref containing a slash (`@release/v1`,
             # `@feature/x`) — a slash is overwhelmingly a branch, since tags almost never
             # carry one. A plain version tag (`@v4`) is deliberately NOT matched: it is
             # mutable too, but flagging it fires on nearly every workflow in existence, and
             # a rule that fires everywhere is a rule that gets suppressed everywhere. The
             # fix text names it as the second-best option instead.
             r"uses:\s*[\w.\-]+/[\w.\-]+@(?:(?:main|master|develop|trunk|latest|stable|HEAD)\b"
             r"|[\w.\-]+/[\w.\-]+)",
             "Pin third-party Actions to a full commit SHA — a branch is mutable and can be "
             "repointed at malicious code (the tj-actions/changed-files CVE-2025-30066 class, "
             "where the attacker moved the refs rather than publishing new code). Dependabot "
             "can still bump the pin. A version tag is better than a branch, a SHA is safest."),
    Detector("SEC-SUPPLY-CURLPIPE", "Remote script piped straight into a shell", "CWE-494", "A03",
             S.HIGH, C.HIGH, (".sh", ".yml", ".yaml"),
             r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b",
             "Download, verify a checksum/signature, then run — never pipe curl/wget to a shell."),

    Detector("SEC-PY-TPL-SAFE-LITERAL", "Template compiled from a literal that disables escaping",
             "CWE-79", "A03", S.HIGH, C.HIGH, (".py",),
             # An inline Jinja template whose own text switches escaping off for the value it is
             # about to be handed. Matched on the raw view because the `|safe` lives *inside* the
             # string literal, which is the only place it can live: `code_view` blanks literal
             # contents, so listing this in CODE_SHAPE_DETECTORS would make it unfirable. Same
             # trap as SEC-RS-CMDI.
             #
             # Which leaves comments, and the dogfood gate caught this rule firing on **its own
             # definition** — the line above used to quote the shape it looks for, in a codebase
             # that renders nothing. Third instance of the same self-report in this repository
             # (`hostPath:` in the exported Semgrep pack, an AKIA-shaped literal in a test), and
             # the fix is the same shape: state the thing the rule is actually about. It is about
             # a call, and a call is not preceded by a `#` on its own line.
             r"^[^#\n]*\bTemplate\s*\(\s*(?:f?['\"])[^'\"]*\{\{[^'\"]*\|\s*safe",
             "Drop `|safe` from the template text and pass the value as context so Jinja "
             "escapes it. If the value really is trusted HTML, sanitize it before rendering.",
             maps_to="V8"),

    # ---- Server-rendered templates ----
    # The half of the XSS surface that does not live in a handler. Until these rules existed no
    # detector named a template extension, so `.html` and `.jinja2` files were never opened by
    # any tier — the engine reported on the view that *builds* the response and never on the
    # document that renders it. Established by reading the labels rather than by assuming: of
    # the external benchmark's XSS labels, 39% sit in a template file, and the single largest
    # shape among them is an explicit `|safe`.
    Detector("SEC-TPL-SAFE-FILTER", "Escaping explicitly disabled on a template variable (|safe)",
             "CWE-79", "A03", S.HIGH, C.MEDIUM, TEMPLATE_EXTS,
             # `{{ x|safe }}` and `{{ x | safe }}`, Django and Jinja alike. Bounded to a single
             # `{{ … }}` expression: `[^}]*` cannot run past the end of the interpolation, so a
             # `|safe` further down the document does not attach itself to an unrelated variable.
             r"\{\{[^}]*\|\s*safe\b",
             "Escape the value — drop `|safe` and let the template escape it, or sanitize the "
             "HTML with a real sanitizer (bleach, nh3) before marking it safe. `|safe` on any "
             "value that reaches the page from a request is stored or reflected XSS.",
             maps_to="V8"),
    Detector("SEC-TPL-AUTOESCAPE-OFF", "Template block with autoescaping switched off",
             "CWE-79", "A03", S.HIGH, C.MEDIUM, TEMPLATE_EXTS,
             # Django spells it `off`, Jinja spells it `false`. Both switch escaping off for
             # every variable in the block, which is strictly wider than `|safe` on one of them.
             r"\{%\s*autoescape\s+(?:off|false)\s*%\}",
             "Turn autoescaping back on and mark only the individual values that are genuinely "
             "trusted HTML. A block-level `off` silently covers every variable added to it "
             "later, including the one somebody adds next year.",
             maps_to="V8"),
    Detector("SEC-TPL-FORM-NO-CSRF", "State-changing form with no CSRF token in it",
             "CWE-352", "A01", S.MEDIUM, C.MEDIUM, TEMPLATE_EXTS,
             # Match the opening tag of a POST form, then walk its body to `</form>` and require
             # that no token appears anywhere inside. The four spellings cover Django
             # (`{% csrf_token %}`), Flask-WTF (`form.hidden_tag()`), Rails-style
             # (`authenticity_token`) and the hand-written hidden input (`_csrf`).
             #
             # Written as a bounded, non-nested walk on purpose. The obvious form of this rule is
             # `<form[^>]*>(.*?)</form>` with a negative lookahead wrapped around a `*`, which is
             # star-height 2 over a document — and this repository ships a detector that reports
             # exactly that shape in anyone else's code, so it does not get to write one. The
             # 6000-character bound is a form long enough to be a real page and short enough that
             # the walk is linear.
             #
             # A commented-out form is not a hole, and this rule used to say otherwise whenever
             # the comment opened on an earlier line: the exclusion was three fixed-width
             # lookbehinds, because Python's `re` allows nothing else, and a `<!-- … -->` block
             # can open any number of lines above the form. The lookbehinds are gone. Template
             # rules are now scanned against `taint.code_view`, which blanks HTML comments with a
             # lexer and preserves every offset, so the reported line is unchanged and the bound
             # that was "real and stated rather than implied" is closed instead of documented.
             r"<form\b(?=[^>]*\bmethod\s*=\s*['\"]?\s*post)[^>]*>"
             r"(?:(?!</form>|csrf|hidden_tag|authenticity_token)[\s\S]){0,6000}</form>",
             "Add the framework's CSRF token to the form — `{% csrf_token %}` in Django, "
             "`{{ form.hidden_tag() }}` with Flask-WTF. Without it any page on the internet can "
             "submit this form as the logged-in user."),
    Detector("SEC-TPL-ERROR-OBJECT", "Exception internals rendered into the page",
             "CWE-209", "A09", S.MEDIUM, C.HIGH, TEMPLATE_EXTS,
             # `{{ error.__dict__ }}` and `{{ traceback }}` are the two shapes an error page uses
             # when somebody wanted the debug view in production.
             r"\{\{[^}]*\.__dict__|\{\{\s*(?:\w+\.)?(?:traceback|stacktrace|stack_trace)\s*[}|]",
             "Render a message and an incident id. A traceback or a dumped exception object "
             "hands the reader your file paths, framework versions, and often the query that "
             "failed with its values still in it."),
    Detector("SEC-TPL-XSS-JS-ATTR", "Template variable interpolated into a JavaScript event handler",
             "CWE-79", "A03", S.HIGH, C.MEDIUM, TEMPLATE_EXTS,
             # Autoescaping is HTML escaping: it turns `<` into `&lt;` and stops there. Inside
             # `onclick="…"` the browser parses the attribute value as JavaScript *after*
             # HTML-decoding it, so an escaped quote is decoded back into a quote before the JS
             # parser ever sees it. The variable is unprotected in this position even in a
             # correctly-autoescaping template, which is what makes it worth its own rule rather
             # than a note on the autoescape ones.
             r"\bon[a-z]{3,15}\s*=\s*['\"][^'\"\n]{0,200}\{\{",
             "Move the value out of the attribute: render it into a `data-` attribute and read "
             "it with `dataset` from a real script block, or emit it as JSON through a "
             "JS-context escaper. HTML escaping does not make a value safe inside JavaScript.",
             maps_to="V8"),
    Detector("SEC-JS-DOMXSS", "DOM XSS — a concatenated string written into the document",
             "CWE-79", "A03", S.HIGH, C.MEDIUM, (*JSTS_EXTS, *TEMPLATE_EXTS),
             # Concatenation is the whole rule. `el.innerHTML = ""` and `innerHTML = template`
             # are ordinary; `innerHTML = "<li>" + comment` and `` `<li>${comment}` `` are the
             # bug. Requiring a `+` or a `${` is what separates them, and it is why this is a
             # separate detector from SEC-JS-XSS rather than a widening of it — that rule names
             # one specific sanitizer-less markdown path and still earns its own evidence line.
             r"(?:\.innerHTML|\.outerHTML)\s*=\s*[^;\n]*(?:\+|\$\{)"
             r"|document\.write(?:ln)?\s*\([^)\n]*(?:\+|\$\{)"
             r"|\.(?:append|prepend|after|before|html)\s*\(\s*['\"`]\s*<[^)\n]*(?:\+|\$\{)",
             "Build the node instead of the markup: `textContent` for text, `createElement` + "
             "`append` for structure. If HTML really is required, sanitize with DOMPurify first.",
             maps_to="V8"),
    Detector("SEC-JS-HTML-CONCAT", "HTML markup built by concatenating a runtime value into it",
             "CWE-79", "A03", S.MEDIUM, C.MEDIUM, JSTS_EXTS,
             # SEC-JS-DOMXSS above requires the SINK on the same line — `innerHTML =`,
             # `document.write(`, `.html(`. That is where the rule's precision comes from and it
             # is also its ceiling, because most of this class does not look like that. Read out
             # of the CVEfixes labels rather than guessed: the markup is assembled somewhere and
             # written somewhere else, often in another function —
             #
             #     out += '<tr><td>' + opt + '</td></tr>';        // sink: 60 lines below
             #     teamHtmlList.push('<a href="#/' + id + '">' + name + '</a>');
             #     grid: '<div class="carousel">' + this.outerHTML(grid[0]) + '</div>',
             #
             # — and a line-oriented rule anchored on the sink cannot see any of it. So this rule
             # drops the sink and keeps the other half: a string literal that is HTML, joined to
             # something that is not a literal. That is the decision to build markup by
             # concatenation, which is the vulnerability whatever line finally writes it.
             #
             # Measured before it was written, on the 2,861 unsealed JavaScript/TypeScript files
             # CVEfixes labels: XSS recall 0.0579 → 0.2690, all classes 0.0696 → 0.1458. On the
             # other side of the ledger it is nine lines across 62 RealVuln repositories and
             # about a dozen across the four JavaScript projects in the noise floor, because
             # healthy modern code builds nodes or uses a template engine.
             #
             # Three precision decisions, each of which cost something and is worth the cost:
             #
             # * **The other operand must not be a literal.** `'<div class="a">' + '<span>'` is a
             #   library assembling a static template — bootstrap's tooltip, jQuery's feature
             #   probe — and never a bug. Requiring `[A-Za-z_$(]` after the `+`, and a value
             #   character before it, is what keeps those out.
             # * **A tag, not an angle bracket.** `'<' + x` and `'a < b: ' + n` are comparison
             #   and prose. The literal has to contain `</name` or `<name` followed by a space,
             #   `>` or `/`, which is markup and not arithmetic.
             # * **No `suppress_if`, and that is the decision, not an omission.** An escaper on
             #   the same line — `escapeHtml`, `DOMPurify`, `htmlEncode` — genuinely does answer
             #   the question, and suppressing on it costs 3 labels out of 221. But this pack's
             #   suppression is per FILE, not per line, and at that scope it costs 27: a module
             #   that escapes four values and forgets the fifth is not a module with no bug, it
             #   is the shape the bug actually comes in. Reported rather than silenced, knowingly.
             #
             # Deliberately NOT in `CODE_SHAPE_DETECTORS`: the evidence *is* the string literal's
             # contents, and `code_view` blanks exactly that. The price is a commented-out
             # example, paid knowingly — the alternative is a rule with nothing to read.
             r"(?:'[^'\n]{0,200}<(?:/[A-Za-z]|[A-Za-z][\w-]*[ >/])[^'\n]{0,200}'"
             r"|\"[^\"\n]{0,200}<(?:/[A-Za-z]|[A-Za-z][\w-]*[ >/])[^\"\n]{0,200}\")\s*\+\s*[A-Za-z_$(]"
             r"|[\w$)\]]\s*\+\s*(?:'[^'\n]{0,200}<(?:/[A-Za-z]|[A-Za-z][\w-]*[ >/])[^'\n]{0,200}'"
             r"|\"[^\"\n]{0,200}<(?:/[A-Za-z]|[A-Za-z][\w-]*[ >/])[^\"\n]{0,200}\")"
             r"|`[^`\n]{0,200}<(?:/[A-Za-z]|[A-Za-z][\w-]*[ >/])[^`\n]{0,200}\$\{\s*[A-Za-z_$(]",
             # Two things on the same line answer this rule's question, and both were found by
             # the noise floor rather than argued: an escaper call, and a **translation
             # catalogue**. `'<div>' + Messages.strMissingColumn + '</div>'` joins a string the
             # application ships with itself — a catalogue key is not a request, a URL or a
             # database row — and that shape was **65 of phpMyAdmin's 220 matched lines**, with
             # the escaper worth another 15. Line scope rather than file scope is what makes
             # this affordable: measured, it costs **2 labelled files instead of 27**.
             #
             # Deliberately narrow. Only the conventional catalogue receivers and gettext-style
             # calls, because the failure mode of this exclusion is a rule that goes quiet on a
             # variable somebody happened to name `messages`.
             suppress_line_if=r"\b(?:escapeHtml|escapeHTML|htmlEscape|htmlEncode|encodeHTML"
                              r"|escapeExpression|sanitizeHtml|DOMPurify|htmlspecialchars)\s*\("
                              r"|\b(?:Messages|Strings|i18n|I18n)\s*[.\[]"
                              r"|\b(?:gettext|ngettext|__|_e|trans|translate)\s*\(",
             fix="Escape the value where it is joined, or stop building markup: `textContent` and "
             "`createElement` for structure, a template engine that escapes by default, or "
             "DOMPurify on the finished string. Concatenated HTML is XSS the moment one of the "
             "joined values comes from a request, a URL or a database row.",
             maps_to="V8"),
]


# Detectors whose pattern describes CODE SHAPE rather than literal text. These are scanned
# against `taint.code_view` — comments and string-literal contents blanked — so a rule catalog
# that mentions `eval(` in a string, or a comment naming a vulnerability class, no longer reads
# as the vulnerability itself. Everything NOT listed here keeps the raw view, because it
# legitimately matches inside a literal: a hardcoded secret, a SQL fragment, a quoted header
# name, `createHash('md5')`, `alg === 'none'`.
#
# Kept as one explicit set rather than a flag on each of 76 definitions: the decision is
# "which side of one line is this rule on", and it is reviewable in a single screen. Check 22
# in `scripts/check_consistency.py` fails if an id here does not exist.
CODE_SHAPE_DETECTORS = {
    # SEC-JS-DOMXSS is code shape in a `.js` file and raw text in a `.html` one, and it needs
    # both: a `document.write` inside a comment is not a bug, and a template has no lexical
    # model at all. It gets exactly that for free — `code_view` returns None for an extension
    # it cannot model, and `scan_code` falls back to the raw text on None.
    "SEC-JS-DOMXSS",
    # `SEC-TPL-FORM-NO-CSRF` alone among the template rules, added when `code_view` learned HTML.
    # The group it uses for a document lists **no quote characters** — an attribute value is
    # content, not a literal — so the only thing blanked is a `<!-- … -->` block.
    #
    # Only this one, deliberately, and the reason is a cost the gate makes visible: a rule that
    # scans the view cannot be exported to the Semgrep pack, because `pattern-regex` there runs
    # on raw text and would fire inside a comment. Moving all five would have withheld four more
    # rules from the pack to fix a problem measured on exactly one of them — 39 unmatched form
    # findings on the external corpus, against no measurement at all for a commented-out `|safe`.
    # The other four keep the raw view and the export; if one of them is ever measured to report
    # commented-out markup, it moves here and loses its rule, knowingly.
    "SEC-TPL-FORM-NO-CSRF",
    "SEC-JS-SSRF", "SEC-JS-XSS", "SEC-JS-PATHTRAV", "SEC-JS-MASSASSIGN",
    "SEC-JS-EVAL", "SEC-JS-SSTI", "SEC-JS-RANDOM",
    "SEC-PY-XXE", "SEC-PY-TLS", "SEC-PY-CMDI", "SEC-PY-PICKLE", "SEC-PY-YAML",
    "SEC-PY-OSSYSTEM", "SEC-PY-EVAL", "SEC-PY-MD5", "SEC-PY-DEBUG",
    "SEC-PY-DEBUG-DEFAULT", "SEC-PY-COOKIE-FLAGS", "SEC-PY-WEAK-PRNG", "SEC-PY-CSRF-EXEMPT",
    "SEC-PY-AUTOESCAPE-OFF", "SEC-PY-JINJA-ENV-DEFAULT", "SEC-PY-SQL-TRACE", "SEC-PY-MD5-IMPORTED",
    # The round-4 rules that are deliberately NOT here, each for the same reason stated once:
    # their evidence is text the code view blanks. `SEC-PY-CSRF-MIDDLEWARE-OFF` matches a
    # commented-out middleware entry — the comment IS the finding. `SEC-PY-HSTS-DISABLED`,
    # `SEC-PY-CSP-WEAK`, `SEC-PY-DEBUG-DICT` and `SEC-PY-CRED-LITERAL-ARG` all match inside string
    # literals: a header name, a policy value, a settings key, a signing key. Listing any of them
    # would leave the rule unfirable, which is the mistake `SEC-RS-CMDI` records below.
    "SEC-GO-TLS", "SEC-GO-EXEC",
    # SEC-RS-CMDI is deliberately NOT here. It matches `Command::new("sh")` and `.arg("-c")`
    # — the shell name and the flag are string-literal *contents*, which `code_view` blanks,
    # so listing it made the rule unfirable. Caught by planting a Rust fixture: a detector
    # with no fixture is an unmeasured claim, and this one had been wrong since it shipped.
    "SEC-RS-UNSAFE", "SEC-RS-TRANSMUTE",
    "SEC-JAVA-DESER", "SEC-JAVA-EXEC", "SEC-JAVA-SQL",
    # SEC-PHP-UNSER is deliberately NOT here, for the reason SEC-RS-CMDI above is not: its
    # safety check reads a string-literal *content*. `unserialize($x, ['allowed_classes' =>
    # false])` is the one control PHP ships against object injection, and `code_view` blanks the
    # array key, so on the blanked view the rule cannot see the control and reports the fixed
    # call. Caught by the fixture that asserts exactly that, which is why the fixture exists.
    "SEC-PHP-EXEC", "SEC-PHP-SQLI",
    "SEC-RB-MARSHAL", "SEC-RB-EVAL",
    "SEC-CS-DESER", "SEC-CS-SQL",
    "SEC-COOKIE-INSECURE",
    "SEC-ANDROID-JSIF", "SEC-ANDROID-WORLDPERM", "SEC-ANDROID-WEBVIEW-JS",
    "SEC-AI-LANGCHAIN-DANGER", "SEC-AI-PYREPL", "SEC-AI-LLM-EXEC",
}

DETECTORS = [replace(d, literal=False) if d.id in CODE_SHAPE_DETECTORS else d
             for d in DETECTORS]


def group_of(detector_id: str) -> str:
    """The area segment of an id: `SEC-SECRET-AWS` -> `secret`, `TAINT-PY-CMDI` -> `py`.

    Derived from the id rather than kept as a field, so a new detector joins its group by being
    named consistently and there is no second list to forget to update. Ids that do not fit the
    shape fall into `other`, which is visible in `--only other` rather than silently dropped.
    """
    parts = detector_id.split("-")
    return parts[1].lower() if len(parts) >= 3 else "other"


def groups() -> dict[str, int]:
    """{group: detector count}, for `--only` and its error message."""
    out: dict[str, int] = {}
    for d in DETECTORS:
        out[group_of(d.id)] = out.get(group_of(d.id), 0) + 1
    return dict(sorted(out.items()))


def detectors_for(filename: str) -> list[Detector]:
    """Detectors whose file selector matches this filename."""
    import os
    base = os.path.basename(filename)
    ext = os.path.splitext(base)[1].lower()
    out = []
    for d in DETECTORS:
        if "Dockerfile" in d.exts and base == "Dockerfile":
            out.append(d)
        elif ext and ext in d.exts:
            out.append(d)
    return out
