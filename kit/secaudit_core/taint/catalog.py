"""The sink, source and sanitizer catalogs — what the engine considers dangerous.

Data, not logic. This is the file to read to answer "does it detect X", and the file to
edit to make it detect X; the analyzers in `pyanalysis` and `jsanalysis` are the machinery
that walks code looking for what is listed here.
"""
from __future__ import annotations

import re

from ..schema import Severity
from .model import Sink

# --------------------------------------------------------------------------- sink catalog

S = Severity

PY_SINKS: dict[str, Sink] = {
    "os.system": Sink("TAINT-PY-CMDI", "Command injection — untrusted input reaches a shell",
                      "CWE-78", "A03", S.CRITICAL,
                      "Use subprocess with an argument list and no shell; validate the input.",
                      taint_args=(0,)),
    "subprocess.call": Sink("TAINT-PY-CMDI-SHELL",
                            "Command injection — untrusted input reaches `shell=True`",
                            "CWE-78", "A03", S.CRITICAL,
                            "Drop shell=True and pass an argument list; validate the input.",
                            taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.run": Sink("TAINT-PY-CMDI-SHELL",
                           "Command injection — untrusted input reaches `shell=True`",
                           "CWE-78", "A03", S.CRITICAL,
                           "Drop shell=True and pass an argument list; validate the input.",
                           taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.Popen": Sink("TAINT-PY-CMDI-SHELL",
                             "Command injection — untrusted input reaches `shell=True`",
                             "CWE-78", "A03", S.CRITICAL,
                             "Drop shell=True and pass an argument list; validate the input.",
                             taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.check_output": Sink("TAINT-PY-CMDI-SHELL",
                                    "Command injection — untrusted input reaches `shell=True`",
                                    "CWE-78", "A03", S.CRITICAL,
                                    "Drop shell=True and pass an argument list; validate input.",
                                    taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "pickle.loads": Sink("TAINT-PY-DESER", "Insecure deserialization — untrusted bytes unpickled",
                         "CWE-502", "A08", S.CRITICAL,
                         "Never unpickle untrusted data; use JSON with a schema.",
                         taint_args=(0,), maps_to="V20"),
    "pickle.load": Sink("TAINT-PY-DESER", "Insecure deserialization — untrusted stream unpickled",
                        "CWE-502", "A08", S.CRITICAL,
                        "Never unpickle untrusted data; use JSON with a schema.",
                        taint_args=(0,), maps_to="V20"),
    "yaml.load": Sink("TAINT-PY-YAML", "Unsafe YAML load of untrusted input", "CWE-20", "A08",
                      S.HIGH, "Use yaml.safe_load (or Loader=SafeLoader).", taint_args=(0,)),
    "eval": Sink("TAINT-PY-EVAL", "Code injection — untrusted input reaches eval()",
                 "CWE-95", "A03", S.CRITICAL,
                 "Never eval untrusted input; parse data instead.", taint_args=(0,)),
    "exec": Sink("TAINT-PY-EXEC", "Code injection — untrusted input reaches exec()",
                 "CWE-95", "A03", S.CRITICAL,
                 "Never exec untrusted input.", taint_args=(0,)),
    "cursor.execute": Sink("TAINT-PY-SQLI", "SQL injection — untrusted input in the query string",
                           "CWE-89", "A03", S.CRITICAL,
                           "Use bind parameters: cursor.execute(sql, (value,)).",
                           taint_args=(0,), maps_to="V21"),
    "conn.execute": Sink("TAINT-PY-SQLI", "SQL injection — untrusted input in the query string",
                         "CWE-89", "A03", S.CRITICAL,
                         "Use bind parameters instead of building the SQL string.",
                         taint_args=(0,), maps_to="V21"),
    "mark_safe": Sink("TAINT-PY-XSS", "XSS — untrusted input marked as safe HTML",
                      "CWE-79", "A03", S.HIGH,
                      "Do not mark user input safe; let the template escape it, or sanitize "
                      "with a real HTML sanitizer first.", taint_args=(0,)),
    "Markup": Sink("TAINT-PY-XSS", "XSS — untrusted input wrapped in Markup()",
                   "CWE-79", "A03", S.HIGH,
                   "Markup() disables escaping. Pass the value as template context instead.",
                   taint_args=(0,)),
    "HttpResponse": Sink("TAINT-PY-XSS", "XSS — untrusted input written into an HTML response",
                         "CWE-79", "A03", S.HIGH,
                         "Render through a template so it is escaped, or set a non-HTML "
                         "content type and escape the value.", taint_args=(0,)),
    "send_file": Sink("TAINT-PY-PATH", "Path traversal — untrusted input names the file served",
                      "CWE-22", "A01", S.HIGH,
                      "Resolve the path, then verify it stays inside an allowed base directory.",
                      taint_args=(0,)),
    "send_from_directory": Sink("TAINT-PY-PATH",
                                "Path traversal — untrusted input names the file served",
                                "CWE-22", "A01", S.HIGH,
                                "send_from_directory checks the base, but only if the base is "
                                "not itself attacker-controlled; validate the filename too.",
                                taint_args=(1,)),
    "os.remove": Sink("TAINT-PY-PATH", "Path traversal — untrusted input names the file deleted",
                      "CWE-22", "A01", S.HIGH,
                      "Resolve the path, then verify it stays inside an allowed base directory.",
                      taint_args=(0,)),
    "os.unlink": Sink("TAINT-PY-PATH", "Path traversal — untrusted input names the file deleted",
                      "CWE-22", "A01", S.HIGH,
                      "Resolve the path, then verify it stays inside an allowed base directory.",
                      taint_args=(0,)),
    "os.rename": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a rename target",
                      "CWE-22", "A01", S.HIGH,
                      "Resolve both paths, then verify each stays inside an allowed base.",
                      taint_args=(0, 1)),
    "shutil.rmtree": Sink("TAINT-PY-PATH",
                          "Path traversal — untrusted input names a tree to delete",
                          "CWE-22", "A01", S.HIGH,
                          "Resolve the path, then verify it stays inside an allowed base.",
                          taint_args=(0,)),
    "shutil.move": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a move path",
                        "CWE-22", "A01", S.HIGH,
                        "Resolve both paths, then verify each stays inside an allowed base.",
                        taint_args=(0, 1)),
    "shutil.copy": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a copy path",
                        "CWE-22", "A01", S.HIGH,
                        "Resolve both paths, then verify each stays inside an allowed base.",
                        taint_args=(0, 1)),
    "shutil.copyfile": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a copy path",
                            "CWE-22", "A01", S.HIGH,
                            "Resolve both paths, then verify each stays inside an allowed base.",
                            taint_args=(0, 1)),
    "requests.get": Sink("TAINT-PY-SSRF", "SSRF — server fetches an untrusted URL",
                         "CWE-918", "A10", S.HIGH,
                         "Allowlist the destination host; block private/link-local ranges.",
                         taint_args=(0,)),
    "requests.post": Sink("TAINT-PY-SSRF", "SSRF — server posts to an untrusted URL",
                          "CWE-918", "A10", S.HIGH,
                          "Allowlist the destination host; block private/link-local ranges.",
                          taint_args=(0,)),
    "urllib.request.urlopen": Sink("TAINT-PY-SSRF", "SSRF — server opens an untrusted URL",
                                   "CWE-918", "A10", S.HIGH,
                                   "Allowlist the destination host; block private ranges.",
                                   taint_args=(0,)),
    "open": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a filesystem path",
                 "CWE-22", "A01", S.HIGH,
                 "Resolve the path, then verify it stays inside an allowed base directory.",
                 taint_args=(0,)),
    "render_template_string": Sink("TAINT-PY-SSTI",
                                   "Template injection — untrusted input compiled as a template",
                                   "CWE-1336", "A03", S.CRITICAL,
                                   "Pass user data as template context, never as the template.",
                                   taint_args=(0,)),
    # `Template(source).render()` is the same bug as `render_template_string`, written the way
    # Jinja's own API suggests. Both compile a string; only one of them was a sink.
    "Template": Sink("TAINT-PY-SSTI",
                     "Template injection — untrusted input compiled as a template",
                     "CWE-1336", "A03", S.CRITICAL,
                     "Pass user data as template context, never as the template source.",
                     taint_args=(0,)),
    "redirect": Sink("TAINT-PY-OPENREDIR", "Open redirect — untrusted input is the destination",
                     "CWE-601", "A01", S.MEDIUM,
                     "Redirect only to an allowlist of relative paths; reject absolute URLs.",
                     taint_args=(0,)),
    "HttpResponseRedirect": Sink("TAINT-PY-OPENREDIR",
                                 "Open redirect — untrusted input is the destination",
                                 "CWE-601", "A01", S.MEDIUM,
                                 "Redirect only to an allowlist of relative paths.",
                                 taint_args=(0,)),
    "RedirectResponse": Sink("TAINT-PY-OPENREDIR",
                             "Open redirect — untrusted input is the destination",
                             "CWE-601", "A01", S.MEDIUM,
                             "Redirect only to an allowlist of relative paths.",
                             taint_args=(0,)),
}

# Sinks whose receiver cannot be spelled out, because it is a model class, a session object or
# whatever the project called its connection. `PY_SINKS` matches the whole dotted name, which
# works for `os.system` and not at all for `Entry.objects.raw(q)` or `self.db.session.execute(q)`.
#
# This is the gap the RealVuln run found, and it was the expensive one: SQL injection is the
# class this engine leads with, and it scored 2 of 71 on real Django and FastAPI code. Not
# because the dataflow failed — because the ORM escape hatches, which are the only way SQL
# injection still happens in an ORM codebase, were not sinks at all. `.raw()`, `.extra()` and
# `session.execute(text(...))` are precisely the calls a framework provides for "I know what I
# am doing", and they are where the bug lives once an ORM is in play.
#
# Matched on the tail of the dotted name. `receivers=None` means any receiver: `.raw()` and
# `.extra()` are distinctive enough that requiring a tainted argument is the whole guard. For
# `execute` it is not — `executor.execute(task)` is an unrelated, common call — so that one
# names the receivers a database is actually reached through, and a receiver this list does not
# know is a documented miss rather than a mislabelled CWE-89.
PY_METHOD_SINKS: dict[str, tuple[Sink, tuple[str, ...] | None]] = {
    "raw": (Sink("TAINT-PY-SQLI-ORM",
                 "SQL injection — untrusted input in a raw ORM query",
                 "CWE-89", "A03", S.CRITICAL,
                 "Pass parameters to .raw(): `Model.objects.raw(sql, [value])`. The escape "
                 "hatch does not escape.", taint_args=(0,)), None),
    "extra": (Sink("TAINT-PY-SQLI-ORM",
                   "SQL injection — untrusted input in an ORM .extra() clause",
                   "CWE-89", "A03", S.CRITICAL,
                   "`.extra()` interpolates its SQL. Use `params=[...]`, or a filter that the "
                   "ORM compiles.", taint_args=(0,)), None),
    "exec_driver_sql": (Sink("TAINT-PY-SQLI-ORM",
                             "SQL injection — untrusted input passed straight to the driver",
                             "CWE-89", "A03", S.CRITICAL,
                             "Bind parameters instead of building the statement string.",
                             taint_args=(0,)), None),
    "execute": (Sink("TAINT-PY-SQLI", "SQL injection — untrusted input in the query string",
                     "CWE-89", "A03", S.CRITICAL,
                     "Use bind parameters instead of building the SQL string.",
                     taint_args=(0,), maps_to="V21"),
                ("cursor", "conn", "connection", "session", "db", "database", "engine", "pool",
                 "tx", "trans")),
    "executemany": (Sink("TAINT-PY-SQLI",
                         "SQL injection — untrusted input in the query string",
                         "CWE-89", "A03", S.CRITICAL,
                         "Use bind parameters; executemany binds a sequence, not a string.",
                         taint_args=(0,)),
                    ("cursor", "conn", "connection", "session", "db", "database", "engine",
                     "pool", "tx", "trans")),
    # NoSQL injection. A decoded request body handed to a Mongo query is a filter the caller
    # controls — `{"$ne": null}` walks straight past an authentication check. Only the method
    # names that are unmistakably pymongo are listed: a bare `.find()` is `str.find` far more
    # often than it is a collection query, and a wrong CWE-943 on string search would be worse
    # than the miss.
    **{name: (Sink("TAINT-PY-NOSQLI",
                   "NoSQL injection — untrusted input becomes the query document",
                   "CWE-943", "A03", S.HIGH,
                   "Never pass a decoded request body as a filter. Build the query from named "
                   "fields you validate, and reject operator keys ($ne, $gt, $where).",
                   taint_args=(0,)), None)
       for name in ("find_one", "find_one_and_update", "find_one_and_delete", "update_one",
                    "update_many", "delete_one", "delete_many", "count_documents",
                    "aggregate")},
}

# Logging calls. A tainted value reaching one of these is CWE-532 only when the value is the
# kind that must not be persisted — the whole request body, a header, a cookie, a credential.
# Every application logs *some* request-derived data on purpose (a path, a status, an id), so a
# rule that fired on any tainted argument would be noise on every well-behaved service, and the
# first thing anybody did with it would be to switch it off.
PY_LOG_SINK = Sink("TAINT-PY-LOG-SENSITIVE",
                   "Sensitive request data written to the logs unredacted",
                   "CWE-532", "A09", S.MEDIUM,
                   "Log an identifier, not the material: redact credentials, tokens, cookies "
                   "and raw bodies before they reach a log sink or an aggregator.")

_PY_LOG_CALLS = frozenset({"debug", "info", "warning", "warn", "error", "exception",
                           "critical", "log"})

# What makes a logged value sensitive, matched against the source expression the taint came
# from — `request.headers.get('authorization')` names it, `request.body` is the whole payload.
_PY_SENSITIVE_SOURCE = re.compile(
    r"\b(?:authorization|password|passwd|secret|token|api_?key|cookie|cookies|session|"
    r"credential|card|cvv|ssn|headers|body|get_data|stream)\b", re.I)

# Framework request objects: untrusted by construction, so a path rooted here is HIGH.
#
# The second line is the one that was missing, and it cost more than any absent sink: this list
# was the *entry point* to the whole analysis, so an attribute not named here made every sink
# downstream unreachable no matter how well modelled. `request.url` is how a Flask app reflects
# the current page back into an error template; `request.META` and `request.COOKIES` are how
# Django reads headers and cookies at all. Each omission silently switched the engine off for a
# whole framework idiom rather than for one rule.
PY_REQUEST_SOURCES = re.compile(
    r"^(?:request|self\.request|flask\.request)\."
    r"(?:args|form|values|json|data|files|cookies|headers|GET|POST|query_params|body"
    # Flask/Werkzeug: the URL and its parts are attacker-chosen, and so is anything the client
    # sends about itself.
    r"|url|base_url|url_root|full_path|path|query_string|referrer|user_agent|remote_addr"
    r"|host|host_url|stream|get_json|get_data|environ"
    # Django's names for the same things.
    r"|META|COOKIES|FILES|GET|POST|content_params|encoding|scheme|build_absolute_uri"
    r")\b")

# Calls whose result is no longer attacker-controlled in any way that matters to a sink.
PY_SANITIZERS = {
    "int", "float", "bool", "len", "shlex.quote", "shlex.join", "re.escape", "html.escape",
    "urllib.parse.quote", "urllib.parse.quote_plus", "os.path.basename", "uuid.UUID",
}

JS_SINKS: list[tuple[re.Pattern, Sink]] = [
    (re.compile(r"\b(?:db|conn|connection|pool|client|sequelize|knex)\s*\.\s*(?:query|raw)\s*\("),
     Sink("TAINT-JS-SQLI", "SQL injection — untrusted input in the query string",
          "CWE-89", "A03", S.CRITICAL,
          "Use a parameterized query: pass placeholders and bind the value as a parameter.",
          taint_args=(0,), maps_to="V1")),
    (re.compile(r"(?<![.\w])exec(?:Sync)?\s*\(|child_process\s*\.\s*exec(?:Sync)?\s*\("),
     Sink("TAINT-JS-CMDI", "Command injection — untrusted input reaches a shell",
          "CWE-78", "A03", S.CRITICAL,
          "Use execFile/spawn with an argument array (no shell) and validate the input.",
          taint_args=(0,), maps_to="V2")),
    (re.compile(r"(?<![.\w])eval\s*\("),
     Sink("TAINT-JS-EVAL", "Code injection — untrusted input reaches eval()",
          "CWE-95", "A03", S.CRITICAL,
          "Never eval untrusted input; use JSON.parse for data.",
          taint_args=(0,), maps_to="V15")),
    (re.compile(r"\bnew\s+Function\s*\("),
     Sink("TAINT-JS-SSTI", "Template injection — untrusted input compiled as code",
          "CWE-94", "A03", S.CRITICAL,
          "Pass user data as template context; never compile it as code.",
          maps_to="V16")),
    (re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
     Sink("TAINT-JS-XSS-WRITE", "XSS — untrusted input written into the document",
          "CWE-79", "A03", S.HIGH,
          "Build DOM nodes with textContent, or sanitize with DOMPurify first.",
          taint_args=(0,))),
    (re.compile(r"\bres(?:ponse)?\s*\.\s*redirect\s*\("),
     Sink("TAINT-JS-OPENREDIR", "Open redirect — untrusted input in the redirect target",
          "CWE-601", "A01", S.MEDIUM,
          "Redirect only to an allowlist of relative paths.", taint_args=(0,))),
    (re.compile(r"\bres(?:ponse)?\s*\.\s*writeHead\s*\("),
     Sink("TAINT-JS-OPENREDIR", "Open redirect — untrusted input in the Location header",
          "CWE-601", "A01", S.MEDIUM,
          "Redirect only to an allowlist of relative paths.",
          taint_args=(1,), maps_to="V11")),
    (re.compile(r"\bfs\s*\.\s*(?:promises\s*\.\s*)?"
                r"(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|"
                r"writeFileSync|appendFile|appendFileSync|readdir|readdirSync|unlink|"
                r"unlinkSync|rm|rmSync|rmdir|rmdirSync|rename|renameSync|copyFile|"
                r"copyFileSync|open|openSync|mkdir|mkdirSync)\s*\("),
     Sink("TAINT-JS-PATH", "Path traversal — untrusted input in a filesystem path",
          "CWE-22", "A01", S.HIGH,
          "Resolve the path, then verify it stays inside an allowed base directory.",
          taint_args=(0,), maps_to="V12")),
    # Express serves the file named here straight to the caller. `sendFile` takes an absolute
    # path and does no containment check of its own; `download` is the same call with a
    # Content-Disposition header on it.
    (re.compile(r"\bres(?:ponse)?\s*\.\s*(?:sendFile|download)\s*\("),
     Sink("TAINT-JS-PATH", "Path traversal — untrusted input names the file served",
          "CWE-22", "A01", S.HIGH,
          "Resolve the path, then verify it stays inside an allowed base directory — "
          "`res.sendFile` does not do that for you.", taint_args=(0,))),
    # Server-side reflected XSS, which is a different bug from the DOM sinks below and the one
    # real Express code actually has. `res.send(str)` sets `Content-Type: text/html` when it is
    # given a string, so a tainted string here is reflected into an HTML document. `res.json`
    # is deliberately absent: it serialises, and its content type is not HTML.
    (re.compile(r"\bres(?:ponse)?\s*\.\s*(?:send|write|end)\s*\("),
     Sink("TAINT-JS-XSS-REFLECTED",
          "XSS — untrusted input reflected into the HTML response",
          "CWE-79", "A03", S.HIGH,
          "Escape the value, or return it as JSON with `res.json()` so it is never parsed as "
          "HTML.", taint_args=(0,))),
    (re.compile(r"\.\s*insertAdjacentHTML\s*\("),
     Sink("TAINT-JS-XSS-DOM", "XSS — untrusted input inserted as HTML",
          "CWE-79", "A03", S.HIGH,
          "Use textContent or insertAdjacentText, or sanitize with DOMPurify first.",
          taint_args=(1,))),
    (re.compile(r"require\(\s*['\"]https?['\"]\s*\)\s*\.\s*(?:get|request)\s*\(|"
                r"\bhttps?\s*\.\s*(?:get|request)\s*\(|\baxios\s*\.\s*(?:get|post)\s*\(|"
                r"(?<![.\w])fetch\s*\("),
     Sink("TAINT-JS-SSRF", "SSRF — server fetches an untrusted URL",
          "CWE-918", "A10", S.HIGH,
          "Allowlist the destination host and block private / link-local ranges.",
          taint_args=(0,), maps_to="V7")),
    (re.compile(r"\bObject\s*\.\s*assign\s*\("),
     Sink("TAINT-JS-MASSASSIGN", "Mass assignment — untrusted object copied onto a model",
          "CWE-915", "A08", S.HIGH,
          "Copy only an explicit field allowlist; never bind the raw body.",
          taint_args=(1,), maps_to="V13")),
]

# Assignment-shaped sinks: `x.innerHTML = <tainted>`.
JS_ASSIGN_SINKS: list[tuple[re.Pattern, Sink]] = [
    (re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)"),
     Sink("TAINT-JS-XSS-DOM", "XSS — untrusted input assigned to innerHTML",
          "CWE-79", "A03", S.HIGH,
          "Use textContent, or sanitize with DOMPurify before assignment.", maps_to="V8")),
]

JS_REQUEST_SOURCES = re.compile(
    r"\breq(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies|files)(?:\s*\.\s*\w+)?"
    r"|\bctx\s*\.\s*(?:query|params|request)\b"
    r"|\blocation\s*\.\s*(?:search|hash|href)\b"
    r"|\bdocument\s*\.\s*(?:URL|documentURI|referrer)\b"
    r"|\bwindow\s*\.\s*name\b"
    r"|\bprocess\s*\.\s*argv\b")

# A membership test constrains a value to a known finite set, so what comes out of one is no
# longer attacker-chosen. This is what makes `ALLOWLIST.has(next) ? next : '/'` safe.
JS_SANITIZER = re.compile(
    r"\.\s*(?:has|includes)\s*\(|DOMPurify\s*\.\s*sanitize\s*\(|encodeURIComponent\s*\(|"
    r"\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\s*\(")

JS_GUARD_EXIT = re.compile(r"\breturn\b|\bthrow\b|\bnext\s*\(\s*[a-zA-Z]")

