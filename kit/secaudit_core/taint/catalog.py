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
    # Starlette's, and therefore FastAPI's, name for the same thing. Django's was here from the
    # start and this one was not, which left the whole FastAPI half of the corpus with no HTML
    # response sink at all — the same class of omission as a missing source, and with the same
    # effect: the engine is switched off for one framework's idiom while looking complete.
    # `HTMLResponse` is unambiguous in a way `Response` is not: the class name *is* the content
    # type, so there is no non-HTML use of it to be wrong about.
    "HTMLResponse": Sink("TAINT-PY-XSS", "XSS — untrusted input written into an HTML response",
                         "CWE-79", "A03", S.HIGH,
                         "Return JSON, or render through a template that escapes the value. "
                         "HTMLResponse writes the string to the page exactly as given.",
                         taint_args=(0,)),
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
    # The rest of the ordinary outbound-HTTP surface. Until this round the SSRF vocabulary was
    # three names — `requests.get`, `requests.post`, `urllib.request.urlopen` — which is the
    # shape a rule takes when it is written against the two calls in the fixture that motivated
    # it. Measured against the external corpus: 21 SSRF labels missed, and **16 of them had no
    # finding of ours anywhere in the file**. Not a threshold, not a depth problem. The library
    # was simply not in the list.
    #
    # Every name here is unambiguous: it exists to make a request leave the machine, and the
    # rule still requires a proven taint path to reach it. `urlopen` appears bare as well as
    # dotted because `from urllib.request import urlopen` is how it is imported in practice and
    # `PY_SINKS` matches the written dotted name — the same reason `open` is in this table bare.
    **{name: Sink("TAINT-PY-SSRF", "SSRF — server fetches an untrusted URL",
                  "CWE-918", "A10", S.HIGH,
                  "Allowlist the destination host; block private/link-local ranges.",
                  taint_args=(0,))
       for name in ("requests.put", "requests.patch", "requests.delete", "requests.head",
                    "requests.options", "urlopen", "urllib.request.urlretrieve",
                    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
                    "httpx.head", "httpx.options", "httpx.stream")},
    # `request(method, url)` puts the URL second, which is the whole reason these three cannot
    # share the block above: reporting on argument 0 would ask whether the *verb* is attacker-
    # controlled and answer no on every real call.
    **{name: Sink("TAINT-PY-SSRF", "SSRF — server issues a request to an untrusted URL",
                  "CWE-918", "A10", S.HIGH,
                  "Allowlist the destination host; block private/link-local ranges.",
                  taint_args=(1,))
       for name in ("requests.request", "httpx.request", "urllib3.request")},
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
# Receivers an outbound HTTP client is reached through. Deliberately a list rather than `None`:
# `.get()` is the single most common method name in Python and matching it on any receiver would
# label `config.get(key)` and `dict.get(name)` as SSRF. Naming the receivers is what keeps a
# CWE-918 on the calls that actually leave the machine — and a client bound to a name this list
# does not know is a documented miss rather than a mislabelled finding.
# `session` is NOT here, and leaving it out costs real recall on purpose. `requests.Session()`
# is idiomatically bound to `session` — but so is Flask's request session, and `session.get(key)`
# is one of the most common lines in a Flask application. A receiver list that contained both
# would put CWE-918 on a dictionary lookup, and the taint requirement does not save it:
# `session.get(request.args["k"])` is a tainted argument to a `.get()` on a receiver named
# `session`. The same reasoning excludes `s`, `api` and `self`.
#
# `.get()` and `.post()` are not method sinks here at all, for the same reason one level up:
# they are the two most common method names in Python. An HTTP client reached ONLY through
# `client.get(url)` is a documented miss — `limitations()` says so — and the dotted forms
# (`requests.get`, `httpx.get`) are in `PY_SINKS` above, which is how these calls are written
# most of the time.
_HTTP_RECEIVERS = ("conn", "connection", "http", "https", "urllib3", "pool", "manager",
                   "client", "httpx", "requests")


def _ssrf_method(what: str, arg: int) -> Sink:
    return Sink("TAINT-PY-SSRF", f"SSRF — server {what} an untrusted URL",
                "CWE-918", "A10", S.HIGH,
                "Allowlist the destination host; block private/link-local ranges.",
                taint_args=(arg,))


PY_METHOD_SINKS: dict[str, tuple[Sink, tuple[str, ...] | None]] = {
    # `http.client` and `urllib3` put the URL second — `conn.request("GET", path)` — and
    # `putrequest` has the same signature. `session.get(url)` puts it first.
    "putrequest": (_ssrf_method("issues a request to", 1), _HTTP_RECEIVERS),
    "request": (_ssrf_method("issues a request to", 1), _HTTP_RECEIVERS),
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

    # `pathlib`, which this catalog did not model at all. The whole of it read as one sink —
    # the builtin `open` — and modern Python does not call `open`:
    #
    #     parcel_path = BASE_EXPORT_DIR / packet_ref
    #     data = parcel_path.read_text()
    #
    # Ten of the 36 labelled path-traversal misses on RealVuln are that exact shape, across
    # FastAPI and Django, and in every one of them the *source* was already modelled — the
    # engine reported SSRF, SSTI and open-redirect in the same handlers from the same route
    # parameters. Sources were never the gap. This is why `path_traversal` sat at 3 of 39 while
    # two rounds of adding filesystem sinks moved nothing: the sinks being added were more ways
    # to spell `open`, and the code under test had stopped spelling it that way.
    #
    # The taint is in the receiver, not an argument, which is what `taint_receiver` exists for.
    # Listed with `receivers=None` because a Path is held in a variable named whatever the author
    # chose (`parcel_path`, `dest`, `p`), so there is no receiver name to key on — the method
    # names carry the specificity instead. `read_text`/`write_bytes` and friends are `pathlib`
    # and essentially nothing else; a `.open()` on a tainted receiver is the same bug whatever
    # the type turns out to be.
    **{name: (Sink("TAINT-PY-PATH",
                   "Path traversal — untrusted input builds the path being opened",
                   "CWE-22", "A01", S.HIGH,
                   "Resolve the path and verify it stays inside an allowed base directory: "
                   "`p = (base / name).resolve()` then check `p.is_relative_to(base)`. Joining "
                   "onto a base directory is not a check — `../` walks straight out of it.",
                   taint_receiver=True), None)
       for name in ("read_text", "read_bytes", "write_text", "write_bytes", "open")},

    # Same class, taken by argument rather than by receiver: `Path('/tmp').glob(prefix + name)`
    # lets the caller choose the pattern, and `*`/`**` in a pattern reads across directories.
    "glob": (Sink("TAINT-PY-PATH",
                  "Path traversal — untrusted input becomes a filesystem glob pattern",
                  "CWE-22", "A01", S.HIGH,
                  "Match against a validated name, not a pattern built from input: a caller who "
                  "controls the pattern controls which files are enumerated.",
                  taint_args=(0,)), None),
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
    # `new Function(body)` — and `Function(body)` without `new`, which does exactly the same
    # thing and is how the shipped code actually writes it. SecBench.js has two labelled sinks
    # of the second form (`Function('obj', 'return ' + selectorValue)`), and the `new` in this
    # pattern was the whole reason neither was reachable.
    (re.compile(r"(?<![.\w])(?:new\s+)?Function\s*\("),
     Sink("TAINT-JS-SSTI", "Template injection — untrusted input compiled as code",
          "CWE-94", "A03", S.CRITICAL,
          "Pass user data as template context; never compile it as code.",
          maps_to="V16")),
    # Node's `vm` is a sink family too — it is marketed as a sandbox, is not one, and says so in
    # its own documentation. It does not live here: which object `runInContext` belongs to is a
    # question about the file's imports, and `JS_INLINE_MODULE_SINKS` / `js_local_module_sinks`
    # answer it. The reason is one package deep in the corpus — see the note there.
    #
    # `(0, eval)(code)` — indirect eval, which runs in global scope rather than the caller's.
    # A deliberate idiom, always written on purpose, and invisible to a pattern anchored on
    # `eval(` because the parenthesis after `eval` is the one closing the comma expression.
    (re.compile(r"\(\s*0\s*,\s*eval\s*\)\s*\("),
     Sink("TAINT-JS-EVAL", "Code injection — untrusted input reaches indirect eval",
          "CWE-95", "A03", S.CRITICAL,
          "Never eval untrusted input; use JSON.parse for data.",
          taint_args=(0,), maps_to="V15")),
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

# --------------------------------------------------------- who is the receiver of `.exec(`?
#
# `JS_SINKS` anchors its shell entry on a bare `exec(` or the literal receiver `child_process`,
# and that lookbehind is load-bearing: `pattern.exec(string)` is the RegExp method and is the
# most common `.exec(` in the language. Anchoring on the name misses every ordinary spelling of
# the import, though, and SecBench.js says what that costs — **14 of the 44 unsealed
# command-injection misses are a receiver this could not name**:
#
#     const cp = require('child_process');      cp.exec(cmd)
#     import * as childProcess from 'child_process';   childProcess.exec(cmd)
#     child_process_1.exec(cmd)                 // what TypeScript emits for a namespace import
#     require('child_process').execSync(cmd)
#     const cp_exec = util.promisify(cp.exec);  await cp_exec(cmd)
#     const shell = require('shelljs');         shell.exec(cmd)
#
# So the receiver is **resolved from the file's own imports** rather than guessed from its name.
# That is both wider and narrower than a name list: `sh.exec` is a sink in a file that imported
# `child_process` as `sh`, and `re.exec` is not a sink in a file that did not — which is the
# property a name list cannot have. Nothing here decides taint; this only decides what the sink
# *is*, and the value still has to reach it.
#
# Measured with the two seeding fixes it shipped beside (an object-literal method and a
# `function(a)` written without a space both bind parameters now): **command injection 41 → 62
# of 101, code injection 19 → 23 of 33, and path traversal 124 → 129** on SecBench.js, for
# **one additional finding across 382,057 lines** of the noise-floor corpus and no change at all
# on RealVuln.
#
# The same mechanism would serve `fs`/`path` (`const fsp = require('fs').promises`), and it is
# deliberately not wired there yet: those classes are at 74% on the corpus that would measure it,
# so widening them is a round with its own before-and-after rather than a change smuggled in
# beside this one.
_SHELL_MODULES = r"(?:node:)?(?:child_process|shelljs)"
_VM_MODULE = r"(?:node:)?vm"


def _module_aliases(text: str, module: str) -> tuple[set[str], set[str]]:
    """`(namespace receivers, named imports)` this file binds to `module`.

    Receivers are objects the module was imported *as*; named imports are the functions taken
    out of it, under whatever name they were given. Three spellings of each, because a file
    written in TypeScript, CommonJS or ESM says the same thing three ways and the analysis has
    to read all three:

        const cp = require('child_process')      import * as cp from 'child_process'
        import cp = require('child_process')     import cp from 'child_process'
        const { exec: run } = require('...')     import { execSync as sh } from '...'
    """
    receivers: set[str] = set()
    named: set[str] = set()
    for m in re.finditer(
            rf"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]{module}['\"]"
            rf"|import\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['\"]{module}['\"]"
            rf"|import\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]{module}['\"]", text):
        receivers.add(next(g for g in m.groups() if g))
    for m in re.finditer(
            rf"(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*require\s*\(\s*['\"]{module}['\"]"
            rf"|import\s*\{{([^}}]*)\}}\s*from\s*['\"]{module}['\"]", text):
        for part in (m.group(1) or m.group(2) or "").split(","):
            head, _, tail = part.partition(":")
            if not tail:
                head, _, tail = part.partition(" as ")
            name = (tail or head).strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                named.add(name)
    return receivers, named


# `const run = util.promisify(cp.exec)` — the promisified form, which is how every modern
# async wrapper reaches the same shell. The name on the left is the sink from then on.
_JS_PROMISIFIED = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:util\s*\.\s*)?promisify\s*\("
    # Up to the end of the statement rather than to the first `)`: the argument is very often
    # `require('child_process').exec`, and stopping at a bracket stops inside the require.
    r"[^;\n]*?\bexec(?:Sync)?\b")

JS_SHELL_SINK = Sink(
    "TAINT-JS-CMDI", "Command injection — untrusted input reaches a shell",
    "CWE-78", "A03", S.CRITICAL,
    "Use execFile/spawn with an argument array (no shell) and validate the input.",
    taint_args=(0,), maps_to="V2")

JS_VM_SINK = Sink(
    "TAINT-JS-VM", "Code injection — untrusted input compiled by the `vm` module",
    "CWE-94", "A03", S.CRITICAL,
    "`vm` is not a security boundary — its own documentation says so. Do not compile "
    "caller-supplied strings; parse the data you actually need instead.",
    taint_args=(0,), maps_to="V15")

# The methods each family makes dangerous on a resolved receiver.
_SHELL_METHODS = r"exec(?:Sync|File|FileSync)?"
_VM_METHODS = r"runInThisContext|runInNewContext|runInContext|compileFunction"


def js_local_module_sinks(text: str) -> list[tuple[re.Pattern[str], Sink]]:
    """The extra `(pattern, sink)` pairs this file's own imports justify.

    **`vm` is here rather than in the global catalog because of lodash.** The first version
    matched a bare `runInContext(` as well as `vm.runInContext(`, and lodash exports its own
    `runInContext` — a completely unrelated function that rebuilds the library against a
    different global object. One package into the corpus and the rule had a false positive that
    no amount of taint reasoning would have refused, because the call really is
    `runInContext(<something derived from a parameter>)`. A name is not an identity; an import
    is.
    """
    out: list[tuple[re.Pattern[str], Sink]] = []
    receivers, named = _module_aliases(text, _SHELL_MODULES)
    bare = set(named) | {m.group(1) for m in _JS_PROMISIFIED.finditer(text)}
    parts = []
    if receivers:
        parts.append(rf"\b(?:{'|'.join(sorted(re.escape(n) for n in receivers))})"
                     rf"\s*\.\s*(?:{_SHELL_METHODS})\s*\(")
    if bare:
        parts.append(rf"(?<![.\w])(?:{'|'.join(sorted(re.escape(n) for n in bare))})\s*\(")
    if parts:
        out.append((re.compile("|".join(parts)), JS_SHELL_SINK))

    vm_receivers, vm_named = _module_aliases(text, _VM_MODULE)
    vm_parts = []
    if vm_receivers:
        names = "|".join(sorted(re.escape(n) for n in vm_receivers))
        vm_parts.append(rf"\b(?:{names})\s*\.\s*(?:{_VM_METHODS})\s*\(")
        vm_parts.append(rf"\bnew\s+(?:{names})\s*\.\s*Script\s*\(")
    if vm_named:
        names = "|".join(sorted(re.escape(n) for n in vm_named))
        vm_parts.append(rf"(?<![.\w])(?:new\s+)?(?:{names})\s*\(")
    if vm_parts:
        out.append((re.compile("|".join(vm_parts)), JS_VM_SINK))
    return out


# Spellings that name the module at the call site and so need no alias at all.
JS_INLINE_MODULE_SINKS = (
    (re.compile(rf"require\s*\(\s*['\"]{_SHELL_MODULES}['\"]\s*\)\s*\.\s*"
                rf"(?:{_SHELL_METHODS})\s*\("), JS_SHELL_SINK),
    (re.compile(rf"\bvm\s*\.\s*(?:{_VM_METHODS})\s*\(|\bnew\s+vm\s*\.\s*Script\s*\("
                rf"|require\s*\(\s*['\"]{_VM_MODULE}['\"]\s*\)\s*\.\s*"
                rf"(?:{_VM_METHODS})\s*\("), JS_VM_SINK),
)

# Framework request objects. `PY_REQUEST_SOURCES` carries a comment saying that this list is the
# *entry point* to the whole analysis, so an attribute missing from it switches the engine off
# for a whole framework idiom rather than for one rule. That was written about Python and is just
# as true here, and `req.url` — the single most common source in Node — was not in it.
#
# What that cost, measured on SecBench.js: **63 of 84 unsealed path-traversal misses are
# `fs.readFile(<var>)`**, with the filesystem sinks already modelled comprehensively. The corpus
# is full of small static file servers built on `http.createServer`, where there is no Express
# `req.query` anywhere — the request *is* `req.url`:
#
#     function handleRequest(req, res) { loadFile(req.url, …) }
#     var loadFile = function (file, …) { file = path.join(config.dir, file)
#                                         fs.readFile(file, …) }
#
# `path.join` onto a base directory is not a containment check; `../` walks straight out of it.
# The sink was modelled, the source was not, and the two never met — the mirror image of what
# `pathlib` did to `path_traversal` on the Python side in the same round.
JS_REQUEST_SOURCES = re.compile(
    r"\breq(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies|files)(?:\s*\.\s*\w+)?"
    # The raw Node server's whole request surface. `url` is the path and query string as sent;
    # Express adds `originalUrl` (before any router rewrote it), `path` and `baseUrl`.
    r"|\breq(?:uest)?\s*\.\s*(?:url|originalUrl|path|baseUrl)\b"
    r"|\bctx\s*\.\s*(?:query|params|request|url|path|querystring|originalUrl)\b"
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

