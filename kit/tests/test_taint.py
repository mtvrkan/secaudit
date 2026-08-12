#!/usr/bin/env python3
"""Taint tier tests — the source→sink reachability engine and its lexical support.

Three layers, because the engine's value and its risk live in different places:

  1. **Unit** — `code_view`, `blank_strings`, `split_args`. These decide what the analyzer is
     allowed to see, and a bug here is silent: it does not crash, it just stops finding things
     (or starts finding things that are not there).
  2. **Behaviour** — small hand-written snippets, one per rule the engine implements. Each has
     a vulnerable form that MUST be found and a safe form that MUST NOT be, so every assertion
     measures precision and recall together rather than one at a time.
  3. **Corpus** — the shipped fixtures, asserting the classes only the taint tier can reach and
     zero HIGH-confidence paths on the negative control.
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import taint                              # noqa: E402
from secaudit_core.schema import Confidence                  # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")
SECURE = os.path.join(REPO, "tests", "fixtures", "secure-app")

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def sinks(path: str, code: str) -> set[str]:
    return {p.sink.id for p in taint.analyze(path, code)}


def expect(path: str, code: str, sink_id: str, present: bool, label: str) -> None:
    """One snippet, one rule, one direction. `present=False` is a precision assertion."""
    found = sink_id in sinks(path, code)
    if found != present:
        verb = "missed" if present else "false-positived on"
        fails.append(f"{label}: {verb} {sink_id}")


# --------------------------------------------------------------------------- 1. unit

def test_code_view() -> None:
    src = 'x = "eval(a)"  # eval(b)\nif True: eval(c)\n'
    view = taint.code_view(src, "m.py")
    check(view is not None, "code_view returned None for .py")
    check(len(view) == len(src), "code_view changed the length — offsets would shift")
    check(view.count("eval(") == 1, "code_view left a literal or comment `eval(` visible")
    check("eval(c)" in view, "code_view blanked a real call")
    check(view.count("\n") == src.count("\n"), "code_view lost a newline — line numbers shift")

    triple = 'D = """\nos.system(x)\n"""\nos.system(y)\n'
    tview = taint.code_view(triple, "m.py")
    check(tview.count("os.system(") == 1, "code_view did not blank a triple-quoted literal")

    js = "const a = 'exec(1)'; // exec(2)\n/* exec(3) */ exec(4);"
    jview = taint.code_view(js, "m.js")
    check(jview.count("exec(") == 1, "code_view leaked a JS comment/literal sink")

    check(taint.code_view("anything", "m.swift") is None,
          "code_view must return None for an unmodeled language, not a partial blanking")


def test_blank_strings() -> None:
    check(taint.blank_strings("f('data', x)") == "f('    ', x)",
          "blank_strings did not blank a single-quoted literal in place")
    kept = taint.blank_strings("`a${user.name}b`")
    check("user.name" in kept, "blank_strings dropped a template interpolation (it is code)")
    check("a" not in kept.replace("user.name", ""), "blank_strings kept template literal text")


def test_split_args() -> None:
    check(taint.split_args("a, b") == ["a", "b"], "split_args basic")
    check(taint.split_args("f(a, b), c") == ["f(a, b)", "c"], "split_args nested call")
    check(taint.split_args("'a, b', c") == ["'a, b'", "c"], "split_args comma inside a string")
    check(taint.split_args("[1, 2], x") == ["[1, 2]", "x"], "split_args array literal")


# --------------------------------------------------------------------------- 2. behaviour

def test_python_rules() -> None:
    expect("a.py", "import subprocess\n"
                   "def f(host):\n"
                   "    cmd = 'ping ' + host\n"
                   "    subprocess.call(cmd, shell=True)\n",
           "TAINT-PY-CMDI-SHELL", True, "py: param → concat → shell=True")

    expect("a.py", "import subprocess\n"
                   "def f(host):\n"
                   "    subprocess.call(['ping', host])\n",
           "TAINT-PY-CMDI-SHELL", False, "py: argument list without shell=True is the fix")

    expect("a.py", "import subprocess, re\n"
                   "def f(host):\n"
                   "    if not re.match(r'^[a-z]+$', host):\n"
                   "        raise ValueError('bad')\n"
                   "    subprocess.call('ping ' + host, shell=True)\n",
           "TAINT-PY-CMDI-SHELL", False, "py: validate-then-raise guard clears taint")

    expect("a.py", "import pickle, base64\n"
                   "def f(cookie):\n"
                   "    return pickle.loads(base64.b64decode(cookie))\n",
           "TAINT-PY-DESER", True, "py: taint survives a call that is not a sanitizer")

    expect("a.py", "import subprocess\n"
                   "def f(n):\n"
                   "    subprocess.call('sleep ' + str(int(n)), shell=True)\n",
           "TAINT-PY-CMDI-SHELL", False, "py: int() is a sanitizer")

    expect("a.py", "def f(request):\n"
                   "    q = 'SELECT * FROM t WHERE a=' + request.args['a']\n"
                   "    cursor.execute(q)\n",
           "TAINT-PY-SQLI", True, "py: framework request source across lines")

    # A framework request source is HIGH; a bare parameter is only a MEDIUM lead.
    paths = taint.analyze("a.py", "def f(request):\n    eval(request.args['x'])\n")
    check(paths and paths[0].confidence == Confidence.HIGH,
          "py: request-rooted path must be HIGH confidence")
    paths = taint.analyze("a.py", "def f(x):\n    eval(x)\n")
    check(paths and paths[0].confidence == Confidence.MEDIUM,
          "py: parameter-rooted path must be MEDIUM confidence")

    check(taint.analyze("a.py", "def f(:\n") == [],
          "py: a file that does not parse must return [], not raise")


def test_python_interprocedural() -> None:
    """The near-universal real shape: a handler reads the request, a helper does the damage."""
    handler_helper = ("import os\n"
                      "def handler():\n"
                      "    return run(request.args['cmd'])\n"
                      "def run(v):\n"
                      "    return os.system(v)\n")
    paths = taint.analyze("a.py", handler_helper)
    check(len(paths) == 1,
          f"py: one bug must produce one path, not one per view of it (got {len(paths)})")
    check(paths and paths[0].confidence == Confidence.HIGH,
          "py: a request source reaching a sink through a call is HIGH, not a parameter lead")
    check(paths and "passed to run(v)" in paths[0].describe(),
          "py: the rendered path must name the call it crossed, or it cannot be followed")
    check(paths and paths[0].sink.id == "TAINT-PY-CMDI",
          "py: the interprocedural path must carry the callee's sink")
    check(paths and paths[0].sink_line == 5,
          f"py: the path must terminate on the callee's sink line "
          f"(got {paths[0].sink_line if paths else None})")

    two_hops = ("import subprocess\n"
                "def view():\n"
                "    return outer(request.form['host'])\n"
                "def outer(h):\n"
                "    return inner(h)\n"
                "def inner(x):\n"
                "    return subprocess.call('ping ' + x, shell=True)\n")
    paths = taint.analyze("a.py", two_hops)
    check(len(paths) == 1 and paths[0].confidence == Confidence.HIGH,
          "py: a two-hop chain must resolve to a single HIGH path")

    # A local function that does not pass parameter taint to its return value launders it.
    laundered = ("import os\n"
                 "def handler():\n"
                 "    return run(to_id(request.args['n']))\n"
                 "def to_id(v):\n"
                 "    return int(v)\n"
                 "def run(v):\n"
                 "    return os.system(v)\n")
    paths = taint.analyze("a.py", laundered)
    check(not any(p.confidence == Confidence.HIGH for p in paths),
          "py: a local function returning a sanitized value must not carry taint onward")

    # A helper that fetches the source itself, with no parameter involved.
    fetches = ("import os\n"
               "def q():\n"
               "    return request.args['c']\n"
               "def handler():\n"
               "    os.system(q())\n")
    check("TAINT-PY-CMDI" in sinks("a.py", fetches),
          "py: a helper that returns untrusted input must taint its caller")

    # A guard inside the callee still clears the taint for every caller.
    guarded = ("import subprocess, re\n"
               "def handler():\n"
               "    return run(request.args['h'])\n"
               "def run(h):\n"
               "    if not re.match(r'^[a-z]+$', h):\n"
               "        raise ValueError()\n"
               "    return subprocess.call('ping ' + h, shell=True)\n")
    check(not taint.analyze("a.py", guarded),
          "py: a validation guard in the callee must clear taint for callers too")

    # Mutual recursion must terminate rather than iterate forever.
    recursive = ("import os\n"
                 "def a(x):\n"
                 "    return b(x)\n"
                 "def b(x):\n"
                 "    return a(x) if x else os.system(x)\n")
    taint.analyze("a.py", recursive)   # the assertion is that this returns at all


def test_js_interprocedural() -> None:
    """The same shape as `test_python_interprocedural`, deliberately mirrored.

    Two front ends over one summary lattice is only worth the complexity if both actually
    reach the same conclusions, so these assertions are the Python ones transliterated. Where
    they diverge, it is because the JS side genuinely cannot delimit the function — and that
    divergence is asserted too, so it stays a known bound instead of drifting into a surprise.
    """
    handler_helper = ("function run(v) {\n"
                      "  exec(v);\n"
                      "}\n"
                      "app.get('/x', (req, res) => {\n"
                      "  run(req.query.cmd);\n"
                      "});\n")
    paths = taint.analyze("a.js", handler_helper)
    check(len(paths) == 1,
          f"js: one bug must produce one path, not one per view of it (got {len(paths)})")
    check(paths and paths[0].confidence == Confidence.HIGH,
          "js: a request source reaching a sink through a call is HIGH, not a parameter lead")
    check(paths and "passed to run(v)" in paths[0].describe(),
          "js: the rendered path must name the call it crossed, or it cannot be followed")
    check(paths and paths[0].sink_line == 2,
          f"js: the path must terminate on the callee's sink line "
          f"(got {paths[0].sink_line if paths else None})")

    two_hops = ("const outer = (h) => {\n"
                "  return inner(h);\n"
                "};\n"
                "function inner(x) {\n"
                "  exec('ping ' + x);\n"
                "}\n"
                "app.get('/p', (req, res) => outer(req.query.host));\n")
    check(any(p.confidence == Confidence.HIGH for p in taint.analyze("a.js", two_hops)),
          "js: a two-hop chain across an arrow and a declaration must resolve")

    # A local helper that does not pass parameter taint to its return value launders it.
    laundered = ("const ALLOWED = new Set(['a', 'b']);\n"
                 "function pick(v) {\n"
                 "  return ALLOWED.has(v) ? v : 'a';\n"
                 "}\n"
                 "function run(v) {\n"
                 "  exec(v);\n"
                 "}\n"
                 "app.get('/x', (req, res) => {\n"
                 "  run(pick(req.query.cmd));\n"
                 "});\n")
    check(not any(p.confidence == Confidence.HIGH for p in taint.analyze("a.js", laundered)),
          "js: a local function returning a constrained value must not carry taint onward")

    # A helper that fetches the source itself, with no parameter involved.
    fetches = ("function q() {\n"
               "  return location.search;\n"
               "}\n"
               "function boom() {\n"
               "  eval(q());\n"
               "}\n")
    check("TAINT-JS-EVAL" in sinks("a.js", fetches),
          "js: a helper that returns untrusted input must taint its caller")

    # A guard inside the callee clears the taint for every caller.
    guarded = ("function run(h) {\n"
               "  if (!/^[a-z]+$/.test(h)) return;\n"
               "  exec('ping ' + h);\n"
               "}\n"
               "app.get('/p', (req, res) => run(req.query.host));\n")
    check(not taint.analyze("a.js", guarded),
          "js: a validation guard in the callee must clear taint for callers too")

    # A brace inside a string literal must not move a function's boundary — extraction runs
    # over `code_view` precisely so this cannot silently misattribute the sink below.
    braces_in_literal = ("function safe(v) {\n"
                         "  return JSON.stringify({ tpl: '${x} } }' });\n"
                         "}\n"
                         "function run(v) {\n"
                         "  exec(v);\n"
                         "}\n"
                         "app.get('/x', (req, res) => run(req.query.c));\n")
    check(any(p.confidence == Confidence.HIGH for p in taint.analyze("a.js", braces_in_literal)),
          "js: a brace inside a string literal must not shift function boundaries")

    # Documented bound, asserted so it stays documented: a helper on an object property has
    # no delimitable body, so no summary — the path is a MEDIUM lead at best, never a silent
    # claim that the code is clean.
    method_form = ("const h = {\n"
                   "  run(v) { exec(v); }\n"
                   "};\n"
                   "app.get('/x', (req, res) => h.run(req.query.cmd));\n")
    check(not any(p.confidence == Confidence.HIGH for p in taint.analyze("a.js", method_form)),
          "js: an object-method helper is a documented bound — it must not be claimed as HIGH")

    # Mutual recursion must terminate rather than iterate forever.
    recursive = ("function a(x) { return b(x); }\n"
                 "function b(x) { return x ? a(x) : exec(x); }\n")
    taint.analyze("a.js", recursive)   # the assertion is that this returns at all


def test_cross_module() -> None:
    """The import edge — where the route that reads the request and the module that does the
    dangerous thing are, in real code, almost never the same file.

    Every assertion here has a matching negative: a resolution that fires on the wrong pair of
    files is worse than one that does not fire, because it attributes a real sink to a function
    that never sees the value."""
    js = {
        "app/util.js": ("const { exec } = require('child_process');\n"
                        "function runReport(name) {\n"
                        "  exec('report --for ' + name);\n"
                        "}\n"
                        "function pick(raw) { return ALLOW.has(raw) ? raw : 'a'; }\n"
                        "module.exports = { runReport, pick };\n"),
        "app/server.js": ("const { runReport, pick } = require('./util');\n"
                          "app.get('/r', (req, res) => {\n"
                          "  runReport(req.query.label);\n"
                          "});\n"),
    }
    paths = taint.analyze_files(js)
    check(len(paths) == 1, f"js: one cross-module bug must produce one path (got {len(paths)})")
    check(paths and paths[0].confidence == Confidence.HIGH,
          "js: a request reaching an imported helper's sink is HIGH")
    check(paths and paths[0].file == "app/server.js",
          "js: the finding belongs where the untrusted value enters — that is the route "
          "someone has to recognise")
    check(paths and paths[0].sink_file == "app/util.js" and paths[0].sink_line == 3,
          f"js: the sink location must name the callee's file and line "
          f"(got {paths[0].sink_file}:{paths[0].sink_line if paths else 0})")
    check(paths and "app/util.js:runReport()" in paths[0].describe(),
          "js: the rendered path must name the module it crossed")

    # Laundering through an imported helper works the same as through a local one.
    laundered = dict(js)
    laundered["app/server.js"] = ("const { runReport, pick } = require('./util');\n"
                                  "app.get('/r', (req, res) => {\n"
                                  "  runReport(pick(req.query.label));\n"
                                  "});\n")
    check(not any(p.confidence == Confidence.HIGH for p in taint.analyze_files(laundered)),
          "js: an imported helper that constrains its argument must launder across the module "
          "boundary too")

    # A bare specifier is a package, not our code. Resolving it by name would attach our
    # summary to somebody else's function.
    package = {
        "util.js": ("function runReport(name) { exec('report ' + name); }\n"
                    "module.exports = { runReport };\n"),
        "server.js": ("const { runReport } = require('some-npm-package');\n"
                      "app.get('/r', (req, res) => { runReport(req.query.label); });\n"),
    }
    check(not any(p.confidence == Confidence.HIGH for p in taint.analyze_files(package)),
          "a bare specifier must not resolve to a same-named local file")

    py = {
        "svc/helpers.py": "import os\ndef run_job(cmd):\n    return os.system(cmd)\n",
        "svc/views.py": ("from .helpers import run_job\n"
                         "def view():\n"
                         "    return run_job(request.args['cmd'])\n"),
    }
    paths = taint.analyze_files(py)
    check(len(paths) == 1 and paths[0].confidence == Confidence.HIGH,
          f"py: a relative import must carry taint across the module boundary "
          f"(got {len(paths)} path(s))")
    check(paths and paths[0].sink_file == "svc/helpers.py",
          "py: the sink must be attributed to the defining module")

    # `import helpers` + `helpers.run_job(x)` — a dotted call is still a name.
    dotted = {
        "svc/helpers.py": "import os\ndef run_job(cmd):\n    return os.system(cmd)\n",
        "svc/views.py": ("import helpers\n"
                         "def view():\n"
                         "    return helpers.run_job(request.args['cmd'])\n"),
    }
    check(any(p.confidence == Confidence.HIGH for p in taint.analyze_files(dotted)),
          "py: `import mod` + `mod.f(x)` must resolve")

    # An aliased import must follow the alias, not the original name.
    aliased = {
        "svc/helpers.py": "import os\ndef run_job(cmd):\n    return os.system(cmd)\n",
        "svc/views.py": ("from .helpers import run_job as go\n"
                         "def view():\n"
                         "    return go(request.args['cmd'])\n"),
    }
    check(any(p.confidence == Confidence.HIGH for p in taint.analyze_files(aliased)),
          "py: an aliased import must resolve under its local name")

    # Three modules deep: top -> mid -> sink. This needs the module-graph fixed point — until
    # `mid` learns that `boom` reaches a sink, `relay` looks harmless and `top` sees nothing.
    three_hops = {
        "a/sink.py": "import os\ndef boom(c):\n    return os.system(c)\n",
        "a/mid.py": "from .sink import boom\ndef relay(c):\n    return boom(c)\n",
        "a/top.py": ("from .mid import relay\n"
                     "def view():\n"
                     "    return relay(request.args['c'])\n"),
    }
    hops = taint.analyze_files(three_hops)
    check(len(hops) == 1 and hops[0].confidence == Confidence.HIGH,
          f"py: a three-module chain must resolve to one HIGH path (got {len(hops)})")
    check(hops and hops[0].sink_file == "a/sink.py",
          "py: a multi-hop chain must still attribute the sink to the module it lives in")
    check(hops and hops[0].file == "a/top.py",
          "py: and must still report where the untrusted value entered")

    # Mutual imports must terminate rather than iterate forever.
    cyclic = {
        "c/a.py": "from .b import g\ndef f(x):\n    return g(x)\n",
        "c/b.py": "from .a import f\nimport os\ndef g(x):\n    return os.system(x)\n",
    }
    taint.analyze_files(cyclic)   # the assertion is that this returns at all

    # A commented-out import is not an import.
    commented = {
        "util.js": "function runReport(n) { exec('r ' + n); }\nmodule.exports = { runReport };\n",
        "server.js": ("// const { runReport } = require('./util');\n"
                      "app.get('/r', (req, res) => { runReport(req.query.label); });\n"),
    }
    check(not any(p.confidence == Confidence.HIGH and p.file == "server.js"
                  for p in taint.analyze_files(commented)),
          "a commented-out import must not create a cross-module edge")

    # One helper, three callers, one sink: one bug with one fix, not three tickets.
    fanout = {
        "u.js": "function run(n) { exec('x ' + n); }\nmodule.exports = { run };\n",
        "s.js": ("const { run } = require('./u');\n"
                 "app.get('/a', (req, res) => { run(req.query.a); });\n"
                 "app.get('/b', (req, res) => { run(req.query.b); });\n"
                 "app.get('/c', (req, res) => { run(req.query.c); });\n"),
    }
    check(len(taint.analyze_files(fanout)) == 1,
          f"three routes into one sink is one bug with one fix, not three "
          f"(got {len(taint.analyze_files(fanout))})")


def test_module_graph_is_order_independent() -> None:
    """The same files, walked in any order, must produce the same findings.

    This is not a style preference. Cross-module summaries are derived from each other, so an
    implementation that makes a fixed number of passes over the file list settles wherever the
    passes happened to run out — and the file list comes from a directory walk, which differs
    across platforms, filesystems and `--include` filters. The failure it produced was the
    worst-shaped one available: the chain's *entry point* dropped out, so the report kept an
    interior module (a function whose parameter merely might be tainted) and lost the route
    where untrusted input actually enters. Same repo, same version, two answers, and the wrong
    answer looked like a real finding rather than a crash.
    """
    depth = 6
    files = {"top.py": "from m1 import f1\nimport flask\n"
                       "def h():\n    f1(flask.request.args.get('x'))\n"}
    for i in range(1, depth):
        files[f"m{i}.py"] = f"from m{i + 1} import f{i + 1}\ndef f{i}(v):\n    f{i + 1}(v)\n"
    files[f"m{depth}.py"] = f"import os\ndef f{depth}(v):\n    os.system(v)\n"

    def fingerprint(ordered: dict) -> tuple:
        return tuple(sorted((p.file, p.line, p.sink_file, p.sink_line, p.sink.id)
                            for p in taint.analyze_files(ordered)))

    items = list(files.items())
    orders = {
        "declaration order": items,
        "reversed": list(reversed(items)),
        "sinks first": sorted(items, reverse=True),
        "alphabetical": sorted(items),
    }
    seen = {name: fingerprint(dict(o)) for name, o in orders.items()}
    distinct = set(seen.values())
    # Report the paths themselves, not a count: the bug this guards against produces the same
    # NUMBER of findings in every order and a different finding, so counts all match while the
    # answers disagree.
    check(len(distinct) == 1,
          "a directory walk order must not change the findings — got "
          + " | ".join(f"{name}: " + (", ".join(f"{f}:{ln} -> {sf}" for f, ln, sf, _, _ in fp)
                                      or "nothing")
                       for name, fp in seen.items()))

    # ...and the one answer they agree on has to be the right one. Without this the test would
    # still pass if every order agreed on missing the bug.
    settled = next(iter(distinct))
    check(len(settled) == 1 and settled[0][0] == "top.py" and settled[0][2] == f"m{depth}.py",
          f"a {depth}-module chain must report the entry point and the defining module of the "
          f"sink, in every order (got {settled})")


def test_js_rules() -> None:
    expect("a.js", "app.get('/u', (req, res) => {\n"
                   "  const q = \"SELECT * FROM u WHERE n = '\" + req.query.n + \"'\";\n"
                   "  db.query(q, cb);\n"
                   "});\n",
           "TAINT-JS-SQLI", True, "js: source and sink on different lines")

    expect("a.js", "app.get('/u', (req, res) => {\n"
                   "  db.query('SELECT * FROM u WHERE n = ?', [req.query.n], cb);\n"
                   "});\n",
           "TAINT-JS-SQLI", False, "js: taint bound as a query parameter is the fix, not the bug")

    expect("a.js", "function f(req, res) {\n"
                   "  const host = String(req.query.host || '');\n"
                   "  if (!/^[a-z]+$/.test(host)) return res.status(400).end();\n"
                   "  exec('ping ' + host, cb);\n"
                   "}\n",
           "TAINT-JS-CMDI", False, "js: validate-then-return guard clears taint")

    expect("a.js", "function f(req, res) {\n"
                   "  const next = String(req.query.next || '/');\n"
                   "  const dest = ALLOW.has(next) ? next : '/';\n"
                   "  res.writeHead(302, { Location: dest });\n"
                   "}\n",
           "TAINT-JS-OPENREDIR", False, "js: allowlist membership constrains the value")

    expect("a.js", "function f(req, res) {\n"
                   "  res.writeHead(302, { Location: req.query.next });\n"
                   "}\n",
           "TAINT-JS-OPENREDIR", True, "js: unguarded redirect target")

    expect("a.js", "function render(t, data) {\n"
                   "  return new Function('data', 'return `' + t + '`');\n"
                   "}\n",
           "TAINT-JS-SSTI", True, "js: template source compiled as code")

    # The literal `'data'` must not read as a use of the parameter `data`.
    paths = taint.analyze("a.js", "function render(t, data) {\n"
                                  "  return new Function('data', 'x');\n}\n")
    check(not paths, "js: an identifier inside a string literal must not create taint")

    expect("a.js", "function h(el) {\n"
                   "  el.innerHTML = DOMPurify.sanitize(marked.parse(el.dataset.md));\n"
                   "}\n",
           "TAINT-JS-XSS-DOM", False, "js: DOMPurify.sanitize clears the DOM sink")

    expect("a.js", "function h(el) {\n"
                   "  el.innerHTML = marked.parse(el.dataset.md);\n"
                   "}\n",
           "TAINT-JS-XSS-DOM", True, "js: unsanitized markdown to innerHTML")

    # Block scope: a taint introduced inside a block must not leak past its closing brace.
    scoped = ("function a(req) {\n"
              "  { const t = req.query.x; }\n"
              "  eval(t);\n"
              "}\n")
    check("TAINT-JS-EVAL" not in sinks("a.js", scoped),
          "js: taint leaked out of the block it was declared in")


# --------------------------------------------------------------------------- 3. corpus

def corpus_paths(root: str) -> list[taint.TaintPath]:
    out = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            out.extend(taint.analyze(name, f.read()))
    return out


def test_corpora() -> tuple[int, int]:
    vuln = corpus_paths(VULN)
    classes = {p.sink.maps_to for p in vuln if p.sink.maps_to}
    # These are the classes the taint tier reaches on the shipped corpus. It is a floor, not a
    # ceiling: adding a rule should raise it, and losing one must fail this test loudly.
    required = {"V1", "V2", "V7", "V8", "V11", "V12", "V13", "V15", "V16", "V19", "V20",
                "V21"}
    missing = sorted(required - classes, key=lambda v: int(v[1:]))
    check(not missing, f"corpus: taint tier stopped reaching {missing}")

    secure = corpus_paths(SECURE)
    high = [p for p in secure if p.confidence == Confidence.HIGH]
    for p in high:
        fails.append(f"corpus: HIGH-confidence false positive on the secure fixture — "
                     f"{p.sink.id} at {p.file}:{p.line}")
    return len(vuln), len(high)


def main() -> int:
    # A test reporter that cannot print its own failure is worse than no reporter: the console
    # here is cp1254, so one non-Latin-1 character in a message replaces the failure list with
    # a UnicodeEncodeError traceback and the reader debugs the wrong thing.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_code_view()
    test_blank_strings()
    test_split_args()
    test_python_rules()
    test_python_interprocedural()
    test_js_rules()
    test_js_interprocedural()
    test_cross_module()
    test_module_graph_is_order_independent()
    n_vuln, n_high = test_corpora()

    if fails:
        print("TAINT TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"TAINT TESTS PASSED — {n_vuln} paths on the vulnerable corpus, "
          f"{n_high} HIGH-confidence paths on the secure negative control; "
          f"lexical view, propagation, guards, sanitizers and argument positions verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
