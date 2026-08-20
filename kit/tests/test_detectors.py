#!/usr/bin/env python3
"""Prove the multi-language / secret / IaC detectors actually fire (and their safe variants do
not). Snippets are written to a temp dir and scanned by the real engine. Secret literals are
built by concatenation so this test file never itself contains a contiguous key the CI
stray-secret guard scans for."""
from __future__ import annotations

import os
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import engine                       # noqa: E402
from secaudit_core.detectors import DETECTORS          # noqa: E402

# (filename, contents, expected detector id present)
GH = "ghp_" + "A" * 36
PRIVKEY = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
# Modern token shapes, built by concat so this file holds no contiguous key literal.
ANTHROPIC = "sk-ant-" + "A" * 24
GH_PAT = "github_pat_" + "A" * 30
HF = "hf_" + "A" * 34
NPM = "npm_" + "A" * 36

CASES = [
    ("bad.py",   "import os\nos.system('ls ' + x)\n",                 "SEC-PY-OSSYSTEM"),
    ("y.py",     "import yaml\nyaml.load(open('f'))\n",               "SEC-PY-YAML"),
    ("e.py",     "eval(user_input)\n",                                "SEC-PY-EVAL"),
    ("srv.go",   "cfg := &tls.Config{InsecureSkipVerify: true}\n",    "SEC-GO-TLS"),
    ("A.java",   "var o = new ObjectInputStream(in);\n",              "SEC-JAVA-DESER"),
    ("i.php",    "<?php system($_GET['cmd']); ?>\n",                  "SEC-PHP-EXEC"),
    # `.phtml` is the same language — a PHP file that opens in HTML mode. It was unreachable
    # until `langs.PHP_EXTS` existed, the same way `.tsx` was before the JS/TS families.
    ("v.phtml",  "<?php unserialize($_COOKIE['u']); ?>\n",            "SEC-PHP-UNSER"),
    # PHP escapes nothing on the way out, so a superglobal reaching `echo` is reflected XSS with
    # nothing in between — and the superglobal IS the source, which is why these five rules need
    # no taint tier behind them.
    ("out.php",  "<?php echo $_GET['q']; ?>\n",                       "SEC-PHP-XSS-ECHO"),
    ("q.php",    "<?php $pdo->prepare(\"SELECT * FROM u WHERE id=\" . $_GET['id']); ?>\n",
     "SEC-PHP-SQLI-SUPERGLOBAL"),
    ("inc.php",  "<?php include $_GET['page'] . '.php'; ?>\n",        "SEC-PHP-LFI"),
    ("read.php", "<?php readfile($_REQUEST['f']); ?>\n",              "SEC-PHP-PATHTRAV"),
    ("redir.php", "<?php header('Location: ' . $_GET['next']); ?>\n", "SEC-PHP-HEADER-INJECT"),
    ("tpl.phtml", "<td><?= $row['title'] ?></td>\n",                  "SEC-PHP-XSS-SHORTECHO"),
    ("m.rb",     "obj = Marshal.load(blob)\n",                        "SEC-RB-MARSHAL"),
    ("P.cs",     "var f = new BinaryFormatter();\n",                  "SEC-CS-DESER"),
    ("main.tf",  'ingress { cidr_blocks = ["0.0.0.0/0"] }\n',         "SEC-TF-OPENINGRESS"),
    ("t.txt",    f"token = {GH}\n",                                   "SEC-SECRET-GH"),
    ("k.txt",    PRIVKEY + "\n",                                      "SEC-SECRET-PRIVKEY"),
    # The K8s rules carry a file-level precondition, so the manifest header is load-bearing
    # here rather than decoration — see the SAFE block for the documents it now excludes.
    ("pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    privileged: true\n",
     "SEC-K8S-PRIVILEGED"),
    ("hp.yaml",  "apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n    - hostPath:\n        path: /\n",
     "SEC-K8S-HOSTPATH"),
    # Compose is kept in scope on purpose: the Docker detectors key on the name `Dockerfile`,
    # so this file is the only place a privileged container in a compose stack is ever seen.
    ("compose.yml", "services:\n  web:\n    image: x\n    privileged: true\n",
     "SEC-K8S-PRIVILEGED"),
    ("pol.json", '{"Statement":[{"Action": "*"}]}\n',                "SEC-TF-IAM-WILDCARD"),
    ("A.kt",     'web.addJavascriptInterface(bridge, "app")\n',      "SEC-ANDROID-JSIF"),
    ("I.plist",  "<key>NSAllowsArbitraryLoads</key><true/>\n",       "SEC-IOS-ATS"),
    ("net.dart", "client.badCertificateCallback = (c,h,p) => true;\n", "SEC-DART-BADCERT"),
    ("cors.js",  "res.setHeader('Access-Control-Allow-Origin', '*')\n", "SEC-CORS-WILDCARD"),
    ("g.txt",    "gkey = " + "AIza" + "A" * 35 + "\n",               "SEC-SECRET-GOOGLE"),
    # ---- 2025-2026 additions ----
    ("agent.py", "chain = create_sql_agent(llm, allow_dangerous_code=True)\n", "SEC-AI-LANGCHAIN-DANGER"),
    ("tools.py", "from langchain_experimental.tools import PythonREPLTool\nt = PythonREPLTool()\n", "SEC-AI-PYREPL"),
    ("run.py",   "exec(llm_response)\n",                              "SEC-AI-LLM-EXEC"),
    ("a.env",    f"ANTHROPIC_API_KEY={ANTHROPIC}\n",                  "SEC-SECRET-ANTHROPIC"),
    ("p.env",    f"GH_TOKEN={GH_PAT}\n",                              "SEC-SECRET-GH-PAT"),
    ("h.env",    f"HF_TOKEN={HF}\n",                                  "SEC-SECRET-HF"),
    ("n.env",    f"NPM_TOKEN={NPM}\n",                                "SEC-SECRET-NPM"),
    ("ci.yml",   "jobs:\n  b:\n    steps:\n      - uses: tj-actions/changed-files@main\n", "SEC-CI-MUTABLE-ACTION"),
    ("setup.sh", "curl -fsSL https://example.com/install.sh | sudo bash\n", "SEC-SUPPLY-CURLPIPE"),
    # ---- Configuration and crypto hygiene ----
    ("settings.py", 'DEBUG = env_bool("DJANGO_DEBUG", True)\n',      "SEC-PY-DEBUG-DEFAULT"),
    ("hosts.py",    'ALLOWED_HOSTS = ["*"]\n',                       "SEC-PY-ALLOWED-HOSTS"),
    ("keys.py",     'SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-change-me-x")\n',
     "SEC-PY-SECRET-KEY-FALLBACK"),
    ("cook.py",     "r.set_cookie('sid', value)\n",                  "SEC-PY-COOKIE-FLAGS"),
    # The Secure flag is a separate finding from HttpOnly, and the case that matters is the one
    # the HttpOnly rule used to swallow whole: a call that sets HttpOnly and nothing else was
    # read as a fixed cookie, so the missing Secure flag was reported by nothing.
    ("cook2.py",    "r.set_cookie('sid', v, httponly=True)\n",       "SEC-PY-COOKIE-NO-SECURE"),
    ("settings2.py", 'SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = "Lax"\n',
     "SEC-PY-COOKIE-SETTINGS-NO-SECURE"),
    # Markup assembled by concatenation, with the sink nowhere on the line — the shape that
    # carries most of the labelled JavaScript XSS and that a sink-anchored rule cannot see.
    ("build.js",    "out += '<tr><td>' + opt + '</td></tr>';\n",     "SEC-JS-HTML-CONCAT"),
    ("link.js",     "list.push('<a href=\"/u/' + id + '\">' + name + '</a>');\n",
     "SEC-JS-HTML-CONCAT"),
    ("tpl.ts",      "const row = `<li class=\"item\">${entry.title}</li>`;\n",
     "SEC-JS-HTML-CONCAT"),
    ("prng.py",     "import random\notp_code = random.choice('0123456789')\n",
     "SEC-PY-WEAK-PRNG"),
    ("csrf.py",     "@csrf_exempt\ndef v(request):\n    pass\n",     "SEC-PY-CSRF-EXEMPT"),

    # ---- Round 4: the config, credential and template shapes the external corpus labels ----
    # Each of these is a line that was measured as a miss before the rule existed, reduced to
    # the shape rather than copied — the fixture is the rule's claim, not the corpus's row.
    ("mw.py",       "MIDDLEWARE = [\n    #'django.middleware.csrf.CsrfViewMiddleware',\n]\n",
     "SEC-PY-CSRF-MIDDLEWARE-OFF"),
    ("hsts.py",     'headers.append(("Strict-Transport-Security", "max-age=0"))\n',
     "SEC-PY-HSTS-DISABLED"),
    ("csp.py",      'self.send_header("Content-Security-Policy", "default-src * \'unsafe-inline\'")\n',
     "SEC-PY-CSP-WEAK"),
    ("autoesc.py",  "env = Environment(loader=loader, autoescape=False)\n",
     "SEC-PY-AUTOESCAPE-OFF"),
    ("jinjaenv.py", "import jinja2\nenv = Environment(loader=loader)\n",
     "SEC-PY-JINJA-ENV-DEFAULT"),
    ("dbgdict.py",  'settings = {"debug": True}\n',                  "SEC-PY-DEBUG-DICT"),
    ("jwtlit.py",   "data = jwt.decode(token, 'notsosecret', algorithms=['HS256'])\n",
     "SEC-PY-CRED-LITERAL-ARG"),
    ("trace.py",    "conn.set_trace_callback(print)\n",              "SEC-PY-SQL-TRACE"),
    ("md5imp.py",   "from hashlib import md5\nd = md5(password.encode()).hexdigest()\n",
     "SEC-PY-MD5-IMPORTED"),
    ("stack.yml",   "services:\n  api:\n    environment:\n      - SECRET_KEY=supersecret\n",
     "SEC-COMPOSE-ENVSECRET"),
    # The signing-key floor: four characters is the shape the 8-character floor used to hide.
    ("shortkey.py", "app.config['SECRET_KEY'] = 'dvga'\n",           "SEC-PY-SECRET-KEY-LITERAL"),
    # A credential whose name carries a suffix — the keyword no longer has to touch the `=`.
    ("salt.py",     'ACCESS_TOKEN_SALT = "S4828341189aefiasd"\n',    "SEC-SECRET-GENERIC"),
    ("form.html",   '<form method="POST">\n  <input name="amount">\n</form>\n',
     "SEC-TPL-FORM-NO-CSRF"),
    ("err.jinja2",  "<pre>{{ error.__dict__ }}</pre>\n",             "SEC-TPL-ERROR-OBJECT"),
    ("jsattr.html", '<button onclick="submitForm({{ user.id }})">go</button>\n',
     "SEC-TPL-XSS-JS-ATTR"),
]

SAFE = [
    ("safe.py", "import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n", "SEC-PY-YAML"),  # suppressed
    # A SHA-pinned Action must NOT trip the mutable-ref detector (precision guard).
    ("ok.yml",  "steps:\n  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n",
     "SEC-CI-MUTABLE-ACTION"),
    # Each configuration rule in the shape a correct project writes it. These are the
    # assertions that decide whether the rules are usable at all: a config linter that fires on
    # a correct settings module is one everybody switches off on day two.
    ("okdebug.py",  "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n", "SEC-PY-DEBUG-DEFAULT"),
    # The widening's own precision: a name that merely contains DEBUG, the switch turned off,
    # and an assertion that it is off.
    ("okdbgname.py", "LOG_DEBUG = False\nDEBUG = False\n",             "SEC-PY-DEBUG"),
    ("okdbgassert.py", "assert not app.debug\n",                       "SEC-PY-DEBUG"),
    # The raw-text rule reads comments too, which is what `literal=True` costs. A commented-out
    # switch is not a finding.
    ("okdbgcomment.py", "# app.config['DEBUG'] = True\n",              "SEC-PY-DEBUG-CONFIG"),
    ("okhosts.py",  'ALLOWED_HOSTS = ["example.com", "www.example.com"]\n',
     "SEC-PY-ALLOWED-HOSTS"),
    ("okkeys.py",   'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n',
     "SEC-PY-SECRET-KEY-FALLBACK"),
    ("okcook.py",   "r.set_cookie('sid', v, httponly=True, secure=True, samesite='Lax')\n",
     "SEC-PY-COOKIE-FLAGS"),
    ("okcook2.py",  "r.set_cookie('sid', v, httponly=True, secure=True, samesite='Lax')\n",
     "SEC-PY-COOKIE-NO-SECURE"),
    ("oksettings.py", 'SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True\n',
     "SEC-PY-COOKIE-SETTINGS-NO-SECURE"),
    # A module that configures no cookie behaviour at all is not an omission. The rule is about
    # SELECTIVE hardening — without that bound it would fire on every settings file alive, which
    # is the precision failure that gets a config rule switched off on day two.
    ("quietsettings.py", 'DEBUG = False\nALLOWED_HOSTS = ["example.com"]\n',
     "SEC-PY-COOKIE-SETTINGS-NO-SECURE"),
    # Two literals joined is a library assembling a static template — bootstrap's tooltip,
    # jQuery's feature probe. No runtime value enters it, so there is nothing to escape, and
    # this is the single largest thing that keeps the rule off healthy code.
    ("static.js",   "var t = '<div class=\"tip\">' + '<div class=\"arrow\"></div>' + '</div>';\n",
     "SEC-JS-HTML-CONCAT"),
    # A line-scoped suppression, and the two things that answer this rule on the line itself.
    # The escaper is the obvious one; the translation catalogue is the one the noise floor
    # found — a catalogue key is a string the application ships with itself, not a request.
    ("escd.js",     "el.innerHTML = '<div>' + escapeHtml(name) + '</div>';\n",
     "SEC-JS-HTML-CONCAT"),
    ("i18n.js",     "out += '<div>' + Messages.strMissingColumn + '</div>';\n",
     "SEC-JS-HTML-CONCAT"),
    # An angle bracket is not a tag. `'a < b: ' + n` is prose and `x < y` is arithmetic; the
    # rule asks for `<name ` / `<name>` / `</name`, which is markup and nothing else.
    ("compare.js",  "msg = 'items < limit: ' + count;\nif (a < b) { run(); }\n",
     "SEC-JS-HTML-CONCAT"),
    # A call inside the tag is where an escaper would be, and one line cannot tell
    # `$this->escape($x)` from `$obj->rawHtml()`. The rule takes only the shape with no call in
    # it — 240 labelled files instead of 560, and this is the fixture that pins that decision.
    ("esc.phtml", "<td><?= $this->escape($row['title']) ?></td>\n",   "SEC-PHP-XSS-SHORTECHO"),
    # `isset($_GET)` is a test, not output. The rule asks for the subscript, so a superglobal
    # merely checked in the same statement does not read as a sink.
    ("check.php", "<?php if (isset($_GET) && count($_POST)) { echo 'hi'; } ?>\n",
     "SEC-PHP-XSS-ECHO"),
    # A method that shares a name with a language construct is not that construct. `$redis->eval`
    # is Redis' Lua evaluator and `Process::exec` is a class method; those two shapes alone were
    # 104 matched lines in `laravel/framework` before the receiver exclusion.
    ("redis.php", "<?php $this->redis->eval($script, 1);\nProcess::exec($cmd);\n",
     "SEC-PHP-EXEC"),
    # A declaration is where a name is defined, not where it is called.
    ("defn.php",  "<?php class Batch {\n  protected function unserialize($serialized) {}\n}\n",
     "SEC-PHP-UNSER"),
    # The control PHP ships for object injection: no class may be constructed, so no magic
    # method can run, which is the whole of the attack.
    ("safecall.php", "<?php unserialize($blob, ['allowed_classes' => false]);\n",
     "SEC-PHP-UNSER"),
    # `random` is fine for anything that is not security material — the rule is bound to the
    # variable name for exactly this reason, and this is what that buys.
    ("okprng.py",   "import random\ncolour = random.choice(['red', 'blue'])\n",
     "SEC-PY-WEAK-PRNG"),
    ("oksecrets.py", "import secrets\napi_token = secrets.token_urlsafe(32)\n",
     "SEC-PY-WEAK-PRNG"),
    # `.yaml` is a container format, not a language. These are the documents the K8s rules used
    # to fire on, and the first one is not hypothetical: it is the shape of this repository's
    # OWN exported Semgrep pack, where `hostPath:` is the quoted pattern of the rule that looks
    # for hostPath. A security tool reporting its own rule file as a vulnerable manifest is the
    # exact noise that gets a scanner switched off.
    ("rulepack.yaml", "rules:\n  - id: secaudit.sec-k8s-hostpath\n    languages: [regex]\n"
                      "    patterns:\n      - pattern-regex: '(?im)hostPath:'\n",
     "SEC-K8S-HOSTPATH"),
    ("wf.yml", "on: [push]\njobs:\n  b:\n    steps:\n      - run: echo privileged: true\n",
     "SEC-K8S-PRIVILEGED"),

    # ---- Round 4 negatives. These decide whether the new rules are shippable at all. ----
    # A form that already carries the token, and a form that changes nothing. Both are the
    # overwhelming majority shape in any real template directory, so a rule that fires on
    # either is a rule that gets the whole pack muted.
    ("okform.html", '<form method="POST">{% csrf_token %}<input name="amount"></form>\n',
     "SEC-TPL-FORM-NO-CSRF"),
    ("okget.html",  '<form method="GET"><input name="q"></form>\n', "SEC-TPL-FORM-NO-CSRF"),
    # A commented-out form is not a form. This case exists because the first measured run of the
    # rule reported two of them as live holes.
    ("okcmt.html",  '<!-- <form method="POST"><input name="a"></form> -->\n',
     "SEC-TPL-FORM-NO-CSRF"),
    ("okwtf.html",  '<form method="post">{{ form.hidden_tag() }}<input name="a"></form>\n',
     "SEC-TPL-FORM-NO-CSRF"),
    # An event handler with no interpolation in it is just JavaScript.
    ("okjsattr.html", '<button onclick="submitForm()">go</button>\n', "SEC-TPL-XSS-JS-ATTR"),
    # Both bounds on the Jinja default-off rule, one file each: the environment that asks for
    # escaping, and the `Environment` that is not Jinja's at all. Without the second bound the
    # rule fires on every class in the language that happens to carry that name.
    ("okjinja.py",  "import jinja2\nenv = Environment(loader=l, autoescape=select_autoescape())\n",
     "SEC-PY-JINJA-ENV-DEFAULT"),
    ("okenv.py",    "from mylib import Environment\nenv = Environment(region='eu')\n",
     "SEC-PY-JINJA-ENV-DEFAULT"),
    # Declaring the type is not constructing one. Flask's own `templating.py` is this line.
    ("okenvcls.py", "import jinja2\nclass Environment(BaseEnvironment):\n    pass\n",
     "SEC-PY-JINJA-ENV-DEFAULT"),
    # The correct compose form is an interpolation — the secret lives in an untracked file.
    ("okstack.yml", "services:\n  api:\n    environment:\n      - SECRET_KEY=${SECRET_KEY}\n",
     "SEC-COMPOSE-ENVSECRET"),
    ("okhsts.py",   'headers.append(("Strict-Transport-Security", "max-age=31536000"))\n',
     "SEC-PY-HSTS-DISABLED"),
    ("okcsp.py",    'self.send_header("Content-Security-Policy", "default-src \'self\'")\n',
     "SEC-PY-CSP-WEAK"),
    # `md5` that is not hashlib's. The round-3 lesson holds in Python too: a name is not an
    # identity, and this rule asks the file's imports which function it is looking at.
    ("okmd5.py",    "from .digest import md5\nd = md5(payload)\n", "SEC-PY-MD5-IMPORTED"),
    ("okmw.py",     "MIDDLEWARE = [\n    'django.middleware.csrf.CsrfViewMiddleware',\n]\n",
     "SEC-PY-CSRF-MIDDLEWARE-OFF"),
    # The one thing the relaxed length floor still excludes: an unset key is a misconfiguration
    # with its own finding, not a key anybody can sign with.
    ("okemptykey.py", "SECRET_KEY = ''\n", "SEC-PY-SECRET-KEY-LITERAL"),
]


def main() -> int:
    fails: list[str] = []

    if len(DETECTORS) < 60:
        fails.append(f"detector pack shrank unexpectedly: {len(DETECTORS)} < 60")

    with tempfile.TemporaryDirectory() as d:
        for name, body, _ in CASES + SAFE:
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(body)
        # scan each file individually so a hit is unambiguous
        for name, _, want in CASES:
            ids = {f.detector_id for f in engine.scan_code(os.path.join(d, name))}
            if want not in ids:
                fails.append(f"{name}: expected {want}, got {sorted(ids) or 'nothing'}")
        for name, _body, notwant in SAFE:
            ids = {f.detector_id for f in engine.scan_code(os.path.join(d, name))}
            if notwant in ids:
                fails.append(f"{name}: {notwant} should have been suppressed by the safe control")

        # secret evidence must be redacted — the value must never appear in a finding.
        akia = "AKIA" + "IOSFODNN7EXAMPLE"        # built by concat so this file has no literal key
        sp = os.path.join(d, "leak.txt")
        with open(sp, "w", encoding="utf-8") as f:
            f.write(f"aws_key = {akia}\n")
        secret_findings = [f for f in engine.scan_code(sp) if f.detector_id == "SEC-SECRET-AWS"]
        if not secret_findings:
            fails.append("leak.txt: SEC-SECRET-AWS did not fire")
        elif any(akia in f.evidence for f in secret_findings):
            fails.append("leak.txt: SECRET VALUE LEAKED into evidence (must be redacted)")

    if fails:
        print("DETECTOR-PACK TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"DETECTOR-PACK TESTS PASSED — {len(DETECTORS)} detectors; "
          f"{len(CASES)} multi-language/secret/IaC sinks fire, safe variants suppressed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
