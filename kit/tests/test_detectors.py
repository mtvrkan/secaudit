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
    ("m.rb",     "obj = Marshal.load(blob)\n",                        "SEC-RB-MARSHAL"),
    ("P.cs",     "var f = new BinaryFormatter();\n",                  "SEC-CS-DESER"),
    ("main.tf",  'ingress { cidr_blocks = ["0.0.0.0/0"] }\n',         "SEC-TF-OPENINGRESS"),
    ("t.txt",    f"token = {GH}\n",                                   "SEC-SECRET-GH"),
    ("k.txt",    PRIVKEY + "\n",                                      "SEC-SECRET-PRIVKEY"),
    ("pod.yaml", "securityContext:\n  privileged: true\n",           "SEC-K8S-PRIVILEGED"),
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
    ("prng.py",     "import random\notp_code = random.choice('0123456789')\n",
     "SEC-PY-WEAK-PRNG"),
    ("csrf.py",     "@csrf_exempt\ndef v(request):\n    pass\n",     "SEC-PY-CSRF-EXEMPT"),
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
    ("okhosts.py",  'ALLOWED_HOSTS = ["example.com", "www.example.com"]\n',
     "SEC-PY-ALLOWED-HOSTS"),
    ("okkeys.py",   'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n',
     "SEC-PY-SECRET-KEY-FALLBACK"),
    ("okcook.py",   "r.set_cookie('sid', v, httponly=True, secure=True, samesite='Lax')\n",
     "SEC-PY-COOKIE-FLAGS"),
    # `random` is fine for anything that is not security material — the rule is bound to the
    # variable name for exactly this reason, and this is what that buys.
    ("okprng.py",   "import random\ncolour = random.choice(['red', 'blue'])\n",
     "SEC-PY-WEAK-PRNG"),
    ("oksecrets.py", "import secrets\napi_token = secrets.token_urlsafe(32)\n",
     "SEC-PY-WEAK-PRNG"),
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
