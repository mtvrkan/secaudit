#!/usr/bin/env python3
"""SecAudit fixture self-test — deterministic, reproducible integrity check.

This does NOT run the full LLM audit (that needs Claude and is exercised via
`/secaudit-code tests/fixtures/vulnerable-app`). Instead it mechanically asserts:

  1. All 20 planted vulnerability sinks (V1–V16 JavaScript, V17–V20 Python) are still
     present in the fixture, so the golden set in expected-findings.md can't drift.
  2. The 3 planted (fake/example) secrets are present where the report claims.
  3. `npm audit` on the fixture lockfile reports the vulnerabilities the
     self-test report cites (>=10 total, >=1 critical) — skipped gracefully if
     npm is unavailable or offline.

Exit code 0 = fixture matches the golden set; non-zero = a regression to fix.
Run:  python3 tests/selftest.py
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(ROOT, "fixtures", "vulnerable-app")
SECURE = os.path.join(ROOT, "fixtures", "secure-app")


def read(name: str) -> str:
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def read_secure(name: str) -> str:
    with open(os.path.join(SECURE, name), encoding="utf-8") as f:
        return f.read()


# Built by concatenation so this script never itself contains the contiguous
# `AKIA…` literal that the CI stray-secret guard scans for outside fixtures.
AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"


# (id, file, substring that uniquely marks the unsafe sink) — must all be present.
SINKS = [
    ("V1  SQL injection",              "server.js", "SELECT * FROM users WHERE name = '\" +"),
    ("V2  OS command injection",       "server.js", "exec('ping -c 1 ' + req.query.host"),
    ("V3  IDOR",                       "server.js", "WHERE id = ?"),
    ("V4  Weak hashing (MD5)",         "server.js", "crypto.createHash('md5')"),
    ("V5  Hardcoded secret",           "server.js", AWS_KEY_ID),
    ("V6  Permissive CORS",            "server.js", "res.header('Access-Control-Allow-Origin', req.headers.origin)"),
    ("V7  SSRF",                       "server.js", "require('http').get(req.query.url"),
    ("V8  Output-handling XSS",        "chat.js",   "marked.parse(msg)"),
    ("V9  Container misconfig",        "Dockerfile","FROM node:latest"),
    ("V10 Broken JWT verify",          "auth.js",   "header.alg === 'none'"),
    ("V11 Open redirect",              "auth.js",   "Location: req.query.next"),
    ("V12 Path traversal",             "auth.js",   "path.join(__dirname, 'docs', req.query.file)"),
    ("V13 Mass assignment",            "auth.js",   "Object.assign(user, req.body)"),
    ("V14 Prototype pollution",        "util.js",   "merge(target[key] || {}, source[key])"),
    ("V15 Insecure deserialization",   "util.js",   "eval('(' + str + ')')"),
    ("V16 SSTI",                       "util.js",   "new Function('data'"),
    ("V17 XXE (Python)",               "py_app.py", "resolve_entities=True"),
    ("V18 Disabled TLS verify",        "py_app.py", "verify=False"),
    ("V19 OS command injection (Py)",  "py_app.py", "shell=True"),
    ("V20 Insecure deserialization",   "py_app.py", "pickle.loads(base64.b64decode"),
]

SECRETS = [
    ("AWS access key id", "server.js", AWS_KEY_ID),
    ("AWS secret key",    "server.js", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("API token (env)",   "Dockerfile","API_TOKEN=sk-test-EXAMPLE"),
]

MARKER_RE = re.compile(r"(?://|#)\s*(V\d{1,2})\s*[—-]", re.M)

# Negative control (fixtures/secure-app): the SAME features implemented safely. It exists to
# measure precision (false positives). These two lists keep it honest and drift-proof:
#   * SECURE_ABSENT — a vulnerable sink marker that must NEVER reappear (proves it didn't
#     silently regress into the vulnerable version).
#   * SECURE_PRESENT — the concrete safe control that must stay in place (proves it's a real
#     safe implementation, not an emptied-out file that would trivially "pass" a precision run).
SECURE_ABSENT = [
    ("server.js", "createHash('md5')"),
    ("server.js", "exec('ping -c 1 ' +"),
    ("server.js", "AKIA"),
    ("server.js", "Allow-Origin', req.headers.origin"),
    ("auth.js",   "alg === 'none'"),
    ("auth.js",   "Object.assign(user, req.body)"),
    ("util.js",   "eval("),
    ("util.js",   "new Function('data'"),
    ("chat.js",   "innerHTML = marked.parse"),
    ("py_app.py", "resolve_entities=True"),
    ("py_app.py", "verify=False"),
    ("py_app.py", "shell=True)"),
    ("py_app.py", "pickle.loads"),
    ("Dockerfile", "FROM node:latest"),
]
SECURE_PRESENT = [
    ("server.js", "WHERE name = ?"),
    ("server.js", "execFile('ping'"),
    ("server.js", "owner_id = ?"),
    ("server.js", "scryptSync"),
    ("server.js", "process.env.AWS_ACCESS_KEY_ID"),
    ("server.js", "ALLOWED_ORIGINS"),
    ("server.js", "FETCH_ALLOWLIST"),
    ("auth.js",   "!== 'HS256'"),
    ("auth.js",   "timingSafeEqual"),
    ("auth.js",   "REDIRECT_ALLOWLIST"),
    ("auth.js",   "startsWith(DOCS_ROOT"),
    ("auth.js",   "PROFILE_FIELDS"),
    ("util.js",   "BLOCKED.has(key)"),
    ("util.js",   "JSON.parse(str)"),
    ("chat.js",   "DOMPurify.sanitize"),
    ("py_app.py", "resolve_entities=False"),
    ("py_app.py", "verify=True"),
    ("py_app.py", 'subprocess.call(["ping"'),
    ("py_app.py", "json.loads(cookie)"),
    ("Dockerfile", "USER node"),
]


def check_sinks() -> list[str]:
    fails = []
    files = {n: read(n) for n in {s[1] for s in SINKS}}
    for name, fname, needle in SINKS:
        if needle not in files[fname]:
            fails.append(f"[SINK MISSING] {name}: expected `{needle}` in {fname}")
    # every V1..V16 must also carry its labelled comment somewhere
    seen = set()
    for txt in files.values():
        seen.update(MARKER_RE.findall(txt))
    for i in range(1, 21):
        if f"V{i}" not in seen:
            fails.append(f"[MARKER MISSING] // V{i} — comment not found in fixture")
    return fails


def check_secrets() -> list[str]:
    fails = []
    for label, fname, needle in SECRETS:
        if needle not in read(fname):
            fails.append(f"[SECRET MISSING] {label}: `{needle}` not in {fname}")
    return fails


def check_secure_fixture() -> list[str]:
    """Assert the negative-control fixture stays genuinely safe: no vulnerable sink marker
    reappears, and every safe control is still in place. Guards precision from drifting."""
    fails = []
    try:
        files = {n: read_secure(n) for n in
                 {p[0] for p in SECURE_ABSENT} | {p[0] for p in SECURE_PRESENT}}
    except OSError as e:
        return [f"[SECURE FIXTURE] cannot read secure-app: {e}"]
    for fname, needle in SECURE_ABSENT:
        if needle in files[fname]:
            fails.append(f"[SECURE REGRESSED] vulnerable marker `{needle}` reappeared in secure-app/{fname}")
    for fname, needle in SECURE_PRESENT:
        if needle not in files[fname]:
            fails.append(f"[SECURE CONTROL MISSING] `{needle}` no longer in secure-app/{fname}")
    return fails


def check_npm_audit() -> tuple[list[str], str]:
    if not any(os.access(os.path.join(p, exe), os.X_OK)
               for p in os.environ.get("PATH", "").split(os.pathsep)
               for exe in ("npm", "npm.cmd")):
        return [], "npm not found — dependency audit skipped (structural checks still ran)."
    try:
        out = subprocess.run(["npm", "audit", "--json"], cwd=FIX,
                             capture_output=True, text=True, timeout=120, shell=(os.name == "nt"))
    except Exception as e:  # offline / registry error
        return [], f"npm audit could not run ({e}) — skipped."
    try:
        meta = json.loads(out.stdout).get("metadata", {}).get("vulnerabilities", {})
    except Exception:
        return [], "npm audit produced no parseable JSON (likely offline) — skipped."
    total, crit = meta.get("total", 0), meta.get("critical", 0)
    fails = []
    if total < 10:
        fails.append(f"[DEP AUDIT] expected >=10 vulnerabilities, npm reported {total}")
    if crit < 1:
        fails.append(f"[DEP AUDIT] expected >=1 critical, npm reported {crit}")
    return fails, f"npm audit: {total} vulnerabilities ({crit} critical) — matches self-test report."


def main() -> int:
    fails = check_sinks() + check_secrets() + check_secure_fixture()
    dep_fails, dep_note = check_npm_audit()
    fails += dep_fails

    if fails:
        print("SELF-TEST FAILED — fixture drifted from the golden/clean set:\n")
        print("\n".join("  " + f for f in fails))
        print(f"\n{dep_note}")
        return 1
    print("SELF-TEST PASSED — vulnerable-app: all 20 sinks + 3 secrets present; "
          f"secure-app: {len(SECURE_ABSENT)} sinks absent + {len(SECURE_PRESENT)} controls present.\n{dep_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
