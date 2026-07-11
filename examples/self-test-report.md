# Security Audit Report — `tests/fixtures/vulnerable-app` (SecAudit self-test)

> ✅ **Real dogfooding run.** This report was produced by running SecAudit's source-code
> methodology against the kit's own intentionally-vulnerable fixture, in **fallback mode**
> (no `semgrep`/`osv-scanner`/`gitleaks` installed — only `npm` + `curl` + Claude
> analysis). It demonstrates the hybrid engine's zero-tool path. See
> [`../tests/expected-findings.md`](../tests/expected-findings.md) for the golden set.

## Executive Summary

- **Scope:** local source directory `tests/fixtures/vulnerable-app` (Node/Express).
- **Mode:** source-code (SAST + dependency + secret). No live requests.
- **Tools:** `npm audit` (present) for dependencies; Claude analysis for SAST; pattern
  grep for secrets (`gitleaks` not installed). Fallback path.
- **Findings:** Critical 5 · High 8 · Medium 3 (code) + **10 dependency vulns** + 3 secrets.
- **Fastest risk-reduction:** parameterize the SQL query (V1), remove the shell call (V2),
  drop `eval`/`new Function` on untrusted input (V15/V16), sanitize AI/markdown output (V8),
  rotate + remove the hardcoded AWS keys (V5), fix JWT verification (V10), and run
  `npm audit fix` on the outdated Express stack.

## Methodology

P6 source review (taint tracing), P3 dependency scan (`npm audit` against the lockfile),
secret scan (masked pattern grep), and P7 container review of the Dockerfile. Auth/identity
findings mapped via the `auth-identity.md` checklist.

## Findings Summary

| ID | Severity | Title | Location | Verdict |
|---|---|---|---|---|
| V1 | Critical | SQL injection | `server.js:12` `/users` | CONFIRMED |
| V2 | Critical | OS command injection | `server.js:18` `/ping` | CONFIRMED |
| V7 | Critical | SSRF (no allowlist) | `server.js:44` `/fetch` | CONFIRMED |
| V15 | Critical | Insecure deserialization → code injection | `util.js:21` `deserialize` (`eval`) | CONFIRMED |
| V16 | Critical | Server-side template injection | `util.js:27` `render` (`new Function`) | CONFIRMED |
| V10 | High | Broken JWT verification (`alg:none`, no sig/exp) | `auth.js:9` `verifyToken` | CONFIRMED |
| V8 | High | LLM/markdown output → XSS | `chat.js:11,19` | CONFIRMED |
| V5 | High | Hardcoded AWS credentials | `server.js:32-33` | CONFIRMED |
| V3 | High | IDOR — missing ownership check | `server.js:23` `/invoice/:id` | CONFIRMED |
| V6 | High | CORS reflects Origin + credentials | `server.js:37-39` | CONFIRMED |
| V12 | High | Path traversal | `auth.js:26` `readDoc` (`?file=`) | CONFIRMED |
| V14 | High | Prototype pollution | `util.js:10` `merge` | CONFIRMED |
| V13 | High | Mass assignment | `auth.js:33` `updateProfile` | CONFIRMED |
| DEP | High | 10 vulnerable dependencies | `package.json` | CONFIRMED (npm audit) |
| V11 | Medium | Open redirect | `auth.js:20` `redirect` (`?next=`) | CONFIRMED |
| V4 | Medium | Weak password hashing (MD5) | `server.js:28` | CONFIRMED |
| V9 | Medium | Container misconfig (root, `latest`, secret in ENV) | `Dockerfile` | CONFIRMED |

## Detailed Findings (abridged)

### V1 — SQL injection · Critical · A03 / CWE-89 · `server.js`
`"SELECT * FROM users WHERE name = '" + req.query.name + "'"` — request input concatenated
into SQL. `?name=' OR '1'='1` returns all rows.
**Fix:** parameterized query — `db.query('SELECT * FROM users WHERE name = ?', [req.query.name])`.

### V2 — OS command injection · Critical · A03 / CWE-78 · `server.js`
`exec('ping -c 1 ' + req.query.host)` — `?host=x; rm -rf /` runs arbitrary commands.
**Fix:** `execFile('ping', ['-c','1', host])` with strict input validation.

### V7 — SSRF · Critical · A10 / CWE-918 · `server.js`
`/fetch?url=` fetches any user-supplied URL server-side → cloud metadata / internal services.
**Fix:** allowlist destinations, block private/link-local ranges, disable redirects.

### V15 — Insecure deserialization → code injection · Critical · A08 / CWE-502,94 · `util.js`
`deserialize(str)` runs `eval('(' + str + ')')` on untrusted input → RCE.
**Fix:** never `eval` untrusted data; use `JSON.parse` with a schema.

### V16 — Server-side template injection · Critical · A03 / CWE-1336,94 · `util.js`
`render()` compiles user-influenced template source with `new Function` → RCE.
**Fix:** pass user values as data into a sandboxed engine; never compile input as code.

### V10 — Broken JWT verification · High · A07 / CWE-347 · `auth.js`
`verifyToken` accepts `alg:none` and never checks the signature, `exp`, or `aud` → trivial
auth bypass / forgery.
**Fix:** pin the expected algorithm, verify the signature with the correct key, validate
`exp`/`aud`/`iss`. See `auth-identity.md`.

### V8 — Improper output handling → XSS · High · OWASP LLM05 / CWE-79 · `chat.js`
AI/model output rendered with `marked.parse(msg)` into `innerHTML`, no sanitizer (user path
is escaped; the model path is not). Chained with a non-`HttpOnly` cookie → account takeover.
**Fix:** `DOMPurify.sanitize(marked.parse(msg))` on live + history paths; strict CSP.

### V5 — Hardcoded AWS credentials · High · A05 / CWE-798 · `server.js`
AWS key id + secret committed in source. *(Fixture uses AWS's public doc examples — not live.)*
**Fix:** secret manager / env injection, rotate, purge git history. Never printed (masked here).

### V3 — IDOR · High · A01 / CWE-639 · `server.js`
`/invoice/:id` looks up by id with no owner check. **Fix:** `WHERE id=? AND owner_id=?`.

### V6 — Permissive CORS + credentials · High · A05 / CWE-942 · `server.js`
Reflects `Origin` with `Allow-Credentials: true`. **Fix:** explicit origin allowlist.

### V12 — Path traversal · High · A01 / CWE-22 · `auth.js`
`path.join(__dirname,'docs', req.query.file)` with no normalization → `?file=../../etc/passwd`.
**Fix:** resolve + confirm the path stays within the base dir; allowlist filenames.

### V14 — Prototype pollution · High · A08 / CWE-1321 · `util.js`
Recursive `merge` with no `__proto__`/`constructor` guard → poison `Object.prototype`
(auth-bypass / DoS gadget). **Fix:** block those keys, `Object.create(null)`, or `Map`.

### V13 — Mass assignment · High · A08 / CWE-915 · `auth.js`
`Object.assign(user, req.body)` lets a caller set `role`/`isAdmin`. **Fix:** field allowlist.

### V11 — Open redirect · Medium · A01 / CWE-601 · `auth.js`
`Location: req.query.next` unvalidated → phishing / OAuth `redirect_uri` pivot.
**Fix:** allowlist destinations or only permit relative paths.

### V4 — Weak password hashing · Medium · A02 / CWE-327 · `server.js`
MD5, no salt. **Fix:** argon2id or bcrypt with per-user salt.

### V9 — Container misconfig · Medium · A05 / CWE-250 · `Dockerfile`
`FROM node:latest` (unpinned), no `USER` (root), secret in `ENV`. **Fix:** pin digest, non-root
`USER`, inject secrets at runtime.

## Dependency & Known-CVE Register (real `npm audit` output)

`npm audit` reported **10 vulnerabilities (1 critical, 6 high, 3 low)** across:
`express`, `body-parser`, `cookie`, `send`, `serve-static`, `path-to-regexp`, `qs`,
`lodash`, `minimist`, `marked`.

| Package | Issue | Severity | Fix |
|---|---|---|---|
| qs | Prototype pollution (GHSA-hrpp-h998-j3pp) | Critical/High | upgrade Express stack |
| path-to-regexp | ReDoS (GHSA-37ch-88jc-xwx2) | High | upgrade |
| send / serve-static | Template injection → XSS (GHSA-m6fv-jmcg-4jfg) | High | upgrade |
| lodash | Prototype pollution (CVE-2020-8203) | High | 4.17.21 |
| minimist | Prototype pollution (CVE-2020-7598) | — | 1.2.6+ |
| marked | ReDoS + no sanitizer (feeds V8) | — | pin latest + DOMPurify |

**Action:** `npm audit fix` (and `--force` for the Express major bump), then re-audit.

## Secret Findings (masked)

| Type | Location | Masked |
|---|---|---|
| AWS access key id | `server.js:32` | `AKIAIO****` |
| AWS secret key | `server.js:33` | `wJalrXU****` |
| API token | `Dockerfile:4` | `sk-te****` |

Never printed in full. Rotate + move to a secret manager + purge from git history.

## Remediation Roadmap

**24–72h:** V1, V2, V7, V15, V16 (critical RCE/SSRF/injection), V8 (XSS), V10 (JWT bypass),
V5 (rotate keys), `npm audit fix`.
**7–14d:** V3, V6, V12, V13, V14 (authz/CORS/traversal/mass-assignment/proto-pollution),
finish dependency upgrades + retest.
**30–60d:** V4 (hashing migration), V9 (container hardening), V11 (redirect allowlist),
add SAST + `zizmor` to CI.

## Appendix B — Assumptions & Limitations

Best-effort static assessment of a fixture. Run in fallback mode (no dedicated SAST/dep/
secret scanners); with `semgrep`/`opengrep`+`osv-scanner`+`gitleaks` installed, depth would
increase. No live instance was tested. **Coverage vs golden set: 16/16 code findings +
dependency + secret sections populated → PASS.**
