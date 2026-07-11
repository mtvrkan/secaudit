# Golden set — expected findings for `fixtures/vulnerable-app`

A correct SecAudit source-mode run (`/secaudit-code tests/fixtures/vulnerable-app`) must
surface **all** of the planted issues below. Use this to catch regressions in coverage.
Extra findings are fine if valid; **misses are failures**.

> This file is the **recall** half of the eval. Its complement is
> [`expected-clean.md`](expected-clean.md) — the **precision** half, which asserts a correct
> audit stays quiet on the safe `fixtures/secure-app` (no false positives). Measure both.

## Code findings (SAST — must all be found: 20 total)

The fixture is **multi-language on purpose** — V1–V16 are JavaScript/Node, V17–V20 are
Python — so a correct run proves cross-language static coverage, not just JS.

| ID | Class | OWASP / CWE | Location |
|---|---|---|---|
| V1 | SQL injection | A05 / CWE-89 | `server.js` `/users` (string-concatenated query) |
| V2 | OS command injection | A05 / CWE-78 | `server.js` `/ping` (`exec` with user input) |
| V3 | Broken access control (IDOR) | A01 / CWE-639 | `server.js` `/invoice/:id` (no ownership check) |
| V4 | Weak password hashing | A04 / CWE-327 | `server.js` `hashPassword` (MD5, no salt) |
| V5 | Hardcoded secret | A07 / CWE-798 | `server.js` `AWS_ACCESS_KEY_ID` (example values) |
| V6 | Permissive CORS + credentials | A02 / CWE-942 | `server.js` `Access-Control-Allow-Origin` (reflects Origin) |
| V7 | SSRF | A01 / CWE-918 | `server.js` `/fetch` (no allowlist) |
| V8 | Improper output handling → XSS | LLM05 / CWE-79 | `chat.js` `renderMessage`/`loadHistory` (unsanitized `marked.parse`) |
| V9 | Container misconfig | A02 / CWE-250 | `Dockerfile` (root user, `node:latest`, secret in ENV) |
| V10 | Broken JWT verification (`alg:none`, no sig/exp) | A07 / CWE-347 | `auth.js` `verifyToken` |
| V11 | Open redirect | A01 / CWE-601 | `auth.js` `redirect` (`?next=`) |
| V12 | Path traversal | A01 / CWE-22 | `auth.js` `readDoc` (`?file=`) |
| V13 | Mass assignment | A08 / CWE-915 | `auth.js` `updateProfile` (`Object.assign`) |
| V14 | Prototype pollution | A08 / CWE-1321 | `util.js` `merge` (no `__proto__` guard) |
| V15 | Insecure deserialization → code injection | A08 / CWE-502/94 | `util.js` `deserialize` (`eval`) |
| V16 | Server-side template injection | A05 / CWE-1336/94 | `util.js` `render` (`new Function`) |
| V17 | XXE (XML external entities) | A05 / CWE-611 | `py_app.py` `parse_xml` (`resolve_entities`) |
| V18 | Disabled TLS certificate verification | A04 / CWE-295 | `py_app.py` `fetch_secure` (`verify=False`) |
| V19 | OS command injection (Python) | A05 / CWE-78 | `py_app.py` `run_ping` (`shell=True`) |
| V20 | Insecure deserialization (pickle) | A08 / CWE-502 | `py_app.py` `load_session` (`pickle.loads`) |

## Dependency findings (must be found if a lockfile exists or lookups run)

| Package | Version | Example advisory | Class |
|---|---|---|---|
| lodash | 4.17.15 | prototype pollution (CVE-2020-8203 / -28500) | A03 |
| minimist | 1.2.0 | prototype pollution (CVE-2020-7598) | A03 |
| marked | 0.3.6 | ReDoS + no sanitizer (feeds V8) | A03 |
| express | 4.16.0 | pulls vulnerable transitive deps; outdated | A03 |

> `lodash` and `minimist` are declared in `package.json` but not `require`d in the fixture
> code — this is deliberate, so a dependency scan reports them from the manifest/lockfile.
> The verifier may mark them **PLAUSIBLE (unreachable at runtime)** rather than CONFIRMED;
> that is the correct call and still counts as surfaced.

## Secret findings

- AWS key pair in `server.js` and `API_TOKEN` in `Dockerfile` — must be flagged as
  hardcoded secrets, reported **masked**, with rotation guidance. (Values are public
  AWS documentation examples / clearly-fake — not real credentials.)

## Quality expectations (not just detection)

- Each finding has a specific fix (parameterized query, `execFile` w/ args, ownership
  check, argon2/bcrypt, secret manager, strict CORS allowlist, SSRF allowlist +
  private-range block, `DOMPurify.sanitize`, non-root + pinned base image, pin JWT `alg` +
  verify signature/exp/aud, redirect allowlist, path normalization, field allowlist,
  `__proto__` guard, safe deserialization, template data-not-code).
- Severity ordering is sane (RCE/SQLi/SSRF/deserialization/SSTI/JWT-bypass high or critical;
  misconfig medium/low).
- No secret **values** printed in the report.
- Report states it's best-effort and lists any not-assessed areas.

## Pass criteria

- **All 20 code findings** present (16 JS + 4 Python) → coverage pass.
- Dependency + secret sections populated (or clearly marked "tool/lookup unavailable").
- No false "all clear"; no leaked secret values.
