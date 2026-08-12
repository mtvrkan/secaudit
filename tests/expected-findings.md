# Golden set — expected findings for `fixtures/vulnerable-app`

A correct SecAudit source-mode run (`/secaudit-code tests/fixtures/vulnerable-app`) must
surface **all** of the planted issues below. Use this to catch regressions in coverage.
Extra findings are fine if valid; **misses are failures**.

> This file is the **recall** half of the eval. Its complement is
> [`expected-clean.md`](expected-clean.md) — the **precision** half, which asserts a correct
> audit stays quiet on the safe `fixtures/secure-app` (no false positives). Measure both.

## Code findings (SAST — must all be found: 61 total)

The fixture is **multi-language on purpose**: JavaScript/Node (V1–V16, V22, V23), Python
(V17–V21, V49–V52), Go (V24–V26), Java (V27–V29), PHP (V30–V32), Ruby (V33, V34), C#
(V35, V36), Rust (V37–V39), Terraform (V40–V44), Kubernetes (V45–V48), GitHub Actions
(V53, V54), Kotlin/Android (V55–V57), Dart (V58), plist/iOS (V59) and JSON config (V60,
V61). A per-language score is only meaningful for languages that have fixtures, so a
detector with no fixture is an unmeasured claim — which is what this expansion removes.

V21, V22 and V23 are one flaw class at three analysis depths, planted deliberately so each
depth has to be earned separately: V21 crosses a **function** boundary in Python, V22 crosses
a **function** boundary in JavaScript, V23 crosses a **module** boundary. Each is invisible to
the tier below it, and none of them is wrong when its file is read alone — which is the whole
point. A scanner can pass the first and fail the third, and the score has to show that.

A `CWE-a/b/c` list means **any** of those classifications is correct for that flaw — an
`acceptable_cwes` set in the [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark)
sense, not a claim that all of them apply. Two rules govern what may go in one, so the set is
not quietly widened until every scanner passes:

1. **A more specific child of the listed CWE is correct.** V15 lists CWE-95 (Eval Injection)
   alongside CWE-94 (Code Injection) because 95 *is* a 94.
2. **A block that plants several distinct issues lists all of them.** V9's Dockerfile plants
   three — root user (CWE-250), unpinned `:latest` base (CWE-1104) and a secret in `ENV`
   (CWE-798) — so naming any one of them is a correct detection of V9.

Anything else is a label change that needs a reason in the PR, because widening a label is
indistinguishable from improving a scanner if nobody is watching.

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
| V9 | Container misconfig | A02 / CWE-250/1104/798 | `Dockerfile` (root user, `node:latest`, secret in ENV) |
| V10 | Broken JWT verification (`alg:none`, no sig/exp) | A07 / CWE-347 | `auth.js` `verifyToken` |
| V11 | Open redirect | A01 / CWE-601 | `auth.js` `redirect` (`?next=`) |
| V12 | Path traversal | A01 / CWE-22 | `auth.js` `readDoc` (`?file=`) |
| V13 | Mass assignment | A08 / CWE-915 | `auth.js` `updateProfile` (`Object.assign`) |
| V14 | Prototype pollution | A08 / CWE-1321 | `util.js` `merge` (no `__proto__` guard) |
| V15 | Insecure deserialization → code injection | A08 / CWE-502/94/95 | `util.js` `deserialize` (`eval`) |
| V16 | Server-side template injection | A05 / CWE-1336/94 | `util.js` `render` (`new Function`) |
| V17 | XXE (XML external entities) | A05 / CWE-611 | `py_app.py` `parse_xml` (`resolve_entities`) |
| V18 | Disabled TLS certificate verification | A04 / CWE-295 | `py_app.py` `fetch_secure` (`verify=False`) |
| V19 | OS command injection (Python) | A05 / CWE-78 | `py_app.py` `run_ping` (`shell=True`) |
| V20 | Insecure deserialization (pickle) | A08 / CWE-502 | `py_app.py` `load_session` (`pickle.loads`) |
| V21 | SQL injection across a function boundary | A03 / CWE-89 | `py_app.py` `list_users` → `find_by_name` (concatenated query in the helper) |
| V22 | OS command injection across a function boundary | A03 / CWE-78 | `server.js` `/archive` → `archiveLogs` (shell string built in the helper) |
| V23 | OS command injection across a MODULE boundary | A03 / CWE-78 | `server.js` `/report` → `util.js` `runReport` (imported helper builds the shell string) |
| V24 | Disabled TLS certificate verification (Go) | A02 / CWE-295 | `api.go` `client` (`InsecureSkipVerify: true`) |
| V25 | SQL injection (Go) | A03 / CWE-89 | `api.go` `lookup` (`fmt.Sprintf` into SQL) |
| V26 | OS command execution (Go) | A03 / CWE-78 | `api.go` `ping` (`exec.Command` with request value) |
| V27 | Insecure deserialization (Java) | A08 / CWE-502 | `Service.java` `load` (`ObjectInputStream`) |
| V28 | OS command execution (Java) | A03 / CWE-78 | `Service.java` `convert` (`Runtime.getRuntime().exec`) |
| V29 | SQL injection (Java) | A03 / CWE-89 | `Service.java` `find` (concatenated `executeQuery`) |
| V30 | Command execution sink (PHP) | A03 / CWE-78 | `index.php` `archive` (`shell_exec`) |
| V31 | Insecure deserialization (PHP) | A08 / CWE-502 | `index.php` `session_from_cookie` (`unserialize`) |
| V32 | SQL injection (PHP) | A03 / CWE-89 | `index.php` `find_user` (`$_GET` in `mysqli_query`) |
| V33 | Insecure deserialization (Ruby) | A08 / CWE-502 | `worker.rb` `restore` (`Marshal.load`) |
| V34 | Dynamic code execution (Ruby) | A03 / CWE-95 | `worker.rb` `apply_rule` (`eval`) |
| V35 | Insecure deserialization (C#) | A08 / CWE-502 | `Repository.cs` `Load` (`BinaryFormatter`) |
| V36 | SQL injection (C#) | A03 / CWE-89 | `Repository.cs` `Find` (concatenated `SqlCommand`) |
| V37 | `unsafe` without a safety comment (Rust) | A04 / CWE-758 | `lib.rs` `first_byte` |
| V38 | `mem::transmute` with no checks (Rust) | A04 / CWE-704 | `lib.rs` `as_floats` |
| V39 | Shell interpreter re-introduced (Rust) | A03 / CWE-78 | `lib.rs` `run` (`Command::new("sh").arg("-c")`) |
| V40 | Security group open to the world | A01 / CWE-284 | `main.tf` `aws_security_group_rule.admin` (`0.0.0.0/0`) |
| V41 | Public-read storage ACL | A01 / CWE-732 | `main.tf` `aws_s3_bucket_acl.reports` |
| V42 | Over-broad IAM policy | A01 / CWE-732 | `main.tf` `aws_iam_policy.app` (`Action`/`Resource` `*`) |
| V43 | Storage encryption disabled | A02 / CWE-311 | `main.tf` `aws_db_instance.primary` |
| V44 | Database publicly accessible | A01 / CWE-284 | `main.tf` `aws_db_instance.replica` |
| V45 | Host namespaces shared | A05 / CWE-668 | `deploy.yaml` `hostNetwork: true` |
| V46 | Privileged container | A05 / CWE-250 | `deploy.yaml` `privileged: true` |
| V47 | Privilege escalation allowed | A05 / CWE-250 | `deploy.yaml` `allowPrivilegeEscalation: true` |
| V48 | hostPath volume mount | A05 / CWE-552 | `deploy.yaml` `hostPath` |
| V49 | LangChain dangerous execution enabled | A05 / CWE-94 | `agent.py` `build_chain` (`allow_dangerous_requests=True`) |
| V50 | Agent code-execution tool exposed | A05 / CWE-94 | `agent.py` `tools_for` (`PythonREPLTool`) |
| V51 | Agent shell tool exposed | A05 / CWE-78 | `agent.py` `shell_tools` (`load_tools(["terminal"])`) |
| V52 | LLM output flows into a code-exec sink | A05 / CWE-94 | `agent.py` `run_plan` (`eval(response…)`) |
| V53 | Action pinned to a mutable ref | A03 / CWE-1357 | `ci.yml` `tj-actions/changed-files@main` |
| V54 | Remote script piped into a shell | A03 / CWE-494 | `ci.yml` `curl … | sh` |
| V55 | WebView JavaScript bridge | A05 / CWE-749 | `Mobile.kt` `setup` (`addJavascriptInterface`) |
| V56 | WebView JavaScript enabled | A05 / CWE-749 | `Mobile.kt` `setup` (`setJavaScriptEnabled(true)`) |
| V57 | World-readable file mode | A04 / CWE-732 | `Mobile.kt` `save` (`MODE_WORLD_READABLE`) |
| V58 | Flutter accepts any TLS certificate | A02 / CWE-295 | `net.dart` `buildClient` (`badCertificateCallback`) |
| V59 | App Transport Security disabled | A02 / CWE-319 | `Info.plist` `NSAllowsArbitraryLoads` |
| V60 | Hardcoded Stripe secret key | A07 / CWE-798 | `config.json` `stripe_secret_key` |
| V61 | Hardcoded Google API key | A07 / CWE-798 | `config.json` `google_api_key` |

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

- **All 61 code findings** present, across 15 languages (csharp 2, dart 1, docker 1, go 3, java 3, javascript 17, json 2, kotlin 3, php 3, plist 1, python 9, ruby 2, rust 3, terraform 5, yaml 6) → coverage pass.
- Dependency + secret sections populated (or clearly marked "tool/lookup unavailable").
- No false "all clear"; no leaked secret values.
