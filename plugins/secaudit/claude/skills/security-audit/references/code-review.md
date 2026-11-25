# P6 — Source-code review (SAST)

The "unknown vulnerabilities" half for source targets. Trace **user-controlled input →
dangerous sink**. Prioritize reachable issues over theoretical ones. No live requests.

## Workflow

1. **Map the app:** entry points (routes/controllers/handlers/serverless), auth/session
   layer, DB access layer, templating, file handling, external calls, config/secrets.
2. **Run SAST if available:** `semgrep --config auto . --sarif > sem.sarif` (or
   `--json`). Also language linters with security rules. Dedupe, drop test/vendor paths,
   keep security-category rules. Treat as leads → confirm each by reading the code.
3. **Taint-trace manually** for the classes below. For each candidate, follow the data
   from request to sink and confirm no sanitizer/validator neutralizes it in between.
4. **Secret scan:** `gitleaks detect --no-banner --report-format json` (+ git history)
   or `trufflehog filesystem .`. No tool → grep patterns (§Secrets). Never print values.

## What to look for (with common sinks)

- **Missing/weak server-side authorization** — routes without an authz check; ownership
  checks done client-side only; role checks trusting request-supplied fields.
- **Injection** — string-concatenated SQL, `db.query(\`...${x}\`)`, dynamic NoSQL,
  `exec`/`system`/`child_process`/`os.system`/`subprocess` with user input,
  `shell=True`, template rendering of user input (SSTI).
- **XSS sinks** — `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`,
  `eval`, unsanitized `marked.parse()`/markdown/HTML rendering (no DOMPurify).
- **Unsafe deserialization** — `pickle.loads`, `yaml.load` (non-safe), Java
  `ObjectInputStream`/Jackson polymorphic typing, PHP `unserialize`, .NET
  `BinaryFormatter`/`TypeNameHandling`, Ruby `Marshal.load`, Node `node-serialize`/`vm`. The
  risk is a **gadget chain** in the classpath/deps, not just the sink — flag any deserialization
  of untrusted bytes. Fix: safe formats (JSON with a schema), `yaml.safe_load`, allowlist types.
- **Server-side template injection (SSTI)** — user input into a template *expression* (Jinja2
  `{{}}`, Twig, Freemarker, Velocity, ERB, Handlebars, Thymeleaf, Go `text/template`) → RCE.
  Look for `render_template_string`, string-built templates, user input as the template not the
  data. Fix: pass user data as **context variables**, sandbox the engine, never compile user input.
- **Server-side prototype pollution** — unsafe recursive merge of request JSON into objects
  (`__proto__`/`constructor`) → auth bypass, RCE via gadget. Block those keys; `Object.create(null)`.
- **Path traversal / file** — user input in a filesystem path without normalization/
  allowlisting (`../`, absolute paths, null bytes; `fs.readFile(join(base, req.query.f))`,
  CWE-22); unrestricted upload destinations, `include`/`require` with user input, zip-slip.
- **SSRF** — server-side fetch of user-supplied URLs without allowlist/private-range block.
- **XXE (XML external entities, CWE-611)** — an XML parser that resolves external entities on
  untrusted input → local-file read (`file://`) and SSRF via a remote DTD. Look for
  `etree.XMLParser(resolve_entities=True)`/`no_network=False` (Python `lxml`), `DocumentBuilderFactory`
  without `disallow-doctype-decl`/`FEATURE_SECURE_PROCESSING` (Java), `libxml_disable_entity_loader`
  off (PHP), `XmlResolver` set (.NET). Fix: disable DTD/external-entity resolution (`defusedxml`,
  `resolve_entities=False`, secure-processing features).
- **Disabled TLS/cert verification (CWE-295)** — a client that turns off certificate validation
  → network MITM. `requests.get(..., verify=False)`, `ssl._create_unverified_context()`,
  `curl -k`/`--insecure`, `rejectUnauthorized: false` (Node), `InsecureSkipVerify: true` (Go),
  a trust-all `TrustManager`/`HostnameVerifier` (Java). Fix: keep verification on; pin/trust the
  proper CA bundle instead.
- **Weak crypto / randomness** — `Math.random()`/`rand()` for tokens, MD5/SHA1 for
  passwords, ECB mode, hardcoded IV/keys, no salt; passwords not argon2/bcrypt/scrypt.
- **Hardcoded secrets** — API keys, DB creds, JWT/signing secrets, private keys in code.
- **Unsafe JWT/session** — `alg:none` accepted, algorithm confusion (RS256→HS256), `kid`/`jku`
  injection, secret not verified, no expiry/`aud`, secret in client bundle, session id not
  regenerated on login. Deep checklist: `auth-identity.md`.
- **Open redirect** — `res.redirect(req.query.next)` / `Location` from user input without an
  allowlist (CWE-601); also an OAuth `redirect_uri` and SSRF pivot.
- **Mass assignment** — binding the whole request body to a model (`Object.assign(user, req.body)`,
  `Model(**request.json)`) lets a caller set `role`/`isAdmin`/`verified` (CWE-915). Allowlist fields.
- **CORS** — reflecting `Origin` + `Allow-Credentials: true`; `*` with credentials.
- **Missing security headers** — not set by the app/framework middleware.
- **Debug flags / verbose errors** — `DEBUG=True` in prod, stack traces to client.
- **Logging secrets/PII** — tokens/passwords/PII written to logs.
- **CI/CD** — secrets echoed, `pull_request_target` misuse, unpinned actions, overbroad
  `GITHUB_TOKEN` permissions (also `infra-cloud.md`).

## Language hotspots (grep starting points)

```
JS/TS:  eval  innerHTML  dangerouslySetInnerHTML  child_process  \.exec\(  document\.write  new Function
Python: pickle\.loads  yaml\.load\(  subprocess.*shell=True  os\.system  eval\(  \.format\(.*request  f".*SELECT  verify=False  resolve_entities=True
Go:     fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE)  exec\.Command  os/exec  template\.HTML
Java:   ObjectInputStream  Runtime\.getRuntime\(\)\.exec  createQuery\(".*\+  JdbcTemplate.*\+  new File\(.*request
PHP:    eval\(  system\(  exec\(  unserialize\(  include\(.*\$_  mysqli_query\(.*\$_  \$_(GET|POST|REQUEST)
Ruby:   eval\(  system\(  `.*#\{  send\(  constantize  Marshal\.load
C#:     BinaryFormatter  Process\.Start  SqlCommand.*\+  \.Deserialize\(
```

## Secrets — patterns (never print the value)

```
AKIA[0-9A-Z]{16}                     # AWS access key
gh[pousr]_[A-Za-z0-9]{36,}           # GitHub token
sk-[A-Za-z0-9]{20,}                  # OpenAI-style
xox[baprs]-[A-Za-z0-9-]+             # Slack
-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.  # JWT
(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["'][^"']{8,}
```

For each hit: confirm it's a real secret (not a placeholder/`example`/test fixture),
report `file:line + type + masked prefix (e.g. AKIA****)`, and recommend rotation +
moving to a secret manager + purging from git history (`git filter-repo`).

## Deliverable

Per-finding evidence with `file:line`, the tainted data path, and a concrete secure-code
fix. Mark these as **code-review findings** (static, not live-triggered) unless also
confirmed against a running instance.
