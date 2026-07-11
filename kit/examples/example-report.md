# SecAudit report — `tests/fixtures/vulnerable-app`

**Backend:** none  ·  **Tools:** builtin-detectors

## Summary

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 14 |
| Medium | 3 |
| Low | 0 |
| Informational | 0 |

**Total findings:** 21

## Findings

### [Critical] Insecure deserialization (pickle.loads on untrusted data)
- **Location:** `py_app.py:35`
- **Class:** CWE-502 · OWASP A08  ·  **Detector:** `SEC-PY-PICKLE` (builtin, confidence high, verdict unverified)
- **Evidence:** `return pickle.loads(base64.b64decode(cookie))  # UNSAFE: never unpickle untrusted data`
- **Fix:** Use a safe format (JSON with a schema); never unpickle untrusted bytes.

### [Critical] SQL injection via string concatenation
- **Location:** `server.js:12`
- **Class:** CWE-89 · OWASP A03  ·  **Detector:** `SEC-JS-SQLI` (builtin, confidence high, verdict unverified)
- **Evidence:** `const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";`
- **Fix:** Use parameterized queries / prepared statements; never concatenate input into SQL.

### [Critical] OS command injection (exec with concatenated input)
- **Location:** `server.js:18`
- **Class:** CWE-78 · OWASP A03  ·  **Detector:** `SEC-JS-CMDI` (builtin, confidence high, verdict unverified)
- **Evidence:** `exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));`
- **Fix:** Use execFile/spawn with an argument array (no shell) and validate input.

### [Critical] Insecure deserialization / code injection (eval)
- **Location:** `util.js:21`
- **Class:** CWE-95 · OWASP A03  ·  **Detector:** `SEC-JS-EVAL` (builtin, confidence high, verdict unverified)
- **Evidence:** `return eval('(' + str + ')');                        // UNSAFE: never eval untrusted data`
- **Fix:** Never eval untrusted input; parse data with JSON.parse.

### [High] Secret baked into image ENV
- **Location:** `Dockerfile:4`
- **Class:** CWE-798 · OWASP A05  ·  **Detector:** `SEC-DOCKER-ENVSECRET` (builtin, confidence high, verdict unverified)
- **Evidence:** `[redacted] possible secret detected here (value not shown)`
- **Fix:** Inject secrets at runtime (--env / mounted file); never bake them into the image.

### [High] Broken JWT verification (alg:none accepted)
- **Location:** `auth.js:13`
- **Class:** CWE-347 · OWASP A07  ·  **Detector:** `SEC-JS-JWT-NONE` (builtin, confidence high, verdict unverified)
- **Evidence:** `if (header.alg === 'none') return payload;          // UNSAFE: unsigned token accepted`
- **Fix:** Pin the algorithm server-side, verify the signature, and check exp/aud.

### [High] Path traversal (user input in filesystem path)
- **Location:** `auth.js:26`
- **Class:** CWE-22 · OWASP A01  ·  **Detector:** `SEC-JS-PATHTRAV` (builtin, confidence medium, verdict unverified)
- **Evidence:** `const file = path.join(__dirname, 'docs', req.query.file);  // ?file=../../etc/passwd`
- **Fix:** Resolve then verify the result stays within an allowed base directory.

### [High] Mass assignment (whole request body copied to model)
- **Location:** `auth.js:33`
- **Class:** CWE-915 · OWASP A08  ·  **Detector:** `SEC-JS-MASSASSIGN` (builtin, confidence high, verdict unverified)
- **Evidence:** `Object.assign(user, req.body);                      // UNSAFE: no field allowlist`
- **Fix:** Copy only an explicit field allowlist; never bind the raw body.

### [High] Improper output handling → XSS (unsanitized markdown to innerHTML)
- **Location:** `chat.js:12`
- **Class:** CWE-79 · OWASP A03  ·  **Detector:** `SEC-JS-XSS` (builtin, confidence high, verdict unverified)
- **Evidence:** `bubble.innerHTML = marked.parse(msg);          // UNSAFE: raw HTML from model output`
- **Fix:** Sanitize rendered HTML with DOMPurify before assignment (or use textContent).

### [High] Improper output handling → XSS (unsanitized markdown to innerHTML)
- **Location:** `chat.js:18`
- **Class:** CWE-79 · OWASP A03  ·  **Detector:** `SEC-JS-XSS` (builtin, confidence high, verdict unverified)
- **Evidence:** `if (raw) el.innerHTML = marked.parse(raw);       // UNSAFE: same sink on history load`
- **Fix:** Sanitize rendered HTML with DOMPurify before assignment (or use textContent).

### [High] XXE (XML external entity resolution enabled)
- **Location:** `py_app.py:16`
- **Class:** CWE-611 · OWASP A05  ·  **Detector:** `SEC-PY-XXE` (builtin, confidence high, verdict unverified)
- **Evidence:** `parser = etree.XMLParser(resolve_entities=True, no_network=False)  # UNSAFE`
- **Fix:** Disable entities/DTD/network (defusedxml or resolve_entities=False).

### [High] Disabled TLS certificate verification
- **Location:** `py_app.py:23`
- **Class:** CWE-295 · OWASP A02  ·  **Detector:** `SEC-PY-TLS` (builtin, confidence high, verdict unverified)
- **Evidence:** `return requests.get(url, verify=False, timeout=5)  # UNSAFE: verify=False`
- **Fix:** Keep certificate verification on; trust the proper CA bundle.

### [High] OS command injection (subprocess shell=True)
- **Location:** `py_app.py:29`
- **Class:** CWE-78 · OWASP A03  ·  **Detector:** `SEC-PY-CMDI` (builtin, confidence high, verdict unverified)
- **Evidence:** `return subprocess.call('ping -c 1 ' + host, shell=True)  # UNSAFE: shell=True + concat`
- **Fix:** Use an argument list without shell=True and validate input.

### [High] Weak password hashing (MD5)
- **Location:** `server.js:28`
- **Class:** CWE-327 · OWASP A02  ·  **Detector:** `SEC-JS-MD5` (builtin, confidence high, verdict unverified)
- **Evidence:** `return crypto.createHash('md5').update(pw).digest('hex');`
- **Fix:** Use a memory-hard KDF (argon2id / bcrypt / scrypt) with a per-password salt.

### [High] Hardcoded AWS access key id
- **Location:** `server.js:32`
- **Class:** CWE-798 · OWASP A07  ·  **Detector:** `SEC-SECRET-AWS` (builtin, confidence high, verdict unverified)
- **Evidence:** `[redacted] possible secret detected here (value not shown)`
- **Fix:** Remove the secret from source, rotate it, and load from a secret manager / env.

### [High] Possible SSRF (server fetch of user-supplied URL)
- **Location:** `server.js:44`
- **Class:** CWE-918 · OWASP A10  ·  **Detector:** `SEC-JS-SSRF` (builtin, confidence medium, verdict unverified)
- **Evidence:** `require('http').get(req.query.url, (r) => r.pipe(res));`
- **Fix:** Allowlist the destination host and block private / link-local ranges.

### [High] Prototype pollution (unguarded recursive merge)
- **Location:** `util.js:8`
- **Class:** CWE-1321 · OWASP A08  ·  **Detector:** `SEC-JS-PROTO` (builtin, confidence medium, verdict unverified)
- **Evidence:** `for (const key in source) {`
- **Fix:** Skip __proto__/constructor/prototype keys; use a null-prototype target.

### [High] Server-side template injection (dynamic Function)
- **Location:** `util.js:27`
- **Class:** CWE-94 · OWASP A03  ·  **Detector:** `SEC-JS-SSTI` (builtin, confidence high, verdict unverified)
- **Evidence:** `const fn = new Function('data', 'return `' + templateSource + '`');  // UNSAFE`
- **Fix:** Pass user data as template context; never compile it as code.

### [Medium] Unpinned base image (:latest)
- **Location:** `Dockerfile:3`
- **Class:** CWE-1104 · OWASP A06  ·  **Detector:** `SEC-DOCKER-LATEST` (builtin, confidence high, verdict unverified)
- **Evidence:** `FROM node:latest`
- **Fix:** Pin the base image by version and ideally by @sha256 digest.

### [Medium] Open redirect (user-controlled Location)
- **Location:** `auth.js:20`
- **Class:** CWE-601 · OWASP A01  ·  **Detector:** `SEC-JS-OPENREDIR` (builtin, confidence high, verdict unverified)
- **Evidence:** `res.writeHead(302, { Location: req.query.next });   // ?next=https://evil.example`
- **Fix:** Redirect only to an allowlist of relative paths.

### [Medium] Permissive CORS reflecting Origin
- **Location:** `server.js:37`
- **Class:** CWE-942 · OWASP A05  ·  **Detector:** `SEC-JS-CORS` (builtin, confidence high, verdict unverified)
- **Evidence:** `res.header('Access-Control-Allow-Origin', req.headers.origin);`
- **Fix:** Reflect only an explicit origin allowlist; never echo the request Origin with credentials.

## Notes & limitations

- Tier-0 (deterministic, no LLM). IDOR / broken-access-control and other logic flaws are not reliably detectable without the enrichment tier; run with an LLM backend for triage + logic-bug discovery.
- No LLM backend: findings are Tier-0, unverified. Add --backend anthropic|openai|ollama for triage + logic-bug discovery.

> Best-effort assessment, not a guarantee. The deterministic tier is a reproducible floor; detection quality with an LLM backend depends on the model.