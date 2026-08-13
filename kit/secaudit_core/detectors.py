"""Built-in deterministic detector pack (Tier 0, zero external dependencies).

Each detector is a regex sink-matcher with an optional `suppress_if` control-marker: if the
control regex is present in the same file, the finding is cleared (the safe pattern is in
place). This is a small, honest subset of what a full SAST engine (semgrep) does — the kit
uses installed scanners when present (see engine.py) and falls back to this pack when not, so
it always produces a report.

HIGH-confidence detectors match unambiguous sinks and should never fire on correct code —
they are what the precision measurement checks. MEDIUM detectors are leads that want triage;
that triage is exactly what the optional LLM tier adds. `maps_to` ties a detector to a golden
-set id (V1–V20) for the eval harness only; it has no runtime effect.

Honest bound: regex detectors are crude. On the shipped fixtures (which they were tuned
against) recall/precision are high; on arbitrary real code both are lower. This tier is the
reproducible floor, not a guarantee — the LLM tier and real scanners raise the ceiling.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .schema import Severity, Confidence


@dataclass(frozen=True)
class Detector:
    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    confidence: Confidence
    exts: tuple[str, ...]          # file extensions, or ("Dockerfile",) for the special name
    pattern: str
    fix: str
    maps_to: str = ""
    suppress_if: str = ""          # if this regex is found in the file, clear the finding
    mask: bool = False             # redact the evidence line (secret detectors never print values)
    case_sensitive: bool = False   # token-shape secrets (AKIA…, ghp_…) encode a fixed case — a
                                   # case-insensitive match would widen them into false positives
    literal: bool = True           # does this pattern legitimately match INSIDE a string literal
                                   # or comment? Secrets, SQL fragments and quoted header names
                                   # do; a code-shape rule like `eval(` does not, and matching
                                   # one inside a literal is a false positive — `"eval": Sink(…)`
                                   # in a rule catalog is not a call to eval. Detectors marked
                                   # False are scanned against `taint.code_view`, which blanks
                                   # comments and literal contents while preserving offsets.
                                   # Defaults to True so a new detector is never silently
                                   # narrowed; opt into the stricter view deliberately.

    def regex(self) -> re.Pattern:
        flags = re.M if self.case_sensitive else re.I | re.M
        return re.compile(self.pattern, flags)

    def suppressor(self) -> re.Pattern | None:
        return re.compile(self.suppress_if, re.I | re.M) if self.suppress_if else None


S, C = Severity, Confidence

# Secret patterns are language-agnostic — scan every text-ish source file plus Dockerfiles.
_SECRET_EXTS = (".js", ".ts", ".py", ".go", ".rb", ".php", ".java", ".cs", ".json",
                ".yaml", ".yml", ".env", ".txt", ".tf", "Dockerfile")

DETECTORS: list[Detector] = [
    # ---- JavaScript / TypeScript ----
    Detector("SEC-JS-SQLI", "SQL injection via string concatenation", "CWE-89", "A03",
             S.CRITICAL, C.HIGH, (".js", ".ts"),
             # Require an actual SQL statement shape (SELECT…FROM / UPDATE…SET / DELETE FROM /
             # INSERT INTO) followed by string concatenation — so the ordinary method name
             # `.update(...)` does not read as the SQL keyword UPDATE.
             r"(?:SELECT\b[^;\n]*\bFROM\b|INSERT\s+INTO\b|UPDATE\b[^;\n]*\bSET\b|DELETE\s+FROM\b)"
             r"[^;\n]*['\"]\s*\+",
             "Use parameterized queries / prepared statements; never concatenate input into SQL.",
             maps_to="V1"),
    Detector("SEC-JS-CMDI", "OS command injection (exec with concatenated input)", "CWE-78", "A03",
             S.CRITICAL, C.HIGH, (".js", ".ts"),
             r"\bexec\b\s*\(\s*['\"][^)]*\+",
             "Use execFile/spawn with an argument array (no shell) and validate input.",
             maps_to="V2"),
    Detector("SEC-JS-MD5", "Weak password hashing (MD5)", "CWE-327", "A02",
             S.HIGH, C.HIGH, (".js", ".ts"),
             r"createHash\(\s*['\"]md5['\"]",
             "Use a memory-hard KDF (argon2id / bcrypt / scrypt) with a per-password salt.",
             maps_to="V4"),
    Detector("SEC-SECRET-AWS", "Hardcoded AWS access key id", "CWE-798", "A07",
             S.HIGH, C.HIGH, (".js", ".ts", ".py", ".json", ".env", ".txt", "Dockerfile"),
             r"AKIA[0-9A-Z]{16}",
             "Remove the secret from source, rotate it, and load from a secret manager / env.",
             maps_to="V5", mask=True, case_sensitive=True),
    Detector("SEC-JS-CORS", "Permissive CORS reflecting Origin", "CWE-942", "A05",
             S.MEDIUM, C.HIGH, (".js", ".ts"),
             r"Access-Control-Allow-Origin['\"]?\s*,\s*req\.headers\.origin",
             "Reflect only an explicit origin allowlist; never echo the request Origin with credentials.",
             maps_to="V6"),
    Detector("SEC-JS-SSRF", "Possible SSRF (server fetch of user-supplied URL)", "CWE-918", "A10",
             S.HIGH, C.MEDIUM, (".js", ".ts"),
             r"\.get\(\s*req\.(?:query|params|body)",
             "Allowlist the destination host and block private / link-local ranges.",
             maps_to="V7"),
    Detector("SEC-JS-XSS", "Improper output handling → XSS (unsanitized markdown to innerHTML)",
             "CWE-79", "A03", S.HIGH, C.HIGH, (".js", ".ts"),
             r"innerHTML\s*=\s*marked\.parse",
             "Sanitize rendered HTML with DOMPurify before assignment (or use textContent).",
             maps_to="V8"),
    Detector("SEC-JS-JWT-NONE", "Broken JWT verification (alg:none accepted)", "CWE-347", "A07",
             S.HIGH, C.HIGH, (".js", ".ts"),
             r"alg\s*===?\s*['\"]none['\"]",
             "Pin the algorithm server-side, verify the signature, and check exp/aud.",
             maps_to="V10"),
    Detector("SEC-JS-OPENREDIR", "Open redirect (user-controlled Location)", "CWE-601", "A01",
             S.MEDIUM, C.HIGH, (".js", ".ts"),
             r"Location['\"]?\s*:\s*req\.query",
             "Redirect only to an allowlist of relative paths.",
             maps_to="V11"),
    Detector("SEC-JS-PATHTRAV", "Path traversal (user input in filesystem path)", "CWE-22", "A01",
             S.HIGH, C.MEDIUM, (".js", ".ts"),
             r"path\.(?:join|resolve)\([^)]*req\.(?:query|params|body)",
             "Resolve then verify the result stays within an allowed base directory.",
             maps_to="V12", suppress_if=r"\.startsWith\(\s*\w*(?:ROOT|BASE|DIR)"),
    Detector("SEC-JS-MASSASSIGN", "Mass assignment (whole request body copied to model)",
             "CWE-915", "A08", S.HIGH, C.HIGH, (".js", ".ts"),
             r"Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)",
             "Copy only an explicit field allowlist; never bind the raw body.",
             maps_to="V13"),
    Detector("SEC-JS-PROTO", "Prototype pollution (unguarded recursive merge)", "CWE-1321", "A08",
             S.HIGH, C.MEDIUM, (".js", ".ts"),
             r"for\s*\(\s*(?:const|let|var)?\s*\w+\s+in\s+\w+\s*\)",
             "Skip __proto__/constructor/prototype keys; use a null-prototype target.",
             maps_to="V14", suppress_if=r"BLOCKED\.has|Object\.create\(null\)|hasOwnProperty\("),
    Detector("SEC-JS-EVAL", "Insecure deserialization / code injection (eval)", "CWE-95", "A03",
             S.CRITICAL, C.HIGH, (".js", ".ts"),
             r"\beval\s*\(",
             "Never eval untrusted input; parse data with JSON.parse.",
             maps_to="V15"),
    Detector("SEC-JS-SSTI", "Server-side template injection (dynamic Function)", "CWE-94", "A03",
             S.HIGH, C.HIGH, (".js", ".ts"),
             r"new\s+Function\s*\(",
             "Pass user data as template context; never compile it as code.",
             maps_to="V16"),
    # ---- Python ----
    Detector("SEC-PY-XXE", "XXE (XML external entity resolution enabled)", "CWE-611", "A05",
             S.HIGH, C.HIGH, (".py",),
             r"resolve_entities\s*=\s*True",
             "Disable entities/DTD/network (defusedxml or resolve_entities=False).",
             maps_to="V17"),
    Detector("SEC-PY-TLS", "Disabled TLS certificate verification", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".py",),
             r"verify\s*=\s*False",
             "Keep certificate verification on; trust the proper CA bundle.",
             maps_to="V18"),
    Detector("SEC-PY-CMDI", "OS command injection (subprocess shell=True)", "CWE-78", "A03",
             S.HIGH, C.HIGH, (".py",),
             r"subprocess\.\w+\([^)]*shell\s*=\s*True",
             "Use an argument list without shell=True and validate input.",
             maps_to="V19"),
    Detector("SEC-PY-PICKLE", "Insecure deserialization (pickle.loads on untrusted data)",
             "CWE-502", "A08", S.CRITICAL, C.HIGH, (".py",),
             r"pickle\.loads\s*\(",
             "Use a safe format (JSON with a schema); never unpickle untrusted bytes.",
             maps_to="V20"),
    # ---- Container / IaC ----
    Detector("SEC-DOCKER-LATEST", "Unpinned base image (:latest)", "CWE-1104", "A06",
             S.MEDIUM, C.HIGH, ("Dockerfile",),
             r"^FROM\s+\S+:latest\b",
             "Pin the base image by version and ideally by @sha256 digest.",
             maps_to="V9"),
    Detector("SEC-DOCKER-ENVSECRET", "Secret baked into image ENV", "CWE-798", "A05",
             S.HIGH, C.HIGH, ("Dockerfile",),
             r"^ENV\s+\w*(?:TOKEN|SECRET|KEY|PASSWORD)\w*\s*=",
             "Inject secrets at runtime (--env / mounted file); never bake them into the image.",
             maps_to="V9", mask=True),

    # ---- Secret patterns (multi-file) ----
    Detector("SEC-SECRET-GH", "Hardcoded GitHub token", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
             "Revoke the token, rotate it, and load from a secret manager.", mask=True,
             case_sensitive=True),
    Detector("SEC-SECRET-SLACK", "Hardcoded Slack token", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
             "Revoke the token and move it to a secret manager.", mask=True, case_sensitive=True),
    Detector("SEC-SECRET-OPENAI", "Hardcoded OpenAI-style API key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bsk-[A-Za-z0-9]{32,}\b",
             "Revoke the key, rotate it, and load from the environment / a secret manager.",
             mask=True, case_sensitive=True),
    Detector("SEC-SECRET-PRIVKEY", "Private key committed to source", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
             "Remove the key from source, rotate it, and purge it from git history.", mask=True),
    Detector("SEC-SECRET-GENERIC", "Possible hardcoded credential", "CWE-798", "A07", S.MEDIUM, C.MEDIUM,
             _SECRET_EXTS,
             r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]",
             "If real, rotate it and load from env / a secret manager (ignore obvious placeholders).", mask=True),

    # ---- JavaScript / TypeScript (extra) ----
    Detector("SEC-JS-SHA1", "Weak hash (SHA-1)", "CWE-327", "A02", S.MEDIUM, C.MEDIUM, (".js", ".ts"),
             r"createHash\(\s*['\"]sha1['\"]", "Use SHA-256+ (or a KDF for passwords)."),
    Detector("SEC-JS-RANDOM", "Insecure randomness for security value", "CWE-338", "A02",
             S.MEDIUM, C.MEDIUM, (".js", ".ts"), r"Math\.random\s*\(",
             "Use crypto.randomBytes / crypto.getRandomValues for tokens, ids, salts."),

    # ---- Python (extra) ----
    Detector("SEC-PY-YAML", "Unsafe YAML load", "CWE-20", "A08", S.HIGH, C.HIGH, (".py",),
             r"yaml\.load\s*\(", "Use yaml.safe_load (or Loader=SafeLoader).",
             suppress_if=r"SafeLoader"),
    Detector("SEC-PY-OSSYSTEM", "OS command execution (os.system)", "CWE-78", "A03", S.HIGH, C.HIGH,
             (".py",), r"os\.system\s*\(", "Use subprocess with an argument list; validate input."),
    Detector("SEC-PY-EVAL", "Dynamic code execution (eval/exec)", "CWE-95", "A03", S.HIGH, C.HIGH,
             (".py",), r"\b(?:eval|exec)\s*\(", "Never eval/exec untrusted input."),
    Detector("SEC-PY-MD5", "Weak hash (MD5/SHA-1)", "CWE-327", "A02", S.MEDIUM, C.MEDIUM, (".py",),
             r"hashlib\.(?:md5|sha1)\s*\(", "Use SHA-256+ or a password KDF (argon2/bcrypt/scrypt)."),
    Detector("SEC-PY-DEBUG", "Debug mode enabled", "CWE-489", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"(?:DEBUG\s*=\s*True|\.run\([^)]*debug\s*=\s*True)",
             "Disable debug in production; never expose the interactive debugger."),
    # A settings module that defaults debug ON is the same exposure with a switch in front of
    # it: `DEBUG = env_bool("DJANGO_DEBUG", True)` ships debug to every deployment that forgot
    # the variable, which is the deployment that needed it off. The plain `DEBUG = True` above
    # does not match this shape.
    Detector("SEC-PY-DEBUG-DEFAULT", "Debug mode defaults to on when the env var is unset",
             "CWE-16", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"^\s*DEBUG\s*=\s*\w+\([^)]*(?:,\s*(?:True|['\"](?:1|true|yes|on)['\"])\s*\)"
             r"|[^)]*['\"](?:1|true)['\"]\s*\)\s*==\s*['\"](?:1|true)['\"])",
             "Default to False and opt in: `DEBUG = os.environ.get('DJANGO_DEBUG') == '1'`."),
    Detector("SEC-PY-ALLOWED-HOSTS", "ALLOWED_HOSTS accepts any Host header",
             "CWE-16", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"^\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]",
             "List the hostnames you serve. `['*']` enables Host-header injection, cache "
             "poisoning and password-reset poisoning."),
    # The literal is the whole finding: a fallback secret ships in the source, so every
    # deployment that does not set the variable signs its sessions with a key that is public.
    Detector("SEC-PY-SECRET-KEY-FALLBACK",
             "Signing key falls back to a literal committed in the source",
             "CWE-321", "A02", S.HIGH, C.HIGH, (".py",),
             r"^\s*(?:SECRET_KEY|JWT_SECRET\w*|\w*_SECRET_KEY)\s*=\s*(?:os\.)?(?:environ\.get|getenv)"
             r"\s*\(\s*[^)]*,\s*['\"][^'\"]{8,}['\"]",
             "Fail closed when the variable is missing rather than falling back: a committed "
             "default key is a published key.", mask=True),
    # Cookie flags. Suppressed when the call already names the flags, so a correct call is not
    # reported — that suppression is per-file, which is the pack's coarse-grained trade-off.
    Detector("SEC-PY-COOKIE-FLAGS", "Cookie set without Secure/HttpOnly",
             "CWE-1004", "A05", S.MEDIUM, C.MEDIUM, (".py",),
             r"\.set_cookie\s*\((?:[^()]|\([^()]*\))*\)",
             "Set `httponly=True, secure=True, samesite='Lax'` — without HttpOnly the cookie is "
             "readable by any script the page ends up running.",
             suppress_if=r"set_cookie\s*\((?:[^()]|\([^()]*\))*httponly\s*=\s*True"),
    # Randomness for security material. `random` is a Mersenne Twister: observe enough output
    # and the rest is predictable, which is exactly the property a token must not have. Bound
    # to security-shaped names on purpose — `random.choice` picking a demo colour is fine, and
    # a rule that says otherwise gets muted.
    Detector("SEC-PY-WEAK-PRNG", "Security material generated with a non-cryptographic PRNG",
             "CWE-330", "A02", S.HIGH, C.MEDIUM, (".py",),
             r"^\s*\w*(?:key|token|secret|nonce|otp|code|session|salt|iv|password|passwd|pin|"
             r"verifier|challenge)\w*\s*=\s*[^=\n]*\brandom\s*\.\s*"
             r"(?:random|randint|randrange|choice|choices|sample|getrandbits|shuffle|uniform)\s*\(",
             "Use `secrets` (or `os.urandom`): `secrets.token_urlsafe(32)`."),
    Detector("SEC-PY-CSRF-EXEMPT", "CSRF protection switched off",
             "CWE-352", "A01", S.MEDIUM, C.HIGH, (".py",),
             r"@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False"
             r"|\bcsrf\.exempt\b",
             "Keep CSRF protection on for any state-changing route; use a token, not an "
             "exemption."),

    # ---- Go ----
    Detector("SEC-GO-TLS", "Disabled TLS verification (InsecureSkipVerify)", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".go",), r"InsecureSkipVerify:\s*true",
             "Keep certificate verification on; trust the proper CA bundle."),
    Detector("SEC-GO-SQL", "Possible SQL injection (Sprintf into SQL)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".go",),
             r"fmt\.Sprintf\([^)]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
             "Use parameterized queries (database/sql placeholders)."),
    Detector("SEC-GO-EXEC", "OS command execution (exec.Command)", "CWE-78", "A03",
             S.MEDIUM, C.MEDIUM, (".go",), r"exec\.Command\(",
             "Validate arguments; never pass user input to a shell."),

    # ---- Rust ----
    # Rust's memory safety is enforced by the compiler, so the classes worth a rule are the
    # ones where the code opts *out* of it, plus the panic paths that turn a request into a
    # denial of service. Deliberately three narrow rules rather than a broad pack: a language
    # where most of the usual sinks cannot exist deserves rules about what is actually left.
    Detector("SEC-RS-UNSAFE", "`unsafe` block without a safety comment", "CWE-758", "A04",
             S.MEDIUM, C.MEDIUM, (".rs",), r"^\s*unsafe\s*\{",
             "Document the invariants that make this block sound in a `// SAFETY:` comment "
             "directly above it, or replace it with a safe abstraction.",
             suppress_if=r"//\s*SAFETY:"),
    Detector("SEC-RS-TRANSMUTE", "`mem::transmute` reinterprets bytes with no checks",
             "CWE-704", "A04", S.HIGH, C.MEDIUM, (".rs",), r"\bmem::transmute\b|\btransmute::<",
             "Prefer a checked conversion (`TryFrom`, `from_le_bytes`, `bytemuck`); transmute "
             "assumes a layout the compiler does not verify."),
    Detector("SEC-RS-CMDI", "Shell command built with a shell interpreter", "CWE-78", "A03",
             S.MEDIUM, C.MEDIUM, (".rs",),
             r"Command::new\(\s*\"(?:sh|bash|cmd|powershell)\"|\.arg\(\s*\"-c\"",
             "Invoke the program directly with `Command::new(prog).arg(value)`; a `-c` string "
             "re-introduces shell metacharacter injection that Rust otherwise avoids."),

    # ---- Java ----
    Detector("SEC-JAVA-DESER", "Insecure deserialization (ObjectInputStream)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".java",), r"\bObjectInputStream\b",
             "Avoid Java native deserialization of untrusted data; use a safe format."),
    Detector("SEC-JAVA-EXEC", "OS command execution (Runtime.exec)", "CWE-78", "A03",
             S.HIGH, C.HIGH, (".java",), r"Runtime\.getRuntime\(\)\.exec",
             "Use ProcessBuilder with an argument list; validate input."),
    Detector("SEC-JAVA-SQL", "Possible SQL injection (concatenated query)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".java",), r"executeQuery\([^)]*\+",
             "Use PreparedStatement with bind parameters."),

    # ---- PHP ----
    Detector("SEC-PHP-EXEC", "Command/code execution sink", "CWE-78", "A03", S.HIGH, C.HIGH, (".php",),
             r"\b(?:system|exec|shell_exec|passthru|eval)\s*\(",
             "Avoid these on untrusted input; use safe APIs and validation."),
    Detector("SEC-PHP-UNSER", "Insecure deserialization (unserialize)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".php",), r"\bunserialize\s*\(",
             "Never unserialize untrusted data; use JSON."),
    Detector("SEC-PHP-SQLI", "SQL injection (superglobal in query)", "CWE-89", "A03",
             S.HIGH, C.HIGH, (".php",), r"mysqli_query\([^)]*\$_(?:GET|POST|REQUEST)",
             "Use prepared statements (mysqli/PDO bind parameters)."),

    # ---- Ruby ----
    Detector("SEC-RB-MARSHAL", "Insecure deserialization (Marshal.load)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".rb",), r"Marshal\.load",
             "Never Marshal.load untrusted data; use JSON."),
    Detector("SEC-RB-EVAL", "Dynamic code execution (eval)", "CWE-95", "A03", S.HIGH, C.HIGH, (".rb",),
             r"\beval\s*\(", "Never eval untrusted input."),

    # ---- C# ----
    Detector("SEC-CS-DESER", "Insecure deserialization (BinaryFormatter)", "CWE-502", "A08",
             S.HIGH, C.HIGH, (".cs",), r"\bBinaryFormatter\b",
             "BinaryFormatter is unsafe and removed in modern .NET; use a safe serializer."),
    Detector("SEC-CS-SQL", "Possible SQL injection (concatenated SqlCommand)", "CWE-89", "A03",
             S.MEDIUM, C.MEDIUM, (".cs",), r"SqlCommand\([^)]*\+",
             "Use parameterized queries (SqlParameter)."),

    # ---- Container / IaC (extra) ----
    Detector("SEC-DOCKER-CURLSH", "Remote script piped to a shell in RUN", "CWE-494", "A08",
             S.HIGH, C.HIGH, ("Dockerfile",), r"RUN[^\n]*\bcurl\b[^\n]*\|\s*(?:sh|bash)\b",
             "Download, verify a checksum/signature, then execute — never pipe curl to a shell."),
    Detector("SEC-DOCKER-USERROOT", "Container explicitly runs as root", "CWE-250", "A05",
             S.MEDIUM, C.MEDIUM, ("Dockerfile",), r"^USER\s+root\b",
             "Run as a non-root user."),
    Detector("SEC-TF-OPENINGRESS", "Security group open to the world", "CWE-284", "A01",
             S.MEDIUM, C.MEDIUM, (".tf",), r"cidr_blocks\s*=\s*\[?\s*['\"]0\.0\.0\.0/0",
             "Restrict ingress to known CIDRs; avoid 0.0.0.0/0 on sensitive ports."),
    Detector("SEC-TF-PUBLICACL", "Public-read storage ACL", "CWE-732", "A01",
             S.MEDIUM, C.MEDIUM, (".tf",), r"acl\s*=\s*['\"]public-read",
             "Keep buckets private; use signed URLs / explicit policies."),
    Detector("SEC-TF-IAM-WILDCARD", "Over-broad IAM policy (Action/Resource \"*\")", "CWE-732", "A01",
             S.MEDIUM, C.MEDIUM, (".tf", ".json", ".yaml", ".yml"),
             r"['\"](?:Action|Resource)['\"]\s*[:=]\s*['\"]\*['\"]",
             "Scope IAM actions and resources to the minimum needed."),
    Detector("SEC-TF-UNENCRYPTED", "Storage encryption disabled", "CWE-311", "A02",
             S.MEDIUM, C.MEDIUM, (".tf",), r"(?:storage_encrypted|encrypted)\s*=\s*false",
             "Enable encryption at rest."),
    Detector("SEC-TF-PUBLICDB", "Database publicly accessible", "CWE-284", "A01",
             S.HIGH, C.MEDIUM, (".tf",), r"publicly_accessible\s*=\s*true",
             "Keep managed databases in private subnets; never expose them publicly."),

    # ---- Kubernetes ----
    Detector("SEC-K8S-PRIVILEGED", "Privileged container", "CWE-250", "A05", S.HIGH, C.HIGH,
             (".yaml", ".yml"), r"privileged:\s*true",
             "Drop privileged; use least-privilege securityContext + capability drops."),
    Detector("SEC-K8S-PRIVESC", "Privilege escalation allowed", "CWE-250", "A05", S.MEDIUM, C.MEDIUM,
             (".yaml", ".yml"), r"allowPrivilegeEscalation:\s*true",
             "Set allowPrivilegeEscalation: false."),
    Detector("SEC-K8S-HOSTPATH", "hostPath volume mount", "CWE-552", "A05", S.MEDIUM, C.MEDIUM,
             (".yaml", ".yml"), r"hostPath:", "Avoid hostPath; use PVCs / restricted volumes."),
    Detector("SEC-K8S-HOSTNET", "Host network / PID namespace shared", "CWE-668", "A05",
             S.MEDIUM, C.MEDIUM, (".yaml", ".yml"), r"host(?:Network|PID|IPC):\s*true",
             "Do not share the host network/PID/IPC namespaces."),

    # ---- Web / config (cross-language) ----
    Detector("SEC-CORS-WILDCARD", "CORS allows any origin (*)", "CWE-942", "A05", S.MEDIUM, C.MEDIUM,
             (".js", ".ts", ".py", ".go", ".java", ".rb", ".php"),
             r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]",
             "Use an explicit origin allowlist, especially with credentials."),
    Detector("SEC-COOKIE-INSECURE", "Cookie without Secure/HttpOnly", "CWE-1004", "A05",
             S.MEDIUM, C.MEDIUM, (".js", ".ts", ".py"),
             r"(?:secure|httpOnly)\s*[:=]\s*false",
             "Set Secure + HttpOnly (+ SameSite) on session cookies."),

    # ---- Secrets (more providers) ----
    Detector("SEC-SECRET-GOOGLE", "Hardcoded Google API key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bAIza[0-9A-Za-z_\-]{35}\b",
             "Revoke and rotate the key; restrict it; load from a secret manager.", mask=True,
             case_sensitive=True),
    Detector("SEC-SECRET-STRIPE", "Hardcoded Stripe secret key", "CWE-798", "A07", S.HIGH, C.HIGH,
             _SECRET_EXTS, r"\bsk_live_[0-9A-Za-z]{20,}\b",
             "Revoke and rotate immediately; load from a secret manager.", mask=True,
             case_sensitive=True),
    Detector("SEC-SECRET-JWT", "JWT / bearer token in source", "CWE-798", "A07", S.MEDIUM, C.MEDIUM,
             _SECRET_EXTS, r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
             "Do not commit tokens; issue them at runtime and store server-side.", mask=True,
             case_sensitive=True),

    # ---- Mobile: Android (Kotlin / Java) ----
    Detector("SEC-ANDROID-JSIF", "WebView addJavascriptInterface (RCE surface)", "CWE-749", "A05",
             S.HIGH, C.HIGH, (".java", ".kt"), r"addJavascriptInterface\s*\(",
             "Avoid it on untrusted content; require API 17+ and @JavascriptInterface, or drop it."),
    Detector("SEC-ANDROID-WORLDPERM", "World-readable/writable file mode", "CWE-732", "A04",
             S.HIGH, C.HIGH, (".java", ".kt"), r"MODE_WORLD_(?:READABLE|WRITEABLE)",
             "Use MODE_PRIVATE; share via a FileProvider/content URI."),
    Detector("SEC-ANDROID-WEBVIEW-JS", "WebView JavaScript enabled", "CWE-749", "A05",
             S.MEDIUM, C.MEDIUM, (".java", ".kt"), r"setJavaScriptEnabled\s*\(\s*true\s*\)",
             "Enable JS only when required and only for trusted content."),

    # ---- Mobile: iOS (Swift) / Flutter (Dart) ----
    Detector("SEC-IOS-ATS", "App Transport Security disabled", "CWE-319", "A02", S.HIGH, C.HIGH,
             (".plist", ".xml", ".swift"), r"NSAllowsArbitraryLoads",
             "Keep ATS on; allow-list specific domains instead of disabling it globally."),
    Detector("SEC-DART-BADCERT", "Flutter accepts any TLS certificate", "CWE-295", "A02",
             S.HIGH, C.HIGH, (".dart",), r"badCertificateCallback\s*=",
             "Never return true for all certs; pin or validate properly."),

    # ---- AI / LLM / agentic security (2025-2026) ----
    # LLM Top 10:2025 + the emerging Agentic-Apps / MCP risk classes. Regex-detectable
    # surfaces only; deeper prompt-injection / excessive-agency analysis is the LLM tier's job.
    Detector("SEC-AI-LANGCHAIN-DANGER", "LangChain dangerous execution explicitly enabled",
             "CWE-94", "A05", S.HIGH, C.HIGH, (".py", ".js", ".ts"),
             r"allow_dangerous_(?:code|requests|deserialization|tools)\s*=\s*True",
             "Do not enable dangerous execution on untrusted input; sandbox the agent and gate tools."),
    Detector("SEC-AI-PYREPL", "Agent code-execution tool (Python REPL) exposed", "CWE-94", "A05",
             S.MEDIUM, C.MEDIUM, (".py",), r"\bPython(?:Ast)?REPLTool\b",
             "Arbitrary-code tools give an LLM RCE; remove, or run in an isolated sandbox with no secrets."),
    Detector("SEC-AI-SHELL-TOOL", "Agent shell/terminal tool exposed to the model", "CWE-78", "A05",
             S.MEDIUM, C.MEDIUM, (".py",),
             r"\bShellTool\b|load_tools\(\s*\[[^\]]*['\"](?:terminal|shell)['\"]",
             "Giving an LLM a shell is excessive agency; drop it or constrain to an allowlisted command set."),
    Detector("SEC-AI-LLM-EXEC", "LLM/completion output flows into a code-exec sink", "CWE-94", "A05",
             S.HIGH, C.MEDIUM, (".py",),
             r"(?:eval|exec)\(\s*\w*(?:response|completion|message|output|result|llm|answer)\w*",
             "Never execute model output; treat it as untrusted data and validate/parse it."),

    # ---- Secrets: modern token formats (2025-2026 provider shapes) ----
    Detector("SEC-SECRET-ANTHROPIC", "Hardcoded Anthropic API key", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
             "Revoke and rotate the key; load it from the environment / a secret manager.",
             mask=True, case_sensitive=True),
    Detector("SEC-SECRET-GH-PAT", "Hardcoded GitHub fine-grained PAT", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bgithub_pat_[0-9A-Za-z_]{22,}\b",
             "Revoke the token in GitHub settings, rotate it, and load from a secret manager.",
             mask=True, case_sensitive=True),
    Detector("SEC-SECRET-HF", "Hardcoded Hugging Face token", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bhf_[A-Za-z0-9]{34,}\b",
             "Revoke and rotate the token; load it from the environment / a secret manager.",
             mask=True, case_sensitive=True),
    Detector("SEC-SECRET-NPM", "Hardcoded npm access token", "CWE-798", "A07",
             S.HIGH, C.HIGH, _SECRET_EXTS, r"\bnpm_[A-Za-z0-9]{36}\b",
             "Revoke the token (npm token revoke), rotate it, and store it in CI secrets.",
             mask=True, case_sensitive=True),

    # ---- Software supply chain / CI (2025-2026) ----
    # The A03:2025 "Software Supply Chain Failures" surface — mutable-tag CI compromise
    # (the tj-actions/changed-files CVE-2025-30066 class) and install-script execution.
    Detector("SEC-CI-MUTABLE-ACTION", "GitHub Action pinned to a mutable branch ref",
             "CWE-1357", "A03", S.HIGH, C.HIGH, (".yml", ".yaml"),
             # Two branch shapes, because only catching the first missed the one this
             # repository's own release workflow reached for. A bare branch name
             # (`@main`, `@develop`), and any ref containing a slash (`@release/v1`,
             # `@feature/x`) — a slash is overwhelmingly a branch, since tags almost never
             # carry one. A plain version tag (`@v4`) is deliberately NOT matched: it is
             # mutable too, but flagging it fires on nearly every workflow in existence, and
             # a rule that fires everywhere is a rule that gets suppressed everywhere. The
             # fix text names it as the second-best option instead.
             r"uses:\s*[\w.\-]+/[\w.\-]+@(?:(?:main|master|develop|trunk|latest|stable|HEAD)\b"
             r"|[\w.\-]+/[\w.\-]+)",
             "Pin third-party Actions to a full commit SHA — a branch is mutable and can be "
             "repointed at malicious code (the tj-actions/changed-files CVE-2025-30066 class, "
             "where the attacker moved the refs rather than publishing new code). Dependabot "
             "can still bump the pin. A version tag is better than a branch, a SHA is safest."),
    Detector("SEC-SUPPLY-CURLPIPE", "Remote script piped straight into a shell", "CWE-494", "A03",
             S.HIGH, C.HIGH, (".sh", ".yml", ".yaml"),
             r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b",
             "Download, verify a checksum/signature, then run — never pipe curl/wget to a shell."),
]


# Detectors whose pattern describes CODE SHAPE rather than literal text. These are scanned
# against `taint.code_view` — comments and string-literal contents blanked — so a rule catalog
# that mentions `eval(` in a string, or a comment naming a vulnerability class, no longer reads
# as the vulnerability itself. Everything NOT listed here keeps the raw view, because it
# legitimately matches inside a literal: a hardcoded secret, a SQL fragment, a quoted header
# name, `createHash('md5')`, `alg === 'none'`.
#
# Kept as one explicit set rather than a flag on each of 76 definitions: the decision is
# "which side of one line is this rule on", and it is reviewable in a single screen. Check 22
# in `scripts/check_consistency.py` fails if an id here does not exist.
CODE_SHAPE_DETECTORS = {
    "SEC-JS-SSRF", "SEC-JS-XSS", "SEC-JS-PATHTRAV", "SEC-JS-MASSASSIGN", "SEC-JS-PROTO",
    "SEC-JS-EVAL", "SEC-JS-SSTI", "SEC-JS-RANDOM",
    "SEC-PY-XXE", "SEC-PY-TLS", "SEC-PY-CMDI", "SEC-PY-PICKLE", "SEC-PY-YAML",
    "SEC-PY-OSSYSTEM", "SEC-PY-EVAL", "SEC-PY-MD5", "SEC-PY-DEBUG",
    "SEC-PY-DEBUG-DEFAULT", "SEC-PY-COOKIE-FLAGS", "SEC-PY-WEAK-PRNG", "SEC-PY-CSRF-EXEMPT",
    "SEC-GO-TLS", "SEC-GO-EXEC",
    # SEC-RS-CMDI is deliberately NOT here. It matches `Command::new("sh")` and `.arg("-c")`
    # — the shell name and the flag are string-literal *contents*, which `code_view` blanks,
    # so listing it made the rule unfirable. Caught by planting a Rust fixture: a detector
    # with no fixture is an unmeasured claim, and this one had been wrong since it shipped.
    "SEC-RS-UNSAFE", "SEC-RS-TRANSMUTE",
    "SEC-JAVA-DESER", "SEC-JAVA-EXEC", "SEC-JAVA-SQL",
    "SEC-PHP-EXEC", "SEC-PHP-UNSER", "SEC-PHP-SQLI",
    "SEC-RB-MARSHAL", "SEC-RB-EVAL",
    "SEC-CS-DESER", "SEC-CS-SQL",
    "SEC-COOKIE-INSECURE",
    "SEC-ANDROID-JSIF", "SEC-ANDROID-WORLDPERM", "SEC-ANDROID-WEBVIEW-JS",
    "SEC-AI-LANGCHAIN-DANGER", "SEC-AI-PYREPL", "SEC-AI-LLM-EXEC",
}

DETECTORS = [replace(d, literal=False) if d.id in CODE_SHAPE_DETECTORS else d
             for d in DETECTORS]


def group_of(detector_id: str) -> str:
    """The area segment of an id: `SEC-SECRET-AWS` -> `secret`, `TAINT-PY-CMDI` -> `py`.

    Derived from the id rather than kept as a field, so a new detector joins its group by being
    named consistently and there is no second list to forget to update. Ids that do not fit the
    shape fall into `other`, which is visible in `--only other` rather than silently dropped.
    """
    parts = detector_id.split("-")
    return parts[1].lower() if len(parts) >= 3 else "other"


def groups() -> dict[str, int]:
    """{group: detector count}, for `--only` and its error message."""
    out: dict[str, int] = {}
    for d in DETECTORS:
        out[group_of(d.id)] = out.get(group_of(d.id), 0) + 1
    return dict(sorted(out.items()))


def detectors_for(filename: str) -> list[Detector]:
    """Detectors whose file selector matches this filename."""
    import os
    base = os.path.basename(filename)
    ext = os.path.splitext(base)[1].lower()
    out = []
    for d in DETECTORS:
        if "Dockerfile" in d.exts and base == "Dockerfile":
            out.append(d)
        elif ext and ext in d.exts:
            out.append(d)
    return out
