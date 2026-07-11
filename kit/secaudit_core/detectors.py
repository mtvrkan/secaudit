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
from dataclasses import dataclass

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
]


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
