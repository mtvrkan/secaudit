# Authorization & scope

SecAudit is safe by default and gates anything that could affect a live target. This page
explains the two impact tiers and how to authorize active testing.

## The two tiers

**Passive / no authorization needed** — run freely:
- Reading and analyzing source code, manifests, configs, and IaC you give it.
- Dependency / SBOM / secret / SAST scans of local files.
- For a live URL: fetching pages a normal browser would (`GET /`, `robots.txt`,
  `sitemap.xml`, `.well-known/*`), reading response headers, TLS inspection, technology
  fingerprinting, and checking whether well-known sensitive paths exist — read-only, no
  payloads, ≤1–3 req/s.

**Active / authorization required** — gated:
- Any crafted/probe payload (injection canaries, auth-bypass attempts, IDOR enumeration,
  SSRF probes, fuzzing), authenticated testing, forced-browsing sweeps, or non-`GET`/`HEAD`
  requests that change state.

## How to authorize

Either:
- Add `--active` and confirm ownership when SecAudit asks, **or**
- Copy [`templates/scope.example.yaml`](../templates/scope.example.yaml) to `scope.yaml`,
  fill it in (set `i_am_authorized: true`), and point SecAudit at it. This is best for
  formal engagements — it records owner, approval, in-scope domains, test accounts,
  excluded paths, and rate limits.

`scope.yaml` is gitignored — don't commit a filled-in copy. **A committed one does not
authorize anything**: the hook asks git whether the file is tracked and refuses to count it if
it is. An assertion that travelled with a repository is not an assertion you made, and without
that rule any project could unlock active scanning in your session by shipping the file. If git
cannot answer (not installed), the file is refused rather than trusted — use `SECAUDIT_ACTIVE=1`,
which is the one channel a repository cannot supply.

## Deterministic enforcement (PreToolUse hook)

The passive/active boundary is not left to model discipline alone. The plugin ships a
**PreToolUse hook** (`plugins/secaudit/hooks/active-scan-guard.py`) that runs before every
`Bash` call and **blocks** these active patterns at the harness level:

- offensive/active scanners (`nuclei`, `nmap`, `sqlmap`, ZAP, `hydra`, `ffuf`, `nikto`, …),
- state-changing / payload-bearing HTTP requests (`curl`/`wget`/`httpie` with
  `-X POST|PUT|DELETE|PATCH`, a request body, or a file upload), and
- read-only `GET` requests that nonetheless carry a crafted probe/injection payload in the
  URL or query string (SQLi canary, path-traversal to a system file, cloud-metadata SSRF,
  XSS/SSTI marker, CRLF/null-byte) — a probe, not passive recon.

It allows them only once authorization is asserted — either an **untracked** `scope.yaml` with
`i_am_authorized: true` in the working directory, or `SECAUDIT_ACTIVE=1` in the session.
Passive recon (a plain read-only `GET`/`HEAD` of a real resource) and all local static
analysis (SAST / dependency / secret scans) are never blocked. The probe-payload check targets
the common OWASP canaries with high precision; a sufficiently obfuscated/encoded payload, or
one sent via the `WebFetch` tool (not a shell command), still relies on the skill's
authorization discipline — the hook is defense-in-depth, not a complete WAF. Even when
authorized, the absolute limits below always hold.

## Absolute limits (never crossed, even when authorized)

- No DoS / stress / high-volume fuzzing / resource exhaustion.
- No password/OTP/token brute-force; lockouts and rate limits respected.
- No exfiltration or display of real user data / PII / secrets — masked; canary for proof.
- No exploitation beyond minimum safe proof; no persistence, lateral movement, or privilege
  escalation beyond approved test roles; no third-party systems.
- Only in-scope assets; stop on instability.
- Never produces weaponized exploits, malware, or detection-evasion tooling.

## Legal

Testing systems you don't own or aren't authorized to test is illegal in most
jurisdictions. You are responsible for your authorization. Read the [DISCLAIMER](../DISCLAIMER.md).
