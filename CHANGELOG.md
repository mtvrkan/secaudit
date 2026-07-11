# Changelog

All notable changes to SecAudit are documented here. This project follows
[Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

## [1.0.0] — 2026-07-11

Initial public release — a Claude Code plugin + marketplace for authorized, defensive
security auditing of a live URL or a source-code repo.

### Core
- `/secaudit`, `/secaudit-code`, `/secaudit-passive`, `/secaudit-deps` commands.
- `secaudit` skill with a phased methodology (P1–P9) and progressive-disclosure references.
- `secaudit-verifier` adversarial finding-verification agent — scoped to a **read-only
  scanner allowlist** (`command -v`, `curl -sS/-I`, `osv-scanner`, the per-ecosystem
  `*-audit` tools, `trivy fs/config`, `semgrep`/`opengrep`) so it can never run arbitrary
  or state-changing commands.
- Hybrid scanning engine: auto-uses `semgrep`/`opengrep`, `trivy`, `osv-scanner`,
  `gitleaks`, `trufflehog`, `grype`/`syft`, `noseyparker`, `zizmor`, `checkov`/`kics`,
  `testssl.sh` when installed; LLM-analysis fallback otherwise. Zero tools required to start.
- Safe-by-default posture with an authorization gate for active testing; active-recon tools
  (`nuclei`, `nmap`, ZAP, ProjectDiscovery suite) stay gated behind explicit approval.
- English + Turkish report output.

### Coverage
- OWASP Web Top 10 (2021), API Top 10 (2023), LLM Top 10 (2025), Mobile Top 10 (2024),
  CWE Top 25; dependency/CVE (OSV/GHSA/NVD/CISA KEV); secrets; infra/IaC/containers.
- **Auth & identity** (`auth-identity.md`): JWT (`alg:none`, RS256→HS256 confusion,
  `kid`/`jku` injection), OAuth 2.0 / OIDC (`redirect_uri`, `state`, PKCE), SAML (XSW,
  comment-truncation), sessions, MFA, passkeys/WebAuthn.
- **Modern web** (`web-tests.md`): HTTP request smuggling / desync (CL.TE/TE.CL/CL.0/0.CL),
  web cache poisoning & deception, client-side prototype pollution, DOM clobbering,
  client-side path traversal (CSPT), Cross-Site WebSocket Hijacking, and XXE (CWE-611).
- **Agentic-AI & MCP** (`llm-ai-security.md`): OWASP Top 10 for Agentic Applications (2026)
  and MCP Top 10 (2025) — tool poisoning, rug-pull tool definitions, memory poisoning,
  indirect prompt injection (RAG / tool output / multimodal / Unicode-tag smuggling),
  per-action authz, tool sandboxing.
- **Supply chain**: self-replicating install-script worms (Shai-Hulud family), mutable-tag
  CI compromise (`tj-actions` CVE-2025-30066), slopsquatting, `xz`-style build backdoors,
  provenance verification (npm provenance / SLSA v1.2 / Sigstore, `npm audit signatures`).
- **CI/CD hardening** (`infra-cloud.md`): `zizmor` auditor, SHA-pinning, `pull_request_target`
  and script-injection checks, OIDC / trusted publishing, subdomain-takeover / dangling DNS.
- **API depth** (`api-tests.md`): GraphQL (introspection, depth/alias/batching), rate-limit
  bypass, gRPC, HTTP/2 Rapid Reset (CVE-2023-44487) — assessed by version/config, never flooding.
- **Mobile** (`mobile.md`): IPC/exported-component & deep-link/universal-link takeover,
  runtime hardening (Frida/objection), dynamic toolchain (MobSF, apktool/jadx, adb, proxy).
- Business-logic / race-condition and cloud IAM privilege-escalation coverage.

### Reporting
- Severity-ranked findings with impact, evidence, root cause, specific fix, and retest step.
- `CONFIRMED` / `PLAUSIBLE` / `REFUTED` verdicts plus a "Considered & Dismissed" section, a
  dependency/CVE register, positive controls, and a 24h/7d/30d remediation roadmap.

### Quality & safety
- Self-test harness: an intentionally-vulnerable fixture (`tests/fixtures/`) with **16 planted
  code flaws**, a golden set (`tests/expected-findings.md`), and a real fallback-mode dogfooding
  run (`examples/self-test-report.md`) proving the zero-tool path end-to-end.
- CI validation workflow (`permissions: contents: read`, SHA-pinned actions): JSON-manifest,
  frontmatter, reference-integrity, relative-link, and stray-secret checks + `zizmor` self-lint.
- Scope template, sanitized example report, and full documentation set.
