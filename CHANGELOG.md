# Changelog

All notable changes to SecAudit are documented here. This project follows
[Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

## [1.0.0] — 2026-07-11

Initial public release — a Claude Code plugin + marketplace for authorized, defensive
security auditing of a live URL or a source-code repo.

### Core
- `/secaudit`, `/secaudit-code`, `/secaudit-passive`, `/secaudit-deps` commands.
- `security-audit` skill with a phased methodology (P1–P9) and progressive-disclosure references.
- `secaudit-verifier` adversarial finding-verification agent — **read-only** (`Read`, `Grep`,
  `Glob`, `WebFetch`, `WebSearch`, `Bash`; `Write`/`Edit` denied) with an explicitly skeptical,
  refute-first prompt. Fine-grained Bash scoping is enforced by the parent command's
  `allowed-tools` and the session's permission rules, not the agent frontmatter.
- Hybrid scanning engine: auto-uses `semgrep`/`opengrep`, `trivy`, `osv-scanner`,
  `gitleaks`, `trufflehog`, `grype`/`syft`, `noseyparker`, `zizmor`, `checkov`/`kics`,
  `testssl.sh` when installed; LLM-analysis fallback otherwise. Zero tools required to start.
- Safe-by-default posture with an authorization gate for active testing; active-recon tools
  (`nuclei`, `nmap`, ZAP, ProjectDiscovery suite) stay gated behind explicit approval.
- **Deterministic passive/active enforcement** via a PreToolUse hook
  (`hooks/active-scan-guard.py`): blocks offensive scanners, state-changing/payload-bearing
  HTTP requests, and read-only `GET`s carrying a crafted probe payload (SQLi/traversal/SSRF/
  XSS/SSTI/CRLF canaries) at the harness level unless `scope.yaml` asserts
  `i_am_authorized: true` or `SECAUDIT_ACTIVE=1` is set — not left to model discipline. The
  probe-payload check is high-precision (defense-in-depth, not a WAF). Ships with a
  `--selftest` (18 active blocked, 12 passive allowed) gated in CI.
- English + Turkish report output.

### Coverage
- OWASP Web Top 10 (2025), API Top 10 (2023), LLM Top 10 (2025), Mobile Top 10 (2024),
  CWE Top 25; dependency/CVE (OSV/GHSA/NVD/CISA KEV); secrets; infra/IaC/containers.
- **Auth & identity** (`auth-identity.md`): JWT (`alg:none`, RS256→HS256 confusion,
  `kid`/`jku` injection), OAuth 2.0 / OIDC (`redirect_uri`, `state`, PKCE), SAML (XSW,
  comment-truncation), sessions, MFA, passkeys/WebAuthn.
- **Modern web** (`web-tests.md`): HTTP request smuggling / desync (CL.TE/TE.CL/CL.0/0.CL),
  web cache poisoning & deception, client-side prototype pollution, DOM clobbering,
  client-side path traversal (CSPT), Cross-Site WebSocket Hijacking, and XXE (CWE-611).
- **Agentic-AI & MCP** (`llm-ai-security.md`): OWASP Top 10 for Agentic Applications (2026, emerging)
  and MCP Top 10 (2025) — tool poisoning, rug-pull tool definitions, memory poisoning,
  indirect prompt injection (RAG / tool output / multimodal / Unicode-tag smuggling),
  per-action authz, tool sandboxing.
- **Supply chain**: self-replicating install-script worms (Shai-Hulud family), mutable-tag
  CI compromise (`tj-actions` CVE-2025-30066), slopsquatting, `xz`-style build backdoors,
  provenance verification (npm provenance / SLSA / Sigstore, `npm audit signatures`).
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
  dependency/CVE register, positive controls, and a 24–72h / 7–14d / 30–60d remediation roadmap.

### Quality & safety
- Self-test harness: a **multi-language** intentionally-vulnerable fixture (`tests/fixtures/`)
  with **20 planted code flaws** (16 JavaScript + 4 Python), a golden set
  (`tests/expected-findings.md`), a fallback-mode dogfooding run (`examples/self-test-report.md`),
  and a deterministic `tests/selftest.py` that mechanically asserts all 20 sinks + 3 secrets
  are present and that `npm audit` reports the cited CVEs.
- **Precision (negative control):** a paired **secure** fixture (`tests/fixtures/secure-app`)
  implementing the *same* 20 features safely (S1–S20 ↔ V1–V20), with an expected-clean spec
  (`tests/expected-clean.md`). Measures false-positive rate — the complement of the vulnerable
  fixture's recall. `selftest.py` gates it deterministically: no vulnerable sink marker may
  reappear **and** every safe control must stay present, so the corpus can't drift into being
  vulnerable or be emptied out.
- Report grader (`tests/grade-report.py`): scores any produced report against the golden set
  (CWE + unique-token matching, coverage + dependency/secret-section gates), and runs in CI
  against the reference report (`--min 20`) so it can never silently drop a finding.
- CI validation workflow (`permissions: contents: read`, SHA-pinned actions): JSON-manifest
  validity, unknown-manifest-field rejection (mirrors `--strict`), frontmatter, command
  Bash-allowlist-subset, reference-integrity, relative-link, and stray-secret checks, the
  fixture self-test, the golden-set coverage gate, the **PreToolUse hook config + guard
  self-test**, and a **pinned, blocking** `zizmor` self-lint.
- Scope template, sanitized example report, and full documentation set.

### Standalone kit (provider-agnostic, self-running)
- `kit/` — a dependency-free Python CLI that runs **outside** a Claude Code session (CI / cron /
  shell) and is **not tied to Claude**. Two tiers: **Tier 0** (deterministic detectors + installed
  scanners + `npm audit`, no LLM, always runs) and **Tier 1** (optional LLM enrichment — triage +
  logic-bug discovery — with a pluggable backend: `anthropic` / `openai` / `ollama` (local) /
  `none`, all over urllib, no vendor SDK). Claude stays the best default but is optional.
- **Detector pack:** 66 built-in deterministic detectors across JS/TS, Python, Go, Java, PHP,
  Ruby, C#, Kotlin, Swift, Dart, Dockerfile, Terraform, and Kubernetes — injection,
  deserialization, SSRF, XXE, weak crypto, secrets (AWS/GitHub/Slack/OpenAI/Google/Stripe/JWT/
  private-key), CORS/cookie config, cloud IAM/storage misconfig, and mobile (WebView JS-interface,
  ATS, world-perms, Flutter cert-bypass) — each with an optional `suppress_if` control marker.
  Secret findings are **redacted** (the kit never prints secret values; asserted in tests).
- **Installed-scanner integration:** semgrep (SARIF), gitleaks (JSON), and osv-scanner (JSON)
  are used when present and normalized into the common schema; higher-fidelity sources win on
  collision. Gracefully falls back to the built-in pack when a scanner is absent.
- **Reproducible, LLM-free measurement** (`kit/tests/test_engine.py`, CI-gated): **19/19** target
  sink classes found on the vulnerable corpus with **0 HIGH-confidence false positives** on the
  secure negative control. The one class the deterministic tier can't reach (V3 / IDOR / missing
  authz) is reserved, by design, for the LLM tier.
- **Real-code precision** (`kit/tests/test_dogfood.py`): the engine scans the kit's own ~1.5k-line
  production source (real code, nothing planted) and must report **0 High/Critical** — a
  false-positive check on genuine code, not a tuned fixture.
- **Two-tier pipeline, verified whole:** `kit/tests/test_enrich_e2e.py` runs Tier-0 → LLM triage →
  report in CI via a *replayed* model response (no key), asserting the LLM tier adds the IDOR/V3
  finding and triages Tier-0 leads. `kit/tests/test_live_llm.py` runs the same against a **real**
  provider when a key/Ollama is present and skips cleanly in CI. A `replay` backend makes captured
  responses reusable.
- **Output & CI:** Markdown / JSON / **SARIF 2.1.0** (GitHub code scanning); `--min` severity gate
  (non-zero exit); a bundled composite **GitHub Action** (`kit/action.yml`) + example workflow.
  Packaged via `pyproject.toml` (`secaudit` console entry point, zero runtime deps). UTF-8 output
  forced so a legacy console codepage can't crash a report.
