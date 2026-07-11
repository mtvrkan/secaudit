<div align="center">

# 🛡️ SecAudit — Authorized Security Audit Kit for Claude Code

**Point Claude at a URL or a codebase. Get a prioritized, remediation-focused security report.**

Find known (CVE / dependency) **and** unknown (logic / code) vulnerabilities across the
OWASP Web, API, LLM, and Mobile Top 10 and the CWE Top 25 — using industry scanners when
you have them, and Claude's analysis when you don't.

[![Validate plugin](https://github.com/mtvrkan/secaudit/actions/workflows/validate.yml/badge.svg)](https://github.com/mtvrkan/secaudit/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-Plugin-8A2BE2)](https://docs.claude.com/en/docs/claude-code/plugins)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Top%2010%20aligned-000000)](https://owasp.org/www-project-top-ten/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

> ⚠️ **Defensive use only.** SecAudit is for auditing systems **you own or are explicitly
> authorized to test**. It defaults to safe/passive checks; active testing requires you to
> assert authorization. It will never produce weaponized exploits, malware, DoS payloads,
> or unauthorized-access tooling. See [Ethics & Legal](#ethics--legal).

## Why SecAudit?

Most "security scanners" give you a wall of raw findings with no context. SecAudit uses
Claude to **triage, verify, and explain** — separating real, reachable issues from noise,
chaining findings into real-world impact, and handing your developers a concrete fix and a
retest step for each one.

- 🎯 **Two modes, one command** — audit a **live URL** or a **source-code repo** (or both,
  and cross-reference them).
- 🔍 **Known + unknown vulns** — dependency/CVE scanning *and* logic/code analysis. Not
  just `npm audit`; actual OWASP-methodology testing.
- 🧰 **Hybrid engine** — auto-uses `semgrep`/`opengrep`, `trivy`, `osv-scanner`, `gitleaks`,
  `trufflehog`, `zizmor`, `testssl.sh` if installed (plus authorized-only `nuclei`/ZAP for active
  scans); falls back to Claude analysis if not. **Zero tools required to start.**
- 🧠 **Verified, not noisy** — an adversarial verifier agent tries to *refute* each
  high/critical finding before it reaches your report.
- 🌐 **OWASP Web + API + LLM + Mobile Top 10, CWE Top 25** — plus the 2025–2026 additions most
  scanners miss: **agentic-AI + MCP** risks (tool poisoning, excessive agency), **auth/identity**
  (JWT/OAuth/OIDC/SAML), **HTTP request smuggling**, **cache poisoning**, and current
  **supply-chain** attacks (self-replicating install-script worms, mutable-tag CI compromise,
  slopsquatting, provenance/SLSA).
- 📄 **Report you can act on** — severity-ranked findings, dependency/CVE register,
  positive controls, and a 24–72h / 7–14d / 30–60d remediation roadmap. English or Turkish.
- 🔒 **Safe by default** — passive recon needs no authorization; active testing is gated by a
  deterministic **PreToolUse hook** (not just model discipline) that blocks offensive scanners
  and state-changing requests until you assert authorization; no DoS, no brute-force, no data
  exfiltration, ever.

## Install

**Requires [Claude Code](https://docs.claude.com/en/docs/claude-code).** In a Claude Code session:

```
/plugin marketplace add mtvrkan/secaudit
/plugin install secaudit@secaudit-kit
```

That's it. No tools to install to get started — SecAudit works with just Claude. For deeper
scans, optionally install the [recommended tools](docs/tooling-setup.md) (`semgrep`,
`osv-scanner`, `gitleaks`, `testssl.sh`).

<details>
<summary>Manual install (without the marketplace)</summary>

```bash
git clone https://github.com/mtvrkan/secaudit
cp -r secaudit/plugins/secaudit/skills/*   ~/.claude/skills/
cp -r secaudit/plugins/secaudit/commands/* ~/.claude/commands/
cp -r secaudit/plugins/secaudit/agents/*   ~/.claude/agents/
```

> ⚠️ Manual install copies the skill, commands, and agent — but **not** the PreToolUse
> `hooks/`, which the marketplace install wires automatically. Without the hook, the
> passive/active authorization gate falls back to model discipline only (the deterministic,
> harness-level block on active scanners and probe payloads is not active). To keep it, also
> register `plugins/secaudit/hooks/active-scan-guard.py` as a PreToolUse hook — see
> [`hooks/README.md`](plugins/secaudit/hooks/README.md).
</details>

## Usage

```bash
/secaudit https://your-site.com        # full audit of a live target (passive by default)
/secaudit ./path/to/your/repo          # static source-code + dependency + secret audit
/secaudit https://site.com ./repo      # both — code confirms live findings and vice-versa

/secaudit-code                         # source-only audit of the current directory
/secaudit-passive https://site.com     # recon only, zero authorization needed
/secaudit-deps                         # dependency + supply-chain + secret scan only

/secaudit https://site.com --active    # authorized active testing (you assert ownership)
/secaudit ./repo --lang tr             # report in Turkish
```

For active testing against a live target, fill in
[`templates/scope.example.yaml`](templates/scope.example.yaml) or assert authorization in
chat. See [Authorization](docs/authorization.md).

## Run it without Claude Code (standalone kit)

The [`kit/`](kit) directory is a dependency-free Python CLI that runs **outside** a Claude Code
session — in CI, cron, or a plain shell — and is **not tied to Claude**:

```bash
python -m secaudit_core.cli /path/to/repo --min high        # Tier 0: deterministic, no LLM, no key
python -m secaudit_core.cli /path/to/repo --backend ollama  # optional local-model enrichment
ANTHROPIC_API_KEY=… python -m secaudit_core.cli /path/to/repo --backend anthropic   # or Claude/OpenAI
```

**Tier 0** (built-in detector pack + `npm audit`) always runs and is reproducible; **Tier 1**
optionally adds LLM triage + logic-bug discovery with a pluggable backend (`anthropic` / `openai`
/ `ollama` / `none`). On the shipped corpora the LLM-free tier measures **19/19** target sink
classes with **0 high-confidence false positives** — see [`kit/README.md`](kit/README.md).

## What you get

A structured report: executive summary → scope & constraints → methodology → severity-ranked
findings (each with impact, evidence, root cause, **specific fix**, and a **retest step**) →
dependency/CVE register → positive controls you already have → a prioritized remediation
roadmap. See a [sanitized example report](examples/example-report.md).

> 🧪 **Tested on itself — recall *and* precision.** SecAudit ships two paired fixtures. The
> **vulnerable** one plants **20 code flaws** across **JavaScript and Python** (SQLi, command
> injection, SSRF, insecure deserialization, SSTI, broken-JWT, IDOR, path traversal, mass
> assignment, prototype pollution, XSS, CORS, open redirect, weak crypto, hardcoded creds,
> container misconfig, XXE, disabled TLS verification) + 10 dependency vulns + 3 secrets — the
> committed [self-test report](examples/self-test-report.md) is a captured fallback-mode run
> (no scanners installed) that surfaces them all (**recall**). The **secure** fixture
> ([`secure-app`](tests/fixtures/secure-app)) implements the *same* 20 features safely; a correct
> audit stays quiet on it (**precision** — no crying wolf). CI gates both: `selftest.py` asserts
> every planted sink is still present *and* that the secure fixture hasn't drifted (no sink
> reappears, every control stays), and `grade-report.py` fails if the reference report drops any
> finding. See the [golden set](tests/expected-findings.md) and the
> [negative control](tests/expected-clean.md). Detection quality on your own code depends on the
> model at run time; these fixtures make it **measurable**, and every report states its own limitations.

## How it works

```
Target ──▶ Detect type (URL / source / both) & available tools
       ──▶ Authorization gate  (passive = free · active = must assert ownership)
       ──▶ Phased methodology:
             P1 Passive recon      P4 OWASP web tests    P7 Infra / cloud / IaC
             P2 Attack surface     P5 API tests          P8 Mobile (if app)
             P3 Known CVEs/deps    P6 Source review      P9 AI/LLM security (if AI)
       ──▶ Verify each finding (adversarial refutation of highs/criticals)
       ──▶ Prioritize (CISA KEV → exposure → impact)
       ──▶ Report (EN/TR) with fixes + retest checklist
```

Full methodology: [docs/methodology.md](docs/methodology.md).

## Features at a glance

| | |
|---|---|
| **Live URL audit** | headers, TLS, cookies, exposure, tech fingerprint, OWASP web/API tests |
| **Source audit (SAST)** | taint tracing to sinks, authz gaps, injection, SSTI, deserialization, secrets, weak crypto |
| **Auth & identity** | JWT (alg confusion, `alg:none`), OAuth/OIDC (`redirect_uri`, PKCE, `state`), SAML (XSW), sessions, MFA, passkeys |
| **Modern web** | HTTP request smuggling/desync, cache poisoning/deception, prototype pollution, DOM clobbering, CSWSH, CSPT |
| **Dependency / supply chain** | multi-ecosystem CVEs, slopsquatting, install-script worms, mutable-tag CI compromise, provenance/SLSA, KEV cross-ref |
| **Secret detection** | code + git history; masked reporting, rotation guidance |
| **Infra / IaC / CI/CD** | Dockerfile, Terraform, CloudFormation, K8s, Compose, cloud IAM, GitHub Actions (`zizmor`, SHA-pinning) |
| **AI / LLM / agents** | prompt injection (direct + indirect/RAG/multimodal), output → XSS, excessive agency, MCP tool poisoning, agentic threats, cost limits |
| **Mobile** | Android / iOS / Flutter — MASVS / Mobile Top 10 |

## Ethics & Legal

SecAudit is a **defensive** tool. By using it you agree to test only assets you own or are
explicitly authorized to test. Unauthorized scanning or testing of systems is illegal in
most jurisdictions. The maintainers accept no liability for misuse. Read the full
[DISCLAIMER](DISCLAIMER.md) and [SECURITY.md](.github/SECURITY.md).

It will refuse to: run DoS/brute-force, exfiltrate real data/PII, exploit beyond minimal
proof, or produce weaponized exploit code, malware, or detection-evasion tooling.

## Documentation

- [Getting started](docs/getting-started.md) · [Authorization & scope](docs/authorization.md)
- [Live URL mode](docs/live-url-mode.md) · [Source-code mode](docs/source-code-mode.md)
- [Tooling setup](docs/tooling-setup.md) · [Methodology](docs/methodology.md) · [FAQ](docs/faq.md)

## Contributing

New checks, tool integrations, language coverage, and false-positive fixes are very welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © mtvrkan

<div align="center">
<sub>Built for <a href="https://docs.claude.com/en/docs/claude-code">Claude Code</a>. Not affiliated with Anthropic or OWASP. If SecAudit helped secure your product, please ⭐ the repo.</sub>
</div>
