---
description: Run an authorized, defensive security audit on a target (live URL or source-code path) and produce a prioritized, remediation-focused report.
argument-hint: "<url | path> [--lang tr|en] [--passive] [--active] [--code] [--deps]"
allowed-tools: Read, Grep, Glob, WebFetch, WebSearch, Task, Bash(curl -sS*), Bash(curl -I*), Bash(command -v*), Bash(semgrep*), Bash(osv-scanner*), Bash(trivy fs*), Bash(trivy config*), Bash(trivy image*), Bash(gitleaks detect*), Bash(trufflehog filesystem*), Bash(testssl.sh*), Bash(npm audit*), Bash(pnpm audit*), Bash(pip-audit*), Bash(govulncheck*), Bash(cargo audit*), Bash(composer audit*), Bash(checkov*), Bash(tfsec*)
---

Run the **security-audit** skill against the target below.

Target / arguments: `$ARGUMENTS`

Instructions:

1. If no target is given, use the current working directory as a **source target**.
2. Parse flags from the arguments:
   - `--lang tr|en` — report language (default: match the user's language, else English).
   - `--passive` — never send active/probe requests, even to a live target (recon only).
   - `--active` — the user is asserting authorization for active testing; still confirm
     ownership/scope per the skill's authorization gate before probing.
   - `--code` — treat the target as source code only (skip live requests).
   - `--deps` — limit to dependency + secret + SBOM scanning.
3. Follow the security-audit skill: detect target type and available tools, enforce the
   authorization gate, run the phased methodology (passive recon → attack surface →
   known CVEs/deps → OWASP web/API → source review → infra → mobile/LLM if applicable),
   verify findings with minimal safe proof, and produce the final report in the
   skill's report format.

Default posture is **safe/passive**. Never perform DoS, brute-force, data
exfiltration, or produce weaponized exploits. State that the result is a best-effort
assessment, not a guarantee.
