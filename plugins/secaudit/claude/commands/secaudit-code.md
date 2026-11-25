---
description: Static source-code security audit (SAST + dependency + secret scan). No live requests — safe to run on any codebase you can read.
argument-hint: "[path] [--lang tr|en]"
allowed-tools: Read, Grep, Glob, WebSearch, WebFetch, Task, Bash(command -v*), Bash(semgrep*), Bash(opengrep*), Bash(osv-scanner*), Bash(trivy fs*), Bash(trivy config*), Bash(gitleaks detect*), Bash(trufflehog filesystem*), Bash(noseyparker*), Bash(npm audit*), Bash(pnpm audit*), Bash(pip-audit*), Bash(govulncheck*), Bash(cargo audit*), Bash(composer audit*), Bash(checkov*), Bash(kics*), Bash(tfsec*), Bash(zizmor*), Bash(grype*), Bash(syft*)
---

Run the **security-audit** skill in **source-code mode** against: `$ARGUMENTS`
(default to the current working directory if no path is given).

Do source review only — no live/network requests to any deployed target:

1. Detect the stack and available tools (semgrep, osv-scanner/trivy, gitleaks, per-eco
   audit tools). Use them if present; fall back to LLM analysis otherwise.
2. Run: dependency & SBOM CVE scan (P3), secret scan, and source-code review (P6) —
   trace user-controlled input to dangerous sinks; check authz, injection, unsafe
   deserialization, path traversal, SSRF, hardcoded secrets, weak crypto, unsafe
   JWT/session handling, and the CWE Top 25.
3. Include IaC/container review (P7) and LLM-safety (P9) if those files/features exist.
4. Verify reachability before flagging; triage scanner false positives.
5. Produce the report in the skill's format, language per `--lang` (default: user's
   language, else English).
