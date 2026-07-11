---
description: Dependency, SBOM, and secret scan of a codebase — find vulnerable packages (CVE), supply-chain risks, and leaked secrets. Fast, safe, no live requests.
argument-hint: "[path] [--lang tr|en]"
allowed-tools: Read, Grep, Glob, WebSearch, WebFetch, Bash(command -v*), Bash(osv-scanner*), Bash(trivy fs*), Bash(gitleaks detect*), Bash(trufflehog filesystem*), Bash(noseyparker*), Bash(grype*), Bash(syft*), Bash(zizmor*), Bash(npm audit*), Bash(npm audit signatures*), Bash(pnpm audit*), Bash(pip-audit*), Bash(govulncheck*), Bash(cargo audit*), Bash(composer audit*), Bash(dotnet list package*)
---

Run the **security-audit** skill limited to **dependency + supply-chain + secret** scanning
against: `$ARGUMENTS` (default: current working directory).

1. Detect manifests/lockfiles (npm/pnpm/yarn, pip/poetry, go, cargo, composer, gem,
   maven/gradle, nuget) and available tools.
2. Dependency CVEs: prefer `osv-scanner -r .` or `trivy fs .`; else per-ecosystem
   audit tools; else look up each pinned version on OSV/GHSA via web search.
3. Supply-chain checks: unpinned versions, freshly-published/slopsquatted packages, lockfile
   integrity drift, malicious install scripts, package provenance (`npm audit signatures` /
   SLSA-Sigstore), and unpinned GitHub Actions (`zizmor` — must be SHA-pinned). See
   `known-vulns-deps.md` §"Recent-incident awareness" for the current attack patterns.
4. Secret scan: prefer `gitleaks detect` / `trufflehog filesystem .`; else grep known
   key patterns. Confirm each hit is a real secret; **never print secret values** —
   show file:line + type + masked prefix only.
5. Cross-reference CISA KEV for actively-exploited components; prioritize those.
6. Output the dependency/CVE register + secret findings in the report format; language
   per `--lang` (default: user's language, else English).
