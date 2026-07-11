# Tooling — hybrid engine (detect → use → fall back)

The kit works with **zero tools installed** (LLM analysis + `curl`). When a scanner is
present it is used for depth. Never block on a missing tool: note it, suggest the
one-line install, and continue with LLM analysis.

## Detect (run once, quietly)

Check availability without failing. Cross-platform (Git Bash / PowerShell / Linux / mac):

```bash
for t in curl semgrep opengrep trivy osv-scanner grype syft gitleaks trufflehog \
         noseyparker nuclei httpx katana subfinder testssl.sh sslscan nmap \
         npm pnpm yarn pip-audit safety govulncheck cargo-audit bundler-audit \
         composer dotnet checkov trivy-config kics tfsec kube-score kube-bench \
         zizmor dependency-check retire; do
  command -v "$t" >/dev/null 2>&1 && echo "OK   $t" || echo "MISS $t"
done
```

`opengrep` is the maintained community fork of Semgrep CE (Jan 2025) — restores cross-function
taint tracking; same rule format/SARIF, so it's a drop-in where `semgrep` is absent.

On Windows PowerShell: `Get-Command <tool> -ErrorAction SilentlyContinue`.

Record which are present. Pick tools per phase from the table below. Prefer:
`osv-scanner`/`trivy` for deps, `semgrep` for SAST, `gitleaks`/`trufflehog` for
secrets, `testssl.sh` for TLS, `nuclei` (templates only) for live misconfig — **active
templates require authorization** (§Active-testing note).

> **Allowlist note.** The commands' `allowed-tools` frontmatter permits only passive/static
> scanners (SAST, dependency, secret, config, TLS-read) so nothing active runs unprompted.
> Active-recon tools listed below — `nuclei`, `httpx`, `katana`, `subfinder`, `nmap`,
> OWASP ZAP, `dependency-check`, `safety` — are **intentionally not** in that allowlist; they
> only run against an authorized live target after the user explicitly approves the Bash call.

## Tool matrix

| Job | Preferred | Alt | LLM fallback if none |
|---|---|---|---|
| Dependency CVEs (multi-eco) | `osv-scanner -r .` | `trivy fs .` | Read manifests, look up each pinned version on OSV/GHSA via WebSearch |
| npm/yarn/pnpm audit | `npm audit --audit-level=moderate` | `pnpm audit` / `yarn npm audit` | same as above |
| Python deps | `pip-audit -r requirements.txt` | `safety check` | same |
| Go deps | `govulncheck ./...` | `trivy fs .` | same |
| Rust deps | `cargo audit` | — | same |
| Ruby deps | `bundle audit check --update` | — | same |
| PHP deps | `composer audit` | — | same |
| .NET deps | `dotnet list package --vulnerable` | `trivy fs .` | same |
| Java deps | `dependency-check` / `trivy fs .` | — | same |
| SBOM | `syft . -o cyclonedx-json` | `trivy fs . --format cyclonedx` | manual manifest inventory |
| SAST (code) | `semgrep --config auto .` | `opengrep --config auto .` / language linters | manual taint tracing (`code-review.md`) |
| Secrets in repo/history | `gitleaks detect --no-banner` | `trufflehog filesystem .` (verifies) / `noseyparker scan` (low-FP) | grep for key patterns (`code-review.md` §secrets) |
| JS client-side / retired libs | `retire --path .` | `npm audit` | version-check bundled libs |
| Container image | `trivy image <img>` | `grype <img>` | read Dockerfile, base-image tag age/CVEs |
| Dockerfile / IaC misconfig | `checkov -d .` | `trivy config .` / `kics scan -p .` / `tfsec .` | manual IaC review (`infra-cloud.md`) |
| K8s manifests | `kube-score score *.yaml` | `checkov` / `kics` | manual review |
| K8s cluster benchmark (authorized) | `kube-bench` (CIS) | — | manual CIS checklist |
| GitHub Actions / CI | `zizmor <workflow.yml>` | manual review | check SHA-pinning, `permissions:`, triggers (`infra-cloud.md` §CI/CD) |
| Package provenance | `npm audit signatures` | — | check for SLSA/Sigstore attestation |
| TLS posture | `testssl.sh <host>` | `sslscan <host>` / `nmap --script ssl-enum-ciphers` | `curl -vI` + cert parse |
| HTTP headers / probing | `httpx -title -tech-detect -status-code` | `curl -sSI -L` | (curl always available) |
| Endpoint/crawl discovery (passive) | `katana -jc -d 2` (read-only crawl) | grep JS bundles | manual (`attack-surface.md`) |
| Subdomain enum (passive) | `subfinder -silent -d <domain>` | cert-transparency lookup | passive only |
| Live web misconfig/exposure | `nuclei -t http/exposures,http/misconfiguration` | — | manual path checks (`passive-recon.md`) |
| Port/service exposure | `nmap -sV --top-ports 1000` (authorized) | — | passive fingerprint only |
| DAST baseline | OWASP ZAP baseline (authorized) | `nuclei` safe templates | manual OWASP tests (`web-tests.md`) |

## Install hints (offer, don't require)

```
# Multi-purpose (recommended core)
semgrep:      pipx install semgrep            (or: pip install semgrep)
opengrep:     https://github.com/opengrep/opengrep   (maintained Semgrep-CE fork)
trivy:        https://trivy.dev/latest/getting-started/installation/
osv-scanner:  go install github.com/google/osv-scanner/cmd/osv-scanner/v2@latest
gitleaks:     https://github.com/gitleaks/gitleaks#installing  (brew/scoop/go)
trufflehog:   https://github.com/trufflesecurity/trufflehog    (verifies live secrets)
noseyparker:  https://github.com/praetorian-inc/noseyparker    (low-false-positive, ML)
nuclei:       go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
httpx/katana/subfinder: https://github.com/projectdiscovery (recon toolkit)
testssl.sh:   git clone https://github.com/drwetter/testssl.sh
checkov:      pipx install checkov            kics: https://github.com/Checkmarx/kics
zizmor:       pipx install zizmor             (GitHub Actions static auditor)
grype/syft:   https://github.com/anchore      (SCA + SBOM)
kube-bench:   https://github.com/aquasecurity/kube-bench   (CIS K8s, cluster access)
# Per-ecosystem audit tools ship with their package managers (npm/pip/go/cargo/…).
```

Recommend the **core five** to new users: `semgrep` (or `opengrep`), `osv-scanner` (or
`trivy`), `gitleaks` (or `trufflehog`), `zizmor` (if using GitHub Actions), and `testssl.sh`.
They cover code, deps, secrets, CI, and TLS. On Windows, prefer Docker images or WSL for the
Go/OCaml tools; `trivy`, `gitleaks`, `nuclei`, and the ProjectDiscovery suite ship native
Windows binaries.

## `osv-scanner` guided remediation

`osv-scanner` can propose the minimum-impact upgrade set: run `osv-scanner fix --non-interactive
-r .` (or `--strategy in-place`) to compute lockfile changes that clear the most vulns with the
fewest major bumps. Review the diff — never auto-apply upgrades in an audit.

## Safe invocation rules

- **Passive by default.** Dep/SAST/secret/IaC/TLS scans on local files or read-only
  header/cert fetches need no authorization.
- **Active tools gate.** `nuclei` (beyond info/exposure templates), `nmap` service
  scans, ZAP active scan, and any fuzzing are ACTIVE — run only with authorization,
  rate-limited (`nuclei -rate-limit 10 -c 5`), never `-t` on intrusive/DoS templates.
- **Timeouts + rate limits always.** `curl --max-time 25`, scanner concurrency low.
- **Parse, don't dump.** Pipe machine-readable output (`--format json`, `-o json`,
  `--sarif`) and summarize; never paste thousands of raw lines into the report.
- **Triage every hit.** Scanner output is leads. Confirm reachability/version/context
  before it becomes a finding. See `severity-cvss.md` §triage.

## Parsing tips

- `osv-scanner --format json` / `trivy fs . --format json` → group by package, keep
  only fixable + reachable, map to the dependency register table.
- `semgrep --sarif` or `--json` → dedupe by rule+file+line, drop test/vendor paths,
  keep security-category rules.
- `gitleaks detect --report-format json` → for each hit, confirm it's a live secret
  (not a placeholder/example) before flagging; **never print the secret value**, show
  file:line + type + masked prefix.
- `testssl.sh --jsonfile out.json <host>` → extract protocol support, cert, cipher,
  vuln checks (BEAST/POODLE/Heartbleed/etc.).
