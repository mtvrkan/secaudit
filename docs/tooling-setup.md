# Tooling setup

SecAudit runs with **zero tools installed** (Claude analysis + `curl`). Installing scanners
adds depth. SecAudit auto-detects what's on your PATH and uses it; missing tools fall back
to LLM analysis — you're never blocked.

## Core four (recommended)

| Tool | Purpose | Install |
|---|---|---|
| `semgrep` | SAST (source code) | `pipx install semgrep` |
| `osv-scanner` | dependency CVEs (all ecosystems) | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` |
| `gitleaks` | secret detection (code + git history) | `brew install gitleaks` / `scoop install gitleaks` |
| `testssl.sh` | TLS/cert posture | `git clone https://github.com/drwetter/testssl.sh` |

## Full list

| Job | Tool | Install |
|---|---|---|
| All-in-one (deps + secrets + misconfig + images) | `trivy` | https://trivy.dev — `brew install trivy` |
| SBOM | `syft` | `brew install syft` |
| Container image CVEs | `grype` | `brew install grype` |
| IaC / Terraform / K8s | `checkov` | `pipx install checkov` |
| Terraform | `tfsec` | `brew install tfsec` |
| Kubernetes manifests | `kube-score` | https://github.com/zegl/kube-score |
| Live web misconfig/exposure (gated) | `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Secrets (alt) | `trufflehog` | `brew install trufflehog` |
| JS retired libs | `retire` | `npm i -g retire` |
| Python deps | `pip-audit` | `pipx install pip-audit` |
| Go deps | `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| Rust deps | `cargo-audit` | `cargo install cargo-audit` |
| Ruby deps | `bundler-audit` | `gem install bundler-audit` |

Per-ecosystem audit tools that ship with the package manager (`npm audit`, `composer
audit`, `dotnet list package --vulnerable`) need no extra install.

## Windows

Most tools have Windows builds via [`scoop`](https://scoop.sh) or `winget`
(`scoop install semgrep gitleaks trivy`). `testssl.sh` and `nuclei` run under Git Bash /
WSL. If a tool isn't available on your platform, SecAudit uses Claude analysis for that step.

## Verifying

SecAudit checks tool availability at the start of a run and tells you which it found. You
can also list them yourself — see `references/tooling.md` in the plugin for the detection
snippet.

## Active tools note

`nuclei` (beyond info/exposure templates), `nmap` service scans, and OWASP ZAP active scans
are **active testing** — SecAudit only runs them with authorization, rate-limited, and never
with intrusive/DoS templates. See [authorization.md](authorization.md).
