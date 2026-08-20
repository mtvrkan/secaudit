# Source-code mode

Static audit of a codebase. No live/network requests — safe on any repo you can read.

```
/secaudit-code ./                 # audit current directory
/secaudit ./path/to/repo --code   # explicit source mode
/secaudit-deps ./                 # dependency + supply-chain + secrets only
```

## What runs

- **P6 Source review (SAST)** — traces user-controlled input to dangerous sinks. Uses
  `semgrep`/`opengrep` if installed; otherwise Claude reads the code. Covers: missing/weak
  server-side authorization, injection (SQL/NoSQL/command/SSTI), XSS sinks, unsafe
  deserialization + gadget chains, path traversal, SSRF, open redirect, weak crypto/randomness,
  hardcoded secrets, JWT/OAuth/OIDC/SAML flaws (`auth-identity.md`), server-side prototype
  pollution, permissive CORS (the reflected `Origin` as well as the literal `*`), mass
  assignment, debug flags, logging of secrets/PII, CSV formula injection in exports, account
  enumeration through differential error messages, access decisions made from a caller-supplied
  cookie or header, cleartext storage of sensitive columns, allocation sized by a request
  parameter, and exception or environment detail returned in a response.
- **P3 Dependencies** — `osv-scanner`/`trivy` or per-ecosystem audit tools; else looks up
  each lockfile-pinned version on OSV/GHSA. Cross-references CISA KEV.
- **Secrets** — `gitleaks`/`trufflehog` (code + git history) or pattern grep. Secrets are
  reported masked (type + `file:line` + masked prefix); values are never printed.
- **P7 Infra/IaC** — Dockerfile, Terraform, CloudFormation, K8s, Compose, CI/CD workflows (if present).
- **P8 Mobile** / **P9 AI-LLM** — if the repo is a mobile app or calls an LLM.

## Why it's strong

Source mode finds the **unknown** vulns a URL scan can't see (logic flaws, unreachable-vs-
reachable dependency CVEs, secrets, taint paths) and confirms findings by reading the exact
`file:line`. It's also the cheapest to run — no live traffic, no cost, no authorization.

## Supported ecosystems

npm/pnpm/yarn, pip/poetry/pipenv, Go, Rust, Composer (PHP), Bundler (Ruby), Maven/Gradle
(Java), NuGet (.NET) — plus Dockerfile, Terraform, CloudFormation, Kubernetes, Compose.

## Tips

- Run from the repo root so manifests/lockfiles are discovered.
- Installing `semgrep` + `osv-scanner` + `gitleaks` gives the deepest results; without
  them SecAudit still runs via Claude analysis.
- Combine with live mode for the fullest picture.
