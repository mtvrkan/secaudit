# Methodology

SecAudit follows a phased methodology aligned with the OWASP Web Security Testing Guide.
Each phase has a dedicated reference file (loaded into Claude's context only when that phase
runs, keeping analysis focused).

## Phases

| Phase | Runs when | Covers |
|---|---|---|
| **P1 Passive recon** | live target | headers, TLS, cookies, redirect, public files, exposure, tech fingerprint |
| **P2 Attack-surface map** | live target | routes, auth flows, API endpoints, inputs, third parties |
| **P3 Known vulns & deps** | any (versions/manifests found) | CVE/dependency lookup (OSV/GHSA/NVD/CISA KEV), supply chain |
| **P4 OWASP web tests** | live + authorized | access control, authn/session, injection, XSS, CSRF/CORS, upload, SSRF, misconfig, crypto, business logic |
| **P5 API tests** | API + authorized | OWASP API Top 10 (BOLA, mass assignment, BFLA, …) |
| **P6 Source review (SAST)** | source target | taint tracing to sinks, authz gaps, secrets, weak crypto |
| **P7 Infra / cloud / IaC** | IaC/containers/cloud config | Dockerfile, Terraform, K8s, Compose, exposure, CI/CD |
| **P8 Mobile** | mobile app | OWASP MASVS / Mobile Top 10 |
| **P9 AI / LLM security** | app calls an LLM / is an agent / uses MCP | OWASP LLM Top 10 (2025) + Agentic Apps (2026) + MCP Top 10 — prompt injection (direct + indirect), output handling, excessive agency, tool poisoning, cost |

A cross-cutting **`auth-identity.md`** reference (OAuth 2.0 / OIDC / SAML / JWT / sessions / MFA /
passkeys) is loaded on top of these whenever the target uses federated login or token sessions.

## Known vs unknown vulnerabilities

- **Known** — publicly documented CVEs in your dependencies/components (P3). Found by
  matching exact installed versions against vulnerability databases.
- **Unknown** — flaws specific to *your* code and configuration: logic errors, missing
  authorization, injection sinks, secrets, misconfigurations (P4–P9). Found by testing and
  code analysis, not a database lookup.

A real audit needs both. Dependency scanners alone miss the unknown class entirely.

## Verify → prioritize → report

1. **Verify.** Every candidate is triaged: reachable? version-accurate? already mitigated?
   real impact? Raw scanner hits are leads, not findings. High/critical findings are run
   through the adversarial `secaudit-verifier` agent, which tries to *refute* them.
2. **Prioritize.** CISA KEV (actively exploited) → internet-exposed unauthenticated →
   auth/authz bypass → sensitive-data exposure → RCE/SSRF → reachable vulnerable deps →
   misconfig → hardening. See `references/severity-cvss.md`.
3. **Report.** Severity-ranked findings, each with impact, evidence, root cause, a specific
   fix, and a retest step; plus a dependency/CVE register, the positive controls you already
   have, and a 24h/7d/30d remediation roadmap.

## Honesty

SecAudit always states its result is a **best-effort assessment**, never "all
vulnerabilities found," and lists what it could not test and why. Confirmed findings are
separated from plausible (code-review-only) ones and from untested areas.

## Standards referenced

OWASP WSTG · OWASP Top 10 (2021) · OWASP API Top 10 (2023) · OWASP LLM Top 10 (2025) ·
OWASP Top 10 for Agentic Applications (2026) · OWASP MCP Top 10 (2025) · OWASP Mobile Top 10
(2024) · CWE Top 25 · CISA KEV · NVD/CVE · OSV.dev · GitHub Advisory DB · SLSA / Sigstore
(provenance) · PortSwigger research (request smuggling / desync).
