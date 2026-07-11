# Vulnerability catalog — the master checklist

Use this so nothing is missed. "Known" vulns = P3 (CVE/deps). "Unknown" vulns = the
classes below, found via P4–P9. Each maps to OWASP + CWE for the report.

## OWASP Top 10 — Web (2021)

- **A01 Broken Access Control** — IDOR/BOLA, vertical/horizontal authz, forced browsing,
  method authz, CSRF (moved here). CWE-284/639/862/863.
- **A02 Cryptographic Failures** — weak/no TLS, weak hashing, secrets in transit/at rest,
  sensitive data in URLs. CWE-259/327/319.
- **A03 Injection** — SQL/NoSQL/OS-command/LDAP/XPath/**SSTI** + **XSS** (reflected/stored/DOM)
  + **HTTP request smuggling/desync** (CWE-444, `web-tests.md` §4.11). CWE-79/89/78/90/94.
- **A04 Insecure Design** — missing threat modeling, weak recovery flows, business-logic
  flaws. CWE-209/256/501.
- **A05 Security Misconfiguration** — default creds, verbose errors, missing headers,
  open dirs, exposed debug, permissive CORS, **web cache poisoning/deception** (CWE-524/525,
  `web-tests.md` §4.12). CWE-16/548/693.
- **A06 Vulnerable & Outdated Components** — see P3. CWE-1104/937.
- **A07 Identification & Authentication Failures** — weak auth, enumeration, session
  fixation, weak reset, missing MFA, **JWT/OAuth/OIDC/SAML flaws** (alg confusion, `redirect_uri`,
  XSW — see `auth-identity.md`). CWE-287/384/620/640/347.
- **A08 Software & Data Integrity Failures** — insecure deserialization, unsigned
  updates, CI/CD tampering, unpinned deps. CWE-502/345/494.
- **A09 Security Logging & Monitoring Failures** — no audit trail, no alerting,
  logging secrets/PII. CWE-778/532.
- **A10 SSRF** — server-side fetch of user URLs, cloud-metadata access. CWE-918.

## OWASP API Top 10 (2023)

API1 BOLA · API2 Broken Auth · API3 Broken Object Property Level Authz (mass assignment,
excessive data exposure) · API4 Unrestricted Resource Consumption · API5 Broken Function
Level Authz · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8
Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.
Details: `api-tests.md`.

## OWASP LLM Top 10 (2025) + Agentic (2026) + MCP (2025)

LLM01 Prompt Injection (direct + indirect: RAG/tool-output/multimodal/Unicode-tag smuggling) ·
LLM02 Sensitive Info Disclosure · LLM03 Supply Chain · LLM04 Data/Model Poisoning · LLM05
Improper Output Handling (→ XSS/SQLi/RCE) · LLM06 Excessive Agency · LLM07 System Prompt Leakage ·
LLM08 Vector/Embedding Weaknesses (RAG) · LLM09 Misinformation · LLM10 Unbounded Consumption.
**Agentic (OWASP Top 10 for Agentic Applications 2026):** goal hijack, memory poisoning,
tool/parameter injection, per-action authz, multi-agent trust. **MCP (OWASP MCP Top 10 2025):**
tool poisoning, rug-pull tool definitions, confused deputy, MCP-server supply chain. Details:
`llm-ai-security.md`.

## OWASP Mobile Top 10 (2024)

M1–M10 — see `mobile.md`.

## CWE Top 25 (most dangerous) — cross-check

Out-of-bounds write (787) · XSS (79) · SQLi (89) · CSRF (352) · path traversal (22) ·
OS command injection (78) · use-after-free (416) · missing authz (862) · unrestricted
upload (434) · code injection (94) · improper input validation (20) · out-of-bounds read
(125) · hardcoded creds (798) · SSRF (918) · missing authn (306) · integer overflow
(190) · deserialization (502) · improper auth (287) · NULL deref (476) · use of
insufficiently random values (330) · sensitive data exposure (200) · incorrect
permission assignment (732) · improper privilege management (269) · weak password
recovery (640) · LDAP/XML injection.

## Client-side (browser) classes

DOM-based XSS · **client-side prototype pollution** · **DOM clobbering** · **client-side path
traversal (CSPT)** · **Cross-Site WebSocket Hijacking (CSWSH)** · `postMessage` origin flaws ·
open redirect · sensitive data in JS bundles/source maps. Details: `web-tests.md` §4.13–4.14.

## Supply chain & secrets (A03/A08)

Vulnerable/outdated deps (P3) · unpinned deps & GitHub Actions (mutable-tag compromise, e.g.
`tj-actions` CVE-2025-30066) · typosquatting/dependency-confusion/**slopsquatting** (AI-
hallucinated names) · freshly-published packages · **self-replicating install-script worms**
(Shai-Hulud family) · lockfile integrity drift · malicious postinstall scripts · missing
provenance/attestation (SLSA/Sigstore/npm provenance) · hardcoded secrets & leaked keys (in
code, history, source maps, client bundles, logs). Details: `known-vulns-deps.md`, `infra-cloud.md`.

## Infra / cloud / container

Public buckets · open security groups · overbroad IAM · unencrypted storage · exposed
DBs/dashboards/metrics · container CVEs · root containers · privileged pods · exposed
K8s dashboard/kubelet · dangling DNS · missing WAF. See `infra-cloud.md`.

## Quick coverage self-check before writing the report

Did I consider, for this target: access control · authn/session · **federated auth
(OAuth/OIDC/SAML/JWT)** · injection · XSS · SSTI · **request smuggling** · CSRF/CORS ·
**cache poisoning/deception** · SSRF · **deserialization** · file upload · **client-side
(prototype pollution / DOM clobbering / CSPT / WebSocket)** · misconfig/headers · crypto/secrets ·
business logic/race · dependencies/CVEs · **supply chain (provenance, CI, slopsquatting)** ·
infra/IaC · (mobile if app) · (LLM/agent/MCP if AI)? Note any class I could not assess and
**why** — that goes in the limitations appendix.
