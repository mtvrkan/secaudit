# Vulnerability catalog — the master checklist

Use this so nothing is missed. "Known" vulns = P3 (CVE/deps). "Unknown" vulns = the
classes below, found via P4–P9. Each maps to OWASP + CWE for the report.

## OWASP Top 10 — Web (2025)

> Uses the **OWASP Top 10:2025** ordering (released Nov 2025). Two 2021 categories were
> folded in: **SSRF** (2021 A10) is now part of **A01 Broken Access Control**, and
> **Vulnerable & Outdated Components** (2021 A06) is now part of **A03 Software Supply
> Chain Failures**. New for 2025: **A10 Mishandling of Exceptional Conditions**.

- **A01 Broken Access Control** — IDOR/BOLA, vertical/horizontal authz, forced browsing,
  method authz, CSRF (moved here), **SSRF** (server-side fetch of user URLs, cloud-metadata
  access — folded into A01 in 2025). CWE-284/639/862/863/352/918.
- **A02 Security Misconfiguration** — default creds, verbose errors, missing headers,
  open dirs, exposed debug, permissive CORS, **web cache poisoning (CWE-349) / cache
  deception (CWE-524)** (`web-tests.md` §4.12). CWE-16/548/693.
- **A03 Software Supply Chain Failures** — vulnerable/outdated components (see P3),
  unpinned deps & GitHub Actions, typosquatting/**slopsquatting**, install-script worms,
  missing provenance/attestation (SLSA/Sigstore). CWE-1104/937/1357. See "Supply chain" below.
- **A04 Cryptographic Failures** — weak/no TLS, **disabled cert validation** (`verify=False`,
  trust-all — CWE-295), weak hashing, secrets in transit/at rest, sensitive data in URLs.
  CWE-259/327/319/295.
- **A05 Injection** — SQL/NoSQL/OS-command/LDAP/XPath/**SSTI** + **XSS** (reflected/stored/DOM)
  + **XXE** (external entities → file read/SSRF, CWE-611) + **HTTP request smuggling/desync**
  (CWE-444, `web-tests.md` §4.11). CWE-79/89/78/90/94/611.
- **A06 Insecure Design** — missing threat modeling, weak recovery flows, business-logic
  flaws. CWE-209/256/501.
- **A07 Authentication Failures** — weak auth, enumeration, session
  fixation, weak reset, missing MFA, **JWT/OAuth/OIDC/SAML flaws** (alg confusion, `redirect_uri`,
  XSW — see `auth-identity.md`). CWE-287/384/620/640/347.
- **A08 Software or Data Integrity Failures** — insecure deserialization, unsigned
  updates, CI/CD tampering, unpinned deps. CWE-502/345/494.
- **A09 Security Logging & Alerting Failures** — no audit trail, no alerting,
  logging secrets/PII. CWE-778/532.
- **A10 Mishandling of Exceptional Conditions** — improper error/exception handling,
  fail-open logic on error, leaked stack traces, unhandled edge cases that bypass a control.
  CWE-209/755/391.

## OWASP API Top 10 (2023)

API1 BOLA · API2 Broken Auth · API3 Broken Object Property Level Authz (mass assignment,
excessive data exposure) · API4 Unrestricted Resource Consumption · API5 Broken Function
Level Authz · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8
Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.
Details: `api-tests.md`.

## OWASP LLM Top 10 (2025) + Agentic (2026, draft) + MCP (2025, draft)

LLM01 Prompt Injection (direct + indirect: RAG/tool-output/multimodal/Unicode-tag smuggling) ·
LLM02 Sensitive Info Disclosure · LLM03 Supply Chain · LLM04 Data/Model Poisoning · LLM05
Improper Output Handling (→ XSS/SQLi/RCE) · LLM06 Excessive Agency · LLM07 System Prompt Leakage ·
LLM08 Vector/Embedding Weaknesses (RAG) · LLM09 Misinformation · LLM10 Unbounded Consumption.
**Agentic (OWASP Top 10 for Agentic Applications, 2026 — draft/emerging):** goal hijack, memory
poisoning, tool/parameter injection, per-action authz, multi-agent trust. **MCP (OWASP MCP Top 10,
2025 — draft/emerging):** tool poisoning, rug-pull tool definitions, confused deputy, MCP-server
supply chain. Details: `llm-ai-security.md`.

> The Agentic-Apps and MCP "Top 10" lists are still evolving OWASP drafts, not finalized standards
> like the Web/API/LLM Top 10. Treat their category names as a working taxonomy and confirm against
> the current OWASP drafts when citing them in a report.

## OWASP Mobile Top 10 (2024)

M1–M10 — see `mobile.md`.

## CWE Top 25 (2024, MITRE) — cross-check

The official **2024 CWE Top 25 Most Dangerous Software Weaknesses** (published Nov 2024),
ordered most → least dangerous:

1. XSS (CWE-79) · 2. out-of-bounds write (787) · 3. SQLi (89) · 4. CSRF (352) ·
5. path traversal (22) · 6. out-of-bounds read (125) · 7. OS command injection (78) ·
8. use-after-free (416) · 9. missing authorization (862) · 10. unrestricted file upload (434) ·
11. code injection (94) · 12. improper input validation (20) · 13. command injection (77) ·
14. improper authentication (287) · 15. improper privilege management (269) ·
16. deserialization of untrusted data (502) · 17. sensitive-info exposure (200) ·
18. incorrect authorization (863) · 19. SSRF (918) · 20. improper memory-bounds restriction (119) ·
21. NULL pointer dereference (476) · 22. hardcoded credentials (798) · 23. integer overflow (190) ·
24. uncontrolled resource consumption (400) · 25. missing authentication for a critical function (306).

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
