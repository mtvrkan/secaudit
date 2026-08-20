# Security Audit Report — demo-app.example.com

> ⚠️ **Fully fictional, sanitized example.** The target, findings, and evidence below are
> invented to demonstrate SecAudit's output format. No real system was tested.

## Executive Summary

- **Scope:** `https://demo-app.example.com` (live, passive + authorized read-only) + source repo.
- **Testing dates:** 2026-07-11
- **Overall risk rating:** **High**
- **Findings:** Critical 0 · High 2 · Medium 2 · Low 3 · Informational 1
- **Main business risks:** An unsanitized AI-chat response combined with a non-`HttpOnly`
  session cookie could let an attacker take over accounts. User enumeration on login aids
  targeted phishing.
- **Fastest risk-reduction actions:** (1) sanitize AI/markdown output with DOMPurify;
  (2) set `HttpOnly; Secure; SameSite` on the session cookie; (3) return a single generic
  login error.

## Scope & Constraints

- In-scope: the domain above and the provided source repository.
- Out-of-scope: payments, account deletion, any other domain.
- Source available: **yes** · Authenticated testing: **read-only, user-provided session** ·
  Environment: **production**.
- Authorization: asserted by owner in session; scope confirmed.
- Limitations: no second test account (horizontal-authz coverage partial); paid AI endpoint
  not live-triggered (findings from code review).

## Methodology

Passive recon (headers/TLS/cookies/exposure), attack-surface mapping, dependency/CVE
lookup (OSV/GHSA/KEV), source-code review (SAST), and AI/LLM-security review. Tools:
`osv-scanner`, `gitleaks`, `testssl.sh`; Claude analysis for logic/code and triage.

## Findings Summary

| ID | Severity | Title | Affected Asset | Verdict | Status |
|---|---|---|---|---|---|
| F-001 | High | AI response rendered without sanitization → XSS | `/chat` client render | PLAUSIBLE (code review) | Open |
| F-002 | High | Session cookie missing HttpOnly/Secure/SameSite | `Set-Cookie` | CONFIRMED | Open |
| F-003 | Medium | User enumeration on login | `/login` | CONFIRMED | Open |
| F-004 | Medium | No Content-Security-Policy | all pages | CONFIRMED | Open |
| F-005 | Low | Missing HSTS | all responses | CONFIRMED | Open |
| F-006 | Low | Directory listing enabled | `/assets/` | CONFIRMED | Open |
| F-007 | Low | Verbose framework 404 (tech disclosure) | `/api/*` | CONFIRMED | Open |
| F-008 | Info | Health endpoint discloses AI model names | `/api/health` | CONFIRMED | Open |

## Detailed Findings

### F-001 — AI chat response rendered without sanitization → XSS  ·  Severity: High
- **Class / OWASP / CWE:** A05 Injection / OWASP LLM05 Improper Output Handling · CWE-79
- **Affected asset:** `web/src/chat/render.js:142`
- **Verdict:** PLAUSIBLE — found via code review; not live-triggered (paid AI endpoint).
- **Evidence:**
  ```js
  // user message — safe:
  bubble.innerHTML = escapeHtml(msg);
  // AI response — UNSAFE (raw HTML from markdown, no sanitizer):
  bubble.innerHTML = marked.parse(aiText);   // marked v15, no DOMPurify
  ```
- **Impact:** An attacker who influences the model output — directly, or **indirectly via a
  poisoned document in the RAG store** — can inject HTML/JS. Chained with F-002 (no
  `HttpOnly`), the script can read `document.cookie` → **account takeover**, and can read
  the CSRF token from the DOM to act as the victim.
- **Likelihood:** Medium-High; indirect injection needs only an uploaded document that
  other users later query.
- **Reproduction (safe):** In a test environment, have the endpoint return
  `<img src=x onerror=alert(1)>` inside the AI reply; observe it executes rather than
  rendering as text.
- **Root cause:** Model output treated as trusted; `marked` passes raw HTML through by design.
- **Fix:** `bubble.innerHTML = DOMPurify.sanitize(marked.parse(aiText))`. Apply to
  history-render path too. Add a strict CSP (F-004) as defense-in-depth. Treat all model
  output as untrusted input.
- **Retest:** payload renders as escaped text; no script executes.
- **References:** OWASP LLM Top 10 (LLM05); CWE-79; DOMPurify docs.

### F-002 — Session cookie missing HttpOnly / Secure / SameSite  ·  Severity: High
- **Class / OWASP / CWE:** A02 / A07 · CWE-1004, CWE-614
- **Affected asset:** `Set-Cookie: SESSIONID=...; path=/`
- **Verdict:** CONFIRMED
- **Evidence:** response omits all three flags.
- **Impact:** Any XSS (F-001) can steal the session → account takeover; cookie can leak over
  HTTP (no HSTS, F-005); CSRF surface widened.
- **Fix (framework example):** set cookie params before session start —
  `secure: true, httponly: true, samesite: 'Lax'`.
- **Retest:** `curl -I` shows `HttpOnly; Secure; SameSite=Lax` on the session cookie.

### F-003 — User enumeration on login  ·  Severity: Medium
- **Class / OWASP / CWE:** A07 · CWE-203/204
- **Verdict:** CONFIRMED
- **Evidence:** "email not found" vs "wrong password" are distinct messages.
- **Impact:** Confirms which emails are registered → targeted phishing / credential stuffing.
- **Fix:** return one generic message ("email or password is incorrect") in both cases; same
  for password reset and registration.
- **Retest:** existing vs non-existing email produce identical responses.

### F-004 — No Content-Security-Policy  ·  Severity: Medium
CWE-693. No CSP header; inline scripts + external CDNs present. Add a scoped CSP (start in
`Content-Security-Policy-Report-Only`, then enforce). Reduces F-001 blast radius.

### F-005 — Missing HSTS  ·  Severity: Low
CWE-319. HTTP→HTTPS redirect exists but no `Strict-Transport-Security`. Add
`max-age=31536000; includeSubDomains` (then `preload` once all subdomains are HTTPS-ready).

### F-006 — Directory listing enabled on `/assets/`  ·  Severity: Low
CWE-548. Apache "Index of" listing. Only public assets exposed, but it's an unnecessary
hardening gap. Fix: `Options -Indexes` (Apache) / `autoindex off;` (nginx).

### F-007 — Verbose framework 404  ·  Severity: Low
CWE-200. `Cannot GET /x` reveals Express. Add a custom JSON 404 and ensure
`NODE_ENV=production`.

### F-008 — Health endpoint discloses AI model names  ·  Severity: Informational
CWE-200. `/api/health` returns provider + exact model names to any authenticated user.
Restrict to admin/monitoring or return a minimal `{status:"healthy"}`.

## Dependency & Known-CVE Register

| Component | Installed | CVE/Advisory | Severity | In KEV? | Reachable? | Fix Version | Status |
|---|---:|---|---|---|---|---|---|
| marked | 15.0.x (unpinned CDN) | none (missing sanitizer → F-001) | — | No | Yes | pin + DOMPurify | Open |
| (example) lodash | 4.17.20 | CVE-2021-23337 | High | No | Yes | 4.17.21 | Open |

## Positive Security Controls Observed

- CSRF tokens enforced server-side (state-changing POSTs rejected without a valid token).
- Vertical authorization works (low-priv user redirected away from `/admin`).
- Parameterized queries (SQLi canaries returned literal non-matches, no SQL errors).
- Session ID regenerated on login (no session fixation).
- TLS certificate valid; HTTP→HTTPS redirect present.

## Remediation Roadmap

**24–72h:** F-001 (sanitize AI output), F-002 (cookie flags), F-008 (trim health endpoint).
**7–14d:** F-003 (generic login error), F-004 (CSP), pin/upgrade dependencies.
**30–60d:** F-005 (HSTS + preload), F-006/F-007 (hardening), second-account IDOR pass.

## Retest Checklist

| Finding | Severity | Retest step | Result |
|---|---|---|---|
| F-001 | High | payload renders escaped, no script exec | ☐ |
| F-002 | High | `curl -I` shows all cookie flags | ☐ |
| F-003 | Medium | identical login error messages | ☐ |

## Appendix A — Activity Log

| Timestamp | Action | Target | Result |
|---|---|---|---|
| 2026-07-11 09:12 | Passive recon (headers/TLS/cookies) | `demo-app.example.com` | F-002, F-004–F-008 |
| 2026-07-11 09:31 | Dependency + secret scan (source repo) | provided repo | register populated |
| 2026-07-11 10:05 | Source review (AI-chat render path) | `web/src/chat/` | F-001 (code review) |
| 2026-07-11 10:40 | Authorized read-only session checks | login/enumeration | F-003 |

## Appendix B — Assumptions & Limitations

Best-effort assessment, not a guarantee. Bounded by scope, access, and tooling. Not tested:
horizontal authz beyond one account, the live AI endpoint (cost), and payment flows
(excluded). F-001 is a code-review finding pending live confirmation in a test environment.
