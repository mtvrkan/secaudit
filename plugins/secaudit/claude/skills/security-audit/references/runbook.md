# Runbook — safety rules, phase flow, operating loop

This is the master operating document. The phase-specific reference files hold the
detailed checks; this file holds the rules that apply across all of them.

## Hard safety rules (never cross)

1. **Scope.** Test only assets the user owns or is explicitly authorized to test.
   For live targets without asserted authorization, stay passive (§Impact tiers in
   `SKILL.md`).
2. **No destruction.** Do not modify production data except clearly harmless test
   records created by approved test accounts. Never `DELETE`/`DROP`/`TRUNCATE`, never
   trigger payments, account deletion, emails/SMS to real users, or irreversible state.
3. **No data exfiltration.** Never dump, copy, or display sensitive data / PII /
   secrets. For proof show only masked values, minimal metadata, or a harmless canary.
4. **No brute-force.** Do not brute-force passwords, OTPs, tokens, reset flows, rate
   limits, or lockouts. One or two probes max, then stop and reason.
5. **No DoS.** No stress, load, resource-exhaustion, or high-volume fuzzing.
6. **Minimum proof.** Stop at the least action that confirms the issue. No persistence,
   lateral movement, or privilege escalation beyond approved test roles.
7. **No third parties.** Never target cloud metadata endpoints, internal networks, or
   any system not in scope.
8. **Stop on instability.** If error rates rise or the target degrades, halt and report.
9. **High-risk findings → explain, don't exploit.** Pivot from PoC to remediation.
10. **Keep a log.** Timestamped actions, tested URLs, request IDs, results → Appendix A.
11. **No weaponization.** Never output working exploit code, malware, C2, or
    detection-evasion tooling. Describe the class and the fix instead.

## Session & credential hygiene during authenticated testing

Learned from a real dogfood audit where these were nearly gotten wrong:

1. **Cache tokens/session state to a scratch file immediately after auth succeeds.**
   Shell/tool invocations in this environment do not share process state (env vars set in
   one Bash call are gone in the next) — re-authenticating for every subsequent request
   both wastes login attempts against the rate limiter and risks re-triggering any CAPTCHA/
   challenge flow unnecessarily. Solve the auth challenge once, persist the resulting
   token(s) to a file in the scratch/session directory, and read from that file for every
   later request in the same engagement.
2. **Budget active-auth requests against the rate limit you can already observe.** Before
   firing more login/register/reset attempts, count how many you've already sent in the
   current window (from your own action log) — hitting the target's own rate-limiter by
   accident wastes attempts, can lock the real account out for its full cooldown window,
   and produces a noisy false start. If you must confirm the rate-limiter works (a
   legitimate, valuable check — see `web-tests.md` §4.2), do it deliberately, once, late in
   the session, not as an accidental side effect of sloppy retry logic.
3. **Real/production credentials the user hands you are not the same thing as disposable
   test accounts.** If the user provides their actual account's email+password (as opposed
   to accounts created specifically for this audit), avoid any live action that mutates
   that account's real state irreversibly within the test window — changing its password,
   disabling 2FA, deleting data — even if doing so would let you *confirm* a finding live.
   Prefer verifying such findings by code review only (mark `PLAUSIBLE`, not `CONFIRMED`,
   in the report) and say explicitly why it wasn't live-tested. This is a stronger
   restriction than the general "no destruction" rule above — it applies even to actions
   that are technically reversible, because the account is not the auditor's to reset.
4. **Clean up after yourself.** At the end of authenticated testing: call logout/session-
   revoke for every session your testing created (confirm it actually took effect — a
   revoked token should be rejected on the next request, don't just assume), and delete
   any locally-cached token/credential files from the scratch directory before finishing.
   Note the cleanup in Appendix A so the client can see the engagement left no dangling
   sessions.

## Parallelizing a "Both" (source + live) engagement

When source code and a live target are both in scope (the best case — `SKILL.md` §0.1),
don't run the phases strictly sequentially. Static source review (P3/P6/P7 — dependency
scan, code review, infra/IaC) has no dependency on live findings and vice versa: dispatch
the source-code track to a background subagent at the start of the engagement, and run
passive recon + attack-surface mapping + authenticated live testing (P1/P2/P4/P5) in the
foreground concurrently. Cross-reference at the end — code review explains *why* a live
finding exists (root cause, exact file:line for the fix); live testing *confirms* a code
finding is actually reachable/exploitable rather than theoretical. This cut real engagement
time roughly in half in practice with no loss of coverage, and each track's findings
sharpened the other's evidence (e.g. a live CSP header sample resolved which of two
policies found in source actually reaches the browser).

## Operating loop

1. Restate scope + safety tier (passive vs authorized-active).
2. Ask only for inputs required to avoid unsafe testing (missing authorization, test
   accounts). Otherwise proceed.
3. Detect tools (`tooling.md`) and target type.
4. Run phases in order (`SKILL.md` §2), loading each reference on demand.
5. For each candidate issue: verify with minimal safe proof → triage false positives →
   collect evidence → draft finding.
6. Rate + prioritize (`severity-cvss.md`).
7. Adversarially re-check criticals/highs.
8. Write the report (`report-template.md`).

## Phase deliverables (optional intermediate files)

For large engagements, write per-phase notes so context stays lean and the user can
follow along. Otherwise keep them in memory and emit only the final report.

| # | Deliverable |
|---|---|
| P0 | `00_scope_and_safety.md` — authorization, scope, tiers |
| P1 | `01_passive_recon.md` |
| P2 | `02_attack_surface.md` |
| P3 | `03_known_vulns_deps.md` |
| P4 | `04_web_findings.md` |
| P5 | `05_api_findings.md` |
| P6 | `06_code_review.md` |
| P7 | `07_infra_findings.md` |
| P8 | `08_mobile_findings.md` (if a mobile app) |
| P9 | `09_llm_ai_findings.md` (if the app uses an LLM / is an agent / uses MCP) |
| — | `SECURITY_REPORT.md` — final consolidated report |

## Trusted sources to check during a run

- OWASP Web Security Testing Guide — methodology.
- OWASP Top 10 (2025) — web risk categories. `vuln-catalog.md`.
- OWASP API Security Top 10 (2023) — API risks.
- OWASP LLM Top 10 & Mobile Top 10 — when applicable.
- OWASP Cheat Sheet Series — remediation patterns.
- CISA Known Exploited Vulnerabilities (KEV) — actively-exploited; prioritize these.
- NVD / CVE — CVE records + CVSS.
- OSV.dev + GitHub Advisory Database — open-source dependency advisories.
- Vendor advisories for the exact framework/CMS/library/server/DB/CDN/cloud in use.

Look these up live (WebSearch/WebFetch) for the specific detected versions — do not
rely on memory for whether a version is vulnerable. Cite the source in the finding.

## Authorization questions (ask before active testing, if not already answered)

- Do you own / have written authorization for every domain + subdomain in scope?
- Is this production or staging?
- What testing window is approved?
- Any WAF/rate-limit rules to respect?
- Forbidden workflows (payments, deletion, email/SMS, account changes)?
- Test accounts per role available?
- Is source code / a dependency manifest available?
- Are APIs documented (OpenAPI/Swagger/Postman)?
- Who do we contact if the target becomes unstable?

## Honesty rules

- Say "best-effort assessment," never "all vulnerabilities found."
- Separate *observed/verified* from *inferred/code-review-only* from *not-tested*.
- List what you could NOT test and why (no account, no source, cost, scope) — the
  existing example reports do this well; it's a feature, not a weakness.
