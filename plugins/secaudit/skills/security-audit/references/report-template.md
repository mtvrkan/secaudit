# Report template

Write the report in the requested language (`--lang`, default: user's language, else
English). Keep CWE/CVE/OWASP IDs and code in their canonical form. Findings are ordered
Critical → High → Medium → Low → Informational.

## Per-finding block (English)

```markdown
### F-001 — <concise title>  ·  Severity: <Critical|High|Medium|Low|Informational>
- **Class / OWASP / CWE:** A0x <name> · CWE-nnn  (+ API/LLM/M id if applicable)
- **Affected asset:** <URL/endpoint/file:line/component>
- **Verdict:** CONFIRMED (live-verified) | PLAUSIBLE (code-review, not live-triggered)
  (A candidate the verifier marks **REFUTED** is a false positive — drop it from the
  findings, or note it under §"Considered & Dismissed" if a scanner raised it.)
- **Evidence:** <masked/sanitized proof — headers, response snippet, code excerpt>
- **Impact:** <what an attacker gains; chain with other findings if relevant>
- **Likelihood:** <preconditions, how easy>
- **Reproduction (minimal, safe):** <steps / one curl>
- **Root cause:** <why it exists>
- **Fix:** <specific, actionable — secure code/config snippet; version target if a dep>
- **Retest:** <exact check that proves it's fixed>
- **References:** <CVE / OWASP / vendor advisory / cheat sheet>
```

## Per-finding block (Turkish)

```markdown
### F-001 — <kısa başlık>  ·  Önem: <Kritik|Yüksek|Orta|Düşük|Bilgi>
- **Sınıf / OWASP / CWE:** A0x <ad> · CWE-nnn
- **Etkilenen varlık:** <URL/uç nokta/dosya:satır/bileşen>
- **Doğrulama:** DOĞRULANDI (canlı) | OLASI (kod incelemesi, canlı tetiklenmedi)
- **Kanıt:** <maskeli/temizlenmiş kanıt>
- **Etki:** <saldırganın elde ettiği; varsa diğer bulgularla zincir>
- **Olasılık:** <ön koşullar, kolaylık>
- **Yeniden üretim (asgari, güvenli):** <adımlar / tek curl>
- **Kök neden:** <neden var>
- **Düzeltme:** <net, uygulanabilir — güvenli kod/config; bağımlılıksa sürüm hedefi>
- **Retest:** <düzeldiğini kanıtlayan kontrol>
- **Referanslar:** <CVE / OWASP / üretici bülteni>
```

## Final report structure

```markdown
# Security Audit Report — <target>

## Executive Summary
- Scope · Testing dates · Overall risk rating
- Findings by severity: Critical N · High N · Medium N · Low N · Info N
- Main business risks (plain language)
- Fastest risk-reduction actions (top 3)

## Scope & Constraints
- In-scope / out-of-scope assets
- Source available? · Authenticated testing? · Production/staging?
- Authorization: <who approved, when — or "asserted by user in-session">
- Testing limitations

## Methodology
Which phases ran (passive recon, attack surface, known-CVE/deps, OWASP web/API,
source review, infra, mobile/LLM), and which tools (installed) vs LLM analysis.

## Findings Summary
| ID | Severity | Title | Affected Asset | Verdict | Status |
|---|---|---|---|---|---|

## Detailed Findings
<severity-ordered per-finding blocks>

## Dependency & Known-CVE Register
| Component | Installed | CVE/Advisory | Severity | In KEV? | Reachable? | Fix Version | Status |
|---|---:|---|---|---|---|---|---|

## Positive Security Controls Observed
<what's already done right — don't break these>

## Considered & Dismissed (optional)
<scanner hits or candidate findings the verifier REFUTED — with the one-line reason
(unreachable, version not affected, mitigated by X). Shows rigor and prevents re-litigation.>

## Remediation Roadmap
### Fix within 24–72h
### Fix within 7–14 days
### Fix within 30–60 days

## Retest Checklist
| Finding ID | Severity | Retest step | Result |
|---|---|---|---|

## Appendix A — Activity Log
| Timestamp | Action | Target | Result |
|---|---|---|---|

## Appendix B — Assumptions & Limitations
- Best-effort assessment, not a guarantee that no vulnerabilities remain.
- Bounded by scope, access, source availability, time, and tooling.
- What was NOT tested and why (no 2nd account, cost, out-of-scope, tool absent).
```

## Style notes

- Lead with impact, then fix. Developers act on specific fixes, not "sanitize input."
- Always include a **Positive controls** section — it builds trust and prevents
  regressions.
- Separate CONFIRMED from PLAUSIBLE from NOT-TESTED. Never overclaim.
- Mask every secret/PII/token. Use canaries for proof, never real data.
- Offer to write the report to a file and, if the user wants, a shareable summary.
```
