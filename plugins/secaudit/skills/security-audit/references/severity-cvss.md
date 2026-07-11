# Severity, CVSS & prioritization

## Severity model (report labels)

| Severity | Criteria |
|---|---|
| **Critical** | Likely full compromise: unauthenticated RCE, widespread sensitive-data exposure, or active in-the-wild exploitation with direct impact here. |
| **High** | Auth/authz bypass, privilege escalation, high-impact IDOR/BOLA, exploitable injection, sensitive-data exposure, or a KEV-listed reachable component. |
| **Medium** | Limited-impact injection, control bypass needing conditions, misconfig with plausible abuse, or important missing hardening. |
| **Low** | Minor info disclosure, missing non-critical header, low-impact misconfig. |
| **Informational** | Best-practice improvement, no direct exploit path. |

## CVSS (optional, adds rigor)

When useful, compute a CVSS v3.1/v4.0 base score and include the vector string, e.g.
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`. Don't let a score override context:
a "medium" CVSS that is internet-facing, unauthenticated, and KEV-listed is a
top-priority fix. Severity in the report reflects **contextual risk**, not raw CVSS.

## Prioritization order

1. Known **exploited in the wild** (CISA KEV) and reachable.
2. Internet-exposed, unauthenticated, critical.
3. Authentication / authorization bypass.
4. Sensitive-data exposure.
5. RCE or SSRF with real impact.
6. Vulnerable dependencies with public exploit + reachable code path.
7. Misconfig enabling account takeover / data exposure / privesc.
8. Medium/low hardening.

## Triage (turn scanner hits into findings)

Before a raw hit becomes a finding, confirm:
- **Reachable?** Is the code path/endpoint reachable from untrusted input?
- **Version-accurate?** Installed (lockfile) version genuinely in the affected range?
- **Mitigated?** Is a control elsewhere already neutralizing it?
- **Real impact?** Concrete, not theoretical.

Mark verdicts: `CONFIRMED` (verified), `PLAUSIBLE` (needs manual confirmation),
`FALSE POSITIVE` (drop, but say you checked). Route Critical/High through the
`secaudit-verifier` agent when available.

## Remediation roadmap buckets

- **24–72h:** criticals + KEV + easy high-impact one-liners (a header, an exposed field).
- **7–14d:** highs, auth/authz fixes, dependency upgrades.
- **30–60d:** mediums, hardening, architectural changes, monitoring.
