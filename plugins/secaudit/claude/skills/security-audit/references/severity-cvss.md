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

When useful, compute a CVSS base score and include the vector string. Prefer **v4.0**
where you can (it splits impact into Vulnerable/Subsequent systems and drops Scope), and
fall back to v3.1:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N   # v4.0
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N                       # v3.1
```

Don't let a score override context: a "medium" CVSS that is internet-facing,
unauthenticated, and KEV-listed is a top-priority fix. Severity in the report reflects
**contextual risk**, not raw CVSS.

## EPSS & KEV (exploitation likelihood)

CVSS rates *severity*, not *probability of exploitation*. Pair it with:
- **CISA KEV** — binary "known exploited in the wild." A KEV listing overrides a modest
  CVSS every time; remediate on the KEV timeline.
- **EPSS** ([FIRST](https://www.first.org/epss/)) — a 0–1 probability that a CVE will be
  exploited in the next 30 days. Use it to rank the long tail of non-KEV CVEs: a high-EPSS
  (e.g. ≥0.5), internet-reachable dependency jumps the queue over a higher-CVSS but
  low-EPSS, unreachable one. Note EPSS is population-level prediction, not a
  reachability check — still confirm the code path (see Triage).

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
