---
name: compliance-pack
allowed-tools: >-
  Read, Grep, Glob, Write,
  Bash(secaudit*), Bash(python3 -m secaudit_core.cli*), Bash(python -m secaudit_core.cli*)
description: >-
  Produce the compliance artefacts a regulator, an auditor or a customer's security
  questionnaire asks for: a CycloneDX or SPDX SBOM, an EU Cyber Resilience Act evidence
  pack, an OpenVEX reachability statement, and CWE→ASVS 5.0 / PCI DSS 4.0.1 mapping.
  Use when the user asks for an SBOM, asks "are we CRA compliant", is filling in a
  vendor security questionnaire, needs a vulnerability register, asks which findings
  map to a standard, or says "SBOM", "CycloneDX", "SPDX", "VEX", "CRA", "ASVS",
  "PCI DSS", "compliance report", and Turkish equivalents ("uyumluluk", "denetim
  raporu", "bağımlılık envanteri").
  NOT for finding vulnerabilities — that is the `security-audit` skill. This one turns
  findings that already exist into documents someone else reads.
license: MIT
---

# Compliance pack

This is the deliverable layer. It does not find anything; it renders what the engine already
found into the shapes other people ask for.

| They asked for | Command |
|---|---|
| An SBOM | `secaudit <path> --format cyclonedx` (or `--format spdx`) |
| "Which advisories actually affect us?" | `secaudit <path> --format openvex` |
| A CRA evidence pack | `secaudit <path> --format cra` |
| "Is anything being exploited?" | add `--exploitation` — see the `exploitation-watch` skill |

The CRA pack is the composite one: SBOM + vulnerability register (with VEX status, reachability,
ASVS chapter, PCI requirement and remediation) + clause coverage + the disclaimer.

## The sentence that has to survive into whatever you write

**It is input to a compliance process. It is not evidence of compliance.** The pack says so in
its own `disclaimer` field, and any summary you produce from it must keep that. There is no
conformity assessment here, no Article 13 risk assessment and no legal opinion.

## What the mappings will and will not claim

Read [`docs/compliance.md`](../../../../docs/compliance.md) before answering a question about
coverage. The short version, because it is the part users push back on:

- **ASVS 5.0** — chapter level (V1–V17). Requirement level is not attempted: ASVS moved external
  cross-references out to OWASP's CRE project, so there is no crosswalk to copy.
- **EU CRA** — clause level. Clause numbers are fixed by the regulation and quotable.
- **PCI DSS 4.0.1** — four requirements only (6.2.4, 6.3.1, 6.3.2, 8.6.2), each one whose text was
  read. PCI SSC publishes no CWE→requirement crosswalk, so these are a reading, and they are input
  to a conversation with the user's QSA.
- **SOC 2 and ISO 27001 — not mapped, and say so plainly if asked.** The AICPA Trust Services
  Criteria and ISO Annex A control texts are behind copyright and paywalls, so a mapping could
  only name control numbers whose text nobody can check. Offer the ASVS/PCI mapping as the nearest
  thing; do not improvise a crosswalk, and do not let a user talk you into one.

Two limits produce most of the unmapped PCI rows and are worth stating unprompted: whether a
component is in scope at all is a cardholder-data-environment decision, and requirements about
account data itself (3.x, 4.x, 9.x) need to know whether a value is a PAN. A source scan
establishes neither.

## If the SBOM comes back nearly empty

That is usually correct rather than broken. Check the ecosystem first — SBOM generation supports
npm manifests today, and an unsupported ecosystem reports "no SBOM produced", which is a different
answer from "a product with no dependencies". Say which one it was.
