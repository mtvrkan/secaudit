# Compliance mapping — what this tool will and will not claim

A finding says *"this code is wrong."* A compliance mapping says *"this is the control you told an
auditor you had."* The second is the layer no in-IDE security assistant produces, because it is not
a coding question — and it is the layer where a security tool can do real damage by being
confidently wrong.

So the rule this page exists to state: **when a citable source exists, map; when it does not, say
so.** Three standards are mapped. Two are refused, by name, with the reason.

| Standard | Granularity | Why that granularity |
|---|---|---|
| OWASP ASVS 5.0 | Chapter (V1–V17) | ASVS 5.0 moved external cross-references out to OWASP's CRE project, so there is no authoritative CWE→requirement crosswalk to copy. A chapter mapping that fits on one screen and can be argued with beats a requirement mapping that looks precise and is guessed. |
| EU CRA (2024/2847) | Clause | Clause numbers are fixed by the regulation and can be quoted. |
| PCI DSS 4.0.1 | Requirement, across four | Only requirements whose text was read and cross-checked. |
| SOC 2 | **not mapped** | AICPA Trust Services Criteria are copyright and not publicly redistributable. |
| ISO/IEC 27001 | **not mapped** | Annex A control text is behind ISO's paywall. |

The asymmetry is the whole point: PCI SSC publishes its standard for free, so its requirement text
could be read. A SOC 2 or ISO mapping could only name control *numbers* whose text this project
cannot quote and no reader could check — which is precisely the shape of a compliance claim that
fails an audit loudly.

## PCI DSS 4.0.1

Four requirements, and each row is this project's reading of the requirement's own wording. **PCI
SSC publishes no CWE→requirement crosswalk**, so nothing here is copied from an authority.

| Requirement | Covers | Why the mapping is a reading and not an invention |
|---|---|---|
| **6.2.4** | Injection, XSS, CSRF, broken auth/session, insecure cryptographic implementations, insecure deserialization, business-logic abuse, attacks on access control | The requirement **enumerates these classes itself**. Mapping a CWE onto it is matching a weakness to a list the standard already wrote. |
| **6.3.1** | A vulnerable third-party component | 6.3.1 requires new vulnerabilities to be identified from industry-recognised sources and risk-ranked, for third-party software as well as your own. That is what the dependency scan does. |
| **6.3.2** | The SBOM | 6.3.2 requires an inventory of bespoke/custom software and the third-party components in it. Reported per scan rather than per finding, because it is an artefact claim. |
| **8.6.2** | A credential in source or config | 8.6.2 is literally about passwords "not hard-coded in scripts, configuration/property files, or bespoke and custom source code." |

### What it refuses to say

Every CWE the engine emits either maps to one of those four or appears in `PCI_NOT_ASSERTABLE`
**with the reason** — consistency check 24 fails the build on a CWE that is in neither, so an
unmapped weakness is a decision on the record rather than something somebody forgot.

The refusals almost all come down to two facts a source scan does not establish:

- **Whether the data is account data.** Missing encryption becomes Requirement 3 only if what is
  unencrypted *is* a PAN. A scanner sees a field, not a cardholder number. Same for a leaking log
  line (`CWE-532`) or error message (`CWE-209`).
- **Whether the component is in scope.** Requirement 2 configuration findings, debug code, excess
  privilege — all of these are PCI findings only inside the cardholder data environment, and CDE
  scope is a QSA's decision.

Naming a requirement anyway would be asserting somebody else's scoping decision. This is why
Requirements 3.x, 4.x and 9.x are deliberately absent from the mapping entirely.

### What you get

`--format cra` carries a `pci_dss` block: the requirements actually referenced by this scan with
their text, the scope note, and the full refusal list with reasons. Every finding in the register
carries `pci_dss_requirement`, which is `null` when the answer is "this tool will not say."

**It is input to a conversation with your QSA. It is not evidence of compliance.**

## EU CRA

Clause-level against Annex I, with `--format cra` emitting the evidence pack: CycloneDX SBOM +
vulnerability register (VEX, reachability, ASVS chapter, PCI requirement, remediation) + clause
coverage + a disclaimer that it is input to a compliance process rather than a certificate.

The vulnerability-handling obligations start **2026-09-11**, and the 24-hour early-warning duty
triggers on *actively exploited* vulnerabilities — see [continuous mode](continuous-mode.md), which
exists for exactly that trigger.

## ASVS 5.0

Chapter level, complete over every CWE the engine emits (gated by check 24). Where a weakness
plausibly sits in two chapters, the one chosen holds *the control you would implement*, not the one
that names the symptom — SSRF lands in Validation because the fix is destination allowlisting.
