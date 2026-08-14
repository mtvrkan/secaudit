"""Compliance mapping — findings to the standards someone will be asked about.

A finding says "this code is wrong". A compliance mapping says "this is the control you told
an auditor you had". The second is what turns an audit report into something a product owner
can act on above the engineering level, and it is the layer no in-IDE security assistant
produces, because it is not a coding question.

Two mappings ship, both at a granularity we can actually defend:

* **OWASP ASVS 5.0**, at **chapter** level (V1–V17). Requirement-level (`v5.0.0-1.2.5`) would
  be more useful and we are not going to invent it: ASVS 5.0 deliberately moved external
  cross-references out to OWASP's Common Requirement Enumeration project, so there is no
  authoritative CWE→requirement crosswalk to copy. A chapter mapping we made ourselves, that
  fits on one screen and can be argued with, beats a requirement mapping that looks precise
  and is guessed. When CRE publishes a machine-readable crosswalk, replace this wholesale.
* **EU Cyber Resilience Act** (Regulation (EU) 2024/2847), at **clause** level, because those
  clause numbers are fixed by the regulation and can be quoted. Vulnerability-handling
  obligations under Annex I Part II start applying **2026-09-11**.

* **PCI DSS 4.0.1**, at **requirement** level, and only across four requirements whose text was
  read and cross-checked. PCI SSC publishes no CWE→requirement crosswalk, so each row is this
  project's reading of the requirement's own wording — which is defensible for 6.2.4 precisely
  because that requirement enumerates its attack classes itself. Weaknesses whose applicable
  requirement depends on whether the data is account data, or on whether the component is in
  the cardholder data environment, are refused by name in `PCI_NOT_ASSERTABLE` rather than
  guessed.

Deliberately NOT mapped: SOC 2 and ISO 27001. Not for lack of effort — the AICPA Trust Services
Criteria and ISO/IEC 27001 Annex A control texts are both behind copyright/paywall, so a mapping
could only name control *numbers* whose text this project cannot quote and no reader could check.
PCI is mapped and these are not for exactly one reason: PCI SSC publishes its standard for free.
When a citable source exists, map; when it does not, say so.

The mapping is keyed on CWE, so it is complete by construction over what the engine emits:
`scripts/check_consistency.py` check 24 fails the build if a detector or taint sink introduces
a CWE with no chapter assigned.
"""
from __future__ import annotations

# --------------------------------------------------------------------------- ASVS 5.0

ASVS_VERSION = "5.0.0"

ASVS_CHAPTERS: dict[str, str] = {
    "V1": "Encoding and Sanitization",
    "V2": "Validation and Business Logic",
    "V3": "Web Frontend Security",
    "V4": "API and Web Service",
    "V5": "File Handling",
    "V6": "Authentication",
    "V7": "Session Management",
    "V8": "Authorization",
    "V9": "Self-contained Tokens",
    "V10": "OAuth and OIDC",
    "V11": "Cryptography",
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V14": "Data Protection",
    "V15": "Secure Coding and Architecture",
    "V16": "Security Logging and Error Handling",
    "V17": "WebRTC",
}

# CWE → the ASVS 5.0 chapter whose controls prevent it. One screen, on purpose: every entry
# is a judgement call someone should be able to disagree with by reading it, not a generated
# table nobody reviews. Where a weakness plausibly sits in two chapters, the one chosen is
# the one that holds the *control you would implement*, not the one that names the symptom —
# SSRF lands in Validation because the fix is destination allowlisting, not in API.
CWE_TO_ASVS: dict[str, str] = {
    # Injection — the sanitization/encoding boundary
    "CWE-89": "V1",     # SQL injection
    "CWE-78": "V1",     # OS command injection
    "CWE-79": "V1",     # Cross-site scripting
    "CWE-94": "V1",     # Code injection
    "CWE-95": "V1",     # Eval injection
    "CWE-1336": "V1",   # Server-side template injection
    "CWE-611": "V1",    # XML external entities
    "CWE-943": "V1",    # NoSQL / query-language injection

    # Input validation and business logic
    "CWE-20": "V2",     # Improper input validation
    "CWE-915": "V2",    # Mass assignment
    "CWE-1321": "V2",   # Prototype pollution
    "CWE-918": "V2",    # SSRF — the control is destination allowlisting
    "CWE-400": "V2",    # Uncontrolled resource consumption

    # Browser-facing surface
    "CWE-601": "V3",    # Open redirect
    "CWE-942": "V3",    # Permissive CORS
    "CWE-1004": "V3",   # Cookie without HttpOnly
    "CWE-1275": "V3",   # Cookie with improper SameSite
    "CWE-352": "V3",    # Cross-site request forgery

    # File handling
    "CWE-22": "V5",     # Path traversal
    "CWE-434": "V5",    # Unrestricted file upload

    # Authentication and tokens
    "CWE-287": "V6",    # Improper authentication
    "CWE-384": "V7",    # Session fixation
    "CWE-347": "V9",    # Improper verification of a cryptographic signature (JWT)

    # Authorization
    "CWE-639": "V8",    # IDOR / authorization bypass through user-controlled key
    "CWE-284": "V8",    # Improper access control
    "CWE-732": "V8",    # Incorrect permission assignment
    "CWE-862": "V8",    # Missing authorization

    # Business logic. Both land in V2 rather than in the chapter that names the symptom: the
    # control you implement for a skipped workflow step is a server-side state check, and the
    # control for a price the client chose is server-side revalidation. Neither is an
    # authorization control, which is why they are not in V8 next to the two above.
    "CWE-841": "V2",    # Improper enforcement of behavioral workflow
    "CWE-602": "V2",    # Client-side enforcement of server-side security

    # Cryptography
    "CWE-327": "V11",   # Broken or risky cryptographic algorithm
    "CWE-338": "V11",   # Cryptographically weak PRNG
    "CWE-330": "V11",   # Use of insufficiently random values
    "CWE-321": "V11",   # Hard-coded cryptographic key
    "CWE-311": "V11",   # Missing encryption of sensitive data
    "CWE-916": "V11",   # Password hash without sufficient computational effort

    # Transport
    "CWE-295": "V12",   # Improper certificate validation
    "CWE-319": "V12",   # Cleartext transmission

    # Configuration and secrets
    "CWE-798": "V13",   # Hardcoded credentials
    "CWE-250": "V13",   # Execution with unnecessary privileges
    "CWE-489": "V13",   # Active debug code
    "CWE-552": "V13",   # Files or directories accessible to external parties
    "CWE-668": "V13",   # Exposure of resource to wrong sphere
    "CWE-16": "V13",    # Configuration

    # Secure coding, architecture and supply chain
    "CWE-502": "V15",   # Insecure deserialization
    "CWE-1104": "V15",  # Use of unmaintained third-party components
    "CWE-1395": "V15",  # Dependency on vulnerable third-party component
    "CWE-494": "V15",   # Download of code without integrity check
    "CWE-1357": "V15",  # Reliance on insufficiently trustworthy component
    "CWE-749": "V15",   # Exposed dangerous method or function
    "CWE-758": "V15",   # Reliance on undefined/unspecified behaviour (Rust `unsafe`)
    "CWE-704": "V15",   # Incorrect type conversion or cast (Rust `transmute`)

    # Logging and error handling
    "CWE-209": "V16",   # Information exposure through an error message
    "CWE-532": "V16",   # Insertion of sensitive information into a log file
}

# A CWE we knowingly do not map, with the reason. Present so check 24 can tell "not mapped
# yet" from "deliberately unmapped" instead of forcing a wrong chapter to make a gate pass.
UNMAPPED_CWES: dict[str, str] = {
    "CWE-Other": "Placeholder emitted when a third-party scanner reports no CWE. Nothing to map.",
}


def asvs_for(cwe: str) -> tuple[str, str] | None:
    """(chapter id, chapter title) for a CWE, or None when it is not mapped."""
    chapter = CWE_TO_ASVS.get(cwe)
    return (chapter, ASVS_CHAPTERS[chapter]) if chapter else None


# --------------------------------------------------------------------------- PCI DSS 4.0.1

PCI_VERSION = "4.0.1"

# Only requirements whose text was read and cross-checked appear here, and only ones a *source
# scanner* can speak to at all. The list is short on purpose: PCI SSC publishes no CWE→requirement
# crosswalk, so every row below is this project's reading of the requirement's own wording, and a
# short defensible mapping beats a long plausible one — the same call already made for ASVS.
PCI_REQUIREMENTS: dict[str, str] = {
    "6.2.4": "Software engineering techniques prevent or mitigate common software attacks in "
             "bespoke and custom software. The requirement enumerates the classes itself — "
             "injection, XSS, CSRF, broken authentication and session management, insecure "
             "cryptographic implementations, insecure deserialization, business-logic abuse and "
             "attacks on access-control mechanisms — which is why a CWE mapping onto it is a "
             "reading rather than an invention.",
    "6.3.1": "New security vulnerabilities are identified from industry-recognised sources and "
             "risk-ranked, for bespoke, custom AND third-party software.",
    "6.3.2": "An inventory of bespoke and custom software and of the third-party components "
             "incorporated into it is maintained, so known component vulnerabilities can be "
             "found. This is the requirement an SBOM answers.",
    "8.6.2": "Passwords/passphrases for application and system accounts that can be used for "
             "interactive login are not hard-coded in scripts, configuration/property files, or "
             "bespoke and custom source code.",
}

CWE_TO_PCI: dict[str, str] = {
    # 6.2.4 — the requirement lists these attack classes in its own text.
    "CWE-89": "6.2.4", "CWE-78": "6.2.4", "CWE-79": "6.2.4", "CWE-94": "6.2.4",
    "CWE-95": "6.2.4", "CWE-1336": "6.2.4", "CWE-611": "6.2.4", "CWE-943": "6.2.4",
    "CWE-502": "6.2.4", "CWE-352": "6.2.4", "CWE-20": "6.2.4", "CWE-915": "6.2.4",
    "CWE-1321": "6.2.4", "CWE-918": "6.2.4", "CWE-400": "6.2.4", "CWE-601": "6.2.4",
    "CWE-942": "6.2.4", "CWE-1004": "6.2.4", "CWE-1275": "6.2.4", "CWE-22": "6.2.4",
    "CWE-434": "6.2.4", "CWE-287": "6.2.4", "CWE-384": "6.2.4", "CWE-347": "6.2.4",
    "CWE-639": "6.2.4", "CWE-284": "6.2.4", "CWE-732": "6.2.4", "CWE-862": "6.2.4",
    "CWE-841": "6.2.4", "CWE-602": "6.2.4", "CWE-306": "6.2.4",
    # ...including "insecure cryptographic implementations", which is about how the software
    # uses cryptography. It is NOT a claim about protecting stored or transmitted account data —
    # that is Requirements 3 and 4, and see PCI_NOT_ASSERTABLE for why those are not here.
    "CWE-327": "6.2.4", "CWE-338": "6.2.4", "CWE-330": "6.2.4", "CWE-916": "6.2.4",
    "CWE-295": "6.2.4", "CWE-319": "6.2.4", "CWE-749": "6.2.4", "CWE-758": "6.2.4",
    "CWE-704": "6.2.4",

    # 8.6.2 — a credential written into source or config is the literal subject of this one.
    "CWE-798": "8.6.2", "CWE-321": "8.6.2",

    # 6.3.1 — a vulnerability in a third-party component, which is what this requires you to
    # find and rank. The SBOM that makes it findable is 6.3.2, reported per scan rather than
    # per finding.
    "CWE-1395": "6.3.1", "CWE-1104": "6.3.1", "CWE-1357": "6.3.1", "CWE-494": "6.3.1",
}

# Weaknesses this tool refuses to attach a PCI requirement to, each with the reason. Every one is
# a case where the requirement that *would* apply depends on a fact about the data or the
# environment that no source scan establishes. Naming a requirement anyway would assert a scoping
# decision belonging to a QSA, and being confidently wrong to an assessor costs more than being
# silent — the same reason PCI is mapped at all rather than SOC 2.
PCI_NOT_ASSERTABLE: dict[str, str] = {
    "CWE-311": "Missing encryption becomes Requirement 3 (protect stored account data) only if "
               "what is unencrypted IS account data. A scanner sees a field, not a PAN.",
    "CWE-209": "An error message leaks PCI-relevant data only when the data is account data; "
               "otherwise it is a hygiene finding with no requirement attached.",
    "CWE-532": "Same as CWE-209, for logs. Requirement 3.3.1 forbids storing sensitive "
               "authentication data after authorization — whether this log line does that is "
               "a question about the value, not about the call.",
    "CWE-16": "Configuration weaknesses map to Requirement 2 only for system components in "
              "scope, and scope is a QSA's decision about the cardholder data environment.",
    "CWE-250": "As CWE-16 — Requirement 7/2 applicability follows from scope, not from code.",
    "CWE-489": "Debug code in a non-CDE service is not a PCI finding. Scope again.",
    "CWE-552": "Exposure matters under PCI when what is exposed is account data. Unknown here.",
    "CWE-668": "As CWE-552.",
    "CWE-Other": "Placeholder emitted when a third-party scanner reports no CWE.",
}


def pci_for(cwe: str) -> tuple[str, str] | None:
    """(requirement id, requirement text) for a CWE, or None when deliberately not asserted."""
    requirement = CWE_TO_PCI.get(cwe)
    return (requirement, PCI_REQUIREMENTS[requirement]) if requirement else None


def pci_scope_note() -> str:
    """Printed wherever a PCI requirement id appears. It is the caveat, not decoration."""
    return (
        f"PCI DSS v{PCI_VERSION} requirement ids below are this project's reading of the "
        f"requirement text, not a crosswalk published by the PCI SSC — no such crosswalk exists. "
        f"They are input to a conversation with your QSA and are not evidence of compliance. "
        f"Two limits matter more than the mapping: whether a component is in scope at all is a "
        f"cardholder-data-environment decision no source scan makes, and requirements about "
        f"account data itself (3.x storage, 4.x transmission, 9.x physical) are deliberately "
        f"unmapped because a scanner cannot tell whether a value is a PAN."
    )


# Deliberately NOT mapped, and this is a decision rather than a gap:
#
# * **SOC 2** — the Trust Services Criteria are AICPA copyright and not publicly redistributable.
#   A mapping would be to criterion *numbers* whose text this project cannot quote or verify, so
#   nobody could check it, which is precisely the shape of a compliance claim that fails an audit
#   loudly.
# * **ISO/IEC 27001** — Annex A control text sits behind ISO's paywall, same problem.
#
# PCI DSS is mapped and these are not for one reason: PCI SSC publishes the standard for free, so
# the requirement text above could be read and cross-checked. When a citable source exists, map;
# when it does not, say so. That asymmetry is the rule, not an accident of effort.


# --------------------------------------------------------------------------- EU CRA

CRA_REGULATION = "Regulation (EU) 2024/2847 (Cyber Resilience Act)"
CRA_REPORTING_STARTS = "2026-09-11"

# Clause → what it obliges. Quoted structure, not invented: Annex I Part I sets product
# properties, Part II sets the vulnerability-handling process obligations.
CRA_CLAUSES: dict[str, str] = {
    "Annex I Part I (2)(a)": "Made available on the market without known exploitable "
                             "vulnerabilities.",
    "Annex I Part I (2)(b)": "Made available with a secure-by-default configuration.",
    "Annex I Part II (1)": "Identify and document vulnerabilities and components, including a "
                           "machine-readable SBOM covering at least top-level dependencies.",
    "Annex I Part II (2)": "Address and remediate vulnerabilities without delay, including by "
                           "providing security updates.",
    "Annex I Part II (3)": "Apply effective and regular security tests and reviews throughout "
                           "the support period.",
    "Annex I Part II (4)": "Publicly disclose information about fixed vulnerabilities.",
    "Annex I Part II (5)": "Operate a coordinated vulnerability disclosure policy.",
}


def cra_clauses_for(finding_cwe: str, is_dependency: bool, actively_exploited: bool) -> list[str]:
    """The CRA clauses a finding bears on.

    Every finding bears on Part I (2)(a) — a known exploitable vulnerability in the product is
    the thing that clause forbids — and on Part II (2), the duty to remediate. A dependency
    advisory additionally bears on Part II (1), the SBOM and component-identification duty.
    Actively exploited ones are what start the Article 14 reporting clock, so they are called
    out rather than left for the reader to infer."""
    clauses = ["Annex I Part I (2)(a)", "Annex I Part II (2)"]
    if is_dependency:
        clauses.append("Annex I Part II (1)")
    if finding_cwe in ("CWE-250", "CWE-489", "CWE-1104", "CWE-16"):
        clauses.append("Annex I Part I (2)(b)")
    if actively_exploited:
        clauses.append("Article 14 (reporting of actively exploited vulnerabilities)")
    return clauses


def scan_evidences() -> list[str]:
    """Clauses that running the audit at all is evidence toward.

    A scan report is not compliance, but Part II (3) obliges *regular security tests and
    reviews*, and a dated, reproducible report with a stated methodology is exactly the
    artefact that obligation expects to see."""
    return ["Annex I Part II (3)"]


def summary() -> dict:
    """What this module claims to cover, for the report's compliance section to state plainly."""
    return {
        "asvs": {"version": ASVS_VERSION, "granularity": "chapter",
                 "chapters": len(ASVS_CHAPTERS), "mapped_cwes": len(CWE_TO_ASVS)},
        "cra": {"regulation": CRA_REGULATION, "reporting_obligations_start": CRA_REPORTING_STARTS,
                "clauses": len(CRA_CLAUSES)},
        "not_mapped": ["PCI DSS", "SOC 2", "ISO 27001"],
    }
