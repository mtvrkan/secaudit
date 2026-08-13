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

Deliberately NOT mapped: PCI DSS, SOC 2, ISO 27001. Each is a real ask and each needs a source
we can cite per control. Shipping a plausible guess for a standard an auditor will check is
worse than shipping nothing, and "we did not map this yet" is a sentence a security tool is
allowed to say. Tracked in ROADMAP.md.

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
