"""Common data model shared by detectors, backends, and the report renderer."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field, asdict
from enum import Enum

# ------------------------------------------------------------------ attacker-authored strings
#
# A finding quotes the file it was found in. That line was written by whoever wrote the code
# being scanned, which on this tool's own terms is an untrusted author — and it is then printed
# to a terminal, pasted into a pull request, and rendered into HTML. `report.to_html` worked this
# out early and escapes; nothing applied the same reasoning to the other two, so three things
# went through verbatim:
#
# * **ANSI escapes.** `\x1b[2J` clears the screen; `\r` overwrites the line already printed. A
#   repository could repaint the report that is describing it.
# * **Bidi overrides.** U+202E and its family are the Trojan Source attack (CVE-2021-42574):
#   source that renders in one order and compiles in another. A scanner that echoes the line
#   verbatim reproduces the illusion inside its own evidence, which is the one place a reader is
#   relying on seeing what is actually there.
# * **Zero-width characters**, which hide the difference between two identifiers entirely.
#
# Replaced rather than stripped, and with the code point spelled out. Deleting them would make
# the report honest and the file's contents invisible; `<U+202E>` says *this line contains a
# right-to-left override*, which for the Trojan Source case is not sanitising the finding — it
# **is** the finding.
def visible_controls(text: str) -> str:
    """Control and format characters replaced by `<U+XXXX>`; everything else untouched.

    Categories `Cc` (control) and `Cf` (format: bidi overrides, zero-width joiners, BOM). `Cs`,
    `Co` and `Cn` are left alone — an unpaired surrogate or a private-use glyph renders as a box
    and drives nothing.
    """
    if not text:
        return text
    if all(unicodedata.category(ch) not in ("Cc", "Cf") for ch in text):
        return text                       # the overwhelmingly common case allocates nothing
    return "".join(f"<U+{ord(ch):04X}>" if unicodedata.category(ch) in ("Cc", "Cf") else ch
                   for ch in text)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}[self.value]


class Confidence(str, Enum):
    # HIGH = an unambiguous sink (used to measure precision — a HIGH finding on safe code
    #        is a real false positive). MEDIUM = a lead that wants triage (the LLM tier's job).
    HIGH = "high"
    MEDIUM = "medium"


class Verdict(str, Enum):
    UNVERIFIED = "unverified"   # Tier-0 only; no model has triaged it yet
    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    REFUTED = "refuted"


@dataclass
class Finding:
    detector_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: str
    file: str
    line: int
    evidence: str
    fix: str
    # Which analysis produced this. `engine._SOURCE_RANK` is the registry — it names every legal
    # value and orders them, and check 31 fails the build on a value that is not in it. This
    # comment used to list them and had gone three sources stale, which is why it now points at
    # the map instead of copying it.
    source: str = "builtin"
    verdict: Verdict = Verdict.UNVERIFIED
    triage_note: str = ""                   # filled by the LLM tier
    maps_to: str = ""                       # golden-set id (eval bookkeeping only)
    # Rendered source → sink chain when the taint tier proved untrusted input reaches this
    # sink. Its presence is what separates "a dangerous API is called here" from "a dangerous
    # API is called here with attacker-controlled data", so it is reported, never summarized
    # away: a reviewer can follow it line by line and refute it.
    taint_path: str = ""
    # OpenVEX status for a dependency advisory: affected / not_affected / under_investigation,
    # with the justification and the evidence behind the call. A `not_affected` advisory is
    # downgraded and labelled, never deleted — a filtered register is not usable as evidence,
    # and under the EU CRA the justification is the part a regulator asks for.
    vex_status: str = ""
    vex_justification: str = ""
    # Exploitation status for a CVE: exploited | elevated | listed | unknown. There is no
    # "not exploited" value on purpose — absence from CISA KEV means unlisted, and a low EPSS
    # is a low probability, not zero. A vocabulary containing a clean-bill value gets used as
    # one. Empty when the exploitation feeds were not consulted (the default).
    exploitation: str = ""
    exploitation_note: str = ""
    # The dependency this finding is about, when it is one. Set by every dependency source
    # (npm audit, osv-scanner) so reachability is classified in one place rather than once per
    # adapter — a per-adapter implementation is how one of them silently ends up without it.
    package: str = ""

    def __post_init__(self) -> None:
        # One choke point, on the constructor, rather than once per renderer. Every tier builds
        # its own `Finding` — patterns, taint, structural, the external scanner adapters, the
        # LLM tier — so a rule applied in `to_markdown` would hold for exactly the renderer it
        # was written in, and the next one added would quietly not have it. `evidence` and
        # `file` are the two fields whose contents the scanned repository chooses.
        self.evidence = visible_controls(self.evidence)
        self.file = visible_controls(self.file)

    def key(self) -> tuple:
        """Dedup key — same rule + location is the same finding."""
        return (self.detector_id, self.file, self.line)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["verdict"] = self.verdict.value
        return d


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    backend: str = "none"
    # How many files the pattern pass actually opened. Zero findings out of zero files read is a
    # different statement from zero findings out of nine hundred, and the report used to render
    # both identically.
    files_scanned: int = 0

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.file, f.line))

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
