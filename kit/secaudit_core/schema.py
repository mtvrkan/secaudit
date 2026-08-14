"""Common data model shared by detectors, backends, and the report renderer."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


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

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.file, f.line))

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
