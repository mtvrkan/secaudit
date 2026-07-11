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
    source: str = "builtin"                 # builtin | semgrep | npm-audit | osv | llm
    verdict: Verdict = Verdict.UNVERIFIED
    triage_note: str = ""                   # filled by the LLM tier
    maps_to: str = ""                       # golden-set id (eval bookkeeping only)

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
