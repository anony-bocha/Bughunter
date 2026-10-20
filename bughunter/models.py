from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .util import canonical_json, sha256_text

_SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
_CONFIDENCE_WEIGHT = {"confirmed": 1.0, "likely": 0.8, "possible": 0.55}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATUS_ORDER = {"rejected": 0, "lead": 1, "confirmed": 2}
_CONFIDENCE_ORDER = {"possible": 0, "likely": 1, "confirmed": 2}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


@dataclass
class Observation:
    kind: str
    asset: str
    key: str
    value: Any
    source: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "asset": self.asset,
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class Signal:
    title: str
    bug_class: str
    asset: str
    severity: Severity | str
    confidence: Confidence | str
    rationale: str
    next_step: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    dedupe_key: str = ""
    status: str | None = None

    def to_hypothesis(self) -> "Hypothesis":
        hypothesis = Hypothesis(
            title=self.title,
            bug_class=self.bug_class,
            asset=self.asset,
            severity=Severity(self.severity),
            confidence=Confidence(self.confidence),
            rationale=self.rationale,
            next_step=self.next_step,
            remediation=self.remediation,
            evidence=self.evidence,
            source=self.source,
            dedupe_key=self.dedupe_key,
            status=self.status or "auto",
        )
        return hypothesis.finalize()


@dataclass
class Hypothesis:
    title: str
    bug_class: str
    asset: str
    severity: Severity
    confidence: Confidence
    rationale: str
    next_step: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    dedupe_key: str = ""
    status: str = "auto"
    priority: float = 0.0
    fingerprint: str = ""

    def finalize(self) -> "Hypothesis":
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)
        if self.status == "auto":
            self.status = "confirmed" if self.confidence == Confidence.CONFIRMED else "lead"
        if self.status not in _STATUS_ORDER:
            raise ValueError(f"invalid hypothesis status {self.status!r}")
        if not self.fingerprint:
            key = self.dedupe_key or self.title
            self.fingerprint = sha256_text(f"{self.bug_class}|{self.asset.lower()}|{key}")
        self.priority = round(
            _SEVERITY_WEIGHT[self.severity.value] * _CONFIDENCE_WEIGHT[self.confidence.value], 2
        )
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "bug_class": self.bug_class,
            "asset": self.asset,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "next_step": self.next_step,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "source": self.source,
            "dedupe_key": self.dedupe_key,
            "status": self.status,
            "priority": self.priority,
            "fingerprint": self.fingerprint,
        }

    def evidence_json(self) -> str:
        return canonical_json(self.evidence)


def severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.get(str(value).lower(), 9)


def status_rank(value: str) -> int:
    return _STATUS_ORDER.get(str(value).lower(), 0)


def confidence_rank(value: str) -> int:
    return _CONFIDENCE_ORDER.get(str(value).lower(), 0)


def priority_for(severity: str, confidence: str) -> float:
    return round(
        _SEVERITY_WEIGHT.get(str(severity).lower(), 1.0) * _CONFIDENCE_WEIGHT.get(str(confidence).lower(), 0.5),
        2,
    )
