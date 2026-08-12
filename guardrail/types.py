"""Core types for the guardrail pipeline.

A guardrail run produces a decision, not a boolean. Real deployments need three
outcomes — allow, transform (redact/repair), block — because binary
allow/deny either leaks data or breaks the product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How bad a finding is. Drives the default action."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Action(str, Enum):
    """What the policy decided to do."""

    ALLOW = "allow"
    REDACT = "redact"      # content modified, request proceeds
    FLAG = "flag"          # proceed, but record for review
    BLOCK = "block"        # refuse outright


class Stage(str, Enum):
    """Which side of the model call a check runs on."""

    INPUT = "input"    # before the prompt reaches the model
    OUTPUT = "output"  # before the response reaches the user


@dataclass
class Finding:
    """One thing a detector noticed."""

    detector: str
    severity: Severity
    message: str
    #: Character span in the inspected text, when the detector can localise it.
    span: tuple[int, int] | None = None
    matched: str | None = None
    confidence: float = 1.0
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


@dataclass
class GuardResult:
    """The outcome of running a guard over some text."""

    action: Action
    text: str                    # possibly redacted/repaired
    original_text: str
    findings: list[Finding] = field(default_factory=list)
    stage: Stage = Stage.INPUT

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    @property
    def modified(self) -> bool:
        return self.text != self.original_text

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def findings_by(self, detector: str) -> list[Finding]:
        return [f for f in self.findings if f.detector == detector]

    def summary(self) -> str:
        if not self.findings:
            return f"{self.action.value}: clean"
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.detector] = counts.get(f.detector, 0) + 1
        detail = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items()))
        return f"{self.action.value}: {detail}"
