"""Detector interface.

A detector inspects text and returns findings. It never decides what to *do* —
that's the policy's job. Keeping detection and decision separate means the same
detector can block in one deployment and merely flag in another, without forking
the detection logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from guardrail.types import Finding, Stage


class Detector(ABC):
    """Inspect text; report findings."""

    name: str = "detector"
    #: Which stages this detector is meaningful on.
    stages: tuple[Stage, ...] = (Stage.INPUT, Stage.OUTPUT)

    @abstractmethod
    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        """Return zero or more findings for ``text``."""

    def redact(self, text: str, findings: list[Finding]) -> str:
        """Return a redacted version of ``text``.

        Default is identity — most detectors have nothing sensible to redact
        (you can't 'redact' a prompt injection, only block it). PII detectors
        override this.
        """
        return text

    def supports(self, stage: Stage) -> bool:
        return stage in self.stages
