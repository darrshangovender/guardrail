"""The Guard — run detectors, apply policy, return a decision.

    guard = Guard(detectors=[InjectionDetector(), PIIDetector()], policy=BALANCED)

    inbound = guard.check_input(user_prompt)
    if not inbound.allowed:
        return refuse(inbound.summary())

    response = model(inbound.text)          # note: possibly redacted

    outbound = guard.check_output(response, source=retrieved_context)
    return outbound.text if outbound.allowed else fallback()

Detectors declare which stage they apply to, so the same Guard can serve both
sides without misapplying an output-only check (groundedness) to an input.
"""

from __future__ import annotations

from guardrail.detectors.base import Detector
from guardrail.policy import BALANCED, Policy
from guardrail.types import Action, Finding, GuardResult, Stage


class Guard:
    """Run a detector set over text and decide what to do."""

    def __init__(self, detectors: list[Detector], policy: Policy | None = None) -> None:
        if not detectors:
            raise ValueError("need at least one detector")
        self.detectors = detectors
        self.policy = policy or BALANCED

    # -- public API -----------------------------------------------------

    def check_input(self, text: str, **context) -> GuardResult:
        return self._run(text, Stage.INPUT, context)

    def check_output(self, text: str, **context) -> GuardResult:
        return self._run(text, Stage.OUTPUT, context)

    # -- internals ------------------------------------------------------

    def _run(self, text: str, stage: Stage, context: dict) -> GuardResult:
        active = [d for d in self.detectors if d.supports(stage)]

        findings: list[Finding] = []
        for det in active:
            findings.extend(det.detect(text, context))

        findings = self.policy.filter(findings)
        action = self.policy.decide(findings)

        out_text = text
        if action is Action.REDACT:
            # Let each detector that found something transform the text. Order
            # follows the detector list so behaviour is predictable.
            for det in active:
                mine = [f for f in findings if f.detector == det.name]
                if mine:
                    out_text = det.redact(out_text, mine)

            # If nothing actually changed, there was nothing to redact — a
            # REDACT decision with no transformation is really a FLAG, and
            # reporting it as REDACT would overstate what happened.
            if out_text == text:
                action = Action.FLAG

        return GuardResult(
            action=action,
            text=out_text,
            original_text=text,
            findings=findings,
            stage=stage,
        )
