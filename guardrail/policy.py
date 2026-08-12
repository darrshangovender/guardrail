"""Policy — turn findings into a decision.

Detection and decision are deliberately separate. The same PII detector should
block in a healthcare deployment and merely redact in an internal tool; forking
the detector to express that would be a maintenance disaster.

A policy maps (detector, severity) → Action, with a sensible default ladder and
per-detector overrides.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardrail.types import Action, Finding, Severity


@dataclass
class Policy:
    """Decide an action from a set of findings.

    Parameters
    ----------
    block_at
        Minimum severity that triggers a block.
    redact_at
        Minimum severity that triggers redaction (for detectors that support it).
    overrides
        Per-detector action override, e.g. ``{"pii": Action.REDACT}`` to always
        redact PII regardless of severity.
    min_confidence
        Findings below this are ignored entirely — the knob you reach for when
        a noisy detector is causing false blocks.
    """

    block_at: Severity = Severity.HIGH
    redact_at: Severity = Severity.MEDIUM
    overrides: dict[str, Action] = field(default_factory=dict)
    min_confidence: float = 0.0

    def decide(self, findings: list[Finding]) -> Action:
        relevant = [f for f in findings if f.confidence >= self.min_confidence]
        if not relevant:
            return Action.ALLOW

        actions: list[Action] = []
        for f in relevant:
            override = self.overrides.get(f.detector)
            if override is not None:
                actions.append(override)
            elif f.severity.rank >= self.block_at.rank:
                actions.append(Action.BLOCK)
            elif f.severity.rank >= self.redact_at.rank:
                actions.append(Action.REDACT)
            else:
                actions.append(Action.FLAG)

        # Most restrictive action wins.
        order = [Action.ALLOW, Action.FLAG, Action.REDACT, Action.BLOCK]
        return max(actions, key=order.index)

    def filter(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.confidence >= self.min_confidence]


#: Redact PII, block everything else high-severity. Good default for most apps.
BALANCED = Policy(overrides={"pii": Action.REDACT})

#: Block on anything medium or above. For regulated or high-trust surfaces.
STRICT = Policy(block_at=Severity.MEDIUM, redact_at=Severity.LOW)

#: Never block; record everything. Use to measure a detector's false-positive
#: rate against real traffic before you let it reject anything.
AUDIT = Policy(
    overrides={d: Action.FLAG for d in ("injection", "pii", "groundedness", "schema")}
)
