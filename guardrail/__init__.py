"""guardrail — a safety gateway for LLM inputs and outputs.

    from guardrail import Guard, BALANCED
    from guardrail.detectors import InjectionDetector, PIIDetector

    guard = Guard([InjectionDetector(), PIIDetector()], policy=BALANCED)
    result = guard.check_input(user_prompt)
    if result.allowed:
        model(result.text)   # redacted if PII was present
"""

from guardrail.detectors import (
    Detector,
    GroundednessDetector,
    InjectionDetector,
    PIIDetector,
    SchemaDetector,
)
from guardrail.guard import Guard
from guardrail.policy import AUDIT, BALANCED, STRICT, Policy
from guardrail.types import Action, Finding, GuardResult, Severity, Stage

__version__ = "0.1.0"

__all__ = [
    "AUDIT",
    "BALANCED",
    "STRICT",
    "Action",
    "Detector",
    "Finding",
    "GroundednessDetector",
    "Guard",
    "GuardResult",
    "InjectionDetector",
    "PIIDetector",
    "Policy",
    "SchemaDetector",
    "Severity",
    "Stage",
]
