"""Prompt-injection detection.

Injection is the hardest problem here and the one where honesty matters most:
**no pattern-based detector catches a determined adversary.** What this does
catch is the large volume of low-effort and copy-pasted attacks that make up
most real traffic, plus injected content arriving through RAG documents and
tool output — which is where injection actually bites in production systems.

Three signal families, deliberately separate so you can tune them independently:

1. **Instruction override** — "ignore previous instructions", "disregard the above"
2. **Role/persona hijack** — "you are now DAN", "act as an unrestricted model"
3. **Exfiltration probes** — "repeat your system prompt", "print your instructions"

Scored, not binary: each match contributes confidence, and the policy decides.
"""

from __future__ import annotations

import re

from guardrail.detectors.base import Detector
from guardrail.types import Finding, Severity, Stage

# (pattern, family, severity, confidence)
_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # -- instruction override ------------------------------------------------
    (r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+"
     r"(?:instructions?|prompts?|rules?|directions?)", "override", Severity.HIGH, 0.95),
    (r"\bdisregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\b",
     "override", Severity.HIGH, 0.9),
    (r"\bforget\s+(?:everything|all)\s+(?:you|above|before|previously)\b",
     "override", Severity.HIGH, 0.9),
    (r"\boverride\s+(?:your\s+)?(?:instructions?|programming|rules?|guidelines?)\b",
     "override", Severity.HIGH, 0.9),
    (r"\bnew\s+instructions?\s*:", "override", Severity.MEDIUM, 0.7),

    # -- role / persona hijack ----------------------------------------------
    (r"\byou\s+are\s+now\s+(?:a|an|DAN|in\s+developer\s+mode)\b",
     "role_hijack", Severity.HIGH, 0.85),
    (r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|uncensored)\b",
     "role_hijack", Severity.HIGH, 0.9),
    (r"\b(?:enable|enter|activate)\s+(?:developer|debug|god|admin)\s+mode\b",
     "role_hijack", Severity.HIGH, 0.85),
    (r"\bpretend\s+(?:that\s+)?you\s+(?:are|have)\s+no\s+(?:restrictions?|rules?|guidelines?)\b",
     "role_hijack", Severity.HIGH, 0.9),
    (r"\bwithout\s+any\s+(?:restrictions?|filters?|limitations?|guidelines?)\b",
     "role_hijack", Severity.MEDIUM, 0.6),

    # -- exfiltration --------------------------------------------------------
    (r"\b(?:repeat|print|show|reveal|output|display|tell\s+me)\s+(?:me\s+)?"
     r"(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)\b",
     "exfiltration", Severity.HIGH, 0.9),
    (r"\bwhat\s+(?:were|are)\s+your\s+(?:original\s+)?(?:instructions?|system\s+prompt)\b",
     "exfiltration", Severity.MEDIUM, 0.8),
    (r"\brepeat\s+(?:everything|the\s+text)\s+above\b",
     "exfiltration", Severity.MEDIUM, 0.75),

    # -- delimiter / structure injection ------------------------------------
    (r"</?(?:system|assistant|user|im_start|im_end)>", "delimiter", Severity.MEDIUM, 0.7),
    (r"\[/?INST\]|<\|.*?\|>", "delimiter", Severity.MEDIUM, 0.65),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), fam, sev, conf) for p, fam, sev, conf in _PATTERNS]

#: Zero-width and bidi control characters used to smuggle hidden instructions
#: past human review. Cheap to check, and a strong signal when present.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")


class InjectionDetector(Detector):
    """Pattern-based prompt-injection detection.

    Parameters
    ----------
    min_confidence
        Findings below this confidence are not reported.
    check_invisible
        Flag zero-width / bidi control characters (hidden-instruction smuggling).
    """

    name = "injection"
    stages = (Stage.INPUT,)

    def __init__(self, min_confidence: float = 0.6, check_invisible: bool = True) -> None:
        self.min_confidence = min_confidence
        self.check_invisible = check_invisible

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []

        for pattern, family, severity, confidence in _COMPILED:
            if confidence < self.min_confidence:
                continue
            for m in pattern.finditer(text):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        message=f"possible prompt injection ({family})",
                        span=(m.start(), m.end()),
                        matched=m.group(0)[:120],
                        confidence=confidence,
                        meta={"family": family},
                    )
                )

        if self.check_invisible:
            for m in _INVISIBLE.finditer(text):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        message="invisible control character (possible hidden instruction)",
                        span=(m.start(), m.end()),
                        matched=repr(m.group(0)),
                        confidence=0.7,
                        meta={"family": "invisible"},
                    )
                )

        return findings
