"""Structured-output validation and repair.

When you ask a model for JSON you get JSON *most* of the time. The rest arrives
wrapped in markdown fences, prefixed with "Here's the JSON:", with trailing
commas, or with single quotes. Each of those is a crash in production if you
call ``json.loads`` directly.

This detector validates, and — importantly — **repairs the mechanical failures**
before giving up. Repair is deterministic string surgery, never a model call:
a retry costs latency and money, and the failures below don't need intelligence
to fix.
"""

from __future__ import annotations

import json
import re
from typing import Any

from guardrail.detectors.base import Detector
from guardrail.types import Finding, Severity, Stage

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)
_PREAMBLE = re.compile(r"^[^{\[]*(?=[{\[])", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def extract_json(text: str) -> str | None:
    """Pull the most likely JSON payload out of a model response.

    Tries, in order: the raw text, a fenced code block, and the first balanced
    {...} or [...] span.
    """
    candidates: list[str] = [text.strip()]

    m = _FENCE.search(text)
    if m:
        candidates.append(m.group(1).strip())

    stripped = _PREAMBLE.sub("", text, count=1).strip()
    if stripped:
        candidates.append(stripped)
        balanced = _balanced_span(stripped)
        if balanced:
            candidates.append(balanced)

    for c in candidates:
        if c and (c[0] in "{[" ):
            return c
    return None


def _balanced_span(text: str) -> str | None:
    """Return the first balanced {...} or [...] region, ignoring braces in strings."""
    if not text or text[0] not in "{[":
        return None
    opener = text[0]
    closer = "}" if opener == "{" else "]"
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(text):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[: i + 1]
    return None


def repair_json(text: str) -> str:
    """Apply deterministic fixes for the common mechanical failures."""
    out = text.strip()
    m = _FENCE.search(out)
    if m:
        out = m.group(1).strip()
    out = _PREAMBLE.sub("", out, count=1).strip()
    balanced = _balanced_span(out)
    if balanced:
        out = balanced
    out = _TRAILING_COMMA.sub(r"\1", out)
    return out


class SchemaDetector(Detector):
    """Validate that model output is parseable JSON matching an expected shape.

    Parameters
    ----------
    required_keys
        Top-level keys that must be present (for object payloads).
    expect
        ``"object"``, ``"array"``, or None for either.
    attempt_repair
        Try deterministic repair before reporting a parse failure.
    """

    name = "schema"
    stages = (Stage.OUTPUT,)

    def __init__(
        self,
        required_keys: tuple[str, ...] = (),
        expect: str | None = None,
        attempt_repair: bool = True,
    ) -> None:
        if expect not in (None, "object", "array"):
            raise ValueError("expect must be 'object', 'array', or None")
        self.required_keys = required_keys
        self.expect = expect
        self.attempt_repair = attempt_repair
        self._repaired: str | None = None

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        self._repaired = None
        parsed, used_repair = self._parse(text)

        if parsed is None:
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    message="output is not valid JSON and could not be repaired",
                    confidence=1.0,
                )
            ]

        findings: list[Finding] = []
        if used_repair:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.LOW,
                    message="output required repair to parse (fences/preamble/trailing comma)",
                    confidence=1.0,
                    meta={"repaired": True},
                )
            )

        if self.expect == "object" and not isinstance(parsed, dict):
            findings.append(_shape_finding(self.name, "object", parsed))
        elif self.expect == "array" and not isinstance(parsed, list):
            findings.append(_shape_finding(self.name, "array", parsed))

        if self.required_keys and isinstance(parsed, dict):
            missing = [k for k in self.required_keys if k not in parsed]
            if missing:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        message=f"missing required keys: {missing}",
                        confidence=1.0,
                        meta={"missing": missing},
                    )
                )

        return findings

    def redact(self, text: str, findings: list[Finding]) -> str:
        """Return the repaired JSON when repair succeeded, else the original."""
        return self._repaired if self._repaired is not None else text

    def _parse(self, text: str) -> tuple[Any | None, bool]:
        try:
            return json.loads(text), False
        except (json.JSONDecodeError, TypeError):
            pass

        extracted = extract_json(text)
        if extracted:
            try:
                parsed = json.loads(extracted)
                self._repaired = extracted
                return parsed, True
            except json.JSONDecodeError:
                pass

        if self.attempt_repair:
            repaired = repair_json(text)
            try:
                parsed = json.loads(repaired)
                self._repaired = repaired
                return parsed, True
            except json.JSONDecodeError:
                pass

        return None, False


def _shape_finding(name: str, expected: str, parsed: Any) -> Finding:
    return Finding(
        detector=name,
        severity=Severity.HIGH,
        message=f"expected a JSON {expected}, got {type(parsed).__name__}",
        confidence=1.0,
    )
