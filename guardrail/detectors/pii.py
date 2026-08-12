"""PII detection and redaction.

Two directions matter and they are not symmetric:

- **Input**: users paste PII into prompts. You may need to strip it before it
  reaches a third-party model (data-residency, DPA, or plain prudence).
- **Output**: the model regurgitates PII from its context or training data.
  This is the one that becomes an incident report.

Validation, not just matching. A regex that flags every 16-digit number produces
so many false positives that teams switch the check off — which is worse than
having no check. Card numbers are Luhn-validated and South African ID numbers
are checksum-validated, so what gets reported is worth acting on.
"""

from __future__ import annotations

import re

from guardrail.detectors.base import Detector
from guardrail.types import Finding, Severity, Stage

_EMAIL = re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
# E.164-ish and common SA formats; deliberately not trying to match every locale.
_PHONE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SA_ID = re.compile(r"\b(\d{6})(\d{4})(\d)(\d)(\d)\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
_JWT = re.compile(r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+\b")
_BEARER = re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b")


def luhn_valid(digits: str) -> bool:
    """Luhn checksum — filters the vast majority of false-positive card matches."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def sa_id_valid(digits: str) -> bool:
    """South African ID number checksum (Luhn over 13 digits) plus date sanity."""
    if len(digits) != 13 or not digits.isdigit():
        return False
    month, day = int(digits[2:4]), int(digits[4:6])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return luhn_valid(digits)


class PIIDetector(Detector):
    """Detect and redact personal and secret data.

    Parameters
    ----------
    categories
        Which categories to check. Default is everything.
    redact_token
        Template for the replacement; ``{kind}`` is substituted.
    """

    name = "pii"
    stages = (Stage.INPUT, Stage.OUTPUT)

    ALL_CATEGORIES = (
        "email", "phone", "card", "sa_id", "ip", "aws_key", "private_key", "jwt", "api_token",
    )

    def __init__(
        self,
        categories: tuple[str, ...] | None = None,
        redact_token: str = "[REDACTED:{kind}]",
    ) -> None:
        unknown = set(categories or ()) - set(self.ALL_CATEGORIES)
        if unknown:
            raise ValueError(f"unknown PII categories: {sorted(unknown)}")
        self.categories = categories or self.ALL_CATEGORIES
        self.redact_token = redact_token

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        out: list[Finding] = []

        def add(kind: str, m: re.Match, severity: Severity, conf: float = 1.0) -> None:
            out.append(
                Finding(
                    detector=self.name,
                    severity=severity,
                    message=f"{kind} detected",
                    span=(m.start(), m.end()),
                    matched=m.group(0),
                    confidence=conf,
                    meta={"kind": kind},
                )
            )

        if "email" in self.categories:
            for m in _EMAIL.finditer(text):
                add("email", m, Severity.MEDIUM)

        if "card" in self.categories:
            for m in _CARD.finditer(text):
                if luhn_valid(m.group(0)):
                    add("card", m, Severity.CRITICAL)

        if "sa_id" in self.categories:
            for m in _SA_ID.finditer(text):
                if sa_id_valid(m.group(0)):
                    add("sa_id", m, Severity.CRITICAL)

        if "private_key" in self.categories:
            for m in _PRIVATE_KEY.finditer(text):
                add("private_key", m, Severity.CRITICAL)

        if "aws_key" in self.categories:
            for m in _AWS_KEY.finditer(text):
                add("aws_key", m, Severity.CRITICAL)

        if "api_token" in self.categories:
            for m in _BEARER.finditer(text):
                add("api_token", m, Severity.CRITICAL)

        if "jwt" in self.categories:
            for m in _JWT.finditer(text):
                add("jwt", m, Severity.HIGH)

        if "ip" in self.categories:
            for m in _IPV4.finditer(text):
                if all(0 <= int(o) <= 255 for o in m.group(0).split(".")):
                    add("ip", m, Severity.LOW, conf=0.6)

        if "phone" in self.categories:
            claimed = _spans(out)
            for m in _PHONE.finditer(text):
                if _looks_like_phone(m.group(0)) and not _overlaps((m.start(), m.end()), claimed):
                    add("phone", m, Severity.MEDIUM, conf=0.75)

        return out

    def redact(self, text: str, findings: list[Finding]) -> str:
        """Replace matched spans with redaction tokens, right-to-left so earlier
        spans keep their offsets."""
        mine = [f for f in findings if f.detector == self.name and f.span]
        for f in sorted(mine, key=lambda f: f.span[0], reverse=True):
            start, end = f.span
            token = self.redact_token.format(kind=f.meta.get("kind", "pii"))
            text = text[:start] + token + text[end:]
        return text


_DOTTED_QUAD = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_phone(token: str) -> bool:
    """Reject long digit runs and version/IP-shaped strings.

    A bare 16-digit reference number and a dotted quad like 999.999.999.999
    both satisfy a naive '9+ digits' rule. Flagging those as phone numbers is
    the kind of noise that gets a PII check switched off in production, so the
    rule is tightened to E.164-plausible shapes.
    """
    stripped = token.strip()
    if _DOTTED_QUAD.match(stripped):
        return False
    digits = sum(c.isdigit() for c in stripped)
    # E.164 allows at most 15 digits; below 9 is not a dialable number.
    if not 9 <= digits <= 15:
        return False
    # A run of 13+ bare digits with no separators is far more likely an
    # account/reference number than a phone number.
    if digits >= 13 and stripped.isdigit():
        return False
    return True


def _spans(findings: list[Finding]) -> list[tuple[int, int]]:
    return [f.span for f in findings if f.span]


def _overlaps(span: tuple[int, int], others: list[tuple[int, int]]) -> bool:
    s, e = span
    return any(not (e <= o_s or s >= o_e) for o_s, o_e in others)
