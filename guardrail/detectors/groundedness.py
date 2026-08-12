"""Groundedness — is the answer actually supported by the context?

The output-side counterpart to injection detection. In a RAG system the failure
mode isn't usually a jailbreak, it's the model confidently asserting something
the retrieved documents never said.

This detector flags **unsupported specifics**: numbers, dates, percentages,
currency amounts, proper nouns and quoted strings that appear in the answer but
nowhere in the provided context. Those are where hallucination does damage — a
plausible-sounding sentence is survivable, a wrong figure quoted to a customer
is not.

Deliberately narrow: it does not attempt semantic entailment (that needs a model
call and belongs in an eval harness, not a synchronous gateway). It catches the
concrete, checkable claims — cheaply, deterministically, and with no network.
"""

from __future__ import annotations

import re

from guardrail.detectors.base import Detector
from guardrail.types import Finding, Severity, Stage

_NUMBER = re.compile(r"\b\d[\d,]*\.?\d*\s*(?:%|percent|ms|s|kb|mb|gb|tb|k|m|bn)?\b", re.IGNORECASE)
_CURRENCY = re.compile(r"[$£€R]\s?\d[\d,]*\.?\d*\b")
_QUOTED = re.compile(r'"([^"]{4,80})"')
_PROPER = re.compile(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})*\b")

#: Sentence-initial capitals and common words are not evidence of a proper noun.
_COMMON = frozenset(
    "The This That These Those There Here When Where What Which While Although "
    "However Therefore Because Since After Before During Their They Then Thus "
    "Note Yes No If And But For With From Into Over Under Also Only Some Most "
    "Based According Given Using".split()
)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9%.]+", " ", text.lower())


def _digits(token: str) -> str:
    """Digit signature of a numeric token: '$1,200' and '1200' both -> '1200'."""
    return re.sub(r"[^\d.]", "", token).rstrip(".")


def _source_numbers(source: str) -> set[str]:
    """Every numeric value present in the source, as digit signatures.

    Built as a set of extracted tokens rather than substring-searching the raw
    text: thousands separators, currency symbols and unit suffixes all differ
    between how a source states a figure and how an answer restates it, and
    naive substring matching produced false positives on exactly those.
    """
    out: set[str] = set()
    for token in _NUMBER.findall(source) + _CURRENCY.findall(source):
        d = _digits(token)
        if d:
            out.add(d)
            # A figure written "45ms" should also satisfy a claim of "45".
            out.add(d.rstrip("0").rstrip(".") if "." in d else d)
    return out


def _has_unit(token: str) -> bool:
    """True when a numeric token carries a unit or symbol (45ms, 92%, $1,200).

    Bare small integers ('3 steps') are not factual claims worth flagging;
    the same digit with a unit almost always is.
    """
    return bool(re.search(r"[a-zA-Z%$£€]", token))


class GroundednessDetector(Detector):
    """Flag specific claims in the output that are absent from the context.

    Requires ``context={"source": "<the retrieved context>"}``. With no source
    it returns nothing rather than guessing — a groundedness check without
    ground truth is theatre.

    Parameters
    ----------
    check_numbers, check_currency, check_quotes, check_proper_nouns
        Toggle each claim family. Proper nouns are off by default: they produce
        the most false positives, since models legitimately rephrase names.
    """

    name = "groundedness"
    stages = (Stage.OUTPUT,)

    def __init__(
        self,
        check_numbers: bool = True,
        check_currency: bool = True,
        check_quotes: bool = True,
        check_proper_nouns: bool = False,
    ) -> None:
        self.check_numbers = check_numbers
        self.check_currency = check_currency
        self.check_quotes = check_quotes
        self.check_proper_nouns = check_proper_nouns

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        source = (context or {}).get("source")
        if not source:
            return []

        haystack = _norm(source)
        known_numbers = _source_numbers(source)
        findings: list[Finding] = []

        def flag(kind: str, m: re.Match, severity: Severity, conf: float) -> None:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=severity,
                    message=f"unsupported {kind} not found in context",
                    span=(m.start(), m.end()),
                    matched=m.group(0),
                    confidence=conf,
                    meta={"kind": kind},
                )
            )

        currency_spans: list[tuple[int, int]] = []

        if self.check_currency:
            for m in _CURRENCY.finditer(text):
                currency_spans.append((m.start(), m.end()))
                digits = _digits(m.group(0))
                if digits and digits not in known_numbers:
                    flag("currency amount", m, Severity.HIGH, 0.85)

        if self.check_numbers:
            for m in _NUMBER.finditer(text):
                token = m.group(0).strip()
                digits = _digits(token)
                if not digits:
                    continue
                # Skip the digits inside a currency amount already checked above.
                if any(m.start() >= s and m.end() <= e for s, e in currency_spans):
                    continue
                # A bare single-digit integer ("3 steps") is not a claim; the
                # same digit with a unit ("7ms") is.
                if digits.isdigit() and len(digits) <= 1 and not _has_unit(token):
                    continue
                if digits not in known_numbers:
                    flag("figure", m, Severity.HIGH, 0.8)

        if self.check_quotes:
            for m in _QUOTED.finditer(text):
                inner = _norm(m.group(1))
                if inner and inner not in haystack:
                    flag("quotation", m, Severity.HIGH, 0.9)

        if self.check_proper_nouns:
            for m in _PROPER.finditer(text):
                name = m.group(0)
                if name.split()[0] in _COMMON:
                    continue
                if _norm(name) not in haystack:
                    flag("named entity", m, Severity.MEDIUM, 0.6)

        return findings
