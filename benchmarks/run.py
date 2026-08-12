"""Reproducible benchmark: detection rate vs false-positive rate.

Detection rate alone is a useless number — flag everything and score 100%. What
decides whether a guard survives contact with production is the false-positive
rate on benign traffic, because a guard that blocks real users gets switched off
within a week.

Both numbers are reported for every detector, plus precision.

Run:
    python benchmarks/run.py

Fully offline, no API keys. Writes results.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardrail.detectors import GroundednessDetector, InjectionDetector, PIIDetector

from benchmarks.corpus import (
    BENIGN_PROMPTS,
    GROUNDED_ANSWERS,
    GROUNDEDNESS_SOURCE,
    HALLUCINATED_ANSWERS,
    INJECTION_ATTACKS,
    PII_NEGATIVE,
    PII_POSITIVE,
)


def _rates(tp: int, fn: int, fp: int, tn: int) -> dict:
    detection = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * detection / (precision + detection)) if (precision + detection) else 0.0
    return {
        "detection_rate": round(detection, 4),
        "false_positive_rate": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def bench_injection() -> dict:
    det = InjectionDetector()
    tp = sum(1 for t in INJECTION_ATTACKS if det.detect(t))
    fn = len(INJECTION_ATTACKS) - tp
    fp = sum(1 for t in BENIGN_PROMPTS if det.detect(t))
    tn = len(BENIGN_PROMPTS) - fp
    return _rates(tp, fn, fp, tn)


def bench_pii() -> dict:
    det = PIIDetector()
    tp = sum(1 for text, kind in PII_POSITIVE if any(f.meta["kind"] == kind for f in det.detect(text)))
    fn = len(PII_POSITIVE) - tp
    fp = sum(1 for t in PII_NEGATIVE if det.detect(t))
    tn = len(PII_NEGATIVE) - fp
    return _rates(tp, fn, fp, tn)


def bench_groundedness() -> dict:
    det = GroundednessDetector()
    ctx = {"source": GROUNDEDNESS_SOURCE}
    tp = sum(1 for a in HALLUCINATED_ANSWERS if det.detect(a, ctx))
    fn = len(HALLUCINATED_ANSWERS) - tp
    fp = sum(1 for a in GROUNDED_ANSWERS if det.detect(a, ctx))
    tn = len(GROUNDED_ANSWERS) - fp
    return _rates(tp, fn, fp, tn)


def main() -> int:
    results = {
        "injection": bench_injection(),
        "pii": bench_pii(),
        "groundedness": bench_groundedness(),
    }

    print("\n=== guardrail benchmark ===")
    print(
        f"{len(INJECTION_ATTACKS)} injection attacks vs {len(BENIGN_PROMPTS)} benign prompts · "
        f"{len(PII_POSITIVE)} PII positives vs {len(PII_NEGATIVE)} negatives · "
        f"{len(HALLUCINATED_ANSWERS)} hallucinations vs {len(GROUNDED_ANSWERS)} grounded\n"
    )
    print(f"{'detector':16} {'detection':>10} {'false pos':>11} {'precision':>10} {'f1':>7}")
    print("-" * 58)
    for name, r in results.items():
        print(
            f"{name:16} {r['detection_rate']:>9.1%} {r['false_positive_rate']:>10.1%} "
            f"{r['precision']:>9.1%} {r['f1']:>7.2f}"
        )

    print("\nMisses and false alarms are listed in results.json for inspection.")

    # Record the actual failures so the numbers can be audited, not just trusted.
    det = InjectionDetector()
    results["injection"]["missed"] = [t for t in INJECTION_ATTACKS if not det.detect(t)]
    results["injection"]["false_alarms"] = [t for t in BENIGN_PROMPTS if det.detect(t)]

    out = Path(__file__).parent / "results.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
