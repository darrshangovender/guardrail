<div align="center">

# guardrail — a safety gateway for LLM inputs and outputs

[![tests](https://github.com/darrshangovender/guardrail/actions/workflows/tests.yml/badge.svg)](https://github.com/darrshangovender/guardrail/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-none-22c55e)](pyproject.toml)
[![Status](https://img.shields.io/badge/Status-Working%20code-blue)](#)

</div>

---

> Inspect what goes **into** your model and what comes **out** of it.
> Prompt-injection detection, PII redaction, groundedness checking against
> retrieved context, and structured-output repair — behind one `Guard`, with a
> policy layer that decides allow / redact / flag / block.

**Why this exists.** Most LLM features ship with no input validation and no
output validation. The prompt goes straight to the provider and the response
goes straight to the user. That's fine until someone pastes a card number into
the chat box, or the model quotes a figure the retrieved documents never
contained.

> Sibling to [`sql-guardrails`](https://github.com/darrshangovender/sql-guardrails),
> which does the same job for one narrow surface — LLM-generated SQL. This is
> the general case.

---

## The numbers

Reproducible, fully offline (`python benchmarks/run.py` — no API keys, no model downloads):

| detector | detection rate | **false positives** | precision | F1 |
|---|---:|---:|---:|---:|
| injection | 100.0% | **0.0%** | 100.0% | 1.00 |
| pii | 100.0% | **0.0%** | 100.0% | 1.00 |
| groundedness | 80.0% | **0.0%** | 100.0% | 0.89 |

*25 injection attacks vs 25 benign prompts · 7 PII positives vs 6 negatives · 5 hallucinated answers vs 5 grounded.*

**Read the false-positive column first.** Detection rate on its own is a
meaningless number — flag everything and score 100%. What decides whether a
guard survives contact with production is how often it blocks real users,
because a noisy guard gets switched off within a week.

The benign corpus is deliberately adversarial in the other direction: it
contains near-miss phrasing like *"please ignore the typo in my last message"*
and *"the instructions in the manual say to restart first"* that naive keyword
matching gets wrong.

`results.json` records every miss and false alarm by name, so the numbers can be
audited rather than trusted.

---

## Quick start

```bash
pip install -e ".[dev]"      # zero runtime dependencies
python benchmarks/run.py
```

```python
from guardrail import Guard, BALANCED
from guardrail.detectors import InjectionDetector, PIIDetector, GroundednessDetector

guard = Guard(
    [InjectionDetector(), PIIDetector(), GroundednessDetector()],
    policy=BALANCED,
)

# 1. Guard the input.
inbound = guard.check_input(user_prompt)
if not inbound.allowed:
    return refuse(inbound.summary())

# 2. Call the model with the (possibly redacted) text.
answer = model(inbound.text)

# 3. Guard the output against the context it was supposed to use.
outbound = guard.check_output(answer, source=retrieved_context)
return outbound.text if outbound.allowed else fallback()
```

Detectors declare which stage they apply to, so one `Guard` serves both sides
without misapplying an output-only check to an input.

---

## The four detectors

| Detector | Stage | Catches | Can repair? |
|---|---|---|---|
| `InjectionDetector` | input | Instruction override, role hijack, exfiltration probes, delimiter injection, invisible characters | No — you block, not sanitise |
| `PIIDetector` | both | Email, phone, cards (Luhn), SA ID (checksum), IPs, AWS keys, private keys, JWTs, API tokens | **Yes** — span-accurate redaction |
| `GroundednessDetector` | output | Figures, currency amounts and quotations in the answer that are absent from the context | No — flag or block |
| `SchemaDetector` | output | Non-JSON output, missing keys, wrong shape | **Yes** — strips fences, preambles, trailing commas |

### Validation, not just matching

A regex that flags every 16-digit number produces so many false positives that
teams switch the check off — which is worse than having no check. So:

- **Card numbers are Luhn-validated.** `4532015112830366` is flagged; `...367` is not.
- **SA ID numbers are checksum- and date-validated.**
- **Phone numbers must be E.164-plausible.** A bare 16-digit reference number and a dotted quad like `999.999.999.999` are rejected — those two false positives are exactly what dropped the PII false-positive rate from 33% to 0%.
- **IP octets are range-checked.**

---

## Policy: detection and decision are separate

The same PII detector should **block** in a healthcare deployment and merely
**redact** in an internal tool. Forking the detector to express that would be a
maintenance disaster, so detectors only report findings and policies decide.

```python
from guardrail import Policy, Action, Severity, BALANCED, STRICT, AUDIT

BALANCED   # redact PII, block other HIGH findings — good default
STRICT     # block anything MEDIUM or above — regulated surfaces
AUDIT      # never block, record everything — measure before you enforce

Policy(
    block_at=Severity.HIGH,
    overrides={"pii": Action.REDACT},
    min_confidence=0.7,        # the knob for a noisy detector
)
```

**Start with `AUDIT`.** Run it against real traffic for a week, read the
false-positive rate on *your* users, then tighten. Shipping a blocking policy
you haven't measured is how you get an incident on day one.

Four outcomes, not two — binary allow/deny either leaks data or breaks the
product:

`ALLOW` → `FLAG` (proceed, record) → `REDACT` (modify, proceed) → `BLOCK` (refuse)

Most restrictive wins when detectors disagree.

---

## What this does *not* do

Being straight about the limits, because a security tool that oversells itself
is worse than none:

- **Pattern-based injection detection does not stop a determined adversary.** It stops the large volume of low-effort and copy-pasted attacks, and injected content arriving through RAG documents and tool output — which is where injection actually bites. Treat it as defence in depth, never as the only control.
- **Groundedness here is not semantic entailment.** It checks concrete, checkable claims — figures, amounts, quotations. A fluent but wrong *sentence* with no specifics passes. Full entailment needs a model call and belongs in an eval harness, not a synchronous gateway.
- **The corpus is hand-written, not a public benchmark.** 100% on 25 attacks is not 100% in the wild. Swap in your own traffic before trusting the numbers.
- **No semantic PII detection.** A name in free text is not caught; structured identifiers are.

---

## Design decisions

| Decision | Why |
|---|---|
| **Detectors never decide** | The same finding warrants different actions in different deployments. Separating them means one detector, many policies. |
| **Four actions, not two** | Binary allow/deny forces you to either leak PII or break the product. `REDACT` is what most real cases need. |
| **Deterministic repair, never a model call** | Fixing a markdown fence doesn't need intelligence, and a retry costs latency and money. |
| **Checksums over pattern length** | Luhn and date validation are what keep the false-positive rate low enough that the guard stays switched on. |
| **A `REDACT` that changes nothing becomes a `FLAG`** | Reporting a redaction that didn't happen overstates what the guard did. |
| **Zero runtime dependencies** | Installs and runs anywhere, including offline CI. |

---

## Project layout

```
guardrail/
├── types.py              # Severity · Action · Stage · Finding · GuardResult
├── policy.py             # decision layer + BALANCED / STRICT / AUDIT presets
├── guard.py              # the orchestrator
└── detectors/
    ├── injection.py      # override · role hijack · exfiltration · invisible chars
    ├── pii.py            # Luhn + SA-ID checksums, span-accurate redaction
    ├── groundedness.py   # unsupported figures, amounts, quotations
    └── schema.py         # JSON validation + deterministic repair
benchmarks/               # adversarial corpus + detection/FP-rate benchmark
tests/                    # 96 tests, all offline
```

## Tests

```bash
pytest tests/ -q       # 96 tests, no API keys, no network
python benchmarks/run.py
```

CI runs both on every push.

## Author

Darrshan Govender · [Agulhas Code](https://agulhascode.co.za) · Durban, South Africa
