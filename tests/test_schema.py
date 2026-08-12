import pytest

from guardrail.detectors import SchemaDetector, extract_json, repair_json


def test_extract_from_clean_json():
    assert extract_json('{"a": 1}') == '{"a": 1}'


def test_extract_from_fenced_block():
    text = 'Here you go:\n```json\n{"a": 1}\n```'
    assert extract_json(text) == '{"a": 1}'


def test_extract_from_preamble():
    assert extract_json('Sure! {"a": 1}') == '{"a": 1}'


def test_extract_returns_none_for_prose():
    assert extract_json("no json here at all") is None


def test_repair_strips_trailing_comma():
    assert repair_json('{"a": 1,}') == '{"a": 1}'


def test_balanced_span_ignores_braces_in_strings():
    text = '{"note": "this } is not the end", "a": 1} trailing junk'
    assert repair_json(text).endswith("}")
    import json
    assert json.loads(repair_json(text))["a"] == 1


# --- detector ---------------------------------------------------------------

def test_valid_json_is_clean():
    assert SchemaDetector().detect('{"a": 1}') == []


def test_fenced_output_is_repaired_and_flagged_low():
    det = SchemaDetector()
    findings = det.detect('```json\n{"a": 1}\n```')
    assert len(findings) == 1
    assert findings[0].meta.get("repaired") is True
    assert det.redact('```json\n{"a": 1}\n```', findings) == '{"a": 1}'


def test_unparseable_is_high_severity():
    from guardrail.types import Severity

    findings = SchemaDetector().detect("this is just prose, no json")
    assert findings[0].severity is Severity.HIGH


def test_missing_required_keys_reported():
    det = SchemaDetector(required_keys=("name", "email"))
    findings = det.detect('{"name": "Darrshan"}')
    missing = [f for f in findings if "missing" in f.meta]
    assert missing and missing[0].meta["missing"] == ["email"]


def test_required_keys_satisfied():
    det = SchemaDetector(required_keys=("name",))
    assert det.detect('{"name": "Darrshan"}') == []


def test_expect_object_rejects_array():
    findings = SchemaDetector(expect="object").detect("[1, 2, 3]")
    assert any("expected a JSON object" in f.message for f in findings)


def test_expect_array_accepts_array():
    assert SchemaDetector(expect="array").detect("[1, 2, 3]") == []


def test_rejects_bad_expect_value():
    with pytest.raises(ValueError):
        SchemaDetector(expect="dictionary")


def test_repair_can_be_disabled():
    det = SchemaDetector(attempt_repair=False)
    findings = det.detect('{"a": 1,}')
    # Extraction still finds the span, but the trailing-comma fix is off, so it
    # cannot parse.
    assert any(f.severity.value == "high" for f in findings)


def test_redact_returns_original_when_no_repair_needed():
    det = SchemaDetector()
    text = '{"a": 1}'
    assert det.redact(text, det.detect(text)) == text
