import pytest

from guardrail.detectors import PIIDetector, luhn_valid, sa_id_valid
from guardrail.types import Severity

DET = PIIDetector()


# --- checksum helpers -------------------------------------------------------

def test_luhn_accepts_valid_test_card():
    assert luhn_valid("4532015112830366")


def test_luhn_rejects_invalid():
    assert not luhn_valid("4532015112830367")


def test_luhn_rejects_wrong_length():
    assert not luhn_valid("123")


def test_sa_id_rejects_bad_month():
    assert not sa_id_valid("9913015800085")  # month 13


def test_sa_id_rejects_non_digits():
    assert not sa_id_valid("99010158000AB")


# --- detection --------------------------------------------------------------

def test_detects_email():
    f = DET.detect("Contact me at darrshan@example.com please")
    assert any(x.meta["kind"] == "email" for x in f)


def test_detects_valid_card_only():
    valid = DET.detect("Card 4532015112830366 on file")
    invalid = DET.detect("Reference number 4532015112830367 here")
    assert any(x.meta["kind"] == "card" for x in valid)
    assert not any(x.meta["kind"] == "card" for x in invalid)


def test_card_is_critical():
    f = [x for x in DET.detect("4532015112830366") if x.meta["kind"] == "card"]
    assert f[0].severity is Severity.CRITICAL


def test_detects_aws_key():
    f = DET.detect("key AKIAIOSFODNN7EXAMPLE here")
    assert any(x.meta["kind"] == "aws_key" for x in f)


def test_detects_private_key_header():
    f = DET.detect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert any(x.meta["kind"] == "private_key" for x in f)


def test_detects_api_tokens():
    f = DET.detect("use sk-abcdefghijklmnopqrstuvwxyz123456 for auth")
    assert any(x.meta["kind"] == "api_token" for x in f)


def test_detects_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123def456"
    assert any(x.meta["kind"] == "jwt" for x in DET.detect(jwt))


def test_detects_ipv4_and_rejects_impossible_octets():
    assert any(x.meta["kind"] == "ip" for x in DET.detect("host at 192.168.1.1"))
    assert not any(x.meta["kind"] == "ip" for x in DET.detect("version 999.999.999.999"))


def test_phone_does_not_double_flag_card_digits():
    """A card number's digits must not also be reported as a phone number."""
    findings = DET.detect("Card 4532015112830366 on file")
    kinds = [f.meta["kind"] for f in findings]
    assert kinds.count("phone") == 0


def test_clean_text_yields_nothing():
    assert DET.detect("The weather in Durban is warm today.") == []


def test_category_filter():
    det = PIIDetector(categories=("email",))
    f = det.detect("mail me at a@b.com or call 0821234567")
    assert all(x.meta["kind"] == "email" for x in f)


def test_rejects_unknown_category():
    with pytest.raises(ValueError):
        PIIDetector(categories=("not_a_real_category",))


# --- redaction --------------------------------------------------------------

def test_redaction_replaces_value():
    text = "Email darrshan@example.com now"
    findings = DET.detect(text)
    out = DET.redact(text, findings)
    assert "darrshan@example.com" not in out
    assert "[REDACTED:email]" in out


def test_redaction_handles_multiple_spans_correctly():
    text = "a@b.com and c@d.com and e@f.com"
    findings = DET.detect(text)
    out = DET.redact(text, findings)
    assert "@" not in out
    assert out.count("[REDACTED:email]") == 3


def test_custom_redact_token():
    det = PIIDetector(redact_token="<<{kind}>>")
    text = "mail a@b.com"
    assert "<<email>>" in det.redact(text, det.detect(text))
