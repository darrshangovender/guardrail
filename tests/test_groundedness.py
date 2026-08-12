from guardrail.detectors import GroundednessDetector
from guardrail.types import Stage

DET = GroundednessDetector()

SOURCE = (
    "During the postgres performance review the team examined the index path. "
    "The p99 query latency fell to 45ms after the index rebuild. "
    "The change was deployed on the 14th and cost $1,200 in engineering time."
)


def test_no_source_yields_nothing():
    """A groundedness check without ground truth is theatre — return nothing."""
    assert DET.detect("The latency is 99ms.") == []
    assert DET.detect("The latency is 99ms.", {}) == []


def test_supported_figure_passes():
    out = DET.detect("Latency fell to 45ms.", {"source": SOURCE})
    assert out == []


def test_unsupported_figure_flagged():
    out = DET.detect("Latency fell to 12ms.", {"source": SOURCE})
    assert any(f.meta["kind"] == "figure" for f in out)


def test_supported_currency_passes():
    out = DET.detect("It cost $1,200.", {"source": SOURCE})
    assert not any(f.meta["kind"] == "currency amount" for f in out)


def test_unsupported_currency_flagged():
    out = DET.detect("It cost $9,999.", {"source": SOURCE})
    assert any(f.meta["kind"] == "currency amount" for f in out)


def test_fabricated_quotation_flagged():
    out = DET.detect('The report said "we will double capacity".', {"source": SOURCE})
    assert any(f.meta["kind"] == "quotation" for f in out)


def test_genuine_quotation_passes():
    out = DET.detect('It noted "the index rebuild".', {"source": SOURCE})
    assert not any(f.meta["kind"] == "quotation" for f in out)


def test_small_integers_are_not_claims():
    """'3 steps' is not a factual claim worth flagging."""
    out = DET.detect("There are 3 steps.", {"source": SOURCE})
    assert not any(f.meta["kind"] == "figure" for f in out)


def test_proper_nouns_off_by_default():
    out = DET.detect("Acme Corporation reported growth.", {"source": SOURCE})
    assert not any(f.meta["kind"] == "named entity" for f in out)


def test_proper_nouns_when_enabled():
    det = GroundednessDetector(check_proper_nouns=True)
    out = det.detect("Acme Corporation reported growth.", {"source": SOURCE})
    assert any(f.meta["kind"] == "named entity" for f in out)


def test_sentence_initial_common_words_not_flagged_as_entities():
    det = GroundednessDetector(check_proper_nouns=True)
    out = det.detect("However the result held.", {"source": SOURCE})
    assert not any(f.matched == "However" for f in out)


def test_is_output_stage_only():
    assert DET.supports(Stage.OUTPUT)
    assert not DET.supports(Stage.INPUT)
