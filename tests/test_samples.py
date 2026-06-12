"""The demo sample corpus must classify as intended (regression guard)."""
from rphe.classifier import classify_many
from rphe.models import Severity, SignalKind
from rphe.samples import SAMPLE_MESSAGES


def test_demo_corpus_flags_expected_and_ignores_noise():
    signals = classify_many(SAMPLE_MESSAGES)
    flagged_ids = {s.message_id for s in signals}

    # Marketing + receipts must NOT be flagged.
    assert "demo-marketing-1" not in flagged_ids
    assert "demo-receipt-1" not in flagged_ids

    # Every security sample must be flagged.
    for mid in ("demo-breach-1", "demo-darkweb-1", "demo-login-1",
                "demo-reset-1", "demo-mfa-1", "demo-newdevice-1"):
        assert mid in flagged_ids, f"{mid} should have been flagged"


def test_demo_breach_is_top_severity_and_sorted_first():
    signals = classify_many(SAMPLE_MESSAGES)
    assert signals[0].severity == Severity.CRITICAL  # most urgent first


def test_demo_darkweb_classified_as_leak():
    signals = {s.message_id: s for s in classify_many(SAMPLE_MESSAGES)}
    assert signals["demo-darkweb-1"].kind == SignalKind.DATA_LEAK
