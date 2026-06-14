"""Tests for the breach-signal classifier."""
from datetime import datetime, timezone

from rphe.classifier import classify, classify_many
from rphe.models import Severity, SignalKind


def _now():
    return datetime(2026, 6, 1, tzinfo=timezone.utc)


def test_breach_notice_is_critical():
    sig = classify(
        message_id="1", from_header="Security <noreply@dropbox.com>",
        subject="Your account was involved in a data breach",
        body="We detected your data was exposed in a breach. Reset now.",
        received_at=_now())
    assert sig is not None
    assert sig.kind in (SignalKind.BREACH_NOTICE, SignalKind.DATA_LEAK)
    assert sig.severity == Severity.CRITICAL
    assert sig.service_name == "Dropbox"


def test_suspicious_login_is_high():
    sig = classify(
        message_id="2", from_header="GitHub <noreply@github.com>",
        subject="Suspicious sign-in attempt blocked",
        body="We detected a sign-in attempt from a new location.",
        received_at=_now())
    assert sig is not None
    assert sig.severity == Severity.HIGH
    assert sig.kind == SignalKind.SUSPICIOUS_LOGIN


def test_reset_link_extracted_prefers_sender_domain():
    sig = classify(
        message_id="3", from_header="noreply@github.com",
        subject="Reset your password",
        body="Click https://github.com/password_reset?token=ABC123 to continue. "
             "Or visit https://tracking.example.com/x.",
        received_at=_now())
    assert sig is not None
    assert sig.reset_url.startswith("https://github.com/password_reset")


def test_reset_link_ignores_lookalike_domain():
    # 'github.com.evil.test' contains 'github.com' as a substring but is NOT the
    # sender's registrable domain — the real github.com link must be chosen.
    sig = classify(
        message_id="lk", from_header="noreply@github.com",
        subject="Reset your password",
        body="Bad: https://github.com.evil.test/reset?token=BAD "
             "Good: https://github.com/password_reset?token=GOOD",
        received_at=_now())
    assert sig is not None
    assert sig.reset_url.startswith("https://github.com/password_reset")


def test_marketing_email_ignored():
    sig = classify(
        message_id="4", from_header="Deals <news@store.com>",
        subject="50% off everything this weekend!",
        body="Shop our biggest sale of the year.",
        received_at=_now())
    assert sig is None


def test_unsolicited_mfa_escalates():
    sig = classify(
        message_id="5", from_header="noreply@bank.com",
        subject="Your verification code",
        body="Your one-time code is 123456. If this wasn't you, secure your account.",
        received_at=_now())
    assert sig is not None
    assert sig.severity >= Severity.HIGH


def test_audit_dict_redacts_reset_token():
    sig = classify(
        message_id="6", from_header="noreply@github.com",
        subject="Reset your password",
        body="https://github.com/reset?token=SUPERSECRET",
        received_at=_now())
    d = sig.to_audit_dict()
    assert "SUPERSECRET" not in str(d)
    assert d["reset_url"] == "github.com"  # only host kept


def test_sorting_most_urgent_first():
    msgs = [
        {"message_id": "a", "from": "x@b.com", "subject": "new device login",
         "body": "new device", "received_at": _now()},
        {"message_id": "b", "from": "x@c.com", "subject": "data breach",
         "body": "your data was exposed in a breach", "received_at": _now()},
    ]
    sigs = classify_many(msgs)
    assert sigs[0].severity == Severity.CRITICAL
