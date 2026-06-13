"""Tests for anti-phishing reset-link assessment + classifier integration."""
from datetime import datetime, timezone

from rphe.classifier import classify
from rphe.linksafety import assess, registrable_domain
from rphe.models import Severity


def test_registrable_domain_simple():
    assert registrable_domain("mail.github.com") == "github.com"
    assert registrable_domain("github.com") == "github.com"


def test_registrable_domain_multi_tld():
    assert registrable_domain("account.mail.example.co.uk") == "example.co.uk"


def test_link_matching_sender_is_trusted():
    a = assess("https://github.com/password_reset?token=x", "github.com")
    assert a.trusted
    assert a.https


def test_link_mismatch_is_untrusted():
    a = assess("https://github-security-reset.com/x", "github.com")
    assert not a.trusted
    assert "does not match" in a.reason


def test_non_https_untrusted():
    a = assess("http://github.com/reset", "github.com")
    assert not a.trusted
    assert "HTTPS" in a.reason


def test_punycode_untrusted():
    a = assess("https://xn--github-x59d.com/reset", "github.com")
    assert not a.trusted
    assert "look-alike" in a.reason or "punycode" in a.reason


def test_known_alt_domain_trusted():
    # Reddit sends from redditmail.com but resets on reddit.com — should be OK.
    a = assess("https://www.reddit.com/resetpassword?token=x", "redditmail.com")
    assert a.trusted


def test_classifier_flags_phishing_link_and_escalates():
    sig = classify(
        message_id="p1", from_header="Security <noreply@paypa1-secure.com>",
        subject="Your account was breached — reset now",
        body="Reset here: https://paypa1-secure.com/login?token=abc",
        received_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert sig is not None
    # sender == link domain here, so it's "trusted" by host-match but the point
    # is a legit-looking breach from a look-alike sender still classifies; ensure
    # a genuine mismatch is caught:
    sig2 = classify(
        message_id="p2", from_header="PayPal <service@paypal.com>",
        subject="Suspicious sign-in — reset your password",
        body="Reset: https://paypal-account-verify.ru/reset?token=abc",
        received_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert sig2 is not None
    assert sig2.reset_url_trusted is False
    assert sig2.severity >= Severity.HIGH
    assert "UNVERIFIED reset link" in sig2.rationale


def test_password_strength_bits():
    from rphe.passwords import password_strength_bits
    assert password_strength_bits("password") < 40        # weak
    assert password_strength_bits("Xk9$mQ2p!vT4nW7z@Lr5") > 110  # strong
    assert password_strength_bits("") == 0.0
