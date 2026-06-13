"""Tests for email-provider detection (powers the simplified Connect flow)."""
from rphe.providers import detect_provider, suggested_label


def test_gmail():
    p = detect_provider("alice@gmail.com")
    assert p.key == "gmail"
    assert p.imap_host == "imap.gmail.com"
    assert p.oauth == "gmail"
    assert p.app_password_url


def test_outlook_family():
    for addr in ("a@outlook.com", "a@hotmail.com", "a@live.com"):
        p = detect_provider(addr)
        assert p.key == "outlook"
        assert p.imap_host == "outlook.office365.com"
        assert p.oauth == "graph"


def test_icloud_and_yahoo_fastmail():
    assert detect_provider("a@icloud.com").imap_host == "imap.mail.me.com"
    assert detect_provider("a@yahoo.com").imap_host == "imap.mail.yahoo.com"
    assert detect_provider("a@fastmail.com").imap_host == "imap.fastmail.com"


def test_proton_has_bridge_note():
    p = detect_provider("a@proton.me")
    assert p.key == "proton"
    assert "Bridge" in p.note


def test_generic_fallback():
    p = detect_provider("a@my-company.example")
    assert p.key == "generic"
    assert p.imap_host == ""        # unknown -> ask the user
    assert p.oauth == ""


def test_bad_input_does_not_raise():
    assert detect_provider("").key == "generic"
    assert detect_provider("not-an-email").key == "generic"


def test_suggested_label():
    assert suggested_label("you@gmail.com") == "you-gmail"
    assert suggested_label("first.last@fastmail.com") == "first.last-fastmail"
    assert suggested_label("garbage") == "inbox"
