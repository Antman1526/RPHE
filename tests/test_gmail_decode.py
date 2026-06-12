"""Offline tests for the Gmail-specific MIME decoding (no network, no token).

The trickiest Gmail code is walking the `format=full` payload tree and decoding
base64url parts. We build a synthetic payload exactly like the Gmail API returns
and assert reconstruction — this validates the parser without any OAuth.
"""
import base64

from rphe.config import EmailAccount
from rphe.scanners.gmail_scanner import GmailScanner


class _FakeStore:
    """Stand-in SecretStore; the decode path never touches it."""
    def require(self, *a, **k):  # pragma: no cover - not hit by decode tests
        raise AssertionError("decode path must not read secrets")


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode()


def _scanner() -> GmailScanner:
    acct = EmailAccount(label="t", provider="gmail", address="me@gmail.com")
    return GmailScanner(acct, _FakeStore())


def test_decode_plain_text_part():
    payload = {"mimeType": "text/plain", "body": {"data": _b64url("hello breach")}}
    assert _scanner()._decode_body(payload) == "hello breach"


def test_decode_prefers_plain_over_html_in_multipart():
    payload = {
        "mimeType": "multipart/alternative",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": _b64url("PLAIN reset link")}},
            {"mimeType": "text/html",
             "body": {"data": _b64url("<p>HTML <a href='https://x/y'>reset</a></p>")}},
        ],
    }
    body = _scanner()._decode_body(payload)
    assert "PLAIN reset link" in body
    assert "<p>" not in body  # html branch not used when plain exists


def test_decode_falls_back_to_html_when_no_plain():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {"mimeType": "text/html",
             "body": {"data": _b64url(
                 "<div>Suspicious sign-in "
                 "<a href='https://github.com/settings/security'>review</a></div>")}},
        ],
    }
    body = _scanner()._decode_body(payload)
    assert "Suspicious sign-in" in body
    # html_to_text surfaces href targets so the URL extractor can find them
    assert "github.com/settings/security" in body


def test_decode_nested_multipart():
    inner = {
        "mimeType": "multipart/alternative",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": _b64url("deep plain body")}},
        ],
    }
    payload = {"mimeType": "multipart/mixed", "parts": [inner]}
    assert "deep plain body" in _scanner()._decode_body(payload)
