"""Tests for HIBP breach checking — fully offline via an injected fetch."""
import hashlib

import pytest

from rphe.breach import BreachChecker


def _sha1_upper(s: str) -> str:
    return hashlib.sha1(s.encode(), usedforsecurity=False).hexdigest().upper()


def test_pwned_password_detected_and_only_prefix_sent():
    password = "password123"
    digest = _sha1_upper(password)
    prefix, suffix = digest[:5], digest[5:]
    sent_urls = []

    def fake_fetch(url, headers):
        sent_urls.append(url)
        # The API echoes suffixes (not the full hash) with counts.
        body = f"{suffix}:4200\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"
        return 200, body

    checker = BreachChecker(fetch=fake_fetch)
    assert checker.pwned_password_count(password) == 4200
    assert checker.is_pwned(password)
    # Privacy guarantee: only the 5-char prefix is ever in the URL.
    assert prefix in sent_urls[0]
    assert suffix not in sent_urls[0]
    assert password not in sent_urls[0]


def test_safe_password_returns_zero():
    def fake_fetch(url, headers):
        return 200, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9"
    assert BreachChecker(fetch=fake_fetch).pwned_password_count("anything") == 0


def test_account_breaches_requires_key():
    checker = BreachChecker(api_key=None)
    with pytest.raises(RuntimeError, match="API key"):
        checker.account_breaches("a@b.com")


def test_account_breaches_parses_results():
    def fake_fetch(url, headers):
        assert headers.get("hibp-api-key") == "KEY"
        body = ('[{"Name":"Dropbox","Title":"Dropbox","BreachDate":"2012-07-01",'
                '"DataClasses":["Email addresses","Passwords"]}]')
        return 200, body
    checker = BreachChecker(api_key="KEY", fetch=fake_fetch)
    breaches = checker.account_breaches("a@b.com")
    assert len(breaches) == 1
    assert breaches[0].name == "Dropbox"
    assert "Passwords" in breaches[0].data_classes


def test_account_breaches_404_means_clean():
    def fake_fetch(url, headers):
        return 404, ""
    assert BreachChecker(api_key="KEY", fetch=fake_fetch).account_breaches("x@y.com") == []


def test_urllib_fetch_refuses_non_https():
    from rphe.breach import _urllib_fetch
    for bad in ("http://example.com", "file:///etc/passwd", "ftp://x/y"):
        with pytest.raises(ValueError):
            _urllib_fetch(bad, {})


def test_bad_key_raises():
    def fake_fetch(url, headers):
        return 401, ""
    with pytest.raises(RuntimeError, match="401"):
        BreachChecker(api_key="BAD", fetch=fake_fetch).account_breaches("x@y.com")
