"""Assisted-reset must not type the new password into a redirected page.

A vetted reset link can still 302 / open-redirect to an attacker host before the
password fields are filled. `_same_registrable_site` is the gate that prevents
the new password being handed to whatever page finally loaded.
"""
from rphe.reset.orchestrator import _same_registrable_site


def test_same_site_true_for_matching_registrable_domain():
    assert _same_registrable_site(
        "https://account.netflix.com/reset?t=1",
        "https://www.netflix.com/password/new",
    )


def test_same_site_false_on_redirect_to_other_domain():
    # The classic harm: link looked fine, then redirected to a look-alike.
    assert not _same_registrable_site(
        "https://account.netflix.com/reset?t=1",
        "https://netflix.com.evil-login.ru/steal",
    )


def test_same_site_false_when_either_url_has_no_host():
    assert not _same_registrable_site("https://example.com/x", "about:blank")
    assert not _same_registrable_site("", "https://example.com/x")
