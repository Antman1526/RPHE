"""Assisted-reset must not type the new password into a redirected page.

A vetted reset link can still 302 / open-redirect to an attacker host before the
password fields are filled. `_same_registrable_site` is the gate that prevents
the new password being handed to whatever page finally loaded.
"""
from rphe.reset.orchestrator import _autofill_target_ok, _same_registrable_site


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


# --- _autofill_target_ok: domain AND https must both hold -------------------

def test_autofill_ok_on_same_https_site():
    ok, reason = _autofill_target_ok(
        "https://account.netflix.com/reset?t=1",
        "https://www.netflix.com/password/new",
    )
    assert ok and reason == ""


def test_autofill_refused_on_cross_domain_redirect():
    ok, reason = _autofill_target_ok(
        "https://account.netflix.com/reset?t=1",
        "https://netflix.com.evil-login.ru/steal",
    )
    assert not ok
    assert "redirected" in reason


def test_autofill_refused_on_https_to_http_downgrade():
    # Same registrable domain, but the page downgraded to plaintext http:// —
    # the new password must NOT be typed into an SSL-stripped page.
    ok, reason = _autofill_target_ok(
        "https://account.netflix.com/reset?t=1",
        "http://www.netflix.com/password/new",
    )
    assert not ok
    assert "insecure" in reason and "http" in reason
