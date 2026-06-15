from rphe.models import BreachSignal, Severity, SignalKind
from rphe.risk import Tier, AccountRisk


def test_tier_is_ordered_critical_highest():
    assert Tier.CRITICAL > Tier.HIGH > Tier.MEDIUM > Tier.LOW
    assert max(Tier.LOW, Tier.CRITICAL, Tier.MEDIUM) is Tier.CRITICAL


def test_account_risk_defaults():
    r = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH)
    assert r.reasons == [] and r.sources == set()
    assert r.managed is False and r.password_fingerprint is None
    assert r.reset_url_trusted is False and r.reset_host is None


from rphe.risk import build_risk_model


def _login(name, user, url, fp, pwned=0, reuse=1, bits=80.0, item="id1"):
    return {"name": name, "username": user, "url": url, "item_id": item,
            "fingerprint": fp, "pwned_count": pwned, "reuse_count": reuse,
            "weak_bits": bits}


def test_clean_login_is_low_and_managed():
    rows = build_risk_model([], [_login("GitHub", "me@x.com", "https://github.com", "aaaa1111")], [])
    assert len(rows) == 1
    r = rows[0]
    assert r.domain == "github.com" and r.username == "me@x.com"
    assert r.tier is Tier.LOW and r.managed is True
    assert r.vault_item_id == "id1" and r.password_fingerprint == "aaaa1111"
    assert "vault" in r.sources


def test_pwned_password_is_critical():
    rows = build_risk_model([], [_login("Dropbox", "me@x.com", "https://dropbox.com", "bbbb", pwned=3)], [])
    assert rows[0].tier is Tier.CRITICAL
    assert any("breach corpus" in r for r in rows[0].reasons)


def test_widespread_reuse_is_high_exact_two_is_medium():
    high = build_risk_model([], [_login("A", "me@x.com", "https://a.com", "f", reuse=3)], [])
    med = build_risk_model([], [_login("B", "me@x.com", "https://b.com", "f", reuse=2)], [])
    assert high[0].tier is Tier.HIGH and any("reused" in r for r in high[0].reasons)
    assert med[0].tier is Tier.MEDIUM


def test_weak_password_alone_is_medium():
    rows = build_risk_model([], [_login("C", "me@x.com", "https://c.com", "f", bits=40.0)], [])
    assert rows[0].tier is Tier.MEDIUM
    assert any("weak" in r for r in rows[0].reasons)


from datetime import datetime, timezone


def _sig(service, sender_domain, kind, severity, hint=None, reset_url=None, trusted=True):
    return BreachSignal(
        message_id="m", service_name=service, sender_domain=sender_domain,
        subject="x", received_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        kind=kind, severity=severity, reset_url=reset_url, account_hint=hint,
        reset_url_trusted=trusted)


def test_inbox_only_service_creates_unmanaged_row():
    rows = build_risk_model(
        [_sig("LinkedIn", "linkedin.com", SignalKind.BREACH_NOTICE, Severity.CRITICAL)],
        [], [])
    assert len(rows) == 1
    r = rows[0]
    assert r.domain == "linkedin.com" and r.managed is False
    assert r.tier is Tier.CRITICAL and "inbox" in r.sources


def test_domain_inbox_signal_attaches_to_matching_vault_login():
    rows = build_risk_model(
        [_sig("GitHub", "github.com", SignalKind.SUSPICIOUS_LOGIN, Severity.HIGH)],
        [_login("GitHub", "me@x.com", "https://github.com", "f")], [])
    assert len(rows) == 1                      # merged, not duplicated
    r = rows[0]
    assert r.managed is True and r.tier is Tier.HIGH
    assert {"vault", "inbox"} <= r.sources


def test_trusted_reset_link_recorded_as_host_only():
    rows = build_risk_model(
        [_sig("GitHub", "github.com", SignalKind.PASSWORD_RESET_PROMPT, Severity.MEDIUM,
              reset_url="https://github.com/reset?token=SECRET", trusted=True)],
        [], [])
    r = rows[0]
    assert r.reset_url_trusted is True and r.reset_host == "github.com"
    assert "SECRET" not in str(r.__dict__)     # token never retained
