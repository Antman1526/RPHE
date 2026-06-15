from rphe.risk import Tier, AccountRisk


def test_tier_is_ordered_critical_highest():
    assert Tier.CRITICAL > Tier.HIGH > Tier.MEDIUM > Tier.LOW
    assert max(Tier.LOW, Tier.CRITICAL, Tier.MEDIUM) is Tier.CRITICAL


def test_account_risk_defaults():
    r = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH)
    assert r.reasons == [] and r.sources == set()
    assert r.managed is False and r.password_fingerprint is None
    assert r.reset_url_trusted is False and r.reset_host is None
