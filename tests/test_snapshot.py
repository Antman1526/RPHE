# tests/test_snapshot.py
from rphe.risk import AccountRisk, Tier
from rphe.snapshot import RiskSnapshot, snapshot_to_dict, snapshot_from_dict


def _snap():
    row = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH,
                      reasons=["reused on 3 sites"], sources={"vault"},
                      vault_item_id="id1", password_fingerprint="aaaa1111",
                      managed=True, reset_url_trusted=True, reset_host="github.com")
    return RiskSnapshot(generated_at="2026-06-14T20:00:00Z",
                        sources={"vault": {"ok": True}}, accounts=[row])


def test_roundtrip_preserves_fields():
    d = snapshot_to_dict(_snap())
    back = snapshot_from_dict(d)
    r = back.accounts[0]
    assert r.tier is Tier.HIGH and r.password_fingerprint == "aaaa1111"
    assert r.sources == {"vault"} and r.managed is True


def test_serialized_dict_has_fingerprint_but_no_secret_keys():
    d = snapshot_to_dict(_snap())
    blob = str(d)
    assert "aaaa1111" in blob                    # fingerprint kept
    assert "password" not in d["accounts"][0]    # no plaintext field name
    assert "reset_url" not in d["accounts"][0]   # only reset_host is kept
    assert d["accounts"][0]["reset_host"] == "github.com"
