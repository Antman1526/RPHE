"""Engine.audit_vault: weak / reused / breached detection, fully offline."""
import hashlib
from pathlib import Path

from rphe.audit import AuditLog
from rphe.breach import BreachChecker
from rphe.config import Config
from rphe.engine import Engine
from rphe.secrets import SecretStore


def _sha1_suffix(s: str) -> str:
    return hashlib.sha1(s.encode(), usedforsecurity=False).hexdigest().upper()[5:]


class FakeVault:
    def audit_logins(self):
        return [
            {"item_id": "1", "name": "Alpha", "username": "a", "url": None,
             "password": "password"},          # weak + reused + breached
            {"item_id": "2", "name": "Beta", "username": "b", "url": None,
             "password": "password"},          # reused (shares with Alpha)
            {"item_id": "3", "name": "Gamma", "username": "c", "url": None,
             "password": "Xk9$mQ2p!vT4nW7z@Lr5Zb"},  # strong, unique, clean
        ]


def _engine(tmp_path):
    eng = Engine(cfg=Config(), store=SecretStore(), audit=AuditLog(Path(tmp_path)))
    eng._bw = FakeVault()
    # Breach checker that reports "password" as pwned, everything else clean.
    pwned_suffix = _sha1_suffix("password")

    def fake_fetch(url, headers):
        return 200, f"{pwned_suffix}:99999\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1"

    eng.breach_checker = lambda: BreachChecker(fetch=fake_fetch)
    return eng


def test_audit_flags_weak_reused_breached(tmp_path):
    report = _engine(tmp_path).audit_vault()
    assert report["scanned"] == 3
    by_name = {f["name"]: f["issues"] for f in report["findings"]}

    assert "Gamma" not in by_name                      # strong+unique+clean
    assert set(by_name) == {"Alpha", "Beta"}
    for name in ("Alpha", "Beta"):
        joined = " ".join(by_name[name])
        assert "reused" in joined
        assert "breached" in joined
        assert "weak" in joined


def test_audit_clean_vault_has_no_findings(tmp_path):
    eng = _engine(tmp_path)
    eng._bw.audit_logins = lambda: [
        {"item_id": "9", "name": "Solid", "username": "s", "url": None,
         "password": "Xk9$mQ2p!vT4nW7z@Lr5Zb"}]
    report = eng.audit_vault()
    assert report["findings"] == []
