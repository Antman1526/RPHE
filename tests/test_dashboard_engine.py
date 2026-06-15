# tests/test_dashboard_engine.py
import hashlib
from rphe.engine import Engine


class _Bw:
    def __init__(self, logins):
        self._logins = logins
    def audit_logins(self):
        return self._logins


class _Checker:
    def pwned_password_count(self, pw):
        return 5 if pw == "pwned" else 0


def _engine_with(logins, monkeypatch, tmp_path):
    from rphe.config import Config
    eng = Engine(cfg=Config(data_dir=str(tmp_path)))
    eng._bw = _Bw(logins)
    monkeypatch.setattr(eng, "breach_checker", lambda: _Checker())
    return eng


def test_audit_vault_returns_structured_logins(monkeypatch, tmp_path):
    logins = [{"item_id": "id1", "name": "A", "username": "me@x.com",
               "url": "https://a.com", "password": "pwned"},
              {"item_id": "id2", "name": "B", "username": "me@x.com",
               "url": "https://b.com", "password": "pwned"}]
    eng = _engine_with(logins, monkeypatch, tmp_path)
    out = eng.audit_vault()
    assert out["scanned"] == 2
    structured = {l["item_id"]: l for l in out["logins"]}
    a = structured["id1"]
    assert a["pwned_count"] == 5 and a["reuse_count"] == 2
    assert a["fingerprint"] == hashlib.sha256(b"pwned").hexdigest()[:8]
    assert "password" not in a            # no plaintext leaks into the structured row
