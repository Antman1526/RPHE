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


from rphe.models import BreachSignal, SignalKind, Severity
from datetime import datetime, timezone


def test_build_dashboard_refresh_persists_and_degrades(monkeypatch, tmp_path):
    logins = [{"item_id": "id1", "name": "A", "username": "me@x.com",
               "url": "https://a.com", "password": "pwned"}]
    eng = _engine_with(logins, monkeypatch, tmp_path)
    monkeypatch.setattr(eng, "scan_detailed", lambda min_severity=Severity.MEDIUM: ([], []))
    # no HIBP key -> breach_email source unavailable, others still build
    monkeypatch.setattr(eng.store, "get", lambda k: None)
    snap = eng.build_dashboard(refresh=True)
    assert snap.sources["vault"]["ok"] is True
    assert snap.sources["breach_email"]["ok"] is False
    assert any(r.tier.name == "CRITICAL" for r in snap.accounts)
    # persisted: a fresh load returns it
    from rphe.snapshot import load_snapshot
    assert load_snapshot(tmp_path) is not None


def test_build_dashboard_vault_locked_is_partial(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    def _boom(*a, **k):
        raise RuntimeError("vault locked")
    monkeypatch.setattr(eng, "audit_vault", _boom)
    monkeypatch.setattr(eng, "scan_detailed",
                        lambda min_severity=Severity.MEDIUM: (
                            [BreachSignal(message_id="m", service_name="LinkedIn",
                             sender_domain="linkedin.com", subject="x",
                             received_at=datetime(2026,6,1,tzinfo=timezone.utc),
                             kind=SignalKind.BREACH_NOTICE, severity=Severity.CRITICAL)], []))
    monkeypatch.setattr(eng.store, "get", lambda k: None)
    snap = eng.build_dashboard(refresh=True)
    assert snap.sources["vault"]["ok"] is False
    assert any(r.domain == "linkedin.com" for r in snap.accounts)   # still built


def test_build_dashboard_no_refresh_returns_cached(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    assert eng.build_dashboard(refresh=False) is None        # never run yet


from rphe.risk import AccountRisk, Tier


def test_rotate_from_dashboard_delegates(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    captured = {}
    def _fake_rotate(*, service_name, username, password, url=None, kind="manual"):
        captured.update(service_name=service_name, username=username, url=url, kind=kind)
        return "ROT"
    monkeypatch.setattr(eng, "rotate", _fake_rotate)
    monkeypatch.setattr(eng, "password_candidates", lambda n=1: ["Generated-PW-123"])
    row = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH,
                      vault_item_id="id1", managed=True)
    out = eng.rotate_from_dashboard(row)
    assert out == "ROT"
    assert captured["service_name"] == "github.com"
    assert captured["username"] == "me@x.com"
    assert captured["url"] == "https://github.com"
    assert captured["kind"] == "dashboard"
