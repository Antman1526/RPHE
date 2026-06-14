"""engine.diagnose() — the 'Test my setup' health check, fully mocked."""
from pathlib import Path

import rphe.scanners as scanners
from rphe.audit import AuditLog
from rphe.breach import BreachChecker
from rphe.config import Config, EmailAccount
from rphe.engine import Engine


class FakeStore:
    @staticmethod
    def hibp_api_key():
        return "hibp.api_key"

    def get(self, key):
        return None        # no HIBP key configured


class FakeScanner:
    def __init__(self, *a):
        pass

    def check(self):
        return "IMAP OK"


def _engine(tmp_path):
    cfg = Config(
        accounts=[EmailAccount(label="g", provider="imap", address="a@b.com",
                               imap_host="imap.b.com")],
        data_dir=str(tmp_path))
    return Engine(cfg=cfg, store=FakeStore(), audit=AuditLog(Path(tmp_path)))


def test_diagnose_all_pass(tmp_path, monkeypatch):
    eng = _engine(tmp_path)
    eng.bitwarden_status = lambda: {"status": "unlocked", "userEmail": "x@y.com"}
    eng.breach_checker = lambda: BreachChecker(
        fetch=lambda url, headers: (200, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1"))
    monkeypatch.setattr(scanners, "build_scanner", lambda a, s: FakeScanner())

    checks = {c["name"]: c["ok"] for c in eng.diagnose()}
    assert checks["OS keychain"] is True
    assert checks["Bitwarden"] is True
    assert checks["Email · g"] is True
    assert checks["Breach DB (HIBP)"] is True
    assert checks["NordPass CSV path"] is True


def test_diagnose_reports_failures(tmp_path, monkeypatch):
    eng = _engine(tmp_path)
    eng.bitwarden_status = lambda: {"status": "missing-cli"}

    class Boom:
        def __init__(self, *a):
            pass

        def check(self):
            raise RuntimeError("login failed: bad app password")
    monkeypatch.setattr(scanners, "build_scanner", lambda a, s: Boom())
    eng.breach_checker = lambda: BreachChecker(
        fetch=lambda url, headers: (200, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"))

    checks = {c["name"]: c for c in eng.diagnose()}
    assert checks["Bitwarden"]["ok"] is False
    assert checks["Email · g"]["ok"] is False
    assert "bad app password" in checks["Email · g"]["detail"]
