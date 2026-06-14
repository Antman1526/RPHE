"""scan_detailed surfaces per-inbox failures so a silent scan failure can't be
mistaken for 'all clear'."""
from pathlib import Path

import rphe.scanners as scanners
from rphe.audit import AuditLog
from rphe.config import Config, EmailAccount
from rphe.engine import Engine
from rphe.secrets import SecretStore


def test_scan_detailed_captures_inbox_errors(tmp_path, monkeypatch):
    cfg = Config(accounts=[EmailAccount(label="g", provider="imap", address="a@b.com")],
                 data_dir=str(tmp_path))
    eng = Engine(cfg=cfg, store=SecretStore(), audit=AuditLog(Path(tmp_path)))

    class Boom:
        def __init__(self, *a):
            pass

        def fetch(self):
            raise RuntimeError("login failed: bad app password")
    monkeypatch.setattr(scanners, "build_scanner", lambda a, s: Boom())

    signals, errors = eng.scan_detailed()
    assert signals == []
    assert len(errors) == 1
    assert errors[0]["label"] == "g"
    assert "bad app password" in errors[0]["error"]
    # back-compat: scan() still returns just the signals
    assert eng.scan() == []


def test_scan_detailed_clean(tmp_path, monkeypatch):
    cfg = Config(accounts=[EmailAccount(label="g", provider="imap", address="a@b.com")],
                 data_dir=str(tmp_path))
    eng = Engine(cfg=cfg, store=SecretStore(), audit=AuditLog(Path(tmp_path)))

    class Empty:
        def __init__(self, *a):
            pass

        def fetch(self):
            return iter([])
    monkeypatch.setattr(scanners, "build_scanner", lambda a, s: Empty())
    signals, errors = eng.scan_detailed()
    assert signals == [] and errors == []
