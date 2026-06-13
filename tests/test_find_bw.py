"""Tests for the Bitwarden CLI locator (bundled-first, then PATH)."""
import rphe.vaults.bitwarden as bw


def test_env_override_takes_priority(tmp_path, monkeypatch):
    fake = tmp_path / "bw"
    fake.write_text("#!/bin/sh\necho 1\n")
    monkeypatch.setenv("RPHE_BW_PATH", str(fake))
    assert bw.find_bw() == str(fake)


def test_env_override_ignored_if_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("RPHE_BW_PATH", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(bw.shutil, "which", lambda name: "/usr/local/bin/bw")
    assert bw.find_bw() == "/usr/local/bin/bw"


def test_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("RPHE_BW_PATH", raising=False)
    monkeypatch.setattr(bw.shutil, "which",
                        lambda name: "/opt/bw" if name in ("bw", "bw.exe") else None)
    assert bw.find_bw() == "/opt/bw"


def test_returns_none_when_absent(monkeypatch):
    monkeypatch.delenv("RPHE_BW_PATH", raising=False)
    monkeypatch.setattr(bw.shutil, "which", lambda name: None)
    assert bw.find_bw() is None
