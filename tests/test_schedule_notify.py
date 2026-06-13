"""Tests for the scheduling generators, scan command, and notifier."""
import plistlib
import sys

from rphe import notify, schedule


def test_macos_plist_roundtrips():
    raw = schedule.macos_plist_bytes(21600, ["/py", "-m", "rphe", "scan-notify"],
                                     log_dir="/tmp/rphe")
    d = plistlib.loads(raw)
    assert d["Label"] == schedule.LABEL
    assert d["ProgramArguments"] == ["/py", "-m", "rphe", "scan-notify"]
    assert d["StartInterval"] == 21600
    assert d["RunAtLoad"] is False
    assert d["StandardOutPath"].endswith("schedule.out.log")


def test_windows_schtasks_hourly():
    args = schedule.windows_schtasks_create(["py.exe", "-m", "rphe", "scan-notify"], 6)
    assert args[0] == "schtasks" and "/Create" in args
    assert "RPHE-Scan" in args
    assert args[args.index("/SC") + 1] == "HOURLY"
    assert args[args.index("/MO") + 1] == "6"


def test_windows_schtasks_subhour_uses_minutes():
    args = schedule.windows_schtasks_create(["py.exe", "scan"], 0.5)
    assert args[args.index("/SC") + 1] == "MINUTE"
    assert args[args.index("/MO") + 1] == "30"


def test_scan_command_source_install():
    cmd = schedule.scan_command()
    assert cmd[0] == sys.executable
    assert cmd[-1] == "scan-notify"
    assert "rphe" in cmd


def test_desktop_notify_macos(monkeypatch):
    calls = []
    monkeypatch.setattr(notify.sys, "platform", "darwin")
    monkeypatch.setattr(notify.subprocess, "run",
                        lambda *a, **k: calls.append(a[0]))
    assert notify.desktop_notify("Title", 'has "quotes" & \\ stuff') is True
    assert calls and calls[0][0] == "osascript"


def test_desktop_notify_swallows_errors(monkeypatch):
    monkeypatch.setattr(notify.sys, "platform", "darwin")

    def boom(*a, **k):
        raise OSError("no osascript")
    monkeypatch.setattr(notify.subprocess, "run", boom)
    assert notify.desktop_notify("t", "m") is False
