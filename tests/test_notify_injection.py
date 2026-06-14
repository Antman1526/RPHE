"""Desktop-notification text can be email-derived (service names/subjects), so it
must never be interpolated into a shell script. The Windows toast path passes
title/message via environment variables, not into the PowerShell source.
"""
from rphe import notify


def test_windows_notification_passes_text_via_env_not_script(monkeypatch):
    captured = {}

    def fake_run(argv, *args, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env") or {}
        class _P:  # noqa: E306
            returncode = 0
            stdout = stderr = ""
        return _P()

    monkeypatch.setattr(notify.subprocess, "run", fake_run)

    evil_title = 'Breach")); Remove-Item C:\\ -Recurse; ("'
    evil_msg = '$(Invoke-Expression "calc.exe")'
    notify._windows(evil_title, evil_msg)

    script = " ".join(captured["argv"])
    # The attacker-controlled text must NOT appear inside the PowerShell source.
    assert "Remove-Item" not in script
    assert "Invoke-Expression" not in script
    # ...it must be carried out-of-band as inert environment data.
    assert captured["env"]["RPHE_NOTIFY_TITLE"] == evil_title
    assert captured["env"]["RPHE_NOTIFY_MESSAGE"] == evil_msg
    # The script reads from the env vars rather than literals.
    assert "$env:RPHE_NOTIFY_TITLE" in script
    assert "$env:RPHE_NOTIFY_MESSAGE" in script
