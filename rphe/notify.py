"""Cross-platform desktop notifications (best-effort, dependency-free).

  macOS    -> osascript 'display notification'
  Windows  -> PowerShell toast (BurntToast-free, uses the WinRT API)
  Linux    -> notify-send if available

Notifications never contain secrets — only counts and service names. All
failures are swallowed (a missing notifier must never crash a scan).
"""
from __future__ import annotations

import shutil
import subprocess
import sys


def desktop_notify(title: str, message: str) -> bool:
    """Show a desktop notification. Returns True if a notifier was invoked."""
    try:
        if sys.platform == "darwin":
            return _macos(title, message)
        if sys.platform == "win32":
            return _windows(title, message)
        return _linux(title, message)
    except Exception:
        return False


def _esc_applescript(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _macos(title: str, message: str) -> bool:
    script = (f'display notification "{_esc_applescript(message)}" '
              f'with title "{_esc_applescript(title)}"')
    subprocess.run(["osascript", "-e", script], capture_output=True, timeout=10)
    return True


def _windows(title: str, message: str) -> bool:
    # Uses the built-in Windows.UI.Notifications API via PowerShell — no deps.
    ps = f'''
$ErrorActionPreference = 'SilentlyContinue'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $template.GetElementsByTagName("text")
$texts.Item(0).AppendChild($template.CreateTextNode("{title}")) | Out-Null
$texts.Item(1).AppendChild($template.CreateTextNode("{message}")) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("RPHE").Show($toast)
'''
    subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True, timeout=15)
    return True


def _linux(title: str, message: str) -> bool:
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", title, message], capture_output=True, timeout=10)
        return True
    return False
