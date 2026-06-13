"""Install/uninstall a recurring background scan.

  macOS    -> a per-user LaunchAgent (~/Library/LaunchAgents/com.rphe.scan.plist)
  Windows  -> a Scheduled Task (schtasks)

The scheduled job runs `rphe scan-notify`, which scans and shows a desktop
notification if anything is flagged. It needs no master password (email scanning
uses the OS-keystore tokens), so it can run unattended.

The plist / schtasks generators are pure functions so they can be unit-tested.
"""
from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path

LABEL = "com.rphe.scan"
TASK_NAME = "RPHE-Scan"


def scan_command() -> list:
    """The argv the scheduler should run to perform a scan+notify."""
    if getattr(sys, "frozen", False):
        # Packaged app: a hidden headless mode in the launcher.
        return [sys.executable, "--scan-notify"]
    return [sys.executable, "-m", "rphe", "scan-notify"]


def _launch_agents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _plist_path() -> Path:
    return _launch_agents_dir() / f"{LABEL}.plist"


# --- pure generators (unit-tested) -------------------------------------------
def macos_plist_bytes(interval_seconds: int, program_args: list,
                      label: str = LABEL, log_dir: str | None = None) -> bytes:
    d = {
        "Label": label,
        "ProgramArguments": list(program_args),
        "StartInterval": int(interval_seconds),
        "RunAtLoad": False,
        "ProcessType": "Background",
    }
    if log_dir:
        d["StandardOutPath"] = str(Path(log_dir) / "schedule.out.log")
        d["StandardErrorPath"] = str(Path(log_dir) / "schedule.err.log")
    return plistlib.dumps(d)


def windows_schtasks_create(program_args: list, interval_hours: float) -> list:
    tr = " ".join((f'\\"{a}\\"' if " " in a else a) for a in program_args)
    if interval_hours >= 1:
        sc, mo = "HOURLY", str(int(interval_hours))
    else:
        sc, mo = "MINUTE", str(max(1, int(interval_hours * 60)))
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr,
            "/SC", sc, "/MO", mo, "/F"]


# --- install / uninstall / status --------------------------------------------
def install(interval_hours: float = 6.0, data_dir: str | None = None) -> str:
    interval = max(60, int(interval_hours * 3600))
    cmd = scan_command()
    if sys.platform == "darwin":
        path = _plist_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(macos_plist_bytes(interval, cmd, log_dir=data_dir))
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
        subprocess.run(["launchctl", "load", str(path)], capture_output=True)
        return f"Installed LaunchAgent {path} (every {interval_hours}h)."
    if sys.platform == "win32":
        subprocess.run(windows_schtasks_create(cmd, interval_hours),
                       capture_output=True)
        return f"Installed Scheduled Task {TASK_NAME} (every {interval_hours}h)."
    raise RuntimeError("Scheduling is supported on macOS and Windows only.")


def uninstall() -> str:
    if sys.platform == "darwin":
        path = _plist_path()
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
        if path.exists():
            path.unlink()
        return "Removed the RPHE LaunchAgent."
    if sys.platform == "win32":
        subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                       capture_output=True)
        return "Removed the RPHE Scheduled Task."
    raise RuntimeError("Scheduling is supported on macOS and Windows only.")


def status() -> str:
    if sys.platform == "darwin":
        return ("installed" if _plist_path().exists() else "not installed")
    if sys.platform == "win32":
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                           capture_output=True, text=True)
        return "installed" if r.returncode == 0 else "not installed"
    return "unsupported"
