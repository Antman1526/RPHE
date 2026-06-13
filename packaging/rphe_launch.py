"""Frozen-app entry point for PyInstaller.

Normally launches the desktop GUI. Supports a hidden, headless self-test
(`RPHE_SELFTEST=1` or `--rphe-selftest`) that imports every module and resolves
the keyring backend, then exits — used by the build to verify the frozen bundle
has no missing hidden imports, without opening a window.
"""
import os
import sys


def _selftest() -> None:
    import importlib
    mods = [
        "rphe.engine", "rphe.gui", "rphe.breach", "rphe.passkeys",
        "rphe.passwords", "rphe.classifier", "rphe.config", "rphe.audit",
        "rphe.secrets", "rphe.models", "rphe.samples",
        "rphe.scanners", "rphe.scanners.imap_scanner",
        "rphe.scanners.gmail_scanner", "rphe.scanners.graph_scanner",
        "rphe.scanners.eml_scanner", "rphe.reset.orchestrator",
        "rphe.vaults.bitwarden", "rphe.vaults.nordpass", "rphe.vaults.sync",
    ]
    mods.append("rphe.gui_setup")
    for m in mods:
        importlib.import_module(m)
    import keyring
    backend = keyring.get_keyring().__class__.__name__
    # Report whether optional OAuth libs made it into the bundle.
    oauth = []
    for opt in ("google_auth_oauthlib", "googleapiclient", "msal"):
        try:
            importlib.import_module(opt)
            oauth.append(opt)
        except Exception:
            pass
    # Verify the bundled Bitwarden CLI is present and runnable.
    from rphe.vaults.bitwarden import find_bw
    bw = find_bw()
    bw_info = "NOT FOUND"
    if bw:
        try:
            import subprocess
            ver = subprocess.run([bw, "--version"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            bw_info = f"{bw} -> {ver or 'present'}"
        except Exception as exc:
            bw_info = f"{bw} (version check failed: {exc})"
    print(f"RPHE selftest OK: {len(mods)} modules imported; keyring backend={backend}; "
          f"oauth libs bundled: {oauth or 'none (IMAP-only app)'}; bw: {bw_info}")


if __name__ == "__main__":
    if os.environ.get("RPHE_SELFTEST") == "1" or "--rphe-selftest" in sys.argv:
        _selftest()
        sys.exit(0)
    from rphe.gui import launch
    launch()
