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
    for m in mods:
        importlib.import_module(m)
    import keyring
    backend = keyring.get_keyring().__class__.__name__
    print(f"RPHE selftest OK: {len(mods)} modules imported; keyring backend={backend}")


if __name__ == "__main__":
    if os.environ.get("RPHE_SELFTEST") == "1" or "--rphe-selftest" in sys.argv:
        _selftest()
        sys.exit(0)
    from rphe.gui import launch
    launch()
