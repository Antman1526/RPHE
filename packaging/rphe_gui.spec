# PyInstaller spec for the RPHE desktop GUI.
# One spec, two targets:
#   macOS   -> RPHE.app  (windowed bundle, later wrapped into RPHE.dmg)
#   Windows -> RPHE.exe  (single-file, windowed)
#
# Build:  pyinstaller --noconfirm packaging/rphe_gui.spec
# Run from the repo root so `import rphe` resolves.
import sys
from pathlib import Path

# When PyInstaller execs a spec, __file__ is defined; fall back to cwd.
try:
    ROOT = Path(__file__).resolve().parent.parent
except NameError:  # pragma: no cover
    ROOT = Path.cwd()

# keyring loads its OS backend dynamically — name them so they're bundled.
hiddenimports = [
    "rphe", "rphe.gui", "rphe.engine", "rphe.cli", "rphe.breach",
    "rphe.passkeys", "rphe.passwords", "rphe.classifier", "rphe.config",
    "rphe.audit", "rphe.secrets", "rphe.models", "rphe.samples",
    "rphe.scanners", "rphe.scanners.base", "rphe.scanners.imap_scanner",
    "rphe.scanners.gmail_scanner", "rphe.scanners.graph_scanner",
    "rphe.scanners.eml_scanner", "rphe.reset", "rphe.reset.orchestrator",
    "rphe.vaults", "rphe.vaults.base", "rphe.vaults.bitwarden",
    "rphe.vaults.nordpass", "rphe.vaults.sync",
    "keyring.backends.macOS", "keyring.backends.Windows",
    "keyring.backends.SecretService", "keyring.backends.chainer",
]

datas = [(str(ROOT / "config.example.yaml"), ".")]

a = Analysis(
    [str(ROOT / "packaging" / "rphe_launch.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["playwright", "google", "googleapiclient", "msal"],  # optional, GUI doesn't need
    noarchive=False,
)
pyz = PYZ(a.pure)

if sys.platform == "darwin":
    exe = EXE(
        pyz, a.scripts, [], exclude_binaries=True, name="RPHE",
        console=False, disable_windowed_traceback=False,
        argv_emulation=True, target_arch=None,
    )
    coll = COLLECT(exe, a.binaries, a.datas, name="RPHE")
    app = BUNDLE(
        coll, name="RPHE.app", icon=None,
        bundle_identifier="com.rphe.passwordhygiene",
        info_plist={
            "CFBundleShortVersionString": "0.2.0",
            "NSHighResolutionCapable": True,
            "LSApplicationCategoryType": "public.app-category.utilities",
            # No special entitlements needed; Keychain access is per-user.
        },
    )
else:
    # Windows / Linux: single-file windowed executable.
    # (onefile is implied by passing binaries+datas straight to EXE, no COLLECT.)
    exe = EXE(
        pyz, a.scripts, a.binaries, a.datas, [], name="RPHE",
        console=False, disable_windowed_traceback=False,
    )
