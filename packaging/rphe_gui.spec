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
    "rphe", "rphe.gui", "rphe.gui_setup", "rphe.engine", "rphe.cli",
    "rphe.breach", "rphe.linksafety", "rphe.passkeys", "rphe.passwords",
    "rphe.classifier", "rphe.config", "rphe.audit", "rphe.secrets",
    "rphe.models", "rphe.samples", "rphe.notify", "rphe.schedule", "rphe.providers",
    "rphe.scanners", "rphe.scanners.base", "rphe.scanners.imap_scanner",
    "rphe.scanners.gmail_scanner", "rphe.scanners.graph_scanner",
    "rphe.scanners.eml_scanner", "rphe.reset", "rphe.reset.orchestrator",
    "rphe.vaults", "rphe.vaults.base", "rphe.vaults.bitwarden",
    "rphe.vaults.nordpass", "rphe.vaults.sync",
    "keyring.backends.macOS", "keyring.backends.Windows",
    "keyring.backends.SecretService", "keyring.backends.chainer",
]

datas = [(str(ROOT / "config.example.yaml"), ".")]
binaries = []

# Bundle the OAuth libraries IF they're installed in the build env, so the
# app's "Connect Gmail/Outlook" buttons work. Guarded so the build never breaks
# when they're absent (the app then falls back to IMAP/CLI for those providers).
def _collect(pkg):
    try:
        from PyInstaller.utils.hooks import collect_all
        d, b, h = collect_all(pkg)
        datas.extend(d); binaries.extend(b); hiddenimports.extend(h)
        print(f"[rphe.spec] bundled optional lib: {pkg}")
    except Exception as exc:  # not installed -> skip
        print(f"[rphe.spec] skipping optional lib {pkg}: {exc}")

# customtkinter ships theme JSON + assets that must be collected, or the app
# crashes at startup. The others enable the optional OAuth buttons.
for _pkg in ("customtkinter", "google", "googleapiclient", "google_auth_oauthlib",
             "google_auth_httplib2", "msal"):
    _collect(_pkg)

# Bundle the standalone Bitwarden CLI if it was fetched (packaging/fetch_bw.py),
# so the app needs no separately-installed `bw`. It lands in _MEIPASS at runtime
# and rphe.vaults.bitwarden.find_bw() locates it there first.
VENDOR = ROOT / "packaging" / "vendor"
for _bwname in ("bw", "bw.exe"):
    _bwpath = VENDOR / _bwname
    if _bwpath.exists():
        binaries.append((str(_bwpath), "."))
        print(f"[rphe.spec] bundled Bitwarden CLI: {_bwname} "
              f"({_bwpath.stat().st_size // (1024*1024)} MB)")

a = Analysis(
    [str(ROOT / "packaging" / "rphe_launch.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["playwright"],  # heavy, GUI never needs it
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
        coll, name="RPHE.app", icon=str(ROOT / "packaging" / "RPHE.icns"),
        bundle_identifier="com.rphe.passwordhygiene",
        info_plist={
            "CFBundleShortVersionString": "0.7.4",
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
        icon=str(ROOT / "packaging" / "RPHE.ico"),
    )
