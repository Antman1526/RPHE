#!/usr/bin/env bash
# Build RPHE.app and package it into RPHE.dmg.
#
# Needs a Tk-enabled Python. On Apple Silicon, prefer an ARM64-ONLY build
# (e.g. Homebrew `python3.11`): a *universal2* Python (the python.org framework
# build) makes PyInstaller run `lipo -thin arm64`, which fails on already-thin
# dylibs when the build cache is cold. CI uses an arm64-only Python for this
# reason. This script auto-picks a good Python, or honours $PYBIN if you set it.
#
#   ./packaging/build_macos.sh              # auto-pick
#   PYBIN=python3.11 ./packaging/build_macos.sh
#
# Output: dist/RPHE.dmg
set -euo pipefail
cd "$(dirname "$0")/.."

_has_tk() { "$1" -c 'import tkinter' 2>/dev/null; }
_is_universal2() {
  local exe; exe="$("$1" -c 'import sys;print(sys.executable)' 2>/dev/null)" || return 1
  file "$exe" 2>/dev/null | grep -q x86_64 && file "$exe" 2>/dev/null | grep -q arm64
}

# If $PYBIN isn't set, find a Tk-enabled Python — preferring arm64-only on
# Apple Silicon to dodge the universal2 lipo bug.
if [ -z "${PYBIN:-}" ]; then
  for cand in python3.12 python3.11 python3.13 python3.10 python3; do
    command -v "$cand" >/dev/null 2>&1 || continue
    _has_tk "$cand" || continue
    if [ "$(uname -m)" = "arm64" ] && _is_universal2 "$cand"; then continue; fi
    PYBIN="$cand"; break
  done
  PYBIN="${PYBIN:-python3}"
fi

echo "Using Python: $("$PYBIN" -c 'import sys;print(sys.executable, sys.version.split()[0])')"
_has_tk "$PYBIN" || {
  echo "ERROR: this Python has no tkinter. Install python-tk or use the python.org build." >&2
  exit 1
}
if [ "$(uname -m)" = "arm64" ] && _is_universal2 "$PYBIN"; then
  echo "WARNING: $PYBIN is universal2. If PyInstaller fails with a 'lipo -thin' error," >&2
  echo "         clear ~/Library/Application Support/pyinstaller and use an arm64-only" >&2
  echo "         Tk Python (e.g. Homebrew python3.11): PYBIN=python3.11 $0" >&2
fi

"$PYBIN" -m pip install --upgrade pip >/dev/null
"$PYBIN" -m pip install --upgrade pyinstaller typer rich PyYAML keyring customtkinter >/dev/null
# Optional OAuth libs so the bundled app's Connect Gmail/Outlook buttons work.
"$PYBIN" -m pip install --upgrade google-api-python-client google-auth-oauthlib msal >/dev/null

# Download the standalone Bitwarden CLI so it can be bundled into the app.
"$PYBIN" packaging/fetch_bw.py

rm -rf build dist
"$PYBIN" -m PyInstaller --noconfirm packaging/rphe_gui.spec

test -d "dist/RPHE.app" || { echo "ERROR: RPHE.app was not produced" >&2; exit 1; }

# Assemble a DMG staging folder with the app + an Applications drop target.
rm -rf dist/dmg && mkdir -p dist/dmg
cp -R "dist/RPHE.app" "dist/dmg/RPHE.app"
ln -s /Applications "dist/dmg/Applications"

hdiutil create -volname "RPHE" -srcfolder "dist/dmg" -ov -format UDZO "dist/RPHE.dmg"
rm -rf dist/dmg
echo "✓ Built dist/RPHE.dmg"
