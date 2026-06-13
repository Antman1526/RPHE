#!/usr/bin/env bash
# Build RPHE.app and package it into RPHE.dmg.
#
# Requires a Tk-enabled Python (the python.org framework build is ideal):
#   PYBIN=/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 ./packaging/build_macos.sh
#
# Output: dist/RPHE.dmg
set -euo pipefail
cd "$(dirname "$0")/.."

PYBIN="${PYBIN:-python3}"
echo "Using Python: $("$PYBIN" -c 'import sys;print(sys.executable, sys.version.split()[0])')"
"$PYBIN" -c 'import tkinter' 2>/dev/null || {
  echo "ERROR: this Python has no tkinter. Use the python.org build or install python-tk." >&2
  exit 1
}

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
