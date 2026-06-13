# Build RPHE.exe (single-file, windowed) on Windows.
#
# Usage (PowerShell):
#   py -3.12 -m venv .venv-build
#   .\.venv-build\Scripts\Activate.ps1
#   .\packaging\build_windows.ps1
#
# Output: dist\RPHE.exe
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

python -c "import tkinter" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "This Python has no tkinter. Install Python from python.org (includes Tk)."
    exit 1
}

python -m pip install --upgrade pip | Out-Null
python -m pip install --upgrade pyinstaller typer rich PyYAML keyring | Out-Null
# Optional OAuth libs so the bundled app's Connect Gmail/Outlook buttons work.
python -m pip install --upgrade google-api-python-client google-auth-oauthlib msal | Out-Null

if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

python -m PyInstaller --noconfirm packaging/rphe_gui.spec

if (-Not (Test-Path "dist\RPHE.exe")) {
    Write-Error "RPHE.exe was not produced"
    exit 1
}
Write-Host "OK Built dist\RPHE.exe"
