#!/usr/bin/env python3
"""Download the standalone Bitwarden CLI (`bw`) for the current platform.

Writes the single self-contained `bw` / `bw.exe` executable (no Node.js needed)
into packaging/vendor/ so PyInstaller can bundle it into the app. Run this once
before building the installer.

The Bitwarden CLI is GPL-3.0; we invoke it as a separate process (mere
aggregation) and ship its binary unmodified — see THIRD_PARTY_NOTICES.md.

Usage:  python packaging/fetch_bw.py [--version cli-vX.Y.Z]
Env:    GITHUB_TOKEN (optional) raises the GitHub API rate limit.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import ssl
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "packaging" / "vendor"
RELEASES_API = "https://api.github.com/repos/bitwarden/clients/releases?per_page=100"

# Pinned for reproducible, auditable builds. Override with --version cli-vX.Y.Z
# or the RPHE_BW_TAG env var. Bump deliberately, not automatically.
DEFAULT_TAG = "cli-v2026.5.0"

_PLATFORM = {"darwin": "macos", "win32": "windows", "linux": "linux"}.get(sys.platform)


def _ssl_context() -> ssl.SSLContext:
    """Build a verifying SSL context, using certifi if the system store is empty.

    Framework Python builds on macOS often ship without a usable CA store; certifi
    (pulled in by the OAuth deps) provides one so HTTPS verification still works.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _request(url: str, *, api: bool = False) -> bytes:
    if not url.lower().startswith("https://"):
        raise ValueError(f"refusing to fetch non-HTTPS URL: {url}")
    headers = {"User-Agent": "rphe-build"}
    if api:
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(req, timeout=120, context=_ssl_context()) as resp:  # https-enforced
        return resp.read()


def _find_asset(pinned_tag: str | None):
    """Return (tag, asset_name, download_url, sha256) for this platform's bw zip."""
    releases = json.loads(_request(RELEASES_API, api=True))
    cli_releases = [r for r in releases if r.get("tag_name", "").startswith("cli-v")]
    if pinned_tag:
        matched = [r for r in cli_releases if r["tag_name"] == pinned_tag]
        if not matched:
            raise SystemExit(f"Pinned release {pinned_tag} not found in the API window.")
        cli_releases = matched
    for rel in cli_releases:  # GitHub returns newest first
        candidates = []
        for a in rel.get("assets", []):
            name = a["name"]
            # Match e.g. bw-macos-X.Y.Z.zip; exclude arch-specific/oss for the
            # widest-compatibility default (x64 runs on Intel + Apple Silicon).
            if (name.startswith(f"bw-{_PLATFORM}-") and name.endswith(".zip")
                    and "oss" not in name and "arm64" not in name):
                digest = (a.get("digest") or "").split(":")[-1]
                candidates.append((name, a["browser_download_url"], digest))
        if candidates:
            candidates.sort(key=lambda c: c[0])
            name, url, digest = candidates[0]
            return rel["tag_name"], name, url, digest
    raise SystemExit(f"No bw-{_PLATFORM}-*.zip asset found for {pinned_tag or 'latest'}.")


def main() -> None:
    if _PLATFORM is None:
        raise SystemExit(f"Unsupported platform: {sys.platform}")
    pinned = os.environ.get("RPHE_BW_TAG") or DEFAULT_TAG
    if "--version" in sys.argv:
        pinned = sys.argv[sys.argv.index("--version") + 1]
    if "--latest" in sys.argv:
        pinned = None

    VENDOR.mkdir(parents=True, exist_ok=True)
    member_name = "bw.exe" if _PLATFORM == "windows" else "bw"
    existing = VENDOR / member_name
    if existing.exists() and "--force" not in sys.argv:
        ver = (VENDOR / "BW_VERSION.txt").read_text().strip() if (VENDOR / "BW_VERSION.txt").exists() else "?"
        print(f"[fetch_bw] {existing.name} already present ({ver}); use --force to redownload.")
        return

    tag, name, url, digest = _find_asset(pinned)
    print(f"[fetch_bw] downloading {name} ({tag})")
    blob = _request(url)

    # Supply-chain integrity: verify the bytes against the API-published sha256.
    if digest:
        actual = hashlib.sha256(blob).hexdigest()
        if actual.lower() != digest.lower():
            raise SystemExit(
                f"[fetch_bw] SHA-256 MISMATCH for {name}!\n"
                f"  expected {digest}\n  got      {actual}\nAborting.")
        print(f"[fetch_bw] sha256 verified: {actual[:16]}…")
    else:
        print("[fetch_bw] WARNING: no digest published for this asset; skipping verification.")

    zf = zipfile.ZipFile(io.BytesIO(blob))

    member = next((m for m in zf.namelist() if m.split("/")[-1] == member_name),
                  zf.namelist()[0])
    out = VENDOR / member_name
    out.write_bytes(zf.read(member))
    if _PLATFORM != "windows":
        out.chmod(out.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    # Record the version we bundled for the audit trail / about box.
    (VENDOR / "BW_VERSION.txt").write_text(tag, encoding="utf-8")
    print(f"[fetch_bw] wrote {out}  ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
