"""NordPass bridge — CSV import/export.

⚠️  HONEST LIMITATION (read this):
NordPass does NOT publish a public developer API or an official CLI for writing
items into a personal vault. As of this writing the only first-party, supported
mechanisms to get credentials *into* NordPass programmatically are:

    1. CSV import  (Settings → Import → CSV / "Other")  — what we use here.
    2. Direct "import from Bitwarden" inside the NordPass app (manual, one-off).

There is therefore NO way to do silent, real-time, bidirectional sync with
NordPass without either (a) browser-extension UI automation (fragile, against
spirit of ToS, breaks on every UI change) or (b) reverse-engineering their
private API (unsupported, may violate ToS, can break/lock the account).

This module takes the supported path: we generate a NordPass-compatible CSV that
the user imports with two clicks. We treat Bitwarden as the source of truth and
NordPass as a mirror refreshed via CSV. `verify_present` reads back the most
recent CSV we wrote so the sync verifier can still flag drift.

The CSV is written to the data dir with 0600 perms and is meant to be deleted
after import (the CLI offers `rphe nordpass clean`). It necessarily contains
plaintext passwords for the duration of the import — that's inherent to *any*
CSV import workflow, NordPass's included, and is the key risk to weigh.
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import Optional

from ..models import GeneratedCredential, VaultItem
from .base import VaultError, VaultWriter

# NordPass's documented import columns for logins.
_COLUMNS = ["name", "url", "username", "password", "note", "folder"]


class NordPassBridge(VaultWriter):
    name = "nordpass"

    def __init__(self, export_path: Path, folder: str = "RPHE-Rotated"):
        self.export_path = Path(export_path)
        self.folder = folder
        self.export_path.parent.mkdir(parents=True, exist_ok=True)

    def _read_rows(self) -> list[dict]:
        if not self.export_path.exists():
            return []
        with self.export_path.open("r", encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))

    def _write_rows(self, rows: list[dict]) -> None:
        # Write to a temp file then atomically replace, locking perms first.
        tmp = self.export_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=_COLUMNS)
            writer.writeheader()
            for r in rows:
                writer.writerow({c: r.get(c, "") for c in _COLUMNS})
        if sys.platform != "win32":
            os.chmod(tmp, 0o600)
        os.replace(tmp, self.export_path)

    def upsert(self, cred: GeneratedCredential) -> VaultItem:
        rows = self._read_rows()
        target = VaultItem(name=cred.service_name, username=cred.username, url=cred.url)
        key = target.identity_key()

        new_row = {
            "name": cred.service_name,
            "url": cred.url or "",
            "username": cred.username,
            "password": cred.secret,
            "note": cred.notes or "Rotated by RPHE",
            "folder": self.folder,
        }
        replaced = False
        for i, r in enumerate(rows):
            existing_key = VaultItem(
                name=r.get("name", ""), username=r.get("username", ""),
                url=r.get("url") or None,
            ).identity_key()
            if existing_key == key:
                rows[i] = new_row
                replaced = True
                break
        if not replaced:
            rows.append(new_row)
        self._write_rows(rows)

        import hashlib
        return VaultItem(
            name=cred.service_name, username=cred.username, url=cred.url,
            password_fingerprint=hashlib.sha256(cred.secret.encode()).hexdigest()[:8],
        )

    def list_items(self) -> list[VaultItem]:
        import hashlib
        out: list[VaultItem] = []
        for r in self._read_rows():
            pw = r.get("password") or ""
            out.append(VaultItem(
                name=r.get("name", ""),
                username=r.get("username", ""),
                url=r.get("url") or None,
                has_password=bool(pw),
                password_fingerprint=(hashlib.sha256(pw.encode()).hexdigest()[:8]
                                      if pw else None),
            ))
        return out

    def import_instructions(self) -> str:
        return (
            f"NordPass CSV staged at: {self.export_path}\n"
            "To import into NordPass:\n"
            "  1. Open the NordPass desktop app and unlock your vault.\n"
            "  2. Settings → Import → choose 'CSV file' (or 'Other').\n"
            f"  3. Select: {self.export_path}\n"
            "  4. Confirm the column mapping (name/url/username/password/note/folder).\n"
            "  5. After it imports, run `rphe nordpass clean` to delete this CSV.\n"
            "NOTE: NordPass import ADDS items; remove old duplicates inside the app\n"
            "or rely on the sync verifier to flag them."
        )

    def clean(self) -> None:
        """Overwrite the staged CSV with zeros, then delete it.

        Honest caveat: this is *best-effort*. On copy-on-write filesystems
        (APFS/Btrfs) and SSDs (wear-levelling), overwriting in place doesn't
        guarantee the old bytes are gone — treat it as 'delete promptly after
        import', not a forensic secure-erase.
        """
        if not self.export_path.exists():
            return
        try:
            size = self.export_path.stat().st_size
            with self.export_path.open("r+b") as fh:
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        try:
            self.export_path.unlink()
        except OSError as exc:
            raise VaultError(f"Could not delete {self.export_path}: {exc}") from exc
