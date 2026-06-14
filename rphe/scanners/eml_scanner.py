"""Offline .eml folder scanner.

This is the privacy-friendly Gmail bridge: export the emails you're worried
about straight from Gmail (in the web UI: ⋮ → "Download message" → .eml; or
"Show original" → "Download Original"), drop them in a folder, and classify them
locally with ZERO account access and nothing leaving your machine. Perfect for
validating what RPHE would flag before you trust it with an OAuth token.

Config:
    - label: "exported"
      provider: "eml"
      address: ""                 # ignored
      folders: ["~/Desktop/suspicious-emails"]   # one or more directories
      lookback_days: 3650         # files aren't time-filtered; keep this large

It reuses the exact MIME parser the IMAP scanner uses, so behavior is identical.
"""
from __future__ import annotations

import email
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterator

from .base import Scanner, decode_mime_header, message_to_text


class EmlScanner(Scanner):
    def check(self) -> str:
        from pathlib import Path
        for folder in self.account.folders:
            if not Path(folder).expanduser().exists():
                raise FileNotFoundError(f"folder not found: {folder}")
        return "eml folders present"

    def fetch(self) -> Iterator[dict]:
        for folder in self.account.folders:
            base = Path(folder).expanduser()
            if not base.exists():
                raise ValueError(
                    f"account '{self.account.label}': folder does not exist: {base}"
                )
            paths = [base] if base.is_file() else sorted(base.rglob("*.eml"))
            for path in paths:
                try:
                    with path.open("rb") as fh:
                        msg = email.message_from_binary_file(fh)
                except OSError:
                    continue
                try:
                    received = parsedate_to_datetime(msg.get("Date"))
                    if received and received.tzinfo is None:
                        received = received.replace(tzinfo=timezone.utc)
                except Exception:
                    received = self.since_date()
                yield {
                    "message_id": msg.get("Message-ID", str(path)),
                    "from": decode_mime_header(msg.get("From")),
                    "subject": decode_mime_header(msg.get("Subject")),
                    "body": message_to_text(msg),
                    "received_at": (received or self.since_date()).astimezone(timezone.utc),
                }
