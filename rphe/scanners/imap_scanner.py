"""IMAP scanner — the universal fallback that works with any provider.

Trade-offs vs API scanners:
  + Works everywhere (Gmail, Outlook/365, Fastmail, iCloud, self-hosted).
  + Pure stdlib (imaplib) — no OAuth dance, no cloud project to register.
  - Requires an *app password* (Gmail/Microsoft both require app passwords or
    OAuth for IMAP; basic auth is deprecated). App passwords are coarse-grained
    (full mailbox read) — less least-privilege than Gmail API's readonly scope.
  - No server-side message classification; we pull headers+body and classify
    locally.

The app password is read from the OS keystore, never from config.
"""
from __future__ import annotations

import email
import imaplib
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Iterator

from .base import Scanner, decode_mime_header, message_to_text


class ImapScanner(Scanner):
    def _decode(self, value: str | None) -> str:
        return decode_mime_header(value)

    def _extract_body(self, msg: email.message.Message) -> str:
        return message_to_text(msg)

    def fetch(self) -> Iterator[dict]:
        host = self.account.imap_host
        if not host:
            raise ValueError(
                f"account '{self.account.label}' is provider=imap but has no imap_host"
            )
        key = self.store.imap_password_key(self.account.label)
        app_password = self.store.require(key)
        since = self.since_date().strftime("%d-%b-%Y")

        conn = imaplib.IMAP4_SSL(host, self.account.imap_port)
        try:
            conn.login(self.account.address, app_password)
            for folder in self.account.folders:
                # readonly=True => never sets the \Seen flag; truly read-only.
                status, _ = conn.select(f'"{folder}"', readonly=True)
                if status != "OK":
                    continue
                typ, data = conn.search(None, "SINCE", since)
                if typ != "OK" or not data or not data[0]:
                    continue
                for num in data[0].split():
                    typ, msg_data = conn.fetch(num, "(RFC822)")
                    if typ != "OK" or not msg_data or not msg_data[0]:
                        continue
                    raw = msg_data[0][1]
                    msg = email.message_from_bytes(raw)
                    try:
                        received = parsedate_to_datetime(msg.get("Date"))
                        if received and received.tzinfo is None:
                            received = received.replace(tzinfo=timezone.utc)
                    except Exception:
                        received = self.since_date()
                    yield {
                        "message_id": msg.get("Message-ID", f"{folder}:{num.decode()}"),
                        "from": self._decode(msg.get("From")),
                        "subject": self._decode(msg.get("Subject")),
                        "body": self._extract_body(msg),
                        "received_at": received.astimezone(timezone.utc),
                    }
        finally:
            try:
                conn.logout()
            except Exception:
                pass
