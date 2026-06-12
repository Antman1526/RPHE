"""Common scanner interface + shared MIME helpers."""
from __future__ import annotations

import abc
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ..config import EmailAccount
from ..secrets import SecretStore


class Scanner(abc.ABC):
    """All scanners yield normalized message dicts:

        {
          "message_id": str,
          "from": str,           # raw From header
          "subject": str,
          "body": str,           # plaintext (HTML stripped to text)
          "received_at": datetime (tz-aware, UTC),
        }

    Scanners are READ-ONLY. They request the narrowest scope the provider
    allows and never mark, move, or delete mail.
    """

    def __init__(self, account: EmailAccount, store: SecretStore):
        self.account = account
        self.store = store

    @abc.abstractmethod
    def fetch(self) -> Iterator[dict]:
        ...

    def since_date(self) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=self.account.lookback_days)


def decode_mime_header(value: str | None) -> str:
    """Decode an RFC 2047 encoded header (e.g. =?utf-8?b?...?=) to plain text."""
    if not value:
        return ""
    from email.header import decode_header, make_header
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def message_to_text(msg) -> str:
    """Extract a plaintext body from an email.message.Message.

    Prefers text/plain; falls back to HTML reduced to text. Shared by the IMAP
    scanner and the .eml file scanner so there is one parsing implementation.
    """
    if msg.is_multipart():
        plain, html = "", ""
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                plain += text
            elif ctype == "text/html":
                html += text
        return plain if plain.strip() else html_to_text(html)
    # Single part
    try:
        payload = msg.get_payload(decode=True)
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace") if payload else ""
    except Exception:
        text = ""
    return text if msg.get_content_type() == "text/plain" else html_to_text(text)


def html_to_text(html: str) -> str:
    """Very small HTML->text reducer (no external dep).

    Good enough to feed the keyword classifier and to extract URLs. We keep
    href targets because reset links often live in anchor tags.
    """
    import re
    from html import unescape

    # Surface href URLs as visible text so the URL extractor can find them.
    html = re.sub(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)["\']?[^>]*>',
                  r" \1 ", html, flags=re.I)
    html = re.sub(r"(?s)<(script|style).*?</\1>", " ", html, flags=re.I)
    html = re.sub(r"(?s)<br\s*/?>", "\n", html, flags=re.I)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    text = unescape(html)
    return re.sub(r"[ \t]+", " ", text)
