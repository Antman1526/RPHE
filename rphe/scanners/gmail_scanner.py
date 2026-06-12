"""Gmail API scanner — the recommended path for Gmail accounts.

Why preferred over IMAP for Gmail:
  + Least privilege: the `gmail.readonly` scope is read-only by design; the
    token can never send/delete mail even if stolen.
  + Server-side search (`q=`) so we only download recent, relevant messages.
  + No app password; OAuth refresh tokens are revocable per-app from the
    Google account security page.

Setup: create an OAuth *Desktop app* client in Google Cloud Console, download
client_secret.json, and run `rphe auth gmail <label>` once. The resulting token
JSON is stored in the OS keystore (never on disk).

Dependencies (optional install): google-api-python-client, google-auth-oauthlib.
"""
from __future__ import annotations

import base64
import json
from datetime import timezone
from typing import Iterator

from .base import Scanner, html_to_text

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Gmail search query: only messages that plausibly carry a security signal,
# within the lookback window. Keeps download volume + classification cost low.
_SECURITY_QUERY = (
    'newer_than:{days}d ('
    'subject:(security OR "sign-in" OR "sign in" OR login OR password OR breach '
    'OR suspicious OR verify OR unrecognized OR "was accessed" OR "reset") '
    'OR "data breach" OR "unusual activity" OR "new device")'
)


class GmailScanner(Scanner):
    def _service(self):
        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Gmail scanning needs google-api-python-client + google-auth-oauthlib.\n"
                "Install: pip install google-api-python-client google-auth-oauthlib"
            ) from exc

        token_json = self.store.require(self.store.oauth_token_key(self.account.label))
        creds = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
        if creds.expired and creds.refresh_token:
            from google.auth.transport.requests import Request
            creds.refresh(Request())
            # Persist the refreshed token back into the keystore.
            self.store.set(
                self.store.oauth_token_key(self.account.label), creds.to_json()
            )
        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    def profile(self) -> dict:
        """Validate the stored token and return safe identity info.

        Calls users.getProfile (cheapest authenticated call). Returns the
        account email + message count + granted scopes. Never returns the token.
        Used by `rphe auth gmail-check` to confirm setup without scanning.
        """
        svc = self._service()
        prof = svc.users().getProfile(userId="me").execute()
        return {
            "emailAddress": prof.get("emailAddress"),
            "messagesTotal": prof.get("messagesTotal"),
            "scopes": SCOPES,
        }

    def _decode_body(self, payload: dict) -> str:
        """Walk the MIME tree to assemble plaintext (prefer text/plain)."""
        def decode(data: str) -> str:
            return base64.urlsafe_b64decode(data.encode()).decode("utf-8", "replace")

        if payload.get("mimeType") == "text/plain" and payload.get("body", {}).get("data"):
            return decode(payload["body"]["data"])
        if payload.get("mimeType") == "text/html" and payload.get("body", {}).get("data"):
            return html_to_text(decode(payload["body"]["data"]))
        plain, html = "", ""
        for part in payload.get("parts", []) or []:
            sub = self._decode_body(part)
            if part.get("mimeType") == "text/plain":
                plain += sub
            elif part.get("mimeType") == "text/html":
                html += sub
            else:
                plain += sub
        return plain if plain.strip() else html

    def fetch(self) -> Iterator[dict]:
        svc = self._service()
        q = _SECURITY_QUERY.format(days=self.account.lookback_days)
        user = "me"
        resp = svc.users().messages().list(userId=user, q=q, maxResults=200).execute()
        for ref in resp.get("messages", []) or []:
            msg = svc.users().messages().get(
                userId=user, id=ref["id"], format="full"
            ).execute()
            headers = {h["name"].lower(): h["value"]
                       for h in msg.get("payload", {}).get("headers", [])}
            internal_ms = int(msg.get("internalDate", "0"))
            from datetime import datetime
            received = datetime.fromtimestamp(internal_ms / 1000, tz=timezone.utc)
            yield {
                "message_id": msg.get("id", ref["id"]),
                "from": headers.get("from", ""),
                "subject": headers.get("subject", ""),
                "body": self._decode_body(msg.get("payload", {})),
                "received_at": received,
            }
