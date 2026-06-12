"""Microsoft Graph scanner — recommended path for Outlook.com / Microsoft 365.

Why preferred over IMAP for Microsoft accounts:
  + Least privilege: `Mail.Read` (delegated) is read-only.
  + Server-side `$search`/`$filter` so we only pull recent security mail.
  + Token acquired via MSAL device-code or auth-code flow; revocable per-app.

Setup: register an app in Entra ID (Azure AD), add delegated `Mail.Read`, allow
public-client flows, then run `rphe auth graph <label>`. The token cache is
stored in the OS keystore.

Dependencies (optional install): msal, requests.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterator

from .base import Scanner, html_to_text

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = ["Mail.Read"]


class GraphScanner(Scanner):
    def _token(self) -> str:
        try:
            import msal
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Graph scanning needs msal + requests.\n"
                "Install: pip install msal requests"
            ) from exc

        # client_id + token cache are kept in the keystore under this label.
        client_id = self.store.require(f"graph.{self.account.label}.client_id")
        cache_key = self.store.oauth_token_key(self.account.label)
        cache = msal.SerializableTokenCache()
        existing = self.store.get(cache_key)
        if existing:
            cache.deserialize(existing)

        app = msal.PublicClientApplication(
            client_id, authority="https://login.microsoftonline.com/common",
            token_cache=cache,
        )
        result = None
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if not result:
            raise RuntimeError(
                f"No cached Graph token for '{self.account.label}'. "
                f"Run: rphe auth graph {self.account.label}"
            )
        if cache.has_state_changed:
            self.store.set(cache_key, cache.serialize())
        if "access_token" not in result:
            raise RuntimeError(f"Graph auth failed: {result.get('error_description')}")
        return result["access_token"]

    def fetch(self) -> Iterator[dict]:
        import requests

        token = self._token()
        since = self.since_date().strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        # $filter on receivedDateTime keeps the payload small; we classify locally.
        params = {
            "$select": "id,subject,from,receivedDateTime,body,bodyPreview",
            "$filter": f"receivedDateTime ge {since}",
            "$top": "100",
            "$orderby": "receivedDateTime desc",
        }
        url = f"{GRAPH}/me/messages"
        with requests.Session() as s:
            s.headers.update(headers)
            while url:
                r = s.get(url, params=params, timeout=30)
                r.raise_for_status()
                data = r.json()
                for m in data.get("value", []):
                    body = m.get("body", {}) or {}
                    content = body.get("content", "") or m.get("bodyPreview", "")
                    if (body.get("contentType") or "").lower() == "html":
                        content = html_to_text(content)
                    frm = (m.get("from", {}) or {}).get("emailAddress", {}) or {}
                    received = datetime.fromisoformat(
                        m["receivedDateTime"].replace("Z", "+00:00")
                    ).astimezone(timezone.utc)
                    yield {
                        "message_id": m["id"],
                        "from": f'{frm.get("name","")} <{frm.get("address","")}>',
                        "subject": m.get("subject", ""),
                        "body": content,
                        "received_at": received,
                    }
                url = data.get("@odata.nextLink")
                params = None  # nextLink already encodes the query
