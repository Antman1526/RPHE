"""Breach detection via Have I Been Pwned (HIBP).

Two capabilities:

1. **Pwned Passwords (free, no key, privacy-preserving)** — k-anonymity range
   query. We hash the password with SHA-1, send only the **first 5 hex chars**
   of the hash to the API, and match the suffix locally. The password itself
   NEVER leaves the machine. Used to (a) flag any of your existing passwords
   that appear in breaches and (b) guarantee a freshly generated password is not
   already in any known breach before we store it.

2. **Account breach lookup (needs a paid HIBP API key)** — given an email, list
   the breaches it appeared in. The key is read from the OS keystore, never
   config. Without a key this gracefully degrades (capability disabled).

No third-party HTTP library required — uses urllib from the stdlib. A `fetch`
callable can be injected for testing (so unit tests never hit the network).
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
USER_AGENT = "RPHE-password-hygiene-tool"

# fetch(url, headers) -> (status_code, body_text)
FetchFn = Callable[[str, dict], "tuple[int, str]"]


def _urllib_fetch(url: str, headers: dict, timeout: int = 20) -> "tuple[int, str]":
    # Defence in depth: only ever fetch over HTTPS (blocks file:// and other
    # schemes), since URLs are built from constants + URL-encoded user data.
    if not url.lower().startswith("https://"):
        raise ValueError("RPHE only contacts HTTPS endpoints")
    req = urllib.request.Request(url, headers=headers)
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # https-enforced above
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace") if exc.fp else ""


@dataclass
class AccountBreach:
    name: str
    title: str
    breach_date: str
    data_classes: list
    domain: str = ""


class BreachChecker:
    def __init__(self, api_key: Optional[str] = None,
                 fetch: Optional[FetchFn] = None, timeout: int = 20,
                 max_retries: int = 3):
        self.api_key = api_key
        self._fetch = fetch or (lambda u, h: _urllib_fetch(u, h, timeout))
        self.max_retries = max_retries

    @property
    def can_check_accounts(self) -> bool:
        return bool(self.api_key)

    # --- Pwned Passwords (free, k-anonymity) -------------------------------
    def pwned_password_count(self, password: str) -> int:
        """Return how many times this password appears in breaches (0 == safe).

        Only the first 5 chars of the SHA-1 hash are sent over the network.
        """
        # SHA-1 is mandated by the HIBP range API; it is NOT used here as a
        # security primitive (usedforsecurity=False), so this is not a weak-hash
        # vulnerability — switching to SHA-256 would break the API.
        digest = hashlib.sha1(  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        # "Add-Padding" hides the real result size from a network observer.
        status, body = self._call(
            PWNED_RANGE_URL.format(prefix=prefix),
            {"User-Agent": USER_AGENT, "Add-Padding": "true"})
        if status != 200:
            raise RuntimeError(f"Pwned Passwords API returned HTTP {status}")
        for line in body.splitlines():
            h, _, count = line.partition(":")
            if h.strip() == suffix:
                try:
                    return int(count.strip())
                except ValueError:
                    return 0
        return 0

    def is_pwned(self, password: str) -> bool:
        return self.pwned_password_count(password) > 0

    # --- Account breach lookup (needs API key) -----------------------------
    def account_breaches(self, account: str) -> list:
        """List breaches an email/username appeared in. [] == none found.

        Requires an HIBP API key (set via `rphe secrets set hibp.api_key`).
        """
        if not self.api_key:
            raise RuntimeError(
                "Account breach lookup needs an HIBP API key. "
                "Get one at https://haveibeenpwned.com/API/Key and run "
                "`rphe secrets set hibp.api_key`.")
        url = HIBP_BREACH_URL.format(account=urllib.parse.quote(account, safe=""))
        url += "?truncateResponse=false"
        headers = {"User-Agent": USER_AGENT, "hibp-api-key": self.api_key}
        status, body = self._call(url, headers)
        if status == 404:
            return []  # documented: 404 == no breaches for this account
        if status == 401:
            raise RuntimeError("HIBP rejected the API key (HTTP 401).")
        if status != 200:
            raise RuntimeError(f"HIBP breach lookup returned HTTP {status}")
        out = []
        for b in json.loads(body):
            out.append(AccountBreach(
                name=b.get("Name", ""), title=b.get("Title", b.get("Name", "")),
                breach_date=b.get("BreachDate", ""),
                data_classes=b.get("DataClasses", []) or [],
                domain=b.get("Domain", "") or ""))
        return out

    # --- shared call w/ rate-limit handling --------------------------------
    def _call(self, url: str, headers: dict) -> "tuple[int, str]":
        attempt = 0
        while True:
            status, body = self._fetch(url, headers)
            if status == 429 and attempt < self.max_retries:
                # HIBP returns Retry-After; we can't read headers via our simple
                # fetch contract, so back off with a fixed schedule.
                time.sleep(2 * (attempt + 1))
                attempt += 1
                continue
            return status, body
