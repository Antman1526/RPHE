"""OS-native secret storage.

This is the *only* OS-divergent part of the codebase, and the `keyring` library
hides even that:

    macOS    -> Keychain (via the Security framework)
    Windows  -> Windows Credential Manager (via wincred)
    Linux    -> Secret Service / KWallet (dev convenience only)

We store: email OAuth tokens, IMAP app-passwords, the Bitwarden session key, and
any provider client secrets. Nothing sensitive ever touches the YAML config or
the audit log.
"""
from __future__ import annotations

from typing import Optional

try:
    import keyring
    from keyring.errors import KeyringError
except ImportError:  # pragma: no cover
    keyring = None
    KeyringError = Exception

SERVICE = "rphe"  # namespace within the OS keystore


class SecretStore:
    """Thin, testable wrapper over `keyring` with a single namespace."""

    def __init__(self, service: str = SERVICE):
        if keyring is None:
            raise RuntimeError(
                "The 'keyring' package is required for secure storage. "
                "Run: pip install -r requirements.txt"
            )
        self.service = service

    def set(self, key: str, value: str) -> None:
        """Store/overwrite a secret. Raises on backend failure (never silent)."""
        try:
            keyring.set_password(self.service, key, value)
        except KeyringError as exc:  # pragma: no cover - backend specific
            raise RuntimeError(f"Failed to write secret '{key}': {exc}") from exc

    def get(self, key: str) -> Optional[str]:
        try:
            return keyring.get_password(self.service, key)
        except KeyringError as exc:  # pragma: no cover
            raise RuntimeError(f"Failed to read secret '{key}': {exc}") from exc

    def require(self, key: str) -> str:
        """Like get() but raises a clear error if the secret is missing."""
        val = self.get(key)
        if val is None:
            raise KeyError(
                f"Secret '{key}' not found in the OS keystore. "
                f"Set it with: rphe secrets set {key}"
            )
        return val

    def delete(self, key: str) -> None:
        try:
            keyring.delete_password(self.service, key)
        except KeyringError:  # already absent — treat as success
            pass

    # --- Conventional key names, centralized so modules don't hardcode strings ---
    @staticmethod
    def imap_password_key(account_label: str) -> str:
        return f"imap.{account_label}.app_password"

    @staticmethod
    def oauth_token_key(account_label: str) -> str:
        return f"oauth.{account_label}.token_json"

    @staticmethod
    def bitwarden_session_key() -> str:
        return "bitwarden.session"

    @staticmethod
    def bitwarden_account_key() -> str:
        # The email the cached session belongs to, so a session can't be reused
        # against a different logged-in account (rotate into the wrong vault).
        return "bitwarden.account_email"

    @staticmethod
    def bitwarden_master_key() -> str:
        # Optional: only stored if the user opts into unattended unlock.
        return "bitwarden.master_password"

    @staticmethod
    def hibp_api_key() -> str:
        return "hibp.api_key"
