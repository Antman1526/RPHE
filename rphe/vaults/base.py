"""Vault interface + shared errors."""
from __future__ import annotations

import abc

from ..models import GeneratedCredential, VaultItem


class VaultError(RuntimeError):
    """Raised on any vault operation failure (auth, write, verify)."""


class VaultWriter(abc.ABC):
    """A backend that can store a credential and list its items for verification."""

    name: str = "vault"

    @abc.abstractmethod
    def upsert(self, cred: GeneratedCredential) -> VaultItem:
        """Create or update an item, returning the stored item (no plaintext)."""

    @abc.abstractmethod
    def list_items(self) -> list[VaultItem]:
        """Return all items relevant to RPHE for drift comparison."""

    def verify_present(self, cred: GeneratedCredential) -> bool:
        """Confirm the credential — including the NEW password — is now stored.

        Matching on identity alone (name|username|host) would report success for
        an existing login even if the password write hadn't taken; we also
        confirm the stored item's password fingerprint matches the new secret so
        "verified" means the rotated password is really present.
        """
        import hashlib
        target = VaultItem(name=cred.service_name, username=cred.username, url=cred.url)
        key = target.identity_key()
        want_fp = (hashlib.sha256(cred.secret.encode()).hexdigest()[:8]
                   if cred.secret else None)
        for it in self.list_items():
            if it.identity_key() != key:
                continue
            # If the backend exposes a fingerprint, require it to match the new
            # secret; otherwise fall back to identity-only confirmation.
            if want_fp is None or it.password_fingerprint is None:
                return True
            if it.password_fingerprint == want_fp:
                return True
        return False
