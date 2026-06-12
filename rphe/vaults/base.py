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
        """Confirm an item matching this credential now exists in the vault."""
        target = VaultItem(name=cred.service_name, username=cred.username, url=cred.url)
        key = target.identity_key()
        return any(it.identity_key() == key for it in self.list_items())
