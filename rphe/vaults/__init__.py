"""Vault integrations: Bitwarden (CLI), NordPass (CSV bridge), sync verifier."""
from .base import VaultWriter, VaultError
from .bitwarden import BitwardenVault
from .nordpass import NordPassBridge
from .sync import SyncVerifier

__all__ = [
    "VaultWriter",
    "VaultError",
    "BitwardenVault",
    "NordPassBridge",
    "SyncVerifier",
]
