"""Email scanners. Each returns normalized message dicts for the classifier."""
from __future__ import annotations

from ..config import EmailAccount
from ..secrets import SecretStore
from .base import Scanner


def build_scanner(account: EmailAccount, store: SecretStore) -> Scanner:
    """Factory: pick the scanner implementation for an account's provider."""
    provider = account.provider.lower()
    if provider == "imap":
        from .imap_scanner import ImapScanner
        return ImapScanner(account, store)
    if provider == "gmail":
        from .gmail_scanner import GmailScanner
        return GmailScanner(account, store)
    if provider == "graph":
        from .graph_scanner import GraphScanner
        return GraphScanner(account, store)
    if provider == "eml":
        from .eml_scanner import EmlScanner
        return EmlScanner(account, store)
    raise ValueError(f"Unknown email provider '{account.provider}' for {account.label}")
