"""Sync verifier — detects drift between Bitwarden and the NordPass CSV mirror.

It compares the two vaults by logical identity (name|username|host) and by a
password fingerprint (sha256[:8]). It NEVER compares or prints plaintext
passwords — only fingerprints, which reveal nothing but equality.
"""
from __future__ import annotations

from ..models import SyncReport, VaultItem
from .base import VaultWriter


class SyncVerifier:
    def __init__(self, bitwarden: VaultWriter, nordpass: VaultWriter):
        self.bitwarden = bitwarden
        self.nordpass = nordpass

    def compare(self) -> SyncReport:
        bw = {it.identity_key(): it for it in self.bitwarden.list_items()}
        np = {it.identity_key(): it for it in self.nordpass.list_items()}
        report = SyncReport()

        for key, item in bw.items():
            if key not in np:
                report.only_in_bitwarden.append(self._summ(item))
            else:
                report.in_both.append(self._summ(item))
                # If both have fingerprints and they differ -> password drift.
                other = np[key]
                if (item.password_fingerprint and other.password_fingerprint
                        and item.password_fingerprint != other.password_fingerprint):
                    report.password_drift.append(self._summ(item))

        for key, item in np.items():
            if key not in bw:
                report.only_in_nordpass.append(self._summ(item))

        return report

    @staticmethod
    def _summ(item: VaultItem) -> dict:
        return {"name": item.name, "username": item.username, "url": item.url}
