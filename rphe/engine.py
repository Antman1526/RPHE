"""Headless service layer shared by the CLI and the GUI.

Centralizing the operations here means both front-ends run *identical* logic —
no behavior drift between `rphe rotate` and the GUI's Rotate button. The engine
owns lazy construction of the vaults / breach checker and never holds plaintext
beyond the moment it hands a credential to a vault.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .audit import AuditLog
from .breach import BreachChecker
from .classifier import classify_many
from .config import Config, load_config
from .models import BreachSignal, GeneratedCredential, Severity, VaultItem
from .passkeys import PasskeyAdvice, advise
from .passwords import generate_candidates
from .secrets import SecretStore


@dataclass
class RotationResult:
    service_name: str
    username: str
    bitwarden_ok: bool
    bitwarden_id: Optional[str]
    nordpass_staged: bool
    verified: bool
    passkey: PasskeyAdvice
    error: Optional[str] = None


@dataclass
class AccountBreachStatus:
    name: str
    username: str
    breached: bool
    breach_titles: list


class Engine:
    def __init__(self, cfg: Optional[Config] = None,
                 store: Optional[SecretStore] = None,
                 audit: Optional[AuditLog] = None):
        self.cfg = cfg or load_config()
        self.store = store or SecretStore()
        self.audit = audit or AuditLog(self.cfg.resolved_data_dir)
        self._bw = None
        self._np = None

    # --- lazy backends ------------------------------------------------------
    def bitwarden(self):
        if self._bw is None:
            from .vaults import BitwardenVault
            self._bw = BitwardenVault(self.store, self.cfg.bitwarden_folder)
        return self._bw

    def nordpass(self):
        if self._np is None:
            from .vaults import NordPassBridge
            self._np = NordPassBridge(self.cfg.resolved_nordpass_export,
                                      self.cfg.bitwarden_folder)
        return self._np

    def breach_checker(self) -> BreachChecker:
        return BreachChecker(api_key=self.store.get(self.store.hibp_api_key()))

    def unlock_bitwarden(self, master_password: Optional[str] = None) -> None:
        self.bitwarden().unlock(master_password)
        self.audit.event("bitwarden.unlock", result="ok")

    # --- email scan ---------------------------------------------------------
    def scan(self, min_severity: Severity = Severity.MEDIUM) -> list:
        from .scanners import build_scanner
        raw: list[dict] = []
        for account in self.cfg.accounts:
            try:
                for msg in build_scanner(account, self.store).fetch():
                    raw.append(msg)
            except Exception as exc:
                self.audit.event("scan.account_error", account=account.label,
                                 detail=str(exc))
        signals = [s for s in classify_many(raw) if s.severity >= min_severity]
        self.audit.event("scan", flagged=len(signals),
                         signals=[s.to_audit_dict() for s in signals])
        return signals

    # --- breach detection ---------------------------------------------------
    def vault_accounts(self) -> list:
        """Accounts already stored in Bitwarden (requires it to be unlocked)."""
        return self.bitwarden().list_items()

    def check_password_pwned(self, password: str) -> int:
        return self.breach_checker().pwned_password_count(password)

    def check_accounts_breached(self, emails: list) -> list:
        """For each email, look up HIBP breaches (needs an API key)."""
        checker = self.breach_checker()
        results: list[AccountBreachStatus] = []
        for email in emails:
            try:
                breaches = checker.account_breaches(email)
                results.append(AccountBreachStatus(
                    name=email, username=email, breached=bool(breaches),
                    breach_titles=[b.title for b in breaches]))
            except Exception as exc:
                self.audit.event("breach.lookup_error", account=email,
                                 detail=str(exc))
                results.append(AccountBreachStatus(
                    name=email, username=email, breached=False, breach_titles=[]))
        self.audit.event("breach.check", checked=len(emails),
                         breached=sum(1 for r in results if r.breached))
        return results

    # --- password candidates (vetted against breaches) ---------------------
    def password_candidates(self, n: int = 5, vet_pwned: bool = True) -> list:
        reject = None
        if vet_pwned and self.store.get(self.store.hibp_api_key()) is not None:
            pass  # key presence irrelevant for the free password check
        if vet_pwned:
            checker = self.breach_checker()

            def reject(pw: str) -> bool:
                try:
                    return checker.is_pwned(pw)  # free k-anonymity check
                except Exception:
                    return False  # network down → don't block generation
        return generate_candidates(self.cfg.policy, n=n, reject=reject)

    # --- rotation -----------------------------------------------------------
    def rotate(self, *, service_name: str, username: str, password: str,
               url: Optional[str] = None, kind: str = "manual") -> RotationResult:
        cred = GeneratedCredential(
            service_name=service_name, username=username, secret=password,
            url=url,
            notes=f"Rotated by RPHE ({kind}) on {datetime.now(timezone.utc):%Y-%m-%d}",
            created_at=datetime.now(timezone.utc))
        domain = (url or "").replace("https://", "").replace("http://", "").strip("/")
        pk = advise(service_name, domain)

        try:
            item = self.bitwarden().upsert(cred)
            verified = self.bitwarden().verify_present(cred)
            self.audit.event("vault.write", vault="bitwarden",
                             **cred.to_safe_dict(),
                             result="ok" if verified else "unverified")
        except Exception as exc:
            self.audit.event("vault.write", vault="bitwarden",
                             service=service_name, result="error", detail=str(exc))
            return RotationResult(service_name, username, False, None, False,
                                  False, pk, error=str(exc))

        np_ok = True
        try:
            self.nordpass().upsert(cred)
            self.audit.event("vault.write", vault="nordpass-csv",
                             **cred.to_safe_dict(), result="staged")
        except Exception as exc:
            np_ok = False
            self.audit.event("vault.write", vault="nordpass-csv",
                             service=service_name, result="error", detail=str(exc))

        return RotationResult(service_name, username, True, item.item_id, np_ok,
                              verified, pk)

    # --- sync ---------------------------------------------------------------
    def sync_report(self):
        from .vaults import SyncVerifier
        return SyncVerifier(self.bitwarden(), self.nordpass()).compare()

    def passkey_advice(self, service_name: str, domain: str) -> PasskeyAdvice:
        return advise(service_name, domain)
