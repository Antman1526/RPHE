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

    # --- lockout-safe rotation lifecycle -----------------------------------
    def list_pending(self) -> list:
        """Rotations written to the vault but not yet confirmed working."""
        return self.bitwarden().list_pending()

    def confirm_rotation(self, item_id: str) -> None:
        self.bitwarden().set_status(item_id, "confirmed")
        self.audit.event("rotation.confirm", item_id=item_id)

    def revert_rotation(self, item_id: str) -> bool:
        """Roll a vault item back to its previous password (e.g. reset abandoned)."""
        ok = self.bitwarden().revert(item_id)
        self.audit.event("rotation.revert", item_id=item_id, result="ok" if ok else "no-history")
        return ok

    # --- vault-wide audit (weak / reused / breached) -----------------------
    def audit_vault(self, check_pwned: bool = True, weak_below_bits: int = 60) -> dict:
        """Audit EVERY Bitwarden login for breached, reused and weak passwords.

        Uses the free HIBP k-anonymity check (no password leaves the machine) and
        a charset-entropy heuristic. Plaintext is read into memory for the checks
        and never persisted or logged — only issue flags + counts are returned.
        """
        import hashlib

        from .passwords import password_strength_bits
        logins = self.bitwarden().audit_logins()
        checker = self.breach_checker()

        by_fp: dict[str, list] = {}
        for l in logins:
            if l["password"]:
                fp = hashlib.sha256(l["password"].encode()).hexdigest()[:8]
                by_fp.setdefault(fp, []).append(l["name"])

        pwned_cache: dict[str, int] = {}
        findings = []
        for l in logins:
            pw = l["password"]
            if not pw:
                continue
            fp = hashlib.sha256(pw.encode()).hexdigest()[:8]
            issues = []
            if check_pwned:
                if fp not in pwned_cache:
                    try:
                        pwned_cache[fp] = checker.pwned_password_count(pw)
                    except Exception:
                        pwned_cache[fp] = 0
                if pwned_cache[fp] > 0:
                    issues.append(f"breached×{pwned_cache[fp]}")
            if len(by_fp.get(fp, [])) > 1:
                issues.append("reused")
            bits = password_strength_bits(pw)
            if bits < weak_below_bits:
                issues.append(f"weak (~{bits:.0f} bits)")
            if issues:
                findings.append({"name": l["name"], "username": l["username"],
                                 "item_id": l["item_id"], "issues": issues})
        self.audit.event("vault.audit", scanned=len(logins), flagged=len(findings))
        return {"scanned": len(logins), "findings": findings}

    # --- sync ---------------------------------------------------------------
    def sync_report(self):
        from .vaults import SyncVerifier
        return SyncVerifier(self.bitwarden(), self.nordpass()).compare()

    def passkey_advice(self, service_name: str, domain: str) -> PasskeyAdvice:
        return advise(service_name, domain)

    # --- setup helpers (used by the GUI Settings screen) -------------------
    def save(self, cfg: Optional[Config] = None) -> None:
        """Persist config to disk and adopt it as the live config."""
        from .config import save_config
        cfg = cfg or self.cfg
        save_config(cfg)
        self.cfg = cfg
        self._np = None  # paths may have changed

    @staticmethod
    def bitwarden_available() -> bool:
        from .vaults.bitwarden import find_bw
        return find_bw() is not None

    def bitwarden_status(self) -> dict:
        if not self.bitwarden_available():
            return {"status": "missing-cli"}
        return self.bitwarden().status()

    def bitwarden_login_apikey(self, client_id: str, client_secret: str) -> None:
        self.bitwarden().login_apikey(client_id, client_secret)
        self.audit.event("bitwarden.login", method="apikey", result="ok")

    def set_hibp_key(self, key: str) -> None:
        self.store.set(self.store.hibp_api_key(), key)

    def set_imap_app_password(self, account_label: str, password: str) -> None:
        self.store.set(self.store.imap_password_key(account_label), password)

    def connect_gmail(self, label: str, client_secret_path: str) -> str:
        """Run the Gmail OAuth flow (opens a browser) and store the token.

        Returns the verified account email. Raises with a clear message if the
        Google libraries aren't available in this build.
        """
        try:
            from google_auth_oauthlib.flow import InstalledAppFlow
        except ImportError as exc:
            raise RuntimeError(
                "Gmail OAuth needs the Google libraries. In a source install run "
                "`pip install \".[gmail]\"`. (IMAP works without them.)") from exc
        from .scanners.gmail_scanner import SCOPES, GmailScanner
        flow = InstalledAppFlow.from_client_secrets_file(client_secret_path, SCOPES)
        creds = flow.run_local_server(port=0, prompt="consent")
        self.store.set(self.store.oauth_token_key(label), creds.to_json())
        from .config import EmailAccount
        acct = next((a for a in self.cfg.accounts if a.label == label),
                    EmailAccount(label=label, provider="gmail", address=""))
        info = GmailScanner(acct, self.store).profile()
        self.audit.event("auth.gmail", label=label, result="ok")
        return info.get("emailAddress", "")

    def connect_graph(self, label: str, client_id: str, on_message) -> None:
        """Run the Microsoft Graph device-code flow.

        `on_message(text)` is called with the 'go to URL and enter code' message
        so the GUI can display it; this then blocks until the user completes it.
        """
        try:
            import msal
        except ImportError as exc:
            raise RuntimeError(
                "Outlook OAuth needs msal. In a source install run "
                "`pip install \".[graph]\"`. (IMAP works without it.)") from exc
        from .scanners.graph_scanner import SCOPES
        self.store.set(f"graph.{label}.client_id", client_id)
        cache = msal.SerializableTokenCache()
        app = msal.PublicClientApplication(
            client_id, authority="https://login.microsoftonline.com/common",
            token_cache=cache)
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(f"Device flow failed: {flow.get('error_description')}")
        on_message(flow["message"])
        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(f"Auth failed: {result.get('error_description')}")
        self.store.set(self.store.oauth_token_key(label), cache.serialize())
        self.audit.event("auth.graph", label=label, result="ok")
