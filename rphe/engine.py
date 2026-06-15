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
    breach_domains: list = None  # type: ignore[assignment]
    password_exposed: bool = False

    def __post_init__(self):
        if self.breach_domains is None:
            self.breach_domains = []


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

    def lock_bitwarden(self) -> None:
        """Lock the Bitwarden vault and clear the cached session (auto-lock/exit)."""
        try:
            self.bitwarden().lock()
            self.audit.event("bitwarden.lock", result="ok")
        except Exception as exc:
            self.audit.event("bitwarden.lock", result="error", detail=str(exc))

    # --- email scan ---------------------------------------------------------
    def scan_detailed(self, min_severity: Severity = Severity.MEDIUM):
        """Scan all inboxes. Returns (signals, errors) where errors is a list of
        {label, error} for inboxes that couldn't be checked — so a silent failure
        isn't mistaken for 'all clear'.
        """
        from .scanners import build_scanner
        raw: list[dict] = []
        errors: list[dict] = []
        for account in self.cfg.accounts:
            try:
                for msg in build_scanner(account, self.store).fetch():
                    raw.append(msg)
            except Exception as exc:
                errors.append({"label": account.label, "error": str(exc)})
                self.audit.event("scan.account_error", account=account.label,
                                 detail=str(exc))
        signals = [s for s in classify_many(raw) if s.severity >= min_severity]
        self.audit.event("scan", flagged=len(signals), errors=len(errors),
                         signals=[s.to_audit_dict() for s in signals])
        return signals, errors

    def scan(self, min_severity: Severity = Severity.MEDIUM) -> list:
        return self.scan_detailed(min_severity)[0]

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
                    breach_titles=[b.title for b in breaches],
                    breach_domains=[b.domain for b in breaches if b.domain],
                    password_exposed=any("Passwords" in (b.data_classes or [])
                                         for b in breaches)))
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

        # Full hash (not truncated) so distinct passwords can't collide and be
        # mislabelled "reused".
        by_fp: dict[str, list] = {}
        for l in logins:
            if l["password"]:
                fp = hashlib.sha256(l["password"].encode()).hexdigest()
                by_fp.setdefault(fp, []).append(l["name"])

        pwned_cache: dict[str, int] = {}
        findings = []
        structured = []
        for l in logins:
            pw = l["password"]
            if not pw:
                continue
            fp = hashlib.sha256(pw.encode()).hexdigest()
            pwned = 0
            if check_pwned:
                if fp not in pwned_cache:
                    try:
                        pwned_cache[fp] = checker.pwned_password_count(pw)
                    except Exception:
                        pwned_cache[fp] = 0
                pwned = pwned_cache[fp]
            reuse = len(by_fp.get(fp, []))
            bits = password_strength_bits(pw)
            structured.append({                            # plaintext-free row
                "name": l["name"], "username": l["username"],
                "url": l.get("url"), "item_id": l["item_id"],
                "fingerprint": fp[:8], "pwned_count": pwned,
                "reuse_count": reuse, "weak_bits": float(bits)})
            issues = []
            if pwned > 0:
                issues.append(f"breached×{pwned}")
            if reuse > 1:
                issues.append("reused")
            if bits < weak_below_bits:
                issues.append(f"weak (~{bits:.0f} bits)")
            if issues:
                findings.append({"name": l["name"], "username": l["username"],
                                 "item_id": l["item_id"], "url": l.get("url"),
                                 "issues": issues})
        self.audit.event("vault.audit", scanned=len(logins), flagged=len(findings))
        return {"scanned": len(logins), "findings": findings, "logins": structured}

    # --- sync ---------------------------------------------------------------
    def sync_report(self):
        from .vaults import SyncVerifier
        return SyncVerifier(self.bitwarden(), self.nordpass()).compare()

    def passkey_advice(self, service_name: str, domain: str) -> PasskeyAdvice:
        return advise(service_name, domain)

    # --- setup diagnostics ("Test my setup" / `rphe doctor`) ----------------
    def diagnose(self) -> list:
        """Probe every integration and return a list of {name, ok, detail}.
        Does real network/subprocess work — run it off the UI thread.
        """
        import keyring

        from .scanners import build_scanner
        checks = []

        try:
            checks.append({"name": "OS keychain", "ok": True,
                           "detail": keyring.get_keyring().__class__.__name__})
        except Exception as exc:
            checks.append({"name": "OS keychain", "ok": False, "detail": str(exc)[:140]})

        st = self.bitwarden_status()
        s = st.get("status", "unknown")
        detail = {"missing-cli": "Bitwarden CLI not found",
                  "unauthenticated": "not signed in",
                  "locked": "signed in (locked — unlock to use)",
                  "unlocked": f"unlocked ✓ {st.get('userEmail', '')}".strip()}.get(s, s)
        checks.append({"name": "Bitwarden", "ok": s in ("unlocked", "locked"), "detail": detail})

        if not self.cfg.accounts:
            checks.append({"name": "Email", "ok": False, "detail": "no inbox configured yet"})
        for a in self.cfg.accounts:
            try:
                checks.append({"name": f"Email · {a.label}", "ok": True,
                               "detail": build_scanner(a, self.store).check()})
            except Exception as exc:
                checks.append({"name": f"Email · {a.label}", "ok": False, "detail": str(exc)[:140]})

        try:
            checker = self.breach_checker()
            checker.pwned_password_count("password")   # free; verifies HIBP reachability
            if self.store.get(self.store.hibp_api_key()):
                checker.account_breaches("account-exists@hibp-integration-tests.com")
                checks.append({"name": "Breach DB (HIBP)", "ok": True,
                               "detail": "reachable, API key valid"})
            else:
                checks.append({"name": "Breach DB (HIBP)", "ok": True,
                               "detail": "reachable (no key — email lookups disabled)"})
        except Exception as exc:
            checks.append({"name": "Breach DB (HIBP)", "ok": False, "detail": str(exc)[:140]})

        try:
            p = self.cfg.resolved_nordpass_export
            p.parent.mkdir(parents=True, exist_ok=True)
            t = p.parent / ".rphe_write_test"
            t.write_text("ok")
            t.unlink()
            checks.append({"name": "NordPass CSV path", "ok": True, "detail": str(p.parent)})
        except Exception as exc:
            checks.append({"name": "NordPass CSV path", "ok": False, "detail": str(exc)[:140]})

        self.audit.event("diagnose",
                         results=[{"name": c["name"], "ok": c["ok"]} for c in checks])
        return checks

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

    def forget_account_secrets(self, label: str) -> None:
        """Remove every keychain secret tied to an inbox (app password, OAuth
        token, Graph client id) so removing an inbox actually revokes access."""
        for key in (self.store.imap_password_key(label),
                    self.store.oauth_token_key(label),
                    f"graph.{label}.client_id"):
            self.store.delete(key)

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
