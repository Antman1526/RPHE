"""Bitwarden integration via the official `bw` CLI.

Bitwarden is the AUTOMATED SOURCE OF TRUTH: it has a first-party, cross-platform
CLI with a documented, stable JSON interface. We never touch the master password
in plaintext beyond piping it to `bw unlock` — the returned session key is held
in the OS keystore and passed via the BW_SESSION env var for the process
lifetime.

Security notes:
  * The new password is passed to `bw` via STDIN (encoded item JSON), never as a
    command-line argument (argv is visible to other processes via `ps`).
  * We `bw sync` after writes so other devices converge.
  * Secrets are scrubbed from any error text before they bubble up.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models import GeneratedCredential, VaultItem
from ..secrets import SecretStore
from .base import VaultError, VaultWriter

# Bitwarden item type 1 == Login.
_LOGIN_TYPE = 1


def _prepare_bundled(path: Path) -> None:
    """Make a bundled bw runnable: ensure +x and clear macOS quarantine.

    An unsigned app's nested binary can be blocked by Gatekeeper; best-effort
    stripping of the quarantine xattr lets it exec. All failures are ignored.
    """
    try:
        if sys.platform != "win32":
            import stat as _stat
            path.chmod(path.stat().st_mode | _stat.S_IEXEC | _stat.S_IXGRP | _stat.S_IXOTH)
        if sys.platform == "darwin":
            subprocess.run(["xattr", "-d", "com.apple.quarantine", str(path)],
                           capture_output=True, timeout=5)
    except Exception:
        pass


def find_bw() -> Optional[str]:
    """Locate the Bitwarden CLI, preferring a binary bundled with the app.

    Order: $RPHE_BW_PATH → bundled (PyInstaller _MEIPASS / next to the exe) →
    a system `bw` on PATH. Returns None if nothing is found.
    """
    name = "bw.exe" if sys.platform == "win32" else "bw"
    override = os.environ.get("RPHE_BW_PATH")
    if override and Path(override).exists():
        return override
    if getattr(sys, "frozen", False):
        candidates = []
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / name)
        candidates.append(Path(sys.executable).resolve().parent / name)
        for cand in candidates:
            if cand.exists():
                _prepare_bundled(cand)
                return str(cand)
    return shutil.which(name) or shutil.which("bw")


class BitwardenVault(VaultWriter):
    name = "bitwarden"

    def __init__(self, store: SecretStore, folder_name: str = "RPHE-Rotated",
                 timeout: int = 60):
        self.store = store
        self.folder_name = folder_name
        self.timeout = timeout
        self._session: Optional[str] = None
        self._folder_id: Optional[str] = None
        self.bw = find_bw()
        if not self.bw:
            raise VaultError(
                "Bitwarden CLI 'bw' not found. The packaged app bundles it; if you "
                "are running from source, install it:\n"
                "  macOS:   brew install bitwarden-cli\n"
                "  Windows: winget install Bitwarden.CLI   (or: npm i -g @bitwarden/cli)\n"
                "  or set RPHE_BW_PATH to a bw binary."
            )

    # --- low-level command runner ------------------------------------------
    def _run(self, args: list[str], *, stdin: Optional[str] = None,
             with_session: bool = True) -> str:
        env = {"BW_NOINTERACTIVE": "true"}
        if with_session:
            env["BW_SESSION"] = self._require_session()
        import os
        full_env = {**os.environ, **env}
        try:
            proc = subprocess.run(
                [self.bw, *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=full_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise VaultError(f"bw {args[0]} timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            # Never echo stdin (could contain the password JSON).
            raise VaultError(
                f"bw {args[0]} failed (exit {proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    # --- status / login (used by the GUI setup screen) ---------------------
    def status(self) -> dict:
        """Return `bw status` as a dict: status is one of
        'unauthenticated' | 'locked' | 'unlocked'. Never needs a session.
        """
        try:
            out = self._run(["status"], with_session=False)
            return json.loads(out or "{}")
        except (VaultError, json.JSONDecodeError):
            return {"status": "unknown"}

    def login_apikey(self, client_id: str, client_secret: str) -> None:
        """Authenticate with a Bitwarden personal API key (client id/secret).

        Avoids interactive email+password+2FA. Credentials are passed via env,
        never argv. After this you still must unlock() with the master password.
        """
        import os
        env = {**os.environ, "BW_NOINTERACTIVE": "true",
               "BW_CLIENTID": client_id, "BW_CLIENTSECRET": client_secret}
        proc = subprocess.run(
            [self.bw, "login", "--apikey"],
            capture_output=True, text=True, timeout=self.timeout, env=env)
        if proc.returncode != 0 and "already logged in" not in proc.stderr.lower():
            raise VaultError(f"Bitwarden API-key login failed: {proc.stderr.strip()}")

    # --- session management -------------------------------------------------
    def unlock(self, master_password: Optional[str] = None) -> None:
        """Unlock the vault and cache the session key in the OS keystore.

        If master_password is None we look for a stored one (opt-in unattended
        mode); otherwise the caller is expected to have prompted for it.
        """
        # Reuse a cached session if it still validates.
        cached = self.store.get(self.store.bitwarden_session_key())
        if cached:
            self._session = cached
            try:
                self._run(["sync"])  # cheap call that requires a valid session
                return
            except VaultError:
                self._session = None  # stale; fall through to re-unlock

        if master_password is None:
            master_password = self.store.get(self.store.bitwarden_master_key())
        if not master_password:
            raise VaultError(
                "Bitwarden is locked and no master password was provided. "
                "Run `rphe vault unlock` to enter it interactively."
            )
        # Password goes in via STDIN (keeps it off argv, which `ps` can read).
        session = self._unlock_stdin(master_password)
        self._session = session
        self.store.set(self.store.bitwarden_session_key(), session)

    def _unlock_stdin(self, master_password: str) -> str:
        import os
        env = {**os.environ, "BW_NOINTERACTIVE": "true"}
        proc = subprocess.run(
            [self.bw, "unlock", "--raw"],
            input=master_password + "\n",
            capture_output=True, text=True, timeout=self.timeout, env=env,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise VaultError("Bitwarden unlock failed: check master password / login status.")
        return proc.stdout.strip()

    def _require_session(self) -> str:
        if not self._session:
            self._session = self.store.get(self.store.bitwarden_session_key())
        if not self._session:
            raise VaultError("Bitwarden vault is locked. Call unlock() first.")
        return self._session

    # --- folders ------------------------------------------------------------
    def _ensure_folder(self) -> str:
        if self._folder_id:
            return self._folder_id
        folders = json.loads(self._run(["list", "folders"]) or "[]")
        for f in folders:
            if f.get("name") == self.folder_name:
                self._folder_id = f["id"]
                return self._folder_id
        # Create it.
        template = json.loads(self._run(["get", "template", "folder"]))
        template["name"] = self.folder_name
        encoded = self._encode(template)
        created = json.loads(self._run(["create", "folder", encoded]))
        self._folder_id = created["id"]
        return self._folder_id

    @staticmethod
    def _encode(obj: dict) -> str:
        import base64
        return base64.b64encode(json.dumps(obj).encode()).decode()

    # --- VaultWriter API ----------------------------------------------------
    def _find_existing(self, cred: GeneratedCredential) -> Optional[dict]:
        items = json.loads(self._run(["list", "items", "--search", cred.service_name]) or "[]")
        want = VaultItem(name=cred.service_name, username=cred.username, url=cred.url).identity_key()
        for it in items:
            login = it.get("login") or {}
            uris = login.get("uris") or []
            url = uris[0]["uri"] if uris else None
            vi = VaultItem(name=it.get("name", ""), username=login.get("username") or "", url=url)
            if vi.identity_key() == want:
                return it
        return None

    # --- custom-field helpers (RPHE rotation status) -----------------------
    @staticmethod
    def _get_field(item: dict, name: str) -> Optional[str]:
        for f in item.get("fields") or []:
            if f.get("name") == name:
                return f.get("value")
        return None

    @staticmethod
    def _set_field(item: dict, name: str, value: str) -> None:
        fields = item.setdefault("fields", []) or []
        for f in fields:
            if f.get("name") == name:
                f["value"] = value
                return
        fields.append({"name": name, "value": value, "type": 0})
        item["fields"] = fields

    def upsert(self, cred: GeneratedCredential, status: str = "pending") -> VaultItem:
        """Create/update a login. Lockout-safe: the previous password is pushed
        into Bitwarden's passwordHistory and the item is tagged
        rphe_status=<status> so an abandoned reset can be reverted/confirmed.
        """
        folder_id = self._ensure_folder()
        existing = self._find_existing(cred)
        now = (cred.created_at or datetime.now(timezone.utc)).isoformat()

        if existing:
            existing.setdefault("login", {})
            old_pw = existing["login"].get("password")
            if old_pw and old_pw != cred.secret:
                history = existing["login"].get("passwordHistory") or []
                history.insert(0, {"lastUsedDate": now, "password": old_pw})
                existing["login"]["passwordHistory"] = history[:20]
            existing["login"]["password"] = cred.secret
            existing["login"]["username"] = cred.username
            if cred.url:
                existing["login"]["uris"] = [{"match": None, "uri": cred.url}]
            existing["notes"] = (cred.notes or existing.get("notes") or "")
            self._set_field(existing, "rphe_status", status)
            self._set_field(existing, "rphe_rotated_at", now)
            out = json.loads(self._run(["edit", "item", existing["id"],
                                        self._encode(existing)]))
        else:
            template = json.loads(self._run(["get", "template", "item"]))
            template.update({
                "type": _LOGIN_TYPE,
                "name": cred.service_name,
                "folderId": folder_id,
                "notes": cred.notes or f"Rotated by RPHE at {now}",
                "login": {
                    "username": cred.username,
                    "password": cred.secret,
                    "uris": [{"match": None, "uri": cred.url}] if cred.url else [],
                },
                "fields": [
                    {"name": "rphe_status", "value": status, "type": 0},
                    {"name": "rphe_rotated_at", "value": now, "type": 0},
                ],
            })
            out = json.loads(self._run(["create", "item", self._encode(template)]))

        self._run(["sync"])  # converge other devices
        login = out.get("login") or {}
        uris = login.get("uris") or []
        import hashlib
        return VaultItem(
            name=out.get("name", cred.service_name),
            username=login.get("username") or cred.username,
            url=(uris[0]["uri"] if uris else cred.url),
            item_id=out.get("id"),
            password_fingerprint=hashlib.sha256(cred.secret.encode()).hexdigest()[:8],
        )

    # --- pending / confirm / revert ----------------------------------------
    def set_status(self, item_id: str, status: str) -> None:
        item = json.loads(self._run(["get", "item", item_id]))
        self._set_field(item, "rphe_status", status)
        self._run(["edit", "item", item_id, self._encode(item)])
        self._run(["sync"])

    def revert(self, item_id: str) -> bool:
        """Restore the previous password from passwordHistory. Returns False if
        there's nothing to revert to. Never returns/logs the plaintext.
        """
        item = json.loads(self._run(["get", "item", item_id]))
        history = (item.get("login") or {}).get("passwordHistory") or []
        if not history:
            return False
        prev = history[0].get("password")
        if not prev:
            return False
        item["login"]["password"] = prev
        item["login"]["passwordHistory"] = history[1:]
        self._set_field(item, "rphe_status", "reverted")
        self._run(["edit", "item", item_id, self._encode(item)])
        self._run(["sync"])
        return True

    def list_pending(self) -> list[VaultItem]:
        out = []
        for it in json.loads(self._run(["list", "items"]) or "[]"):
            if it.get("type") != _LOGIN_TYPE:
                continue
            if self._get_field(it, "rphe_status") == "pending":
                login = it.get("login") or {}
                uris = login.get("uris") or []
                out.append(VaultItem(
                    name=it.get("name", ""), username=login.get("username") or "",
                    url=(uris[0]["uri"] if uris else None), item_id=it.get("id")))
        return out

    def audit_logins(self) -> list[dict]:
        """Return every login with the data the vault audit needs. The password
        is included (plaintext, in memory only) so the engine can run the free
        breach + strength checks; the engine must NOT persist or log it.
        """
        out = []
        for it in json.loads(self._run(["list", "items"]) or "[]"):
            if it.get("type") != _LOGIN_TYPE:
                continue
            login = it.get("login") or {}
            uris = login.get("uris") or []
            out.append({
                "item_id": it.get("id"),
                "name": it.get("name", ""),
                "username": login.get("username") or "",
                "url": (uris[0]["uri"] if uris else None),
                "password": login.get("password") or "",
            })
        return out

    def list_items(self) -> list[VaultItem]:
        raw = json.loads(self._run(["list", "items"]) or "[]")
        out: list[VaultItem] = []
        for it in raw:
            if it.get("type") != _LOGIN_TYPE:
                continue
            login = it.get("login") or {}
            uris = login.get("uris") or []
            out.append(VaultItem(
                name=it.get("name", ""),
                username=login.get("username") or "",
                url=(uris[0]["uri"] if uris else None),
                item_id=it.get("id"),
                has_password=bool(login.get("password")),
                # We can fingerprint the live password to detect drift vs NordPass.
                password_fingerprint=(
                    __import__("hashlib").sha256(login["password"].encode()).hexdigest()[:8]
                    if login.get("password") else None
                ),
            ))
        return out
