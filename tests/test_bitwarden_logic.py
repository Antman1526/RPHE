"""Bitwarden upsert/revert/pending logic, tested against a fake `bw` CLI.

No real Bitwarden or `bw` binary is needed: we bypass __init__ and stub the
low-level _run() with an in-memory store that interprets the same commands.
"""
import base64
import json
import threading
from datetime import datetime, timezone

from rphe.models import GeneratedCredential
from rphe.vaults.bitwarden import BitwardenVault


class FakeBw:
    def __init__(self):
        self.items = {}
        self.counter = 0
        self.status_email = None   # what `bw status` reports as the logged-in user
        self.argv_log = []         # every argv list `bw` was invoked with
        self.stdin_log = []        # every stdin payload (encoded items live here)

    @staticmethod
    def _dec(enc):
        return json.loads(base64.b64decode(enc))

    def run(self, args, *, stdin=None, with_session=True):
        self.argv_log.append(list(args))
        if stdin is not None:
            self.stdin_log.append(stdin)
        if args[:1] == ["status"]:
            return json.dumps({"status": "unlocked", "userEmail": self.status_email})
        if args[:1] == ["sync"] or args[:1] == ["lock"]:
            return ""
        if args[:3] == ["get", "template", "item"]:
            return json.dumps({"type": 1, "name": "", "notes": "",
                               "login": {"username": "", "password": "", "uris": []},
                               "fields": []})
        if args[:2] == ["list", "items"]:
            return json.dumps(list(self.items.values()))
        if args[:2] == ["get", "item"]:
            return json.dumps(self.items[args[2]])
        if args[:2] == ["create", "item"]:
            # Encoded item now arrives via STDIN, never as an argv argument.
            obj = self._dec(stdin); self.counter += 1
            obj["id"] = f"id{self.counter}"; self.items[obj["id"]] = obj
            return json.dumps(obj)
        if args[:2] == ["edit", "item"]:
            obj = self._dec(stdin); obj["id"] = args[2]
            self.items[obj["id"]] = obj
            return json.dumps(obj)
        return "[]"


class FakeStore:
    def __init__(self):
        self.data = {"bitwarden.session": "sess"}

    @staticmethod
    def bitwarden_session_key():
        return "bitwarden.session"

    @staticmethod
    def bitwarden_account_key():
        return "bitwarden.account_email"

    @staticmethod
    def bitwarden_master_key():
        return "bitwarden.master_password"

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


def _vault():
    v = BitwardenVault.__new__(BitwardenVault)
    v.bw = "/fake/bw"
    v.folder_name = "RPHE-Rotated"
    v.timeout = 10
    v._session = "sess"
    v._folder_id = "fld1"          # skip folder creation
    v._oplock = threading.RLock()  # normally set in __init__ (bypassed here)
    v.store = FakeStore()
    fake = FakeBw()
    v._run = fake.run
    return v, fake


def test_lock_clears_session():
    v, fake = _vault()
    v.lock()
    assert v._session is None
    assert "bitwarden.session" not in v.store.data


def _cred(pw, svc="GitHub", user="me@x.com"):
    return GeneratedCredential(service_name=svc, username=user, secret=pw,
                              url="https://github.com",
                              created_at=datetime(2026, 6, 1, tzinfo=timezone.utc))


def test_upsert_new_is_pending():
    v, fake = _vault()
    item = v.upsert(_cred("FirstPass-111"))
    stored = fake.items[item.item_id]
    assert stored["login"]["password"] == "FirstPass-111"
    assert v._get_field(stored, "rphe_status") == "pending"


def test_upsert_existing_pushes_old_into_history():
    v, fake = _vault()
    first = v.upsert(_cred("OldPass-111"))
    v.upsert(_cred("NewPass-222"))           # same identity -> update
    stored = fake.items[first.item_id]
    assert stored["login"]["password"] == "NewPass-222"
    assert stored["login"]["passwordHistory"][0]["password"] == "OldPass-111"


def test_revert_restores_previous_password():
    v, fake = _vault()
    item = v.upsert(_cred("OldPass-111"))
    v.upsert(_cred("NewPass-222"))
    assert v.revert(item.item_id) is True
    stored = fake.items[item.item_id]
    assert stored["login"]["password"] == "OldPass-111"
    assert v._get_field(stored, "rphe_status") == "reverted"


def test_revert_without_history_returns_false():
    v, fake = _vault()
    item = v.upsert(_cred("OnlyPass-111"))   # brand new, no history
    assert v.revert(item.item_id) is False


def test_confirm_sets_status():
    v, fake = _vault()
    item = v.upsert(_cred("P-111"))
    v.set_status(item.item_id, "confirmed")
    assert v._get_field(fake.items[item.item_id], "rphe_status") == "confirmed"


def test_list_pending_filters():
    v, fake = _vault()
    a = v.upsert(_cred("P-111", svc="A"))
    b = v.upsert(_cred("P-222", svc="B"))
    v.set_status(b.item_id, "confirmed")
    pending = v.list_pending()
    names = {p.name for p in pending}
    assert "A" in names and "B" not in names


def test_unlock_reuses_cached_session_and_binds_account():
    # No account recorded yet: a valid cached session is reused and bound to the
    # current account (trust-on-first-use).
    v, fake = _vault()
    fake.status_email = "alice@example.com"
    v._session = None                       # force the cached-session path
    v.unlock()
    assert v._session == "sess"             # reused, no re-unlock
    assert v.store.data["bitwarden.account_email"] == "alice@example.com"


def test_unlock_rejects_session_from_a_different_account():
    # A valid session whose recorded account no longer matches the logged-in
    # account must be discarded and a fresh unlock performed (H3).
    v, fake = _vault()
    v.store.data["bitwarden.account_email"] = "alice@example.com"
    v.store.data["bitwarden.master_password"] = "pw"   # enable re-unlock
    fake.status_email = "bob@evil.example"            # account swapped out
    v._unlock_stdin = lambda pw: "newsess"            # avoid real `bw` exec
    v._session = None
    v.unlock()
    assert v._session == "newsess"                    # re-unlocked, not reused
    assert v.store.data["bitwarden.session"] == "newsess"
    assert v.store.data["bitwarden.account_email"] == "bob@evil.example"


def test_unlock_fails_closed_when_bound_account_unreadable():
    # An account is bound, but `bw status` returns no email (current=None). We
    # must NOT reuse the cached session on faith — discard it and re-unlock.
    v, fake = _vault()
    v.store.data["bitwarden.account_email"] = "alice@example.com"
    v.store.data["bitwarden.master_password"] = "pw"
    fake.status_email = None                          # account can't be confirmed
    reunlocked = {"called": False}

    def _fake_unlock(pw):
        reunlocked["called"] = True
        return "freshsess"

    v._unlock_stdin = _fake_unlock
    v._session = None
    v.unlock()
    assert reunlocked["called"] is True               # did NOT trust the session
    assert v._session == "freshsess"


def test_verify_present_requires_matching_password_fingerprint():
    # Same identity but a different password must NOT verify — "verified" has to
    # mean the new secret is actually stored, not just that the login exists.
    v, fake = _vault()
    v.upsert(_cred("Stored-Pass-111"))
    assert v.verify_present(_cred("Stored-Pass-111")) is True
    assert v.verify_present(_cred("Different-Pass-999")) is False


def _argv_contains_secret(argv_log, secret):
    """True if the plaintext password (or its base64 encoding) appears in argv."""
    for argv in argv_log:
        for a in argv:
            if secret in a:
                return True
            # Defensive: any base64 blob in argv that decodes to contain the pw.
            try:
                if secret in base64.b64decode(a).decode("utf-8", "ignore"):
                    return True
            except Exception:
                pass
    return False


def test_create_never_puts_password_on_argv():
    # CRITICAL (H1): the encoded item carrying the new plaintext password must
    # travel via STDIN, never as a command-line argument (argv is world-visible
    # via `ps` / /proc/<pid>/cmdline).
    v, fake = _vault()
    secret = "SuperSecret-Create-999"
    v.upsert(_cred(secret))
    assert not _argv_contains_secret(fake.argv_log, secret)
    # ...and it really did go through stdin (base64-encoded item payload).
    def _stdin_has(secret):
        for s in fake.stdin_log:
            try:
                if secret in base64.b64decode(s).decode("utf-8", "ignore"):
                    return True
            except Exception:
                pass
        return False
    assert _stdin_has(secret)


def test_edit_and_revert_never_put_password_on_argv():
    v, fake = _vault()
    v.upsert(_cred("OldPass-111"))
    v.upsert(_cred("NewPass-222"))     # edit path
    item = v.list_pending()[0]
    v.set_status(item.item_id, "confirmed")
    v.revert(item.item_id)             # revert path restores OldPass-111
    for secret in ("OldPass-111", "NewPass-222"):
        assert not _argv_contains_secret(fake.argv_log, secret)


def test_run_redacts_secrets_in_error_text():
    # HIGH (H2): if `bw` exits non-zero and echoes secret-looking text to stderr,
    # it must be scrubbed before bubbling up into an exception / the GUI.
    import subprocess
    from rphe.vaults.base import VaultError
    from rphe.vaults import bitwarden as bw_mod

    v = BitwardenVault.__new__(BitwardenVault)
    v.bw = "/fake/bw"
    v.timeout = 5
    v._session = "sess"
    v.store = FakeStore()

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = 'error: password=Hunter2Plaintext token=abc123 failed'

    def _fake_subprocess_run(*a, **k):
        return _Proc()

    orig = subprocess.run
    bw_mod.subprocess.run = _fake_subprocess_run
    try:
        try:
            v._run(["edit", "item", "x"], stdin="whatever")
            assert False, "expected VaultError"
        except VaultError as exc:
            msg = str(exc)
            assert "Hunter2Plaintext" not in msg
            assert "redacted" in msg.lower()
    finally:
        bw_mod.subprocess.run = orig
