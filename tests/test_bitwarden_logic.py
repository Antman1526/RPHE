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

    @staticmethod
    def _dec(enc):
        return json.loads(base64.b64decode(enc))

    def run(self, args, *, stdin=None, with_session=True):
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
            obj = self._dec(args[2]); self.counter += 1
            obj["id"] = f"id{self.counter}"; self.items[obj["id"]] = obj
            return json.dumps(obj)
        if args[:2] == ["edit", "item"]:
            obj = self._dec(args[3]); obj["id"] = args[2]
            self.items[obj["id"]] = obj
            return json.dumps(obj)
        return "[]"


class FakeStore:
    def __init__(self):
        self.data = {"bitwarden.session": "sess"}

    @staticmethod
    def bitwarden_session_key():
        return "bitwarden.session"

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
