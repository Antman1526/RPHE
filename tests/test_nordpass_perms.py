"""The NordPass CSV bridge holds plaintext passwords, so the file must never be
readable by other users — not even for the brief moment between creation and a
post-hoc chmod.
"""
import stat
import sys

import pytest

from rphe.models import GeneratedCredential
from rphe.vaults.nordpass import NordPassBridge


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission test")
def test_csv_is_owner_only_and_never_world_readable(tmp_path):
    out = tmp_path / "nordpass.csv"
    bridge = NordPassBridge(export_path=out)
    bridge.upsert(GeneratedCredential(
        service_name="GitHub", username="me@x.com",
        secret="PlaintextPass-123", url="https://github.com"))

    assert out.exists()
    mode = stat.S_IMODE(out.stat().st_mode)
    # No group or other permission bits whatsoever.
    assert mode & 0o077 == 0, oct(mode)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission test")
def test_overwrite_preserves_owner_only_perms(tmp_path):
    out = tmp_path / "nordpass.csv"
    bridge = NordPassBridge(export_path=out)
    bridge.upsert(GeneratedCredential(service_name="A", username="a@x.com",
                                      secret="P1", url="https://a.com"))
    bridge.upsert(GeneratedCredential(service_name="B", username="b@x.com",
                                      secret="P2", url="https://b.com"))
    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode & 0o077 == 0, oct(mode)
