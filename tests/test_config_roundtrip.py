"""The GUI Settings screen relies on save_config -> load_config round-tripping."""
import pytest

yaml = pytest.importorskip("yaml")  # save/load need PyYAML

from rphe.config import (Config, EmailAccount, PasswordPolicy, load_config,
                         save_config)


def test_save_load_roundtrip(tmp_path):
    cfg = Config(
        accounts=[
            EmailAccount(label="g", provider="gmail", address="me@gmail.com",
                         lookback_days=14),
            EmailAccount(label="fm", provider="imap", address="me@fastmail.com",
                         imap_host="imap.fastmail.com", imap_port=993,
                         folders=["INBOX", "Archive"], lookback_days=60),
        ],
        policy=PasswordPolicy(length=30, passphrase_mode=True, passphrase_words=7),
        bitwarden_folder="MyFolder",
        automate_resets=True,
    )
    path = tmp_path / "config.yaml"
    save_config(cfg, path)
    loaded = load_config(path)

    assert len(loaded.accounts) == 2
    assert loaded.accounts[0].label == "g"
    assert loaded.accounts[1].imap_host == "imap.fastmail.com"
    assert loaded.accounts[1].folders == ["INBOX", "Archive"]
    assert loaded.policy.length == 30
    assert loaded.policy.passphrase_mode is True
    assert loaded.policy.passphrase_words == 7
    assert loaded.bitwarden_folder == "MyFolder"
    assert loaded.automate_resets is True


def test_save_writes_no_secrets(tmp_path):
    cfg = Config(accounts=[EmailAccount(label="x", provider="imap",
                                        address="a@b.com")])
    path = tmp_path / "config.yaml"
    save_config(cfg, path)
    text = path.read_text()
    # Sanity: the YAML should never contain secret-bearing keys.
    for forbidden in ("password", "token", "secret", "api_key"):
        assert forbidden not in text.lower()
