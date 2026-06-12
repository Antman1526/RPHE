"""Tests for the offline .eml folder scanner + the end-to-end classify pipeline."""
from email.message import EmailMessage

from rphe.classifier import classify_many
from rphe.config import EmailAccount
from rphe.models import Severity
from rphe.scanners.eml_scanner import EmlScanner


def _write_eml(path, *, frm, subject, body):
    msg = EmailMessage()
    msg["From"] = frm
    msg["Subject"] = subject
    msg["Date"] = "Mon, 01 Jun 2026 10:00:00 +0000"
    msg["Message-ID"] = f"<{subject[:8]}@test>"
    msg.set_content(body)
    path.write_bytes(bytes(msg))


def test_eml_scanner_reads_folder_and_classifies(tmp_path):
    _write_eml(tmp_path / "breach.eml",
               frm="Security <noreply@dropbox.com>",
               subject="Your data was exposed in a breach",
               body="We detected a data breach. Reset at "
                    "https://dropbox.com/password_reset?token=XYZ now.")
    _write_eml(tmp_path / "newsletter.eml",
               frm="Deals <news@store.com>",
               subject="Weekend sale",
               body="50% off everything.")

    acct = EmailAccount(label="exported", provider="eml", address="",
                        folders=[str(tmp_path)])
    scanner = EmlScanner(acct, store=None)  # eml scanner never touches the store
    messages = list(scanner.fetch())
    assert len(messages) == 2

    signals = classify_many(messages)
    assert len(signals) == 1  # only the breach email is flagged
    assert signals[0].severity == Severity.CRITICAL
    assert signals[0].service_name == "Dropbox"
    # The reset link is extracted but the audit view keeps only the host.
    assert signals[0].reset_url.startswith("https://dropbox.com/password_reset")
    assert "XYZ" not in str(signals[0].to_audit_dict())


def test_eml_scanner_missing_folder_raises(tmp_path):
    acct = EmailAccount(label="x", provider="eml", address="",
                        folders=[str(tmp_path / "nope")])
    import pytest
    with pytest.raises(ValueError):
        list(EmlScanner(acct, store=None).fetch())
