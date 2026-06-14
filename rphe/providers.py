"""Email-provider detection — powers the 'just type your address' Connect flow.

Given an email address, recommend how to connect: the IMAP host (so the user
never types 'imap.gmail.com'), where to make an app password, and whether a
read-only OAuth path exists. This keeps the Connect page simple — type your
address and RPHE fills in the rest.

Pure and dependency-free, so it's easy to unit-test.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProviderInfo:
    key: str                 # 'gmail' | 'outlook' | ... | 'generic'
    name: str                # human label, e.g. 'Gmail'
    imap_host: str = ""      # blank => unknown, ask the user
    imap_port: int = 993
    app_password_url: str = ""   # where the user creates an app password
    oauth: str = ""          # 'gmail' | 'graph' | '' (read-only advanced path)
    note: str = ""           # special guidance (e.g. Proton Bridge)
    spam_folder: str = "Junk"    # IMAP spam/junk folder (alerts often land here)


_GMAIL = ProviderInfo("gmail", "Gmail", "imap.gmail.com", 993,
                      "https://myaccount.google.com/apppasswords", "gmail",
                      spam_folder="[Gmail]/Spam")
_OUTLOOK = ProviderInfo("outlook", "Outlook", "outlook.office365.com", 993,
                        "https://account.live.com/proofs/AppPassword", "graph",
                        spam_folder="Junk Email")
_ICLOUD = ProviderInfo("icloud", "iCloud Mail", "imap.mail.me.com", 993,
                       "https://support.apple.com/102654", spam_folder="Junk")
_YAHOO = ProviderInfo("yahoo", "Yahoo Mail", "imap.mail.yahoo.com", 993,
                      "https://login.yahoo.com/account/security", spam_folder="Bulk Mail")
_FASTMAIL = ProviderInfo("fastmail", "Fastmail", "imap.fastmail.com", 993,
                         "https://www.fastmail.help/hc/en-us/articles/360058752854",
                         spam_folder="Spam")
_AOL = ProviderInfo("aol", "AOL Mail", "imap.aol.com", 993,
                    "https://login.aol.com/account/security", spam_folder="Spam")
_PROTON = ProviderInfo("proton", "Proton Mail", "127.0.0.1", 1143, "", "",
                       "Proton needs the Proton Mail Bridge app running locally; "
                       "use the host and port Bridge shows you.", spam_folder="Spam")

_DOMAINS = {
    "gmail.com": _GMAIL, "googlemail.com": _GMAIL,
    "outlook.com": _OUTLOOK, "hotmail.com": _OUTLOOK, "live.com": _OUTLOOK,
    "msn.com": _OUTLOOK,
    "icloud.com": _ICLOUD, "me.com": _ICLOUD, "mac.com": _ICLOUD,
    "yahoo.com": _YAHOO, "ymail.com": _YAHOO,
    "fastmail.com": _FASTMAIL, "fastmail.fm": _FASTMAIL,
    "aol.com": _AOL,
    "proton.me": _PROTON, "protonmail.com": _PROTON, "pm.me": _PROTON,
}


def detect_provider(email: str) -> ProviderInfo:
    """Return the best-known connection info for an email address.

    Unknown domains fall back to a generic IMAP entry (host left blank for the
    user to fill). Never raises.
    """
    domain = ""
    if email and "@" in email:
        domain = email.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    info = _DOMAINS.get(domain)
    if info:
        return info
    return ProviderInfo(key="generic", name=(domain or "your provider"),
                        note="Enter your provider's IMAP host (often imap.<domain>).")


def suggested_label(email: str) -> str:
    """A friendly account label derived from the address (e.g. 'you-gmail')."""
    if not email or "@" not in email:
        return "inbox"
    local, domain = email.rsplit("@", 1)
    stem = domain.split(".")[0].lower()
    local = "".join(c for c in local.lower() if c.isalnum() or c in "._-") or "inbox"
    return f"{local}-{stem}"
