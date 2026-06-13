"""Typed domain models shared across the whole pipeline.

Using dataclasses (stdlib) keeps the dependency surface small. Every model that
can carry a secret marks it explicitly so the audit layer can redact it.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so we can sort/filter by risk. Higher == more urgent."""
    INFO = 0          # informational, e.g. "new sign-in on a trusted device"
    LOW = 1           # routine security notice
    MEDIUM = 2        # password-reset prompt, unusual-but-explained activity
    HIGH = 3          # suspicious login / access-from-new-location alert
    CRITICAL = 4      # confirmed breach / data-leak notification

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.upper()]


class SignalKind(enum.Enum):
    """What *kind* of security event an email represents."""
    BREACH_NOTICE = "breach_notice"
    SUSPICIOUS_LOGIN = "suspicious_login"
    NEW_DEVICE_LOGIN = "new_device_login"
    PASSWORD_RESET_PROMPT = "password_reset_prompt"
    MFA_CHALLENGE = "mfa_challenge"
    DATA_LEAK = "data_leak"
    UNKNOWN = "unknown"


@dataclass
class BreachSignal:
    """A single classified email that may indicate a compromised account.

    This is the normalized output of *any* scanner (IMAP / Gmail / Graph), so
    the rest of the pipeline never needs to know where the mail came from.
    """
    message_id: str
    service_name: str                 # best-guess human name, e.g. "GitHub"
    sender_domain: str                # e.g. "github.com"
    subject: str
    received_at: datetime
    kind: SignalKind
    severity: Severity
    reset_url: Optional[str] = None   # extracted self-service reset link, if any
    account_hint: Optional[str] = None  # the email/username the alert targets
    rationale: str = ""               # why the classifier flagged it (for audit)
    raw_snippet: str = ""             # short body excerpt, never the full body
    reset_url_trusted: bool = True    # anti-phishing: link host matches sender?
    reset_url_note: str = ""          # explanation of the trust decision

    def to_audit_dict(self) -> dict:
        import re
        from urllib.parse import urlparse

        d = asdict(self)
        d["received_at"] = self.received_at.isoformat()
        d["kind"] = self.kind.value
        d["severity"] = self.severity.name
        # reset_url can contain a single-use token — keep only the host for logs.
        if self.reset_url:
            d["reset_url"] = urlparse(self.reset_url).hostname or "<redacted>"
        # The body snippet can also embed reset links/tokens — collapse any URL
        # down to its host so nothing single-use survives in the audit record.
        if d.get("raw_snippet"):
            d["raw_snippet"] = re.sub(
                r"https?://([^/\s?#]+)\S*",
                lambda m: f"https://{m.group(1)}/<redacted>",
                d["raw_snippet"],
            )
        return d


@dataclass
class GeneratedCredential:
    """A newly minted credential. `secret` is NEVER serialized to disk/logs."""
    service_name: str
    username: str
    secret: str = field(repr=False)   # repr hidden so it can't leak via print()
    url: Optional[str] = None
    notes: str = ""
    created_at: Optional[datetime] = None

    def to_safe_dict(self) -> dict:
        """Audit-safe view — secret replaced with its length + a fingerprint."""
        import hashlib
        fp = hashlib.sha256(self.secret.encode()).hexdigest()[:8]
        return {
            "service_name": self.service_name,
            "username": self.username,
            "url": self.url,
            "secret": f"<{len(self.secret)} chars sha256:{fp}>",
        }


@dataclass
class VaultItem:
    """A credential as it exists inside a vault (Bitwarden or NordPass)."""
    name: str
    username: str
    url: Optional[str] = None
    has_password: bool = True
    item_id: Optional[str] = None     # provider-native id (Bitwarden only)
    password_fingerprint: Optional[str] = None  # sha256[:8] for drift compare

    def identity_key(self) -> str:
        """Stable key used to match the same logical item across vaults."""
        host = (self.url or "").lower().replace("https://", "").replace("http://", "").strip("/")
        return f"{self.name.strip().lower()}|{self.username.strip().lower()}|{host}"


@dataclass
class SyncReport:
    in_both: list = field(default_factory=list)
    only_in_bitwarden: list = field(default_factory=list)
    only_in_nordpass: list = field(default_factory=list)
    password_drift: list = field(default_factory=list)  # same item, different secret

    @property
    def is_consistent(self) -> bool:
        return not (self.only_in_bitwarden or self.only_in_nordpass or self.password_drift)
