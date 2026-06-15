"""Pure risk-model core for the dashboard.

Merges three already-computed inputs — email-scan signals, vault hygiene
findings, and breach hits — into one ranked list of `AccountRisk` rows. This
module does NO I/O and holds NO plaintext: callers pass derived, redactable data
only, so the whole tiering/merge logic is directly unit-testable.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .linksafety import registrable_domain
from .models import BreachSignal, Severity, SignalKind


class Tier(enum.IntEnum):
    """Risk tier, ordered so 'worst wins' is a max(). Distinct from Severity."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AccountRisk:
    domain: str
    username: Optional[str]
    tier: Tier
    reasons: list = field(default_factory=list)
    sources: set = field(default_factory=set)
    vault_item_id: Optional[str] = None
    password_fingerprint: Optional[str] = None
    managed: bool = False
    reset_url_trusted: bool = False
    reset_host: Optional[str] = None
