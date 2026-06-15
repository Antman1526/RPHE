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


def _domain_of(url: str, fallback_name: str) -> str:
    host = urlparse(url or "").hostname or ""
    rd = registrable_domain(host)
    return rd or (fallback_name or "").strip().lower()


def _key(domain: str, username: Optional[str]) -> tuple:
    return (domain, (username or "").strip().lower() or None)


def build_risk_model(scan_signals, vault_logins, breach_hits,
                     *, weak_below_bits: float = 60.0):
    """Merge inputs into AccountRisk rows. Pure; inputs carry no plaintext.

    vault_logins items: {name, username, url, item_id, fingerprint,
                         pwned_count, reuse_count, weak_bits}
    breach_hits items:  {email, domain, password_exposed}
    """
    rows: dict[tuple, AccountRisk] = {}

    def _bump(row: AccountRisk, tier: Tier, reason: str, source: str) -> None:
        row.tier = max(row.tier, tier)
        if reason and reason not in row.reasons:
            row.reasons.append(reason)
        row.sources.add(source)

    # --- vault logins seed the rows ---
    for l in vault_logins:
        domain = _domain_of(l.get("url"), l.get("name", ""))
        k = _key(domain, l.get("username"))
        row = rows.get(k)
        if row is None:
            row = AccountRisk(domain=domain, username=k[1], tier=Tier.LOW,
                              vault_item_id=l.get("item_id"),
                              password_fingerprint=l.get("fingerprint"),
                              managed=True)
            rows[k] = row
        row.sources.add("vault")
        if l.get("pwned_count", 0) > 0:
            _bump(row, Tier.CRITICAL, "password found in breach corpus", "vault")
        reuse = l.get("reuse_count", 1)
        if reuse >= 3:
            _bump(row, Tier.HIGH, f"reused on {reuse} sites", "vault")
        elif reuse == 2:
            _bump(row, Tier.MEDIUM, "reused on 2 sites", "vault")
        bits = l.get("weak_bits")
        if bits is not None and bits < weak_below_bits:
            _bump(row, Tier.MEDIUM, f"weak password (~{bits:.0f} bits)", "vault")

    # ranking happens at render time; return worst-first for convenience
    return sorted(rows.values(), key=lambda r: (-int(r.tier), r.domain))
