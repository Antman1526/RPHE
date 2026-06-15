"""Persist the dashboard risk model as a redacted, 0600 JSON snapshot.

Stored: derived risk metadata only (domain, username, tier, reasons, sources,
vault_item_id, 8-char password_fingerprint, managed, reset_host). NEVER stored:
plaintext passwords or tokened reset URLs. A final audit._redact pass scrubs the
free-text reason strings.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .audit import _redact
from .risk import AccountRisk, Tier

SNAPSHOT_NAME = "risk_snapshot.json"


@dataclass
class RiskSnapshot:
    generated_at: str
    sources: dict = field(default_factory=dict)
    accounts: list = field(default_factory=list)   # list[AccountRisk]


def _row_to_dict(r: AccountRisk) -> dict:
    return {
        "domain": r.domain,
        "username": r.username,
        "tier": r.tier.name,
        "reasons": [_redact(x) for x in r.reasons],
        "sources": sorted(r.sources),
        "vault_item_id": r.vault_item_id,
        "password_fingerprint": r.password_fingerprint,
        "managed": r.managed,
        "reset_url_trusted": r.reset_url_trusted,
        "reset_host": r.reset_host,
    }


def _row_from_dict(d: dict) -> AccountRisk:
    return AccountRisk(
        domain=d["domain"], username=d.get("username"),
        tier=Tier[d["tier"]], reasons=list(d.get("reasons") or []),
        sources=set(d.get("sources") or []),
        vault_item_id=d.get("vault_item_id"),
        password_fingerprint=d.get("password_fingerprint"),
        managed=bool(d.get("managed")),
        reset_url_trusted=bool(d.get("reset_url_trusted")),
        reset_host=d.get("reset_host"))


def snapshot_to_dict(s: RiskSnapshot) -> dict:
    return {"generated_at": s.generated_at, "sources": s.sources,
            "accounts": [_row_to_dict(r) for r in s.accounts]}


def snapshot_from_dict(d: dict) -> RiskSnapshot:
    return RiskSnapshot(
        generated_at=d.get("generated_at", ""),
        sources=d.get("sources") or {},
        accounts=[_row_from_dict(r) for r in (d.get("accounts") or [])])


def _path(data_dir) -> Path:
    return Path(data_dir) / SNAPSHOT_NAME


def save_snapshot(data_dir, snap: RiskSnapshot) -> Path:
    """Atomically write the snapshot at 0600 (POSIX)."""
    path = _path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    mode = 0o600 if sys.platform != "win32" else 0o666
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(snapshot_to_dict(snap), fh, ensure_ascii=False, indent=2)
    if sys.platform != "win32":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def load_snapshot(data_dir) -> "RiskSnapshot | None":
    """Load the snapshot, or None if absent/corrupt (treated as 'never run')."""
    path = _path(data_dir)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            return snapshot_from_dict(json.load(fh))
    except (json.JSONDecodeError, OSError, KeyError):
        return None
