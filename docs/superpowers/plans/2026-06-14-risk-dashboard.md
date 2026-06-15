# Risk dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tiered, explainable risk dashboard that merges email-scan signals, vault password-hygiene audit, and breach checks into one ranked list of at-risk accounts with a lockout-safe one-click rotate, surfaced via a `rphe dashboard` CLI command and a GUI tab.

**Architecture:** A pure `build_risk_model()` core (no I/O) turns three already-existing engine outputs into `AccountRisk` rows; a redacted 0600 `RiskSnapshot` persists them; `engine.build_dashboard()` loads-or-recomputes and `engine.rotate_from_dashboard()` delegates to the existing `rotate()`. CLI and GUI are thin consumers.

**Tech Stack:** Python 3.11+ stdlib (dataclasses, enum, json, hashlib, urllib), Typer + Rich (CLI), customtkinter (GUI), pytest.

**Spec:** `docs/superpowers/specs/2026-06-14-risk-dashboard-design.md`

---

## File structure

- `rphe/risk.py` (new) — `Tier` enum, `AccountRisk` dataclass, `build_risk_model()`. Pure, no I/O. Depends only on `models` + `linksafety`.
- `rphe/snapshot.py` (new) — `RiskSnapshot` dataclass + `save_snapshot()` / `load_snapshot()` (redacted, 0600 atomic). Depends on `risk` + `audit._redact`.
- `rphe/engine.py` (modify) — enrich `audit_vault()` with a plaintext-free `logins` list; add `password_exposed` to `AccountBreachStatus`; add `build_dashboard()` and `rotate_from_dashboard()`.
- `rphe/cli.py` (modify) — add the `dashboard` command; warm the snapshot from `scan-notify`.
- `rphe/gui.py` (modify) — add a `risk` nav entry + `_page_risk` + `on_risk_refresh` / `_render_risk`.
- `tests/test_risk_model.py`, `tests/test_snapshot.py`, `tests/test_dashboard_engine.py` (new).
- version bump to 0.9.0; `README.md`.

A note on data contracts (decided during planning):
- `build_risk_model` takes plain inputs to avoid an `engine → risk` import cycle: `scan_signals: list[BreachSignal]`, `vault_logins: list[dict]`, `breach_hits: list[dict]`.
- `vault_logins` item shape: `{"name","username","url","item_id","fingerprint","pwned_count","reuse_count","weak_bits"}` (no plaintext).
- `breach_hits` item shape: `{"email","domain","password_exposed"}`.

---

### Task 1: `Tier` + `AccountRisk` skeleton

**Files:**
- Create: `rphe/risk.py`
- Test: `tests/test_risk_model.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_risk_model.py
from rphe.risk import Tier, AccountRisk


def test_tier_is_ordered_critical_highest():
    assert Tier.CRITICAL > Tier.HIGH > Tier.MEDIUM > Tier.LOW
    assert max(Tier.LOW, Tier.CRITICAL, Tier.MEDIUM) is Tier.CRITICAL


def test_account_risk_defaults():
    r = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH)
    assert r.reasons == [] and r.sources == set()
    assert r.managed is False and r.password_fingerprint is None
    assert r.reset_url_trusted is False and r.reset_host is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'rphe.risk'`

- [ ] **Step 3: Write minimal implementation**

```python
# rphe/risk.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add rphe/risk.py tests/test_risk_model.py
git commit -m "feat(risk): Tier enum + AccountRisk model"
```

---

### Task 2: `build_risk_model` — vault rows + hygiene tiering

Implements rows from `vault_logins` with CRITICAL (pwned), HIGH (reuse >=3 / weak+exposure), MEDIUM (weak alone / reuse==2), LOW (clean). Exposure for "weak + exposure" comes from inbox/breach in later tasks, so in this task weak-alone is MEDIUM.

**Files:**
- Modify: `rphe/risk.py`
- Test: `tests/test_risk_model.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_risk_model.py
from rphe.risk import build_risk_model


def _login(name, user, url, fp, pwned=0, reuse=1, bits=80.0, item="id1"):
    return {"name": name, "username": user, "url": url, "item_id": item,
            "fingerprint": fp, "pwned_count": pwned, "reuse_count": reuse,
            "weak_bits": bits}


def test_clean_login_is_low_and_managed():
    rows = build_risk_model([], [_login("GitHub", "me@x.com", "https://github.com", "aaaa1111")], [])
    assert len(rows) == 1
    r = rows[0]
    assert r.domain == "github.com" and r.username == "me@x.com"
    assert r.tier is Tier.LOW and r.managed is True
    assert r.vault_item_id == "id1" and r.password_fingerprint == "aaaa1111"
    assert "vault" in r.sources


def test_pwned_password_is_critical():
    rows = build_risk_model([], [_login("Dropbox", "me@x.com", "https://dropbox.com", "bbbb", pwned=3)], [])
    assert rows[0].tier is Tier.CRITICAL
    assert any("breach corpus" in r for r in rows[0].reasons)


def test_widespread_reuse_is_high_exact_two_is_medium():
    high = build_risk_model([], [_login("A", "me@x.com", "https://a.com", "f", reuse=3)], [])
    med = build_risk_model([], [_login("B", "me@x.com", "https://b.com", "f", reuse=2)], [])
    assert high[0].tier is Tier.HIGH and any("reused" in r for r in high[0].reasons)
    assert med[0].tier is Tier.MEDIUM


def test_weak_password_alone_is_medium():
    rows = build_risk_model([], [_login("C", "me@x.com", "https://c.com", "f", bits=40.0)], [])
    assert rows[0].tier is Tier.MEDIUM
    assert any("weak" in r for r in rows[0].reasons)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: FAIL with `ImportError: cannot import name 'build_risk_model'`

- [ ] **Step 3: Implement**

```python
# append to rphe/risk.py

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
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/risk.py tests/test_risk_model.py
git commit -m "feat(risk): vault hygiene tiering (pwned/reuse/weak)"
```

---

### Task 3: `build_risk_model` — inbox signal merge

Domain-level inbox signals fan out to all logins on that domain; if none, create an unmanaged row. Inbox tier derives from `signal.severity` mapped to `Tier`; "weak + exposure" promotion is applied here (a weak managed row that also has an inbox/breach exposure becomes HIGH).

**Files:**
- Modify: `rphe/risk.py`
- Test: `tests/test_risk_model.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_risk_model.py
from datetime import datetime, timezone


def _sig(service, sender_domain, kind, severity, hint=None, reset_url=None, trusted=True):
    return BreachSignal(
        message_id="m", service_name=service, sender_domain=sender_domain,
        subject="x", received_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        kind=kind, severity=severity, reset_url=reset_url, account_hint=hint,
        reset_url_trusted=trusted)


def test_inbox_only_service_creates_unmanaged_row():
    rows = build_risk_model(
        [_sig("LinkedIn", "linkedin.com", SignalKind.BREACH_NOTICE, Severity.CRITICAL)],
        [], [])
    assert len(rows) == 1
    r = rows[0]
    assert r.domain == "linkedin.com" and r.managed is False
    assert r.tier is Tier.CRITICAL and "inbox" in r.sources


def test_domain_inbox_signal_attaches_to_matching_vault_login():
    rows = build_risk_model(
        [_sig("GitHub", "github.com", SignalKind.SUSPICIOUS_LOGIN, Severity.HIGH)],
        [_login("GitHub", "me@x.com", "https://github.com", "f")], [])
    assert len(rows) == 1                      # merged, not duplicated
    r = rows[0]
    assert r.managed is True and r.tier is Tier.HIGH
    assert {"vault", "inbox"} <= r.sources


def test_trusted_reset_link_recorded_as_host_only():
    rows = build_risk_model(
        [_sig("GitHub", "github.com", SignalKind.PASSWORD_RESET_PROMPT, Severity.MEDIUM,
              reset_url="https://github.com/reset?token=SECRET", trusted=True)],
        [], [])
    r = rows[0]
    assert r.reset_url_trusted is True and r.reset_host == "github.com"
    assert "SECRET" not in str(r.__dict__)     # token never retained
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: FAIL (unmanaged row not created / not merged)

- [ ] **Step 3: Implement** — insert this block in `build_risk_model` *after* the vault loop and *before* the `return`:

```python
    _SEV_TO_TIER = {
        Severity.CRITICAL: Tier.CRITICAL,
        Severity.HIGH: Tier.HIGH,
        Severity.MEDIUM: Tier.MEDIUM,
        Severity.LOW: Tier.LOW,
        Severity.INFO: Tier.LOW,
    }

    def _domain_rows(domain: str):
        return [r for (d, _u), r in rows.items() if d == domain]

    # --- inbox signals merge onto / create rows ---
    for s in scan_signals:
        domain = registrable_domain(s.sender_domain or "")
        if not domain:
            continue
        tier = _SEV_TO_TIER.get(s.severity, Tier.LOW)
        reason = (s.kind.value.replace("_", " ") + " email").capitalize()
        targets = []
        if s.account_hint:
            k = _key(domain, s.account_hint)
            if k in rows:
                targets = [rows[k]]
        if not targets:
            targets = _domain_rows(domain)
        if not targets:
            k = _key(domain, s.account_hint)
            row = AccountRisk(domain=domain, username=k[1], tier=Tier.LOW,
                              managed=False)
            rows[k] = row
            targets = [row]
        for row in targets:
            _bump(row, tier, reason, "inbox")
            if s.reset_url and s.reset_url_trusted and not row.reset_host:
                row.reset_url_trusted = True
                row.reset_host = registrable_domain(urlparse(s.reset_url).hostname or "")
            # weak managed password + any exposure -> promote to HIGH
            if row.managed and any("weak password" in x for x in row.reasons):
                _bump(row, Tier.HIGH, "weak password with active exposure", "inbox")
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/risk.py tests/test_risk_model.py
git commit -m "feat(risk): merge inbox signals (fan-out + unmanaged rows)"
```

---

### Task 4: `build_risk_model` — breach-email merge

Only password-exposing breaches with a domain contribute (CRITICAL); attach to the matching service row or create an unmanaged row keyed `(breach_domain, email)`.

**Files:**
- Modify: `rphe/risk.py`
- Test: `tests/test_risk_model.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_risk_model.py
def test_password_exposing_breach_is_critical_and_can_be_unmanaged():
    rows = build_risk_model(
        [], [],
        [{"email": "me@x.com", "domain": "dropbox.com", "password_exposed": True}])
    assert len(rows) == 1
    r = rows[0]
    assert r.domain == "dropbox.com" and r.username == "me@x.com"
    assert r.tier is Tier.CRITICAL and r.managed is False
    assert "breach_email" in r.sources
    assert any("breach" in x for x in r.reasons)


def test_non_password_breach_is_ignored():
    rows = build_risk_model(
        [], [],
        [{"email": "me@x.com", "domain": "forum.com", "password_exposed": False}])
    assert rows == []


def test_breach_attaches_to_existing_vault_row():
    rows = build_risk_model(
        [], [_login("Dropbox", "me@x.com", "https://dropbox.com", "f")],
        [{"email": "me@x.com", "domain": "dropbox.com", "password_exposed": True}])
    assert len(rows) == 1 and rows[0].tier is Tier.CRITICAL
    assert {"vault", "breach_email"} <= rows[0].sources
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: FAIL

- [ ] **Step 3: Implement** — insert after the inbox block, before `return`:

```python
    # --- breach-email hits (only password-exposing ones) ---
    for h in breach_hits:
        if not h.get("password_exposed"):
            continue
        domain = registrable_domain(h.get("domain") or "")
        email = h.get("email")
        if not domain:
            continue
        k = _key(domain, email)
        row = rows.get(k)
        if row is None:
            existing = _domain_rows(domain)
            if existing:
                for r in existing:
                    _bump(r, Tier.CRITICAL,
                          "email in a breach that exposed passwords", "breach_email")
                continue
            row = AccountRisk(domain=domain, username=k[1], tier=Tier.LOW,
                              managed=False)
            rows[k] = row
        _bump(row, Tier.CRITICAL,
              "email in a breach that exposed passwords", "breach_email")
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_risk_model.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/risk.py tests/test_risk_model.py
git commit -m "feat(risk): merge password-exposing breach hits"
```

---

### Task 5: `RiskSnapshot` model + (de)serialization with redaction

**Files:**
- Create: `rphe/snapshot.py`
- Test: `tests/test_snapshot.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_snapshot.py
from rphe.risk import AccountRisk, Tier
from rphe.snapshot import RiskSnapshot, snapshot_to_dict, snapshot_from_dict


def _snap():
    row = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH,
                      reasons=["reused on 3 sites"], sources={"vault"},
                      vault_item_id="id1", password_fingerprint="aaaa1111",
                      managed=True, reset_url_trusted=True, reset_host="github.com")
    return RiskSnapshot(generated_at="2026-06-14T20:00:00Z",
                        sources={"vault": {"ok": True}}, accounts=[row])


def test_roundtrip_preserves_fields():
    d = snapshot_to_dict(_snap())
    back = snapshot_from_dict(d)
    r = back.accounts[0]
    assert r.tier is Tier.HIGH and r.password_fingerprint == "aaaa1111"
    assert r.sources == {"vault"} and r.managed is True


def test_serialized_dict_has_fingerprint_but_no_secret_keys():
    d = snapshot_to_dict(_snap())
    blob = str(d)
    assert "aaaa1111" in blob                    # fingerprint kept
    assert "password" not in d["accounts"][0]    # no plaintext field name
    assert "reset_url" not in d["accounts"][0]   # only reset_host is kept
    assert d["accounts"][0]["reset_host"] == "github.com"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_snapshot.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'rphe.snapshot'`

- [ ] **Step 3: Implement**

```python
# rphe/snapshot.py
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_snapshot.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/snapshot.py tests/test_snapshot.py
git commit -m "feat(snapshot): RiskSnapshot model + redacted (de)serialization"
```

---

### Task 6: snapshot persistence (0600 atomic write + load)

**Files:**
- Modify: `rphe/snapshot.py`
- Test: `tests/test_snapshot.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_snapshot.py
import sys
import stat
from rphe.snapshot import save_snapshot, load_snapshot


def test_save_then_load_roundtrip(tmp_path):
    save_snapshot(tmp_path, _snap())
    back = load_snapshot(tmp_path)
    assert back is not None and back.accounts[0].domain == "github.com"


def test_missing_snapshot_loads_none(tmp_path):
    assert load_snapshot(tmp_path) is None


def test_saved_file_is_0600(tmp_path):
    if sys.platform == "win32":
        return
    save_snapshot(tmp_path, _snap())
    mode = stat.S_IMODE((tmp_path / "risk_snapshot.json").stat().st_mode)
    assert mode == 0o600
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_snapshot.py -q`
Expected: FAIL with `ImportError: cannot import name 'save_snapshot'`

- [ ] **Step 3: Implement** — append to `rphe/snapshot.py`:

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_snapshot.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/snapshot.py tests/test_snapshot.py
git commit -m "feat(snapshot): 0600 atomic save + tolerant load"
```

---

### Task 7: enrich `audit_vault` with a plaintext-free `logins` list + `password_exposed`

**Files:**
- Modify: `rphe/engine.py:208-255` (`audit_vault`) and `rphe/engine.py:36-46` (`AccountBreachStatus`) and `rphe/engine.py:121-139` (`check_accounts_breached`)
- Test: `tests/test_dashboard_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dashboard_engine.py
import hashlib
from rphe.engine import Engine


class _Bw:
    def __init__(self, logins):
        self._logins = logins
    def audit_logins(self):
        return self._logins


class _Checker:
    def pwned_password_count(self, pw):
        return 5 if pw == "pwned" else 0


def _engine_with(logins, monkeypatch, tmp_path):
    from rphe.config import Config
    eng = Engine(cfg=Config(data_dir=str(tmp_path)))
    eng._bw = _Bw(logins)
    monkeypatch.setattr(eng, "breach_checker", lambda: _Checker())
    return eng


def test_audit_vault_returns_structured_logins(monkeypatch, tmp_path):
    logins = [{"item_id": "id1", "name": "A", "username": "me@x.com",
               "url": "https://a.com", "password": "pwned"},
              {"item_id": "id2", "name": "B", "username": "me@x.com",
               "url": "https://b.com", "password": "pwned"}]
    eng = _engine_with(logins, monkeypatch, tmp_path)
    out = eng.audit_vault()
    assert out["scanned"] == 2
    structured = {l["item_id"]: l for l in out["logins"]}
    a = structured["id1"]
    assert a["pwned_count"] == 5 and a["reuse_count"] == 2
    assert a["fingerprint"] == hashlib.sha256(b"pwned").hexdigest()[:8]
    assert "password" not in a            # no plaintext leaks into the structured row
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: FAIL (`KeyError: 'logins'`)

- [ ] **Step 3: Implement**

In `audit_vault`, build a per-login structured list alongside `findings`. Replace the `return` and add the structured list. The full method body becomes (key additions marked):

```python
    def audit_vault(self, check_pwned: bool = True, weak_below_bits: int = 60) -> dict:
        import hashlib

        from .passwords import password_strength_bits
        logins = self.bitwarden().audit_logins()
        checker = self.breach_checker()

        by_fp: dict[str, list] = {}
        for l in logins:
            if l["password"]:
                fp = hashlib.sha256(l["password"].encode()).hexdigest()
                by_fp.setdefault(fp, []).append(l["name"])

        pwned_cache: dict[str, int] = {}
        findings = []
        structured = []                                    # NEW
        for l in logins:
            pw = l["password"]
            if not pw:
                continue
            fp = hashlib.sha256(pw.encode()).hexdigest()
            pwned = 0
            if check_pwned:
                if fp not in pwned_cache:
                    try:
                        pwned_cache[fp] = checker.pwned_password_count(pw)
                    except Exception:
                        pwned_cache[fp] = 0
                pwned = pwned_cache[fp]
            reuse = len(by_fp.get(fp, []))
            bits = password_strength_bits(pw)
            structured.append({                            # NEW (no plaintext)
                "name": l["name"], "username": l["username"],
                "url": l.get("url"), "item_id": l["item_id"],
                "fingerprint": fp[:8], "pwned_count": pwned,
                "reuse_count": reuse, "weak_bits": float(bits)})
            issues = []
            if pwned > 0:
                issues.append(f"breached×{pwned}")
            if reuse > 1:
                issues.append("reused")
            if bits < weak_below_bits:
                issues.append(f"weak (~{bits:.0f} bits)")
            if issues:
                findings.append({"name": l["name"], "username": l["username"],
                                 "item_id": l["item_id"], "url": l.get("url"),
                                 "issues": issues})
        self.audit.event("vault.audit", scanned=len(logins), flagged=len(findings))
        return {"scanned": len(logins), "findings": findings, "logins": structured}
```

Then add `password_exposed` to `AccountBreachStatus` (default False) and set it in
`check_accounts_breached`:

```python
@dataclass
class AccountBreachStatus:
    name: str
    username: str
    breached: bool
    breach_titles: list
    breach_domains: list = None  # type: ignore[assignment]
    password_exposed: bool = False        # NEW

    def __post_init__(self):
        if self.breach_domains is None:
            self.breach_domains = []
```

In `check_accounts_breached`, when building the success result:

```python
                results.append(AccountBreachStatus(
                    name=email, username=email, breached=bool(breaches),
                    breach_titles=[b.title for b in breaches],
                    breach_domains=[b.domain for b in breaches if b.domain],
                    password_exposed=any("Passwords" in (b.data_classes or [])
                                         for b in breaches)))   # NEW
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: PASS. Also run the existing audit test: `.venv/bin/python -m pytest tests/ -q` — all green (the added dict key is additive).

- [ ] **Step 5: Commit**

```bash
git add rphe/engine.py tests/test_dashboard_engine.py
git commit -m "feat(engine): structured plaintext-free logins + password_exposed"
```

---

### Task 8: `engine.build_dashboard` (load / recompute with per-source degradation)

**Files:**
- Modify: `rphe/engine.py` (add method + imports)
- Test: `tests/test_dashboard_engine.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_dashboard_engine.py
from rphe.models import BreachSignal, SignalKind, Severity
from datetime import datetime, timezone


def test_build_dashboard_refresh_persists_and_degrades(monkeypatch, tmp_path):
    logins = [{"item_id": "id1", "name": "A", "username": "me@x.com",
               "url": "https://a.com", "password": "pwned"}]
    eng = _engine_with(logins, monkeypatch, tmp_path)
    monkeypatch.setattr(eng, "scan_detailed", lambda min_severity=Severity.MEDIUM: ([], []))
    # no HIBP key -> breach_email source unavailable, others still build
    monkeypatch.setattr(eng.store, "get", lambda k: None)
    snap = eng.build_dashboard(refresh=True)
    assert snap.sources["vault"]["ok"] is True
    assert snap.sources["breach_email"]["ok"] is False
    assert any(r.tier.name == "CRITICAL" for r in snap.accounts)
    # persisted: a fresh load returns it
    from rphe.snapshot import load_snapshot
    assert load_snapshot(tmp_path) is not None


def test_build_dashboard_vault_locked_is_partial(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    def _boom(*a, **k):
        raise RuntimeError("vault locked")
    monkeypatch.setattr(eng, "audit_vault", _boom)
    monkeypatch.setattr(eng, "scan_detailed",
                        lambda min_severity=Severity.MEDIUM: (
                            [BreachSignal(message_id="m", service_name="LinkedIn",
                             sender_domain="linkedin.com", subject="x",
                             received_at=datetime(2026,6,1,tzinfo=timezone.utc),
                             kind=SignalKind.BREACH_NOTICE, severity=Severity.CRITICAL)], []))
    monkeypatch.setattr(eng.store, "get", lambda k: None)
    snap = eng.build_dashboard(refresh=True)
    assert snap.sources["vault"]["ok"] is False
    assert any(r.domain == "linkedin.com" for r in snap.accounts)   # still built


def test_build_dashboard_no_refresh_returns_cached(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    assert eng.build_dashboard(refresh=False) is None        # never run yet
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: FAIL (`AttributeError: build_dashboard`)

- [ ] **Step 3: Implement** — add to `Engine` (and `from .risk import build_risk_model`, `from .snapshot import RiskSnapshot, load_snapshot, save_snapshot` at the top of engine.py):

```python
    def build_dashboard(self, refresh: bool = False):
        """Return a RiskSnapshot. refresh=False loads the cached snapshot (or
        None if never run); refresh=True recomputes each source independently,
        builds the risk model, persists, and returns it."""
        from .risk import build_risk_model
        from .snapshot import RiskSnapshot, load_snapshot, save_snapshot
        if not refresh:
            return load_snapshot(self.cfg.resolved_data_dir)

        now = datetime.now(timezone.utc).isoformat()
        sources: dict = {}

        try:
            signals, errors = self.scan_detailed()
            sources["inbox"] = {"at": now, "ok": not errors, "errors": errors}
        except Exception as exc:
            signals = []
            sources["inbox"] = {"at": now, "ok": False, "errors": [{"error": str(exc)}]}

        vault_logins = []
        try:
            vault_logins = self.audit_vault().get("logins", [])
            sources["vault"] = {"at": now, "ok": True}
        except Exception as exc:
            sources["vault"] = {"at": now, "ok": False, "reason": str(exc)}

        breach_hits = []
        if self.store.get(self.store.hibp_api_key()):
            emails = sorted({l["username"] for l in vault_logins
                             if l.get("username") and "@" in l["username"]}
                            | {a.address for a in self.cfg.accounts if a.address})
            try:
                for st in self.check_accounts_breached(list(emails)):
                    for dom in st.breach_domains:
                        breach_hits.append({"email": st.username, "domain": dom,
                                            "password_exposed": st.password_exposed})
                sources["breach_email"] = {"at": now, "ok": True}
            except Exception as exc:
                sources["breach_email"] = {"at": now, "ok": False, "reason": str(exc)}
        else:
            sources["breach_email"] = {"at": now, "ok": False,
                                       "reason": "no HIBP API key"}

        accounts = build_risk_model(signals, vault_logins, breach_hits)
        snap = RiskSnapshot(generated_at=now, sources=sources, accounts=accounts)
        save_snapshot(self.cfg.resolved_data_dir, snap)
        self.audit.event("dashboard.refresh",
                         accounts=len(accounts),
                         sources={k: v.get("ok") for k, v in sources.items()})
        return snap
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/engine.py tests/test_dashboard_engine.py
git commit -m "feat(engine): build_dashboard with per-source degradation + snapshot"
```

---

### Task 9: `engine.rotate_from_dashboard` (delegate to existing rotate)

**Files:**
- Modify: `rphe/engine.py`
- Test: `tests/test_dashboard_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_dashboard_engine.py
from rphe.risk import AccountRisk, Tier


def test_rotate_from_dashboard_delegates(monkeypatch, tmp_path):
    eng = _engine_with([], monkeypatch, tmp_path)
    captured = {}
    def _fake_rotate(*, service_name, username, password, url=None, kind="manual"):
        captured.update(service_name=service_name, username=username, url=url, kind=kind)
        return "ROT"
    monkeypatch.setattr(eng, "rotate", _fake_rotate)
    monkeypatch.setattr(eng, "password_candidates", lambda n=1: ["Generated-PW-123"])
    row = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH,
                      vault_item_id="id1", managed=True)
    out = eng.rotate_from_dashboard(row)
    assert out == "ROT"
    assert captured["service_name"] == "github.com"
    assert captured["username"] == "me@x.com"
    assert captured["url"] == "https://github.com"
    assert captured["kind"] == "dashboard"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: FAIL (`AttributeError: rotate_from_dashboard`)

- [ ] **Step 3: Implement**

```python
    def rotate_from_dashboard(self, row, password: Optional[str] = None):
        """Rotate the account behind an AccountRisk row via the existing
        lockout-safe flow. Generates a vetted password if none supplied, then
        delegates to rotate() (PENDING + old password preserved)."""
        if password is None:
            password = self.password_candidates(n=1)[0]
        url = f"https://{row.domain}" if row.domain else None
        return self.rotate(service_name=row.domain, username=row.username or "",
                           password=password, url=url, kind="dashboard")
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/engine.py tests/test_dashboard_engine.py
git commit -m "feat(engine): rotate_from_dashboard delegates to rotate()"
```

---

### Task 10: CLI `rphe dashboard`

**Files:**
- Modify: `rphe/cli.py` (add command near the other `@app.command()` blocks)
- Test: `tests/test_dashboard_engine.py` (invoke via Typer's CliRunner)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_dashboard_engine.py
import json as _json
from typer.testing import CliRunner
from rphe import cli as cli_mod
from rphe.snapshot import RiskSnapshot, save_snapshot


def test_cli_dashboard_json(monkeypatch, tmp_path):
    row = AccountRisk(domain="github.com", username="me@x.com", tier=Tier.HIGH,
                      reasons=["reused on 3 sites"], sources={"vault"}, managed=True)
    save_snapshot(tmp_path, RiskSnapshot(generated_at="2026-06-14T20:00:00Z",
                                         sources={}, accounts=[row]))
    from rphe.config import Config
    monkeypatch.setattr(cli_mod, "_engine",
                        lambda: cli_mod.Engine(cfg=Config(data_dir=str(tmp_path))))
    res = CliRunner().invoke(cli_mod.app, ["dashboard", "--json"])
    assert res.exit_code == 0
    data = _json.loads(res.stdout)
    assert data["accounts"][0]["domain"] == "github.com"
```

(If `cli.py` constructs the engine differently, adapt the monkeypatch target to
whatever factory the file uses — check the top of `cli.py` for the existing
`Engine()` construction helper and reuse it.)

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py::test_cli_dashboard_json -q`
Expected: FAIL (no `dashboard` command)

- [ ] **Step 3: Implement** — add to `rphe/cli.py`:

```python
@app.command()
def dashboard(
    refresh: bool = typer.Option(False, "--refresh", help="Recompute before showing."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    show_all: bool = typer.Option(False, "--all", help="Include low-risk rows."),
    tier: str = typer.Option("", "--tier", help="Filter: critical|high|medium|low."),
):
    """Show the prioritized account-risk dashboard."""
    from .snapshot import snapshot_to_dict
    eng = _engine()
    snap = eng.build_dashboard(refresh=refresh)
    if snap is None:
        typer.echo("No dashboard yet — run your first scan: rphe dashboard --refresh")
        raise typer.Exit(code=0)
    if as_json:
        typer.echo(json.dumps(snapshot_to_dict(snap), indent=2))
        raise typer.Exit(code=0)

    from rich.table import Table
    from rich.console import Console
    rows = snap.accounts
    if not show_all:
        rows = [r for r in rows if r.tier.name != "LOW"]
    if tier:
        rows = [r for r in rows if r.tier.name == tier.upper()]
    table = Table(title=f"Risk dashboard — as of {snap.generated_at}")
    table.add_column("Tier"); table.add_column("Account"); table.add_column("Why")
    colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green"}
    for r in rows:
        who = r.domain + (f" · {r.username}" if r.username else "")
        table.add_row(f"[{colors.get(r.tier.name,'white')}]{r.tier.name}[/]",
                      who, "; ".join(r.reasons))
    Console().print(table)
    bad = [k for k, v in snap.sources.items() if not v.get("ok", True)]
    if bad:
        typer.echo(f"(partial — couldn't fully check: {', '.join(bad)})")
```

Add `import json` at the top of `cli.py` if not already present.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_dashboard_engine.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rphe/cli.py tests/test_dashboard_engine.py
git commit -m "feat(cli): rphe dashboard command"
```

---

### Task 11: warm the snapshot from `scan-notify`

**Files:**
- Modify: `rphe/cli.py` (the `scan-notify` command, around `rphe/cli.py:564`)

- [ ] **Step 1: Read the current `scan-notify` body**

Run: `.venv/bin/python -c "import inspect,rphe.cli as c; print(inspect.getsource(c.scan_notify))"`
(Confirm the function name; Typer maps `scan-notify` -> `scan_notify`.)

- [ ] **Step 2: Implement** — after the command computes/notifies on `scan_detailed`, add a snapshot refresh so the GUI/CLI dashboard stays warm. Insert near the end of the command body, before it returns:

```python
    try:
        eng.build_dashboard(refresh=True)   # keep the dashboard snapshot warm
    except Exception:
        pass                                # notification already handled above
```

- [ ] **Step 3: Verify nothing broke**

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add rphe/cli.py
git commit -m "feat(cli): scan-notify warms the dashboard snapshot"
```

---

### Task 12: GUI "Risk" tab

GUI is not unit-tested (consistent with the project — Tk stays thin; the worker-thread/queue mechanism is already covered). Follow the existing `_page_*` / `_async` / `_poll_queue` patterns (`rphe/gui.py:49` NAV, `:762` `_async`, `:982` `on_vault_audit`, `:1000` `_render_audit`).

**Files:**
- Modify: `rphe/gui.py`

- [ ] **Step 1: Add the nav entry** — in `NAV` (`rphe/gui.py:49`), add after the `dashboard` row:

```python
    ("risk", "🚨  Risk"),
```

and add `"risk"` to the page-build tuple in `_build_content` (`rphe/gui.py:166`):

```python
        for key in ("dashboard", "risk", "connect", "scan", "health", "settings"):
```

- [ ] **Step 2: Add the page builder + handlers** — add methods to `RpheApp`, mirroring `on_vault_audit`/`_render_audit`:

```python
    def _page_risk(self, page):
        ctk.CTkLabel(page, text="Risk dashboard",
                     font=ctk.CTkFont(size=24, weight="bold")).grid(
                         row=0, column=0, sticky="w")
        ctk.CTkLabel(page, text="Your accounts, ranked by risk — worst first.",
                     text_color=MUTED).grid(row=1, column=0, sticky="w", pady=(2, 14))
        ctk.CTkButton(page, text="🔄  Refresh", width=130,
                      command=self.on_risk_refresh).grid(row=2, column=0, sticky="w")
        self.risk_body = ctk.CTkFrame(page, fg_color="transparent")
        self.risk_body.grid(row=3, column=0, sticky="nsew", pady=(14, 0))
        self.risk_body.grid_columnconfigure(0, weight=1)
        self._render_risk(self.engine.build_dashboard(refresh=False))

    def on_risk_refresh(self):
        self._async(lambda: self.engine.build_dashboard(refresh=True),
                    self._render_risk, busy="Refreshing risk dashboard…",
                    key="risk_refresh")

    def _render_risk(self, snap):
        for w in self.risk_body.winfo_children():
            w.destroy()
        if snap is None:
            ctk.CTkLabel(self.risk_body,
                         text="No data yet — click Refresh to run your first scan.",
                         text_color=MUTED).grid(row=0, column=0, sticky="w")
            return
        ctk.CTkLabel(self.risk_body, text=f"as of {snap.generated_at}",
                     text_color=MUTED, font=ctk.CTkFont(size=11)).grid(
                         row=0, column=0, sticky="w")
        colors = {"CRITICAL": "#dc2626", "HIGH": "#d97706",
                  "MEDIUM": "#2563eb", "LOW": "#16a34a"}
        r = 1
        for acc in snap.accounts:
            if acc.tier.name == "LOW":
                continue
            card = ctk.CTkFrame(self.risk_body, corner_radius=10)
            card.grid(row=r, column=0, sticky="ew", pady=4)
            card.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(card, text="●", text_color=colors.get(acc.tier.name, "#888"),
                         font=ctk.CTkFont(size=18)).grid(row=0, column=0, padx=(12, 8),
                                                         pady=10)
            who = acc.domain + (f"  ·  {acc.username}" if acc.username else "")
            box = ctk.CTkFrame(card, fg_color="transparent")
            box.grid(row=0, column=1, sticky="w")
            ctk.CTkLabel(box, text=who, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(box, text="; ".join(acc.reasons), text_color=MUTED,
                         font=ctk.CTkFont(size=12)).pack(anchor="w")
            label = "Rotate" if acc.managed else "Add to vault"
            ctk.CTkButton(card, text=label, width=110,
                          command=lambda a=acc: self._rotate_risk_row(a)).grid(
                              row=0, column=2, padx=12)
            r += 1

    def _rotate_risk_row(self, acc):
        if not self._ensure_unlocked():       # existing helper used by Scan & Fix
            return
        self._async(lambda: self.engine.rotate_from_dashboard(acc),
                    lambda res: self.on_risk_refresh(),
                    busy=f"Rotating {acc.domain}…", key=f"rotate_{acc.domain}")
```

(If the existing unlock helper has a different name than `_ensure_unlocked`,
reuse whatever `on_vault_audit`/the Scan flow calls to prompt for the master
password — search `gui.py` for the unlock-modal helper and call that.)

- [ ] **Step 3: Manual smoke test**

Run: `RPHE_START_PAGE=risk .venv/bin/python -m rphe.gui` (or launch the app and click Risk). Confirm the page renders, Refresh runs without freezing the UI, and an empty state shows "run your first scan".

- [ ] **Step 4: Commit**

```bash
git add rphe/gui.py
git commit -m "feat(gui): Risk dashboard tab"
```

---

### Task 13: version bump + README + full gate

**Files:**
- Modify: `rphe/__init__.py`, `pyproject.toml`, `packaging/rphe_gui.spec`, `README.md`

- [ ] **Step 1: Bump version 0.8.3 -> 0.9.0** in `rphe/__init__.py`, `pyproject.toml`, `packaging/rphe_gui.spec` (`CFBundleShortVersionString`).

- [ ] **Step 2: Document** — add a "Risk dashboard" section to `README.md` describing the tiers, the `rphe dashboard [--refresh|--json|--all|--tier]` command, the snapshot location/redaction, and the lockout-safe rotate.

- [ ] **Step 3: Run the full gate**

```bash
.venv/bin/python -m ruff check --select E9,F63,F7,F82,F821,F811 rphe tests packaging
.venv/bin/python -m pytest tests/ -q
.venv-build/bin/semgrep --config p/python --config p/security-audit --error --metrics off rphe packaging
```
Expected: ruff "All checks passed!", pytest all green, semgrep clean.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: risk dashboard (v0.9.0)"
```

---

## Self-review

**Spec coverage:** tiered+explainable model (Tasks 2–4), cached snapshot + refresh (Tasks 5,6,8), one row per (domain,username) with fan-out + unmanaged (Tasks 2–4), fingerprints in / plaintext + tokened URLs out (Tasks 5,7), pending+guided rotate delegation (Task 9), CLI + GUI surfaces (Tasks 10,12), scan-notify warming (Task 11), degradation/no-silent-all-clear (Task 8). All spec sections map to a task.

**Type consistency:** `AccountRisk` fields are identical across risk.py, snapshot.py, CLI, and GUI. `build_risk_model(scan_signals, vault_logins, breach_hits, *, weak_below_bits)` and its dict shapes match `audit_vault`'s `logins` output and `build_dashboard`'s `breach_hits` construction. `Tier` names (CRITICAL/HIGH/MEDIUM/LOW) used consistently in CLI/GUI/snapshot.

**Placeholder scan:** Tasks 10/12 note the two spots to confirm against the live `cli.py` engine factory and the `gui.py` unlock helper (named lookups to verify, not vague TODOs). No "TBD"/"handle edge cases" placeholders remain.

**Out of scope (unchanged from spec):** numeric score, dashboard auto-fill, cold-snapshot reset-link re-fetch, per-site recipes, digest emails.
