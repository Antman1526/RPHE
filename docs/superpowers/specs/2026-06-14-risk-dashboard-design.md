# Risk dashboard — design

Date: 2026-06-14
Status: approved (design); pending implementation plan
Target version: v0.9.0

## Goal

A single, prioritized view that merges RPHE's three risk signals — email scan
findings, vault password-hygiene audit, and breach checks — into one ranked list
of at-risk accounts, each with a plain-English "why" and a safe one-click rotate.
It is the culmination of the scan -> find -> rotate mission: instead of running
`scan`, `vault audit`, and breach checks separately and mentally joining them, the
user opens one dashboard that says "here is what to fix, worst first, and here is
the button to fix it."

Delivered as a full vertical slice (Approach 1): a pure risk-model core, a
redacted on-disk snapshot, a `rphe dashboard` CLI command, and a new GUI
"Dashboard" tab.

## Decisions (from brainstorming)

1. **Risk model:** tiered + explainable. Each account lands in CRITICAL / HIGH /
   MEDIUM / LOW driven by its worst signal, and every row shows the plain-English
   reasons. No numeric score (avoids false precision).
2. **Freshness:** cached snapshot + Refresh. Opens instantly on the last computed
   snapshot with an "as of" stamp and per-source freshness; Refresh recomputes.
   The scheduled scan keeps the snapshot warm.
3. **Rotate action:** pending + guided reset. Reuses the existing lockout-safe
   flow (generate -> store PENDING with old password in history -> open the
   anti-phishing-verified reset link / steps -> Confirm/Revert). Nothing is ever
   changed silently; no auto-fill on unknown sites.
4. **Row model:** one row per account, keyed by `(registrable_domain, username)`.
   Vault login + matching inbox alerts + breach hits merge into one row.
   Inbox-only services with no stored login appear as "unmanaged" rows.
5. **Snapshot contents:** derived risk metadata only — includes the 8-char
   SHA-256 password fingerprint (for reuse grouping, stale-row detection, and
   confirming a rotation changed the secret); excludes plaintext passwords and
   tokened reset URLs.

## Architecture

```
scanners ─┐
          ├─ engine.scan_detailed()        ─┐
vaults  ──┤  engine.audit_vault()           ├─> build_risk_model()  (pure)
breach  ──┘  engine.check_accounts_breached()┘        │
                                                       v
                                              list[AccountRisk]
                                                       │
                                  engine.build_dashboard(refresh) ──> RiskSnapshot (0600 JSON)
                                                       │
                              ┌────────────────────────┼────────────────────────┐
                              v                        v                         v
                       rphe dashboard (CLI)     GUI "Dashboard" tab      scan-notify (warms snapshot)
                              │                        │
                              └── rotate_from_dashboard(row) ──> engine.rotate() / confirm / revert
```

New/changed units, each with one clear purpose:

- **`rphe/risk.py` (new)** — the pure core. `AccountRisk` dataclass +
  `build_risk_model(scan_signals, vault_audit, breach_results) -> list[AccountRisk]`.
  No I/O. Holds all tiering and merge logic. The bulk of the tests target this.
- **`rphe/snapshot.py` (new)** — `RiskSnapshot` persistence: serialize a list of
  `AccountRisk` + per-source freshness to a redacted 0600 JSON file in the data
  dir, and load it back. Reuses `audit._redact` for the free-text reason strings
  and the `O_EXCL` atomic-write pattern from `nordpass.py`/`audit.py`.
- **`rphe/engine.py` (extended)** — thin orchestration only:
  - `build_dashboard(refresh=False) -> RiskSnapshot` — load the snapshot, or
    recompute each source independently (capturing per-source errors), run
    `build_risk_model`, persist, and return.
  - `rotate_from_dashboard(row) -> RotationResult` — assemble args from an
    `AccountRisk` row and delegate to the existing `rotate()`.
- **`rphe/cli.py` (extended)** — `rphe dashboard` command.
- **`rphe/gui.py` (extended)** — a new "Dashboard" tab.

## Data model: `AccountRisk`

```
domain             str    registrable domain (eTLD+1), e.g. "dropbox.com"
username           str|None  login username/email; None for inbox-only services
tier               Tier   CRITICAL | HIGH | MEDIUM | LOW
reasons            list[str]  plain-English, ordered worst-first
sources            set[str]   subset of {"vault", "inbox", "breach_email"}
vault_item_id      str|None   Bitwarden item id if a stored login exists
password_fingerprint str|None 8-char SHA-256 prefix of the stored password
managed            bool   True if a stored vault login exists; False = unmanaged
reset_url_trusted  bool   an inbox signal carried an anti-phishing-vetted reset link
reset_host         str|None  the registrable host of that link (NOT the tokened URL)
```

`Tier` is an `IntEnum` so "worst tier wins" is a `max()`. A separate transient
PENDING state (a row mid-rotation) is derived at render time from
`engine.list_pending()`, not stored on `AccountRisk` — it is an action state, not
a risk tier.

## Risk model: tiering rules

Inputs (all already produced by existing engine methods):

- `audit_vault()` -> per stored login: reuse buckets (full SHA-256), weak flag
  (`password_strength_bits < weak_below_bits`, default 60), HIBP pwned count, url,
  username, item_id, 8-char fingerprint.
- `scan_detailed()` -> `(signals, errors)`; each `BreachSignal` has kind,
  `Severity`, service/domain, and `reset_url_trusted` / `reset_url`.
- `check_accounts_breached(emails)` -> per email: list of HIBP breaches, and
  whether any exposed passwords.

Worst-signal-driven; every matched rule appends a reason:

- **CRITICAL** — any of:
  - password present in HIBP Pwned-Passwords corpus (pwned count > 0);
  - an inbox signal of kind BREACH_NOTICE or DATA_LEAK for this service;
  - the login's email is in a breach that exposed passwords.
- **HIGH** — any of:
  - password reused across >= 3 stored logins (widespread reuse);
  - an inbox SUSPICIOUS_LOGIN or unsolicited-MFA signal;
  - weak password combined with any exposure (breach hit or inbox alert).
- **MEDIUM** — any of:
  - weak password alone (no other signal);
  - a medium-severity inbox alert;
  - password reused on exactly 2 stored logins.
- **LOW** — a stored login with none of the above (informational; collapsed in
  the UI by default).

`tier = max(tier_of(rule) for each matched rule)`; `reasons` are ordered by the
tier they came from, worst first.

## Row merge

Key = `(registrable_domain(url or sender_domain), username.lower() or None)` using
the existing `linksafety.registrable_domain`.

- A **vault login** seeds a row with username + domain + item_id + fingerprint.
- An **inbox signal with a username** (rare) attaches to the matching key.
- An **inbox signal without a username** (the common case — "suspicious login on
  Dropbox") attaches to *all* stored logins on that domain. If there are none, it
  creates one **unmanaged** row `(domain, None)` with `managed=False`.
- A **HIBP email-breach** hit attaches to logins whose `username == that email`.

This reuses the same registrable-domain notion the anti-phishing code already
trusts, so the join is consistent with the rest of the system.

## Snapshot persistence, redaction, freshness

File: `risk_snapshot.json` in the existing data dir (next to the audit log),
written atomically (temp file created `O_EXCL` at 0600 on POSIX, then
`os.replace`), matching `nordpass.py`/`audit.py`.

Shape:
```json
{
  "generated_at": "2026-06-14T20:00:00Z",
  "sources": {
    "inbox":  {"at": "...", "ok": true,  "errors": []},
    "vault":  {"at": "...", "ok": false, "reason": "vault locked"},
    "breach_email": {"at": "...", "ok": true, "errors": []}
  },
  "accounts": [ { ...redacted AccountRisk... } ]
}
```

Redaction boundary:

- **Stored:** domain, username/email (the user's own identifiers, local-only,
  0600), tier, reasons, sources, `vault_item_id`, `password_fingerprint` (8-char
  SHA-256 prefix), `managed`, `reset_url_trusted`, `reset_host`.
- **Never stored:** plaintext passwords; password fingerprints longer than 8
  chars; **tokened reset URLs** (these carry one-time secrets). The live tokened
  `reset_url` is held in memory only during a same-session Refresh -> Rotate.
  Rotating from a cold snapshot falls back to "go to the service's password page"
  rather than a persisted token.
- A final `audit._redact` pass scrubs the free-text reason strings as
  belt-and-suspenders.

Rationale for keeping the fingerprint: it enables reuse grouping in the
dashboard, detecting a **stale** row (live vault password no longer matches the
snapshot), and confirming a rotation actually changed the secret. It is a
truncated, unsalted prefix stored beside the keychain it derives from — same
trust boundary, no plaintext.

`engine.build_dashboard(refresh)`:

- `refresh=False`: load the snapshot instantly; if none exists, return a
  "never run" marker (UI: "run your first scan").
- `refresh=True`: recompute each source **independently**, catching per-source
  exceptions, then `build_risk_model` -> persist -> return.

Graceful degradation (no silent "all clear"): sources are independent. Vault
locked -> vault `ok=false` with reason, inbox/breach rows still build (UI prompts
to unlock for full coverage). One of N inboxes fails -> inbox marked partial with
the error, succeeded inboxes still included. `scan-notify` calls
`build_dashboard(refresh=True)` so the snapshot stays warm between opens.

## Surfaces

### CLI — `rphe dashboard`

- default: Rich table, tiers color-coded, reasons column, freshness footer.
- `--refresh`: recompute before rendering.
- `--json`: machine-readable output (the snapshot shape).
- `--all`: include LOW rows (hidden by default).
- `--tier {critical,high,medium,low}`: filter.

### GUI — "Dashboard" tab

- Opens instantly on the cached snapshot; header shows title + "as of" stamp;
  source-freshness chips (inbox / vault / breach) show ok / locked / partial.
- Three tier-count summary cards (Critical / High / Medium).
- An "Awaiting confirmation" section (rows from `list_pending`) with
  Confirm/Revert, separate from the risk tiers.
- Risk rows grouped Critical -> High -> Medium, each with a tinted
  domain-initial avatar (tier cue), domain + username, reasons, and an action:
  **Rotate** (managed), **Add to vault** (unmanaged), or Confirm/Revert (pending).
- LOW rows collapse under "Show N low-risk accounts".
- **Refresh** runs `build_dashboard(refresh=True)` on a worker thread with a
  progress indicator, marshaling results back via the existing result-queue /
  `self.after` pattern, guarded by the existing `_inflight` re-entrancy guard. No
  widget is touched off the main thread.

Visual language follows the established calm/premium system: flat surfaces, 0.5px
borders, sentence case, two font weights, tier color encoded via the existing
semantic palette.

## Rotate integration

Clicking Rotate calls `engine.rotate_from_dashboard(row)`, a thin adapter that
assembles `service_name`, `username`, `url` from the `AccountRisk` row and
delegates to the **existing** `engine.rotate()` — which generates a strong
password, upserts to Bitwarden as PENDING (old password pushed to
passwordHistory), and returns the verified reset link / steps. The row then
renders in the PENDING state; Confirm/Revert call the existing
`confirm_rotation` / `revert_rotation`. If the vault is locked, Rotate prompts for
unlock first (reusing the existing modal).

No new code touches the password-writing path, so this inherits v0.8.2's
STDIN/argv hardening and v0.8.3's session account-binding for free.

## Error handling

- A partially-failed Refresh still renders, with per-source error chips; the
  snapshot records which sources were partial/unavailable.
- A Rotate failure surfaces the `VaultError` text (already secret-scrubbed by
  `_redact`) without leaving a half-written row — `rotate()` only marks PENDING
  after `bw` succeeds.
- A missing/corrupt snapshot file is treated as "never run" rather than crashing.

## Testing

- **`build_risk_model` (bulk):** table-driven over synthetic
  `(scan_signals, vault_audit, breach_results)` — each tier rule, worst-signal-
  wins, exact reasons, row merge by `(domain, username)`, domain-level signal
  fan-out, unmanaged rows, HIBP email attach. Deterministic, no I/O.
- **Snapshot:** round-trip preserves data; 0600 perms (POSIX); atomic write;
  redaction asserted by scanning serialized bytes (no plaintext / no tokened URL
  present; fingerprint present).
- **Freshness / degradation:** `build_dashboard(refresh=True)` with a raising
  source -> that source partial/unavailable, others present; vault-locked path.
  (Engine source calls mocked.)
- **Rotate delegation:** `rotate_from_dashboard` calls `rotate()` once with the
  right args (existing fake-`bw` harness); PENDING state derived from
  `list_pending`.
- **CLI:** `rphe dashboard --json` shape; `--tier` filter; no-snapshot message.
- **GUI:** not unit-tested (Tk kept thin; the worker-thread/queue mechanism is
  already tested); manual smoke via the existing launch path.

## Out of scope (YAGNI)

- Numeric 0-100 risk score (explicitly rejected in favor of tiers).
- Automated Playwright auto-fill from the dashboard (the guided pending flow only;
  auto-fill remains a separate, existing capability).
- Re-fetching expired reset links from a cold snapshot.
- Per-site reset recipes, scheduled-scan digest emails (separate future features).

## File-by-file change list

- `rphe/risk.py` — new: `AccountRisk`, `Tier`, `build_risk_model`.
- `rphe/snapshot.py` — new: `RiskSnapshot` persist/load + redaction.
- `rphe/engine.py` — add `build_dashboard`, `rotate_from_dashboard`.
- `rphe/cli.py` — add `dashboard` command.
- `rphe/gui.py` — add the "Dashboard" tab + handlers.
- `rphe/cli.py` `scan-notify` — also warm the snapshot via `build_dashboard(True)`.
- `tests/test_risk_model.py` — new (bulk).
- `tests/test_snapshot.py` — new (persistence + redaction).
- `tests/test_dashboard_engine.py` — new (degradation + rotate delegation).
- `README.md` — document the dashboard + `rphe dashboard`.
- version bump to 0.9.0 across `rphe/__init__.py`, `pyproject.toml`,
  `packaging/rphe_gui.spec`.
