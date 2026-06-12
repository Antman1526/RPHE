"""RPHE command-line interface (identical on macOS and Windows).

Commands:
  rphe gui                        Launch the desktop GUI (same engine as the CLI).
  rphe init                       Write a starter config file.
  rphe demo                       Run the classifier on built-in sample emails.
  rphe breach                     Check accounts against Have I Been Pwned.
  rphe gen                        Generate one password (test the policy).
  rphe secrets set/del/check      Manage OS-keystore secrets (no plaintext echo).
  rphe auth gmail  <label> <json> One-time Gmail OAuth (stores token in keystore).
  rphe auth gmail-check <label>   Validate a stored Gmail token (no scan).
  rphe auth graph  <label> <id>   One-time Microsoft Graph device-code auth.
  rphe vault unlock               Unlock Bitwarden (prompts for master password).
  rphe scan                       Scan inboxes, classify, print at-risk accounts.
  rphe rotate                     Interactive: rotate flagged accounts end-to-end.
  rphe sync verify                Compare Bitwarden vs the NordPass CSV mirror.
  rphe nordpass instructions      Show how to import the staged CSV.
  rphe nordpass clean             Securely delete the staged NordPass CSV.
  rphe audit                      Print the (redacted) audit log.

Rich is used for nice tables; Typer for arg parsing. Both are cross-platform.
"""
from __future__ import annotations

import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from . import __version__
from .audit import AuditLog
from .classifier import classify_many
from .config import (Config, EmailAccount, PasswordPolicy, default_config_dir,
                     load_config)
from .models import GeneratedCredential, Severity
from .passwords import estimate_strength, generate_password
from .reset import ResetOrchestrator
from .secrets import SecretStore

app = typer.Typer(add_completion=False, help="RPHE — Recovery & Password-Hygiene Engine")
secrets_app = typer.Typer(help="Manage OS-keystore secrets.")
auth_app = typer.Typer(help="One-time email provider authentication.")
vault_app = typer.Typer(help="Vault (Bitwarden) operations.")
sync_app = typer.Typer(help="Cross-vault sync verification.")
nordpass_app = typer.Typer(help="NordPass CSV bridge operations.")
app.add_typer(secrets_app, name="secrets")
app.add_typer(auth_app, name="auth")
app.add_typer(vault_app, name="vault")
app.add_typer(sync_app, name="sync")
app.add_typer(nordpass_app, name="nordpass")

console = Console()


def _ctx() -> tuple[Config, SecretStore, AuditLog]:
    cfg = load_config()
    store = SecretStore()
    audit = AuditLog(cfg.resolved_data_dir)
    return cfg, store, audit


# --------------------------------------------------------------------------- #
# Basic
# --------------------------------------------------------------------------- #
@app.command()
def version():
    """Print version."""
    console.print(f"RPHE v{__version__}")


@app.command()
def init(force: bool = typer.Option(False, help="Overwrite an existing config.")):
    """Write a starter config.yaml you can edit."""
    cfg_dir = default_config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.yaml"
    if cfg_path.exists() and not force:
        console.print(f"[yellow]Config already exists at {cfg_path} (use --force).[/]")
        raise typer.Exit(1)
    template = (Path(__file__).parent.parent / "config.example.yaml")
    cfg_path.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    console.print(f"[green]Wrote starter config to {cfg_path}[/]")
    console.print("Edit it to add your email accounts, then run `rphe auth ...`.")


@app.command()
def gen(
    length: int = typer.Option(24, help="Password length."),
    passphrase: bool = typer.Option(False, help="Generate a passphrase instead."),
    words: int = typer.Option(6, help="Words in passphrase mode."),
):
    """Generate one password (prints it — for testing the policy only)."""
    policy = PasswordPolicy(length=length, passphrase_mode=passphrase, passphrase_words=words)
    pw = generate_password(policy)
    bits = estimate_strength(policy)
    console.print(pw)
    console.print(f"[dim]~{bits:.0f} bits of entropy[/]")


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #
@secrets_app.command("set")
def secrets_set(key: str):
    """Store a secret (value read from a hidden prompt, never argv)."""
    store = SecretStore()
    value = getpass.getpass(f"Value for '{key}' (hidden): ")
    if not value:
        console.print("[red]Empty value — aborted.[/]")
        raise typer.Exit(1)
    store.set(key, value)
    console.print(f"[green]Stored secret '{key}' in the OS keystore.[/]")


@secrets_app.command("del")
def secrets_del(key: str):
    """Delete a stored secret."""
    SecretStore().delete(key)
    console.print(f"[green]Deleted '{key}' (if it existed).[/]")


@secrets_app.command("check")
def secrets_check(key: str):
    """Report whether a secret exists (never prints the value)."""
    exists = SecretStore().get(key) is not None
    console.print(f"{key}: {'present' if exists else 'MISSING'}")


# --------------------------------------------------------------------------- #
# Auth (OAuth one-time flows)
# --------------------------------------------------------------------------- #
@auth_app.command("gmail")
def auth_gmail(label: str, client_secret_json: Path):
    """Run the Gmail OAuth desktop flow and store the token in the keystore.

    One-time setup. Opens your browser, you approve the read-only scope, and the
    refresh token is saved to the OS keystore (never to disk). Immediately
    self-checks by calling getProfile so you know it works.
    """
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        console.print("[red]Gmail auth needs: pip install \".[gmail]\"[/]")
        raise typer.Exit(1)
    if not client_secret_json.exists():
        console.print(f"[red]client_secret file not found: {client_secret_json}[/]\n"
                      "Download it from Google Cloud Console → Credentials → "
                      "OAuth client ID (Desktop app). See docs/GMAIL_SETUP.md.")
        raise typer.Exit(1)

    from .scanners.gmail_scanner import SCOPES
    try:
        flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_json), SCOPES)
        console.print("[dim]Opening your browser to approve read-only Gmail access…[/]")
        creds = flow.run_local_server(port=0, prompt="consent")
    except Exception as exc:
        console.print(f"[red]OAuth flow failed: {exc}[/]\n"
                      "Common causes: you weren't added as a Test user on the "
                      "OAuth consent screen, or the client is not a 'Desktop app'. "
                      "See docs/GMAIL_SETUP.md → Troubleshooting.")
        raise typer.Exit(1)

    store = SecretStore()
    store.set(store.oauth_token_key(label), creds.to_json())
    console.print(f"[green]Gmail token for '{label}' stored (read-only scope).[/]")

    # Self-check so the user gets immediate confirmation it actually works.
    try:
        cfg = load_config()
        acct = next((a for a in cfg.accounts if a.label == label),
                    EmailAccount(label=label, provider="gmail", address=""))
        from .scanners.gmail_scanner import GmailScanner
        info = GmailScanner(acct, store).profile()
        console.print(f"[green]✓ Verified: signed in as {info['emailAddress']} "
                      f"({info['messagesTotal']} messages, scope=gmail.readonly).[/]")
    except Exception as exc:
        console.print(f"[yellow]Token stored, but self-check failed: {exc}[/]")


@auth_app.command("gmail-check")
def auth_gmail_check(label: str):
    """Validate a stored Gmail token (refreshes it, prints the account email)."""
    store = SecretStore()
    if store.get(store.oauth_token_key(label)) is None:
        console.print(f"[red]No Gmail token for '{label}'. Run `rphe auth gmail {label} "
                      "<client_secret.json>` first.[/]")
        raise typer.Exit(1)
    cfg = load_config()
    acct = next((a for a in cfg.accounts if a.label == label),
                EmailAccount(label=label, provider="gmail", address=""))
    try:
        from .scanners.gmail_scanner import GmailScanner
        info = GmailScanner(acct, store).profile()
    except Exception as exc:
        console.print(f"[red]Gmail token check failed: {exc}[/]")
        raise typer.Exit(1)
    console.print(f"[green]✓ {label}: {info['emailAddress']} "
                  f"— {info['messagesTotal']} messages, scopes={info['scopes']}[/]")


@auth_app.command("graph")
def auth_graph(label: str, client_id: str):
    """Run the Microsoft Graph device-code flow and cache the token."""
    try:
        import msal
    except ImportError:
        console.print("[red]Install: pip install msal[/]")
        raise typer.Exit(1)
    from .scanners.graph_scanner import SCOPES
    store = SecretStore()
    store.set(f"graph.{label}.client_id", client_id)
    cache = msal.SerializableTokenCache()
    appm = msal.PublicClientApplication(
        client_id, authority="https://login.microsoftonline.com/common",
        token_cache=cache)
    flow = appm.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        console.print(f"[red]Device flow failed: {flow.get('error_description')}[/]")
        raise typer.Exit(1)
    console.print(flow["message"])  # tells the user the code + URL
    result = appm.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        console.print(f"[red]Auth failed: {result.get('error_description')}[/]")
        raise typer.Exit(1)
    store.set(store.oauth_token_key(label), cache.serialize())
    console.print(f"[green]Graph token for '{label}' cached. (Mail.Read scope)[/]")


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #
@vault_app.command("unlock")
def vault_unlock():
    """Unlock Bitwarden by prompting for the master password (kept off argv)."""
    from .vaults import BitwardenVault, VaultError
    cfg, store, audit = _ctx()
    try:
        bw = BitwardenVault(store, cfg.bitwarden_folder)
        master = getpass.getpass("Bitwarden master password (hidden): ")
        bw.unlock(master)
        audit.event("bitwarden.unlock", result="ok")
        console.print("[green]Bitwarden unlocked; session cached in keystore.[/]")
    except VaultError as exc:
        audit.event("bitwarden.unlock", result="error", detail=str(exc))
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def _scan_all(cfg: Config, store: SecretStore):
    """Run every configured scanner and return classified signals."""
    from .scanners import build_scanner
    raw_messages: list[dict] = []
    for account in cfg.accounts:
        try:
            scanner = build_scanner(account, store)
            count = 0
            for msg in scanner.fetch():
                raw_messages.append(msg)
                count += 1
            console.print(f"[dim]{account.label}: fetched {count} candidate messages[/]")
        except Exception as exc:  # one bad account shouldn't kill the run
            console.print(f"[red]{account.label}: scan failed — {exc}[/]")
    return classify_many(raw_messages)


def _render_signals(signals, title: str) -> None:
    table = Table(title=title)
    for col in ("Severity", "Service", "Kind", "Received", "Reset link?", "Why"):
        table.add_column(col, overflow="fold")
    for s in signals:
        table.add_row(
            s.severity.name, s.service_name, s.kind.value,
            s.received_at.strftime("%Y-%m-%d"),
            "yes" if s.reset_url else "no", s.rationale,
        )
    console.print(table)


@app.command()
def scan(
    min_severity: str = typer.Option("MEDIUM", help="INFO/LOW/MEDIUM/HIGH/CRITICAL"),
    dry_run: bool = typer.Option(False, help="Don't write anything to the audit log."),
):
    """Scan inboxes and list accounts that look compromised or at-risk."""
    cfg, store, audit = _ctx()
    if not cfg.accounts:
        console.print("[yellow]No accounts configured. Run `rphe init` first, "
                      "or try `rphe demo` to see the classifier on sample emails.[/]")
        raise typer.Exit(1)
    threshold = Severity.from_name(min_severity)
    signals = [s for s in _scan_all(cfg, store) if s.severity >= threshold]

    _render_signals(signals, f"At-risk accounts (>= {threshold.name})")
    if not dry_run:
        audit.event("scan", accounts=len(cfg.accounts), flagged=len(signals),
                    signals=[s.to_audit_dict() for s in signals])
    console.print(f"\n[bold]{len(signals)} account(s) flagged.[/]"
                  + ("  [dim](dry-run: not logged)[/]" if dry_run else "")
                  + "  Run `rphe rotate` to fix them.")


@app.command()
def demo(min_severity: str = typer.Option("INFO", help="INFO/LOW/MEDIUM/HIGH/CRITICAL")):
    """Run the classifier on built-in sample emails — zero setup, no inbox access.

    The fastest way to see exactly what RPHE flags (and what it ignores) before
    connecting any account. The samples are synthetic; nothing leaves your machine.
    """
    from .samples import SAMPLE_MESSAGES
    threshold = Severity.from_name(min_severity)
    signals = [s for s in classify_many(SAMPLE_MESSAGES) if s.severity >= threshold]
    _render_signals(signals, f"Demo: classifier on {len(SAMPLE_MESSAGES)} sample emails")
    ignored = len(SAMPLE_MESSAGES) - len(classify_many(SAMPLE_MESSAGES))
    console.print(f"\n[bold]{len(signals)} flagged[/], [dim]{ignored} correctly ignored "
                  "(marketing/receipts).[/]")


# --------------------------------------------------------------------------- #
# Rotate (the end-to-end flow)
# --------------------------------------------------------------------------- #
def _pick_password(engine, n: int = 5) -> Optional[str]:
    """Generate n breach-vetted candidates and let the user choose one."""
    console.print("[dim]Generating and breach-checking candidates…[/]")
    cands = engine.password_candidates(n=n, vet_pwned=True)
    if not cands:
        console.print("[red]Could not generate vetted candidates.[/]")
        return None
    from .passwords import estimate_strength
    bits = estimate_strength(engine.cfg.policy)
    for i, pw in enumerate(cands, 1):
        console.print(f"  [bold]{i}[/]. {pw}  [dim](~{bits:.0f} bits, "
                      "not in any known breach ✓)[/]")
    while True:
        choice = typer.prompt(f"Choose a password [1-{len(cands)}] (or 'r' to regenerate)")
        if choice.lower() == "r":
            return _pick_password(engine, n)
        if choice.isdigit() and 1 <= int(choice) <= len(cands):
            return cands[int(choice) - 1]
        console.print("[yellow]Enter a number from the list, or 'r'.[/]")


@app.command()
def rotate(
    min_severity: str = typer.Option("HIGH", help="Only rotate at/above this severity."),
    automate: bool = typer.Option(False, help="Use Playwright assisted reset (still pauses for you)."),
    yes: bool = typer.Option(False, help="Don't prompt per account (still pauses for resets)."),
):
    """For each flagged account: pick from 5 vetted passwords, store in both vaults, guide the reset + passkey."""
    from .engine import Engine
    from .passkeys import render as render_passkey
    from .vaults import VaultError
    cfg, store, audit = _ctx()
    engine = Engine(cfg, store, audit)
    threshold = Severity.from_name(min_severity)

    try:
        engine.unlock_bitwarden()  # cached session/stored master, else instructs
    except VaultError as exc:
        console.print(f"[red]{exc}[/]\nRun `rphe vault unlock` first.")
        raise typer.Exit(1)

    orch = ResetOrchestrator(automate=automate)
    signals = engine.scan(threshold)
    if not signals:
        console.print("[green]Nothing at or above that severity. You're clear.[/]")
        return

    try:
        import pyperclip
    except ImportError:
        pyperclip = None

    rotated = 0
    for s in signals:
        console.rule(f"{s.service_name}  [{s.severity.name}]")
        console.print(f"Why flagged: {s.rationale}")
        if not yes and not Confirm.ask(f"Rotate the password for {s.service_name}?", default=True):
            continue

        username = typer.prompt(f"Username/email for {s.service_name}",
                                default=s.account_hint or "")
        new_password = _pick_password(engine)
        if not new_password:
            continue

        url = f"https://{s.sender_domain}" if s.sender_domain else None
        res = engine.rotate(service_name=s.service_name, username=username,
                            password=new_password, url=url, kind=s.kind.value)
        if not res.bitwarden_ok:
            console.print(f"[red]Bitwarden write failed: {res.error} — skipping.[/]")
            continue
        console.print(f"[green]Bitwarden: "
                      f"{'stored & verified' if res.verified else 'stored'}[/]"
                      f" (id {res.bitwarden_id})")
        console.print(f"[green]NordPass: "
                      f"{'staged into CSV' if res.nordpass_staged else 'FAILED'}[/]")

        if pyperclip:
            try:
                pyperclip.copy(new_password)
                console.print("[dim]New password copied to clipboard.[/]")
            except Exception:
                pass

        plan = orch.build_plan(s)
        console.print(plan.render())
        if automate and plan.automatable:
            console.print("[yellow]Launching assisted browser… it will pause for you.[/]")
            console.print(f"[dim]{orch.assist(plan, res_cred(s, username, new_password, url))}[/]")
        console.print("\n" + render_passkey(res.passkey))
        audit.event("reset.plan", service=s.service_name, automatable=plan.automatable)
        rotated += 1

    console.rule("Done")
    console.print(f"[bold]Rotated {rotated} account(s).[/]")
    console.print(engine.nordpass().import_instructions())
    if pyperclip:
        try:
            pyperclip.copy("")  # clear clipboard
        except Exception:
            pass


def res_cred(signal, username, password, url):
    """Build a GeneratedCredential for the (optional) assisted-reset autofill."""
    return GeneratedCredential(service_name=signal.service_name, username=username,
                               secret=password, url=url)


@app.command()
def gui():
    """Launch the desktop GUI (same engine as the CLI)."""
    try:
        from .gui import launch
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    launch()


@app.command()
def breach(
    email: Optional[str] = typer.Option(None, help="Check one email (default: all configured inbox addresses)."),
):
    """Check accounts against Have I Been Pwned (needs hibp.api_key for email lookup)."""
    from .engine import Engine
    cfg, store, audit = _ctx()
    engine = Engine(cfg, store, audit)
    if store.get(store.hibp_api_key()) is None:
        console.print("[yellow]No HIBP API key set. Get one at "
                      "https://haveibeenpwned.com/API/Key then run "
                      "`rphe secrets set hibp.api_key`.[/]\n"
                      "[dim](The free password-breach check still runs during "
                      "rotation without a key.)[/]")
        raise typer.Exit(1)
    emails = [email] if email else sorted({a.address for a in cfg.accounts if a.address})
    if not emails:
        console.print("[yellow]No email addresses to check.[/]")
        raise typer.Exit(1)
    results = engine.check_accounts_breached(emails)
    table = Table(title="Have I Been Pwned — account breach report")
    table.add_column("Account"); table.add_column("Breached?"); table.add_column("Where")
    for r in results:
        table.add_row(r.name, "[red]YES[/]" if r.breached else "[green]no[/]",
                      ", ".join(r.breach_titles[:6]))
    console.print(table)


# --------------------------------------------------------------------------- #
# Sync
# --------------------------------------------------------------------------- #
@sync_app.command("verify")
def sync_verify():
    """Compare Bitwarden and the NordPass CSV mirror; flag any drift."""
    from .vaults import BitwardenVault, NordPassBridge, SyncVerifier, VaultError
    cfg, store, audit = _ctx()
    try:
        bw = BitwardenVault(store, cfg.bitwarden_folder)
        bw.unlock()
    except VaultError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    npass = NordPassBridge(cfg.resolved_nordpass_export, cfg.bitwarden_folder)
    report = SyncVerifier(bw, npass).compare()

    console.print(f"In both vaults: [green]{len(report.in_both)}[/]")
    console.print(f"Only in Bitwarden: [yellow]{len(report.only_in_bitwarden)}[/]")
    console.print(f"Only in NordPass CSV: [yellow]{len(report.only_in_nordpass)}[/]")
    console.print(f"Password drift: [red]{len(report.password_drift)}[/]")
    for label, rows in (("only_in_bitwarden", report.only_in_bitwarden),
                        ("only_in_nordpass", report.only_in_nordpass),
                        ("password_drift", report.password_drift)):
        for r in rows:
            console.print(f"  [{label}] {r['name']} / {r['username']}")
    audit.event("sync.verify", consistent=report.is_consistent,
                only_bw=len(report.only_in_bitwarden),
                only_np=len(report.only_in_nordpass),
                drift=len(report.password_drift))
    if not report.is_consistent:
        console.print("\n[yellow]Drift detected. Re-import the CSV into NordPass "
                      "(`rphe nordpass instructions`).[/]")


# --------------------------------------------------------------------------- #
# NordPass bridge
# --------------------------------------------------------------------------- #
@nordpass_app.command("instructions")
def nordpass_instructions():
    """Show how to import the staged CSV into NordPass."""
    cfg, _, _ = _ctx()
    from .vaults import NordPassBridge
    console.print(NordPassBridge(cfg.resolved_nordpass_export,
                                 cfg.bitwarden_folder).import_instructions())


@nordpass_app.command("clean")
def nordpass_clean():
    """Securely delete the staged NordPass CSV (overwrite then unlink)."""
    cfg, _, audit = _ctx()
    from .vaults import NordPassBridge
    NordPassBridge(cfg.resolved_nordpass_export, cfg.bitwarden_folder).clean()
    audit.event("nordpass.clean", result="ok")
    console.print("[green]Staged CSV shredded.[/]")


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
@app.command()
def audit(tail: int = typer.Option(20, help="Show the last N events.")):
    """Print the (already-redacted) audit log."""
    cfg, _, log = _ctx()
    events = log.read_all()[-tail:]
    if not events:
        console.print("[dim]No audit events yet.[/]")
        return
    table = Table(title=f"Audit log (last {len(events)})")
    table.add_column("Time"); table.add_column("Action"); table.add_column("Detail")
    for e in events:
        detail = {k: v for k, v in e.items() if k not in ("ts", "action")}
        table.add_row(e.get("ts", ""), e.get("action", ""), str(detail)[:80])
    console.print(table)


def main():  # console-script entrypoint
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
