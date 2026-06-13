"""Minimal cross-platform desktop GUI (Tkinter).

Why Tkinter: it ships with Python on macOS and Windows, bundles cleanly with
PyInstaller into a .dmg/.exe, and adds zero third-party dependencies — important
for a security tool's audit surface. It's not flashy, but it's reliable and
identical on both OSes.

Threading rule (enforced throughout): all network / vault / subprocess work runs
in a worker thread; widgets are only ever touched on the main thread via
``root.after``. This keeps the window responsive and avoids Tk's
single-thread-affinity crashes.
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Optional

from . import __version__
from .engine import Engine
from .models import GeneratedCredential, Severity
from .passwords import estimate_strength

try:
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, simpledialog, ttk
except Exception:  # pragma: no cover - headless/Tk-less environments
    tk = None


class RpheGui:
    def __init__(self, engine: Optional[Engine] = None):
        if tk is None:
            raise RuntimeError("Tkinter is not available in this Python build.")
        self.engine = engine or Engine()
        self.signals = []
        self._results_q: "queue.Queue" = queue.Queue()

        self.root = tk.Tk()
        self.root.title(f"RPHE — Recovery & Password-Hygiene Engine  v{__version__}")
        self.root.geometry("920x560")
        self.root.minsize(760, 460)
        self._build()
        self._poll_queue()
        # Auto-lock: lock Bitwarden on close and after idle.
        self._last_activity = time.monotonic()
        self._locked_by_idle = False
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        for ev in ("<Any-KeyPress>", "<Any-Button>"):
            self.root.bind_all(ev, self._mark_active, add="+")
        self.root.after(30_000, self._check_idle)
        # First-run nudge: if no accounts are configured, point to Setup.
        if not self.engine.cfg.accounts:
            self.root.after(400, lambda: self.status.set(
                "No accounts configured yet — click 'Setup…' to add an inbox, "
                "connect Gmail/Outlook, and log in to Bitwarden."))

    # --- layout -------------------------------------------------------------
    def _build(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(side=tk.TOP, fill=tk.X)
        self._btn(bar, "Setup…", self.on_setup)
        self._btn(bar, "Unlock Bitwarden", self.on_unlock)
        self._btn(bar, "Scan Inboxes", self.on_scan)
        self._btn(bar, "Breach Report", self.on_breach_report)
        self._btn(bar, "Vault Audit", self.on_vault_audit)
        self._btn(bar, "Rotate Selected…", self.on_rotate)
        self._btn(bar, "Pending…", self.on_pending)
        self._btn(bar, "Sync Verify", self.on_sync)
        self._btn(bar, "NordPass Import…", self.on_nordpass)
        self._btn(bar, "Audit Log", self.on_audit_log)
        self._btn(bar, "About", self.on_about)

        cols = ("severity", "service", "kind", "reset", "breach")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings",
                                 selectmode="extended")  # multi-select for bulk rotate
        for c, w, label in (("severity", 80, "Severity"), ("service", 180, "Service"),
                            ("kind", 170, "Signal"), ("reset", 110, "Reset link"),
                            ("breach", 110, "Breach DB")):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, anchor=tk.W)
        self.tree.tag_configure("CRITICAL", foreground="#b00020")
        self.tree.tag_configure("HIGH", foreground="#c25e00")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=6)
        self.tree.bind("<Double-1>", lambda e: self.on_rotate())

        # Status bar with an indeterminate progress spinner for long operations.
        self._busy = 0
        bottom = ttk.Frame(self.root)
        bottom.pack(side=tk.BOTTOM, fill=tk.X)
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=120)
        self.progress.pack(side=tk.RIGHT, padx=8, pady=2)
        self.status = tk.StringVar(value="Ready. Click 'Setup…' to configure "
                                         "accounts. Nothing is sent anywhere but "
                                         "your own providers and vaults.")
        ttk.Label(bottom, textvariable=self.status, relief=tk.SUNKEN,
                  anchor=tk.W, padding=(8, 4)).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _btn(self, parent, text, cmd):
        ttk.Button(parent, text=text, command=cmd).pack(side=tk.LEFT, padx=4)

    # --- async plumbing -----------------------------------------------------
    def _run_async(self, fn: Callable, on_done: Callable, busy: str):
        self.status.set(busy)
        self._busy += 1
        if self._busy == 1:
            self.progress.start(12)

        def worker():
            try:
                self._results_q.put(("ok", on_done, fn()))
            except Exception as exc:  # surfaced on the main thread
                self._results_q.put(("err", on_done, exc))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                kind, on_done, payload = self._results_q.get_nowait()
                self._busy = max(0, self._busy - 1)
                if self._busy == 0:
                    self.progress.stop()
                if kind == "ok":
                    on_done(payload)
                else:
                    self.status.set(f"Error: {payload}")
                    messagebox.showerror("RPHE", str(payload))
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    # --- actions ------------------------------------------------------------
    def on_setup(self):
        from .gui_setup import SettingsWindow

        def saved():
            # Adopt the freshly-saved config so a subsequent Scan sees new accounts.
            from .engine import Engine
            self.engine = Engine()
            self.status.set("Settings saved. You can Scan now.")
        SettingsWindow(self.root, self.engine, on_saved=saved)

    def on_unlock(self):
        pw = simpledialog.askstring("Unlock Bitwarden",
                                    "Bitwarden master password:", show="*",
                                    parent=self.root)
        if not pw:
            return
        self._run_async(lambda: self.engine.unlock_bitwarden(pw),
                        lambda _: self.status.set("Bitwarden unlocked."),
                        "Unlocking Bitwarden…")

    def on_scan(self):
        def done(signals):
            self.signals = signals
            self.tree.delete(*self.tree.get_children())
            for i, s in enumerate(signals):
                if not s.reset_url:
                    reset_cell = "no"
                elif s.reset_url_trusted:
                    reset_cell = "yes"
                else:
                    reset_cell = "yes ⚠ phishing?"
                tags = (s.severity.name,) if s.reset_url_trusted else ("CRITICAL",)
                self.tree.insert("", tk.END, iid=str(i),
                                 values=(s.severity.name, s.service_name,
                                         s.kind.value, reset_cell, "—"),
                                 tags=tags)
            self.status.set(f"Scan complete — {len(signals)} account(s) flagged.")
        self._run_async(lambda: self.engine.scan(Severity.MEDIUM), done,
                        "Scanning inboxes…")

    def on_breach_report(self):
        emails = sorted({a.address for a in self.engine.cfg.accounts if a.address})
        if not emails:
            messagebox.showinfo("Breach Report", "No inbox addresses configured.")
            return
        if self.engine.store.get(self.engine.store.hibp_api_key()) is None:
            messagebox.showwarning(
                "Breach Report",
                "No HIBP API key set. The account-breach lookup needs one:\n"
                "get a key at haveibeenpwned.com/API/Key, then run:\n"
                "  rphe secrets set hibp.api_key")
            return

        def done(results):
            lines, domains = [], set()
            for r in results:
                if r.breached:
                    lines.append(f"⚠  {r.name}: {', '.join(r.breach_titles[:8])}")
                    domains.update(d.lower() for d in (r.breach_domains or []))
                else:
                    lines.append(f"✓  {r.name}: no known breaches")
            self._annotate_breach_rows(domains)
            self._show_text("Breach Report (Have I Been Pwned)", "\n".join(lines))
            self.status.set("Breach report complete.")
        self._run_async(lambda: self.engine.check_accounts_breached(emails), done,
                        "Checking Have I Been Pwned…")

    def _annotate_breach_rows(self, breached_domains):
        """Badge each flagged row whose sender domain is in a known breach."""
        from .linksafety import registrable_domain
        for i, s in enumerate(self.signals):
            iid = str(i)
            if not self.tree.exists(iid):
                continue
            rd = registrable_domain(s.sender_domain)
            badge = "⚠ in breach" if rd and rd in breached_domains else "—"
            vals = list(self.tree.item(iid, "values"))
            if len(vals) >= 5:
                vals[4] = badge
                self.tree.item(iid, values=vals)

    def on_rotate(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Rotate", "Select one or more flagged accounts (or Scan).")
            return
        # Bulk rotate: open the dialog for each selected account in sequence.
        queue_ = [self.signals[int(iid)] for iid in sel]

        def open_next(_=None):
            if queue_:
                RotateDialog(self.root, self.engine, queue_.pop(0), on_close=open_next)
        open_next()

    def on_vault_audit(self):
        def done(report):
            lines = [f"Scanned {report['scanned']} logins; "
                     f"{len(report['findings'])} need attention.\n"]
            for f in report["findings"]:
                lines.append(f"⚠ {f['name']} / {f['username']}: {', '.join(f['issues'])}")
            if not report["findings"]:
                lines.append("✓ No weak, reused or breached passwords found.")
            self._show_text("Vault Audit (weak / reused / breached)", "\n".join(lines))
            self.status.set("Vault audit complete.")
        self._run_async(self.engine.audit_vault, done,
                        "Auditing every vault login (k-anonymity, local)…")

    def on_pending(self):
        PendingDialog(self.root, self.engine)

    def on_sync(self):
        def done(report):
            txt = (f"In both vaults: {len(report.in_both)}\n"
                   f"Only in Bitwarden: {len(report.only_in_bitwarden)}\n"
                   f"Only in NordPass CSV: {len(report.only_in_nordpass)}\n"
                   f"Password drift: {len(report.password_drift)}\n\n"
                   + ("✓ Vaults are consistent." if report.is_consistent
                      else "⚠ Drift detected — re-import the NordPass CSV."))
            self._show_text("Sync Verify", txt)
            self.status.set("Sync verification complete.")
        self._run_async(self.engine.sync_report, done, "Comparing vaults…")

    def on_nordpass(self):
        self._show_text("NordPass Import",
                        self.engine.nordpass().import_instructions())

    def on_audit_log(self):
        def done(events):
            if not events:
                self._show_text("Audit Log", "No audit events yet.")
                return
            lines = []
            for e in events[-200:]:
                detail = {k: v for k, v in e.items() if k not in ("ts", "action")}
                lines.append(f"{e.get('ts','')}  {e.get('action','')}  "
                             f"{str(detail)[:120]}")
            self._show_text("Audit Log (redacted, last 200)", "\n".join(lines))
            self.status.set("Audit log shown.")
        self._run_async(self.engine.audit.read_all, done, "Reading audit log…")

    def on_about(self):
        def gather():
            import keyring
            from . import __version__
            from .vaults.bitwarden import find_bw
            bw = find_bw()
            bwver = "not found"
            if bw:
                try:
                    import subprocess
                    bwver = subprocess.run([bw, "--version"], capture_output=True,
                                           text=True, timeout=20).stdout.strip() or bw
                except Exception:
                    bwver = bw
            try:
                backend = keyring.get_keyring().__class__.__name__
            except Exception:
                backend = "unknown"
            from .config import default_config_dir
            return (f"RPHE — Recovery & Password-Hygiene Engine\n"
                    f"Version: {__version__}\n"
                    f"Bitwarden CLI: {bwver}\n"
                    f"Keychain backend: {backend}\n"
                    f"Config dir: {default_config_dir()}\n"
                    f"Data dir: {self.engine.cfg.resolved_data_dir}\n"
                    f"Auto-lock: {self.engine.cfg.auto_lock_minutes} min idle\n\n"
                    "Secrets live only in your OS keychain; passwords are never "
                    "logged or sent to any third party.")
        self._run_async(gather, lambda txt: self._show_text("About RPHE", txt),
                        "Gathering version info…")

    # --- helpers ------------------------------------------------------------
    def _show_text(self, title: str, body: str):
        top = tk.Toplevel(self.root)
        top.title(title)
        top.geometry("640x420")
        box = scrolledtext.ScrolledText(top, wrap=tk.WORD, padx=10, pady=10)
        box.insert(tk.END, body)
        box.configure(state=tk.DISABLED)
        box.pack(fill=tk.BOTH, expand=True)

    # --- auto-lock ----------------------------------------------------------
    def _mark_active(self, _event=None):
        self._last_activity = time.monotonic()
        self._locked_by_idle = False

    def _check_idle(self):
        minutes = getattr(self.engine.cfg, "auto_lock_minutes", 15)
        if minutes and not self._locked_by_idle:
            idle = time.monotonic() - self._last_activity
            if idle >= minutes * 60:
                self._locked_by_idle = True
                threading.Thread(target=self.engine.lock_bitwarden, daemon=True).start()
                self.status.set(f"Vault auto-locked after {minutes} min idle. "
                                "Unlock again to continue.")
        self.root.after(30_000, self._check_idle)

    def _on_close(self):
        # Lock the vault on exit so a cached session doesn't outlive the app.
        try:
            self.engine.lock_bitwarden()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


class RotateDialog:
    """Modal-ish dialog: pick one of 5 vetted passwords, then store to both vaults."""

    def __init__(self, parent, engine: Engine, signal, on_close=None):
        self.engine = engine
        self.signal = signal
        self.on_close_cb = on_close
        self._closed = False
        self.candidates: list[str] = []
        self.choice = tk.StringVar()

        self.top = tk.Toplevel(parent)
        self.top.title(f"Rotate — {signal.service_name}")
        self.top.geometry("620x460")
        self.top.transient(parent)
        self.top.protocol("WM_DELETE_WINDOW", self._close)

        frm = ttk.Frame(self.top, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text=f"Service: {signal.service_name}   "
                            f"[{signal.severity.name}]  {signal.kind.value}",
                  font=("", 12, "bold")).pack(anchor=tk.W)
        row = ttk.Frame(frm); row.pack(fill=tk.X, pady=6)
        ttk.Label(row, text="Username / email:").pack(side=tk.LEFT)
        self.username = ttk.Entry(row, width=40)
        self.username.insert(0, signal.account_hint or "")
        self.username.pack(side=tk.LEFT, padx=6)

        ttk.Button(frm, text="Generate 5 vetted passwords",
                   command=self.on_generate).pack(anchor=tk.W, pady=4)
        ttk.Label(frm, text="Pick one (each is checked against breach databases):"
                  ).pack(anchor=tk.W)
        self.options = ttk.Frame(frm); self.options.pack(fill=tk.X, pady=4)

        btns = ttk.Frame(frm); btns.pack(side=tk.BOTTOM, fill=tk.X, pady=8)
        ttk.Button(btns, text="Apply & Store in both vaults",
                   command=self.on_apply).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=self._close).pack(side=tk.RIGHT, padx=6)
        self.info = tk.StringVar(value="")
        ttk.Label(frm, textvariable=self.info, foreground="#555").pack(
            side=tk.BOTTOM, anchor=tk.W)

    def on_generate(self):
        self.info.set("Generating and breach-checking candidates…")
        self.top.update_idletasks()

        def worker():
            try:
                cands = self.engine.password_candidates(n=5, vet_pwned=True)
                self.top.after(0, lambda: self._show_candidates(cands))
            except Exception as exc:
                self.top.after(0, lambda exc=exc: self.info.set(f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _show_candidates(self, cands):
        for w in self.options.winfo_children():
            w.destroy()
        self.candidates = cands
        if cands:
            self.choice.set(cands[0])
        for pw in cands:
            bits = estimate_strength(self.engine.cfg.policy)
            ttk.Radiobutton(self.options, variable=self.choice, value=pw,
                            text=f"{pw}    (~{bits:.0f} bits, not in any known breach ✓)"
                            ).pack(anchor=tk.W)
        self.info.set(f"{len(cands)} candidates ready. Choose one and Apply.")

    def on_apply(self):
        pw = self.choice.get()
        if not pw:
            messagebox.showinfo("Rotate", "Generate and select a password first.")
            return
        username = self.username.get().strip()
        if not username:
            messagebox.showinfo("Rotate", "Enter the username/email for this account.")
            return
        url = f"https://{self.signal.sender_domain}" if self.signal.sender_domain else None
        self.info.set("Storing in Bitwarden + NordPass…")
        self.top.update_idletasks()

        def worker():
            try:
                res = self.engine.rotate(
                    service_name=self.signal.service_name, username=username,
                    password=pw, url=url, kind=self.signal.kind.value)
                self.top.after(0, lambda: self._done(res))
            except Exception as exc:
                self.top.after(0, lambda exc=exc: self.info.set(f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, res):
        from .passkeys import render as render_pk
        from .reset import ResetOrchestrator
        plan = ResetOrchestrator().build_plan(self.signal)
        lines = [
            f"Bitwarden: {'stored & verified ✓' if res.verified else 'stored (unverified)'}"
            + (f"  id={res.bitwarden_id}" if res.bitwarden_id else ""),
            f"NordPass CSV: {'staged ✓' if res.nordpass_staged else 'FAILED'}",
            "Status: PENDING — use the 'Pending…' button to Confirm once the new "
            "password works on the site, or Revert to roll back.",
            "",
            "Now complete the reset on the website:",
            plan.render(),
            "",
            render_pk(res.passkey),
            "",
            "Finally: import the NordPass CSV (NordPass Import…), then "
            "`rphe nordpass clean`.",
        ]
        if res.error:
            lines.insert(0, f"⚠ Error: {res.error}")
        # Show the result in an independent popup, then close (chaining bulk rotate).
        top = tk.Toplevel()
        top.title(f"Rotation complete — {res.service_name}")
        top.geometry("640x520")
        box = scrolledtext.ScrolledText(top, wrap=tk.WORD, padx=10, pady=10)
        box.insert(tk.END, "\n".join(lines))
        box.configure(state=tk.DISABLED)
        box.pack(fill=tk.BOTH, expand=True)
        self._close()

    def _close(self):
        if self._closed:
            return
        self._closed = True
        cb = self.on_close_cb
        try:
            self.top.destroy()
        finally:
            if cb:
                cb()


class PendingDialog:
    """List unconfirmed rotations with per-item Confirm / Revert actions."""

    def __init__(self, parent, engine):
        self.engine = engine
        self.top = tk.Toplevel(parent)
        self.top.title("Pending rotations")
        self.top.geometry("540x380")
        self.top.transient(parent)
        self.frame = ttk.Frame(self.top, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.msg = tk.StringVar(value="Loading…")
        ttk.Label(self.top, textvariable=self.msg).pack(side=tk.BOTTOM, anchor=tk.W,
                                                        padx=10, pady=4)
        self._reload()

    def _reload(self):
        for w in self.frame.winfo_children():
            w.destroy()

        def worker():
            try:
                items = self.engine.list_pending()
                self.top.after(0, lambda: self._render(items))
            except Exception as exc:
                self.top.after(0, lambda exc=exc: self.msg.set(f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _render(self, items):
        if not items:
            ttk.Label(self.frame, text="No pending rotations.").pack(anchor=tk.W)
            self.msg.set("")
            return
        ttk.Label(self.frame, text="Confirm once the new password works on the "
                  "site; Revert to roll back to the previous one.").pack(anchor=tk.W, pady=4)
        for it in items:
            row = ttk.Frame(self.frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=f"{it.name} / {it.username}", width=34).pack(side=tk.LEFT)
            ttk.Button(row, text="Confirm",
                       command=lambda i=it: self._act("confirm", i)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row, text="Revert",
                       command=lambda i=it: self._act("revert", i)).pack(side=tk.LEFT)
        self.msg.set(f"{len(items)} pending.")

    def _act(self, kind, item):
        def worker():
            try:
                if kind == "confirm":
                    self.engine.confirm_rotation(item.item_id)
                    res = "confirmed"
                else:
                    res = "reverted" if self.engine.revert_rotation(item.item_id) \
                        else "no previous password to revert to"
                self.top.after(0, lambda: (self.msg.set(f"{item.name}: {res}"), self._reload()))
            except Exception as exc:
                self.top.after(0, lambda exc=exc: self.msg.set(f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()


def launch():
    RpheGui().run()


if __name__ == "__main__":
    launch()
