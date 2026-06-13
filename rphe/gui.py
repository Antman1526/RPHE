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
        self._btn(bar, "Rotate Selected…", self.on_rotate)
        self._btn(bar, "Sync Verify", self.on_sync)
        self._btn(bar, "NordPass Import…", self.on_nordpass)

        cols = ("severity", "service", "kind", "reset")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings",
                                 selectmode="browse")
        for c, w, label in (("severity", 90, "Severity"), ("service", 200, "Service"),
                            ("kind", 200, "Signal"), ("reset", 90, "Reset link")):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, anchor=tk.W)
        self.tree.tag_configure("CRITICAL", foreground="#b00020")
        self.tree.tag_configure("HIGH", foreground="#c25e00")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=6)
        self.tree.bind("<Double-1>", lambda e: self.on_rotate())

        self.status = tk.StringVar(value="Ready. Configure accounts in config.yaml, "
                                          "then Scan. Nothing is sent anywhere but "
                                          "your own providers and vaults.")
        ttk.Label(self.root, textvariable=self.status, relief=tk.SUNKEN,
                  anchor=tk.W, padding=(8, 4)).pack(side=tk.BOTTOM, fill=tk.X)

    def _btn(self, parent, text, cmd):
        ttk.Button(parent, text=text, command=cmd).pack(side=tk.LEFT, padx=4)

    # --- async plumbing -----------------------------------------------------
    def _run_async(self, fn: Callable, on_done: Callable, busy: str):
        self.status.set(busy)

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
                self.tree.insert("", tk.END, iid=str(i),
                                 values=(s.severity.name, s.service_name,
                                         s.kind.value, "yes" if s.reset_url else "no"),
                                 tags=(s.severity.name,))
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
            lines = []
            for r in results:
                if r.breached:
                    lines.append(f"⚠  {r.name}: {', '.join(r.breach_titles[:8])}")
                else:
                    lines.append(f"✓  {r.name}: no known breaches")
            self._show_text("Breach Report (Have I Been Pwned)", "\n".join(lines))
            self.status.set("Breach report complete.")
        self._run_async(lambda: self.engine.check_accounts_breached(emails), done,
                        "Checking Have I Been Pwned…")

    def on_rotate(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Rotate", "Select a flagged account first (or Scan).")
            return
        s = self.signals[int(sel[0])]
        RotateDialog(self.root, self.engine, s)

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

    # --- helpers ------------------------------------------------------------
    def _show_text(self, title: str, body: str):
        top = tk.Toplevel(self.root)
        top.title(title)
        top.geometry("640x420")
        box = scrolledtext.ScrolledText(top, wrap=tk.WORD, padx=10, pady=10)
        box.insert(tk.END, body)
        box.configure(state=tk.DISABLED)
        box.pack(fill=tk.BOTH, expand=True)

    def run(self):
        self.root.mainloop()


class RotateDialog:
    """Modal-ish dialog: pick one of 5 vetted passwords, then store to both vaults."""

    def __init__(self, parent, engine: Engine, signal):
        self.engine = engine
        self.signal = signal
        self.candidates: list[str] = []
        self.choice = tk.StringVar()

        self.top = tk.Toplevel(parent)
        self.top.title(f"Rotate — {signal.service_name}")
        self.top.geometry("620x460")
        self.top.transient(parent)

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
        ttk.Button(btns, text="Cancel", command=self.top.destroy).pack(side=tk.RIGHT, padx=6)
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
                self.top.after(0, lambda: self.info.set(f"Error: {exc}"))
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
                self.top.after(0, lambda: self.info.set(f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, res):
        from .passkeys import render as render_pk
        from .reset import ResetOrchestrator
        plan = ResetOrchestrator().build_plan(self.signal)
        lines = [
            f"Bitwarden: {'stored & verified ✓' if res.verified else 'stored (unverified)'}"
            + (f"  id={res.bitwarden_id}" if res.bitwarden_id else ""),
            f"NordPass CSV: {'staged ✓' if res.nordpass_staged else 'FAILED'}",
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
        self.top.destroy()
        # Reuse the parent's text popup.
        top = tk.Toplevel()
        top.title(f"Rotation complete — {res.service_name}")
        top.geometry("640x520")
        box = scrolledtext.ScrolledText(top, wrap=tk.WORD, padx=10, pady=10)
        box.insert(tk.END, "\n".join(lines))
        box.configure(state=tk.DISABLED)
        box.pack(fill=tk.BOTH, expand=True)


def launch():
    RpheGui().run()


if __name__ == "__main__":
    launch()
