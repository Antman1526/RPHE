"""In-app Settings / Account-setup screens (Tkinter).

Makes the installed app self-contained: add/edit email accounts, store IMAP app
passwords and the HIBP key straight into the OS keychain, log in / unlock
Bitwarden, connect Gmail/Outlook via OAuth, and tune the password policy — all
without touching a YAML file or the CLI.

Threading rule (as in gui.py): blocking work (OAuth, bw subprocess) runs in a
worker thread; widgets are only updated on the main thread via ``after``.
"""
from __future__ import annotations

import copy
import threading
from typing import Optional

from .config import EmailAccount
from .engine import Engine

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception:  # pragma: no cover
    tk = None

PROVIDERS = ["imap", "gmail", "graph", "eml"]


class SettingsWindow:
    def __init__(self, parent, engine: Engine, on_saved=None):
        if tk is None:
            raise RuntimeError("Tkinter is not available.")
        self.engine = engine
        self.on_saved = on_saved
        # Work on a copy so Cancel discards changes.
        self.cfg = copy.deepcopy(engine.cfg)
        self.accounts: list = list(self.cfg.accounts)

        self.win = tk.Toplevel(parent)
        self.win.title("RPHE — Settings & Account Setup")
        self.win.geometry("720x560")
        self.win.transient(parent)

        nb = ttk.Notebook(self.win)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.tab_accounts = ttk.Frame(nb, padding=10)
        self.tab_bw = ttk.Frame(nb, padding=10)
        self.tab_hibp = ttk.Frame(nb, padding=10)
        self.tab_policy = ttk.Frame(nb, padding=10)
        nb.add(self.tab_accounts, text="Email Accounts")
        nb.add(self.tab_bw, text="Bitwarden")
        nb.add(self.tab_hibp, text="Breach (HIBP)")
        nb.add(self.tab_policy, text="Password Policy")

        self._build_accounts()
        self._build_bitwarden()
        self._build_hibp()
        self._build_policy()

        footer = ttk.Frame(self.win, padding=(8, 4))
        footer.pack(fill=tk.X)
        self.savemsg = tk.StringVar(value="")
        ttk.Label(footer, textvariable=self.savemsg, foreground="#2a7").pack(side=tk.LEFT)
        ttk.Button(footer, text="Close", command=self.win.destroy).pack(side=tk.RIGHT)
        ttk.Button(footer, text="Save settings", command=self.on_save).pack(
            side=tk.RIGHT, padx=6)

    # ---- small helpers -----------------------------------------------------
    @staticmethod
    def _labeled(parent, label, value="", show=None, width=38):
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text=label, width=18).pack(side=tk.LEFT)
        ent = ttk.Entry(row, width=width, show=show)
        ent.insert(0, str(value))
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True)
        return ent

    def _async(self, fn, on_done, busy=""):
        if busy:
            self.savemsg.set(busy)

        def worker():
            try:
                res = fn()
                self.win.after(0, lambda: on_done(res))
            except Exception as exc:
                self.win.after(0, lambda exc=exc: self._error(exc))
        threading.Thread(target=worker, daemon=True).start()

    def _error(self, exc):
        self.savemsg.set("")
        messagebox.showerror("RPHE", str(exc), parent=self.win)

    # ---- Accounts tab ------------------------------------------------------
    def _build_accounts(self):
        left = ttk.Frame(self.tab_accounts)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        ttk.Label(left, text="Accounts").pack(anchor=tk.W)
        self.listbox = tk.Listbox(left, width=24, height=16, exportselection=False)
        self.listbox.pack(fill=tk.Y, expand=True)
        self.listbox.bind("<<ListboxSelect>>", lambda e: self._load_selected())
        btns = ttk.Frame(left); btns.pack(fill=tk.X, pady=4)
        ttk.Button(btns, text="Add", command=self._add_account).pack(side=tk.LEFT)
        ttk.Button(btns, text="Remove", command=self._remove_account).pack(side=tk.LEFT, padx=4)

        form = ttk.Frame(self.tab_accounts)
        form.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.f_label = self._labeled(form, "Label", "")
        prow = ttk.Frame(form); prow.pack(fill=tk.X, pady=2)
        ttk.Label(prow, text="Provider", width=18).pack(side=tk.LEFT)
        self.f_provider = ttk.Combobox(prow, values=PROVIDERS, state="readonly", width=12)
        self.f_provider.pack(side=tk.LEFT)
        self.f_provider.bind("<<ComboboxSelected>>", lambda e: self._refresh_provider_area())
        self.f_address = self._labeled(form, "Email address", "")
        self.f_imap_host = self._labeled(form, "IMAP host", "")
        self.f_imap_port = self._labeled(form, "IMAP port", "993", width=10)
        self.f_folders = self._labeled(form, "Folders (comma)", "INBOX")
        self.f_lookback = self._labeled(form, "Lookback days", "30", width=10)

        self.provider_area = ttk.Frame(form)
        self.provider_area.pack(fill=tk.X, pady=8)

        ttk.Button(form, text="Save this account to the list",
                   command=self._apply_account).pack(anchor=tk.W, pady=4)
        self._refresh_list()

    def _refresh_list(self):
        self.listbox.delete(0, tk.END)
        for a in self.accounts:
            self.listbox.insert(tk.END, f"{a.label} ({a.provider})")

    def _selected_index(self) -> Optional[int]:
        sel = self.listbox.curselection()
        return int(sel[0]) if sel else None

    def _load_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        a = self.accounts[idx]
        for ent, val in ((self.f_label, a.label), (self.f_address, a.address),
                         (self.f_imap_host, a.imap_host), (self.f_imap_port, a.imap_port),
                         (self.f_folders, ",".join(a.folders)),
                         (self.f_lookback, a.lookback_days)):
            ent.delete(0, tk.END); ent.insert(0, str(val))
        self.f_provider.set(a.provider)
        self._refresh_provider_area()

    def _form_to_account(self) -> EmailAccount:
        try:
            port = int(self.f_imap_port.get() or 993)
        except ValueError:
            port = 993
        try:
            lookback = int(self.f_lookback.get() or 30)
        except ValueError:
            lookback = 30
        folders = [f.strip() for f in self.f_folders.get().split(",") if f.strip()] or ["INBOX"]
        return EmailAccount(
            label=self.f_label.get().strip() or "account",
            provider=(self.f_provider.get() or "imap"),
            address=self.f_address.get().strip(),
            imap_host=self.f_imap_host.get().strip(), imap_port=port,
            folders=folders, lookback_days=lookback)

    def _apply_account(self):
        acct = self._form_to_account()
        idx = self._selected_index()
        if idx is not None:
            self.accounts[idx] = acct
        else:
            self.accounts.append(acct)
        self._refresh_list()
        self.savemsg.set(f"Account '{acct.label}' updated (remember to Save settings).")

    def _add_account(self):
        self.accounts.append(EmailAccount(label="new-account", provider="imap", address=""))
        self._refresh_list()
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(tk.END)
        self._load_selected()

    def _remove_account(self):
        idx = self._selected_index()
        if idx is None:
            return
        del self.accounts[idx]
        self._refresh_list()

    def _refresh_provider_area(self):
        for w in self.provider_area.winfo_children():
            w.destroy()
        provider = self.f_provider.get()
        if provider == "imap":
            ttk.Label(self.provider_area,
                      text="IMAP needs an app password (Gmail/Outlook/iCloud/Fastmail "
                           "all support these). Stored in your OS keychain.").pack(anchor=tk.W)
            self.f_app_pw = self._labeled(self.provider_area, "App password", "", show="*")
            ttk.Button(self.provider_area, text="Save app password to Keychain",
                       command=self._save_imap_pw).pack(anchor=tk.W, pady=2)
        elif provider == "gmail":
            ttk.Label(self.provider_area,
                      text="Gmail API (read-only). Click Connect to authorize in your "
                           "browser. Needs a client_secret.json (see docs/GMAIL_SETUP.md)."
                      ).pack(anchor=tk.W)
            ttk.Button(self.provider_area, text="Connect Gmail (OAuth)…",
                       command=self._connect_gmail).pack(anchor=tk.W, pady=2)
        elif provider == "graph":
            ttk.Label(self.provider_area,
                      text="Outlook / Microsoft 365 (Mail.Read). Enter your Entra app "
                           "client ID, then Connect.").pack(anchor=tk.W)
            self.f_client_id = self._labeled(self.provider_area, "Client ID", "")
            ttk.Button(self.provider_area, text="Connect Outlook (OAuth)…",
                       command=self._connect_graph).pack(anchor=tk.W, pady=2)
        else:  # eml
            ttk.Label(self.provider_area,
                      text="Offline .eml files: put exported emails in the folder(s) "
                           "listed above; no account access needed.").pack(anchor=tk.W)

    def _save_imap_pw(self):
        label = self.f_label.get().strip()
        pw = self.f_app_pw.get()
        if not (label and pw):
            messagebox.showinfo("RPHE", "Enter a label and the app password first.",
                                parent=self.win)
            return
        self.engine.set_imap_app_password(label, pw)
        self.f_app_pw.delete(0, tk.END)
        self.savemsg.set(f"App password for '{label}' saved to keychain.")

    def _connect_gmail(self):
        self._apply_account()
        label = self.f_label.get().strip()
        path = filedialog.askopenfilename(
            title="Select client_secret.json", filetypes=[("JSON", "*.json")],
            parent=self.win)
        if not path:
            return
        self._async(lambda: self.engine.connect_gmail(label, path),
                    lambda email: self.savemsg.set(f"Gmail connected: {email}"),
                    "Opening browser for Gmail consent…")

    def _connect_graph(self):
        self._apply_account()
        label = self.f_label.get().strip()
        client_id = getattr(self, "f_client_id", None)
        cid = client_id.get().strip() if client_id else ""
        if not cid:
            messagebox.showinfo("RPHE", "Enter the Client ID first.", parent=self.win)
            return

        def show_msg(text):
            self.win.after(0, lambda: messagebox.showinfo(
                "Connect Outlook", text, parent=self.win))
        self._async(lambda: self.engine.connect_graph(label, cid, show_msg),
                    lambda _: self.savemsg.set(f"Outlook connected for '{label}'."),
                    "Starting Microsoft device-code sign-in…")

    # ---- Bitwarden tab -----------------------------------------------------
    def _build_bitwarden(self):
        self.bw_status = tk.StringVar(value="Checking…")
        ttk.Label(self.tab_bw, textvariable=self.bw_status, font=("", 12, "bold")
                  ).pack(anchor=tk.W, pady=4)
        ttk.Button(self.tab_bw, text="Refresh status", command=self._refresh_bw).pack(
            anchor=tk.W)

        ttk.Separator(self.tab_bw).pack(fill=tk.X, pady=8)
        ttk.Label(self.tab_bw, text="Log in with a personal API key "
                  "(Bitwarden → Settings → Security → Keys):").pack(anchor=tk.W)
        self.bw_cid = self._labeled(self.tab_bw, "client_id", "")
        self.bw_secret = self._labeled(self.tab_bw, "client_secret", "", show="*")
        ttk.Button(self.tab_bw, text="Log in with API key",
                   command=self._bw_login).pack(anchor=tk.W, pady=2)

        ttk.Separator(self.tab_bw).pack(fill=tk.X, pady=8)
        ttk.Label(self.tab_bw, text="Unlock (master password — stays on this device):"
                  ).pack(anchor=tk.W)
        self.bw_master = self._labeled(self.tab_bw, "master password", "", show="*")
        ttk.Button(self.tab_bw, text="Unlock vault",
                   command=self._bw_unlock).pack(anchor=tk.W, pady=2)
        self._refresh_bw()

    def _refresh_bw(self):
        def done(st):
            s = st.get("status", "unknown")
            if s == "missing-cli":
                self.bw_status.set("Bitwarden CLI not found — install `bw` "
                                   "(brew install bitwarden-cli / winget Bitwarden.CLI).")
            else:
                email = st.get("userEmail") or ""
                self.bw_status.set(f"Bitwarden: {s}" + (f"  ({email})" if email else ""))
        self._async(self.engine.bitwarden_status, done)

    def _bw_login(self):
        cid, secret = self.bw_cid.get().strip(), self.bw_secret.get().strip()
        if not (cid and secret):
            messagebox.showinfo("RPHE", "Enter client_id and client_secret.", parent=self.win)
            return
        self._async(lambda: self.engine.bitwarden_login_apikey(cid, secret),
                    lambda _: (self.bw_secret.delete(0, tk.END), self._refresh_bw(),
                               self.savemsg.set("Bitwarden logged in.")),
                    "Logging in to Bitwarden…")

    def _bw_unlock(self):
        master = self.bw_master.get()
        if not master:
            return
        self._async(lambda: self.engine.unlock_bitwarden(master),
                    lambda _: (self.bw_master.delete(0, tk.END), self._refresh_bw(),
                               self.savemsg.set("Bitwarden unlocked.")),
                    "Unlocking…")

    # ---- HIBP tab ----------------------------------------------------------
    def _build_hibp(self):
        present = self.engine.store.get(self.engine.store.hibp_api_key()) is not None
        ttk.Label(self.tab_hibp, text=(
            "The free password breach-check needs no key. To enable EMAIL breach "
            "lookups, buy a key at haveibeenpwned.com/API/Key and paste it here.")
        ).pack(anchor=tk.W, pady=4)
        self.hibp_status = tk.StringVar(
            value="A key is currently saved ✓" if present else "No key saved.")
        ttk.Label(self.tab_hibp, textvariable=self.hibp_status).pack(anchor=tk.W)
        self.hibp_key = self._labeled(self.tab_hibp, "HIBP API key", "", show="*")
        ttk.Button(self.tab_hibp, text="Save key to Keychain",
                   command=self._save_hibp).pack(anchor=tk.W, pady=2)

    def _save_hibp(self):
        key = self.hibp_key.get().strip()
        if not key:
            return
        self.engine.set_hibp_key(key)
        self.hibp_key.delete(0, tk.END)
        self.hibp_status.set("A key is currently saved ✓")
        self.savemsg.set("HIBP key saved to keychain.")

    # ---- Policy tab --------------------------------------------------------
    def _build_policy(self):
        p = self.cfg.policy
        self.pol_len = tk.IntVar(value=p.length)
        row = ttk.Frame(self.tab_policy); row.pack(fill=tk.X, pady=4)
        ttk.Label(row, text="Length", width=18).pack(side=tk.LEFT)
        ttk.Spinbox(row, from_=8, to=128, textvariable=self.pol_len, width=8).pack(side=tk.LEFT)

        self.pol_upper = tk.BooleanVar(value=p.use_upper)
        self.pol_lower = tk.BooleanVar(value=p.use_lower)
        self.pol_digits = tk.BooleanVar(value=p.use_digits)
        self.pol_symbols = tk.BooleanVar(value=p.use_symbols)
        self.pol_ambig = tk.BooleanVar(value=p.avoid_ambiguous)
        for text, var in (("Uppercase", self.pol_upper), ("Lowercase", self.pol_lower),
                          ("Digits", self.pol_digits), ("Symbols", self.pol_symbols),
                          ("Avoid ambiguous (O0Il1)", self.pol_ambig)):
            ttk.Checkbutton(self.tab_policy, text=text, variable=var).pack(anchor=tk.W)

        ttk.Separator(self.tab_policy).pack(fill=tk.X, pady=8)
        self.pol_phrase = tk.BooleanVar(value=p.passphrase_mode)
        ttk.Checkbutton(self.tab_policy, text="Passphrase mode (words, not symbols)",
                        variable=self.pol_phrase).pack(anchor=tk.W)
        self.pol_words = tk.IntVar(value=p.passphrase_words)
        row2 = ttk.Frame(self.tab_policy); row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="Passphrase words", width=18).pack(side=tk.LEFT)
        ttk.Spinbox(row2, from_=3, to=12, textvariable=self.pol_words, width=8).pack(side=tk.LEFT)

    def _collect_policy(self):
        p = self.cfg.policy
        p.length = int(self.pol_len.get())
        p.use_upper = bool(self.pol_upper.get())
        p.use_lower = bool(self.pol_lower.get())
        p.use_digits = bool(self.pol_digits.get())
        p.use_symbols = bool(self.pol_symbols.get())
        p.avoid_ambiguous = bool(self.pol_ambig.get())
        p.passphrase_mode = bool(self.pol_phrase.get())
        p.passphrase_words = int(self.pol_words.get())

    # ---- save all ----------------------------------------------------------
    def on_save(self):
        self._collect_policy()
        self.cfg.accounts = self.accounts
        try:
            self.engine.save(self.cfg)
        except Exception as exc:
            self._error(exc)
            return
        self.savemsg.set("Settings saved to config.yaml ✓")
        if self.on_saved:
            self.on_saved()
