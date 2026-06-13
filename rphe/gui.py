"""Modern desktop GUI for RPHE (customtkinter).

A friendly, goal-oriented interface that mirrors what the tool is *for*:

    1. Connect   — your email inboxes, Bitwarden, NordPass, breach database
    2. Scan & Fix — find compromised accounts and rotate their passwords
    3. Vault Health — audit every stored password; keep both vaults in sync

Layout: a left sidebar for navigation + a content area that swaps "pages". All
network/vault work runs on worker threads; widgets are only touched on the main
thread via a result queue. Same engine as the CLI, so behaviour is identical.
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
from typing import Callable, Optional

from . import __version__
from .config import EmailAccount
from .engine import Engine
from .models import Severity
from .passwords import estimate_strength

try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
except Exception:  # pragma: no cover - headless / no Tk
    ctk = None

# ---- palette (light, dark) — calm & premium: neutral surfaces, one accent -----
CARD = ("#ffffff", "#202024")
BORDER = ("#e4e6eb", "#2d2d33")
SIDEBAR = ("#ffffff", "#161619")
TEXT = ("#1a1a1f", "#f2f2f5")
MUTED = ("#6b7280", "#9aa3af")
ACCENT_BG = ("#2563eb", "#3b82f6")   # the single accent — primary CTA + active nav
ACCENT_TEXT = ("#2563eb", "#60a5fa")
GREEN = ("#16a34a", "#22c55e")
AMBER = ("#d97706", "#f59e0b")
RED = ("#dc2626", "#ef4444")
GREY = ("#9aa3af", "#5b6068")
SEV_COLOR = {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": ("#ca8a04", "#eab308"),
             "LOW": ("#2563eb", "#3b82f6"), "INFO": GREY}

NAV = [
    ("dashboard", "🏠  Dashboard"),
    ("connect", "🔌  Connect"),
    ("scan", "🛡️  Scan & Fix"),
    ("health", "🔑  Vault Health"),
    ("settings", "⚙️  Settings"),
]


def _require_ctk():
    if ctk is None:
        raise RuntimeError(
            "The desktop GUI needs customtkinter + Tk. Install with "
            "`pip install \".[gui]\"` and use a Tk-enabled Python.")


class RpheApp(ctk.CTk if ctk else object):
    def __init__(self, engine: Optional[Engine] = None):
        _require_ctk()
        super().__init__()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        self.engine = engine or Engine()
        self.signals = []
        self._scanned = False
        self._results_q: "queue.Queue" = queue.Queue()
        self._busy = 0
        self.nav_buttons: dict = {}
        self.pages: dict = {}
        self.checklist: dict = {}

        self.title("RPHE — Recovery & Password-Hygiene Engine")
        self.geometry("1060x700")
        self.minsize(940, 620)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content()
        self._poll_queue()

        # auto-lock
        self._last_activity = time.monotonic()
        self._locked_by_idle = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        for ev in ("<Any-KeyPress>", "<Any-Button>"):
            self.bind_all(ev, self._mark_active, add="+")
        self.after(30_000, self._check_idle)

        self.show_page(self._initial_page())
        self.after(200, self.refresh_status)

    def _initial_page(self) -> str:
        """Which page to open on launch. Defaults to 'dashboard'; overridable via
        `--start-page <name>` (open … --args --start-page connect) or the
        RPHE_START_PAGE env var. Useful for deep-linking and screenshots."""
        page = os.environ.get("RPHE_START_PAGE", "dashboard")
        if "--start-page" in sys.argv:
            i = sys.argv.index("--start-page")
            if i + 1 < len(sys.argv):
                page = sys.argv[i + 1]
        return page if page in self.pages else "dashboard"

    # ===================================================================== UI
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self, width=212, corner_radius=0, fg_color=SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsew")
        bar.grid_rowconfigure(99, weight=1)
        bar.grid_propagate(False)

        ctk.CTkLabel(bar, text="🛡  RPHE", font=ctk.CTkFont(size=22, weight="bold")
                     ).grid(row=0, column=0, padx=20, pady=(22, 0), sticky="w")
        ctk.CTkLabel(bar, text="Recovery & Password Hygiene", font=ctk.CTkFont(size=11),
                     text_color=MUTED).grid(row=1, column=0, padx=20, pady=(0, 18), sticky="w")

        for i, (key, label) in enumerate(NAV):
            b = ctk.CTkButton(bar, text=label, anchor="w", height=40, corner_radius=8,
                              fg_color="transparent", text_color=("#1f2937", "#e5e7eb"),
                              hover_color=("#e5e7eb", "#26262c"),
                              font=ctk.CTkFont(size=14),
                              command=lambda k=key: self.show_page(k))
            b.grid(row=2 + i, column=0, padx=12, pady=3, sticky="ew")
            self.nav_buttons[key] = b

        bottom = ctk.CTkFrame(bar, fg_color="transparent")
        bottom.grid(row=100, column=0, padx=12, pady=14, sticky="ew")
        self.appearance = ctk.CTkSegmentedButton(
            bottom, values=["Light", "Dark", "System"],
            command=lambda v: ctk.set_appearance_mode(v))
        self.appearance.set("System")
        self.appearance.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(bottom, text="🔒  Lock vault", height=34, fg_color="transparent",
                      border_width=1, text_color=("#1f2937", "#e5e7eb"),
                      hover_color=("#e5e7eb", "#26262c"),
                      command=self.on_lock).pack(fill="x")
        ctk.CTkLabel(bottom, text=f"v{__version__}", font=ctk.CTkFont(size=11),
                     text_color=MUTED).pack(pady=(8, 0))

    def _build_content(self):
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=("#fafafa", "#0e0e10"))
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        # Status bar first — pages reference self.status/self.progress at build time.
        sb = ctk.CTkFrame(self.content, height=34, corner_radius=0,
                          fg_color=("#f0f0f2", "#161619"))
        sb.grid(row=1, column=0, sticky="ew")
        sb.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(sb, text="Ready.", anchor="w", text_color=MUTED,
                                   font=ctk.CTkFont(size=12))
        self.status.grid(row=0, column=0, sticky="ew", padx=14)
        self.progress = ctk.CTkProgressBar(sb, width=150, mode="indeterminate")
        self.progress.grid(row=0, column=1, padx=14, pady=6)
        self.progress.set(0)

        for key in ("dashboard", "connect", "scan", "health", "settings"):
            page = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
            page.grid(row=0, column=0, sticky="nsew", padx=40, pady=(32, 10))
            page.grid_columnconfigure(0, weight=1)
            self.pages[key] = page
            getattr(self, f"_page_{key}")(page)

    def show_page(self, key: str):
        for k, page in self.pages.items():
            page.grid_remove()
        self.pages[key].grid()
        for k, b in self.nav_buttons.items():
            if k == key:
                b.configure(fg_color=("#e8eefc", "#1d3a8a"), text_color=ACCENT_TEXT)
            else:
                b.configure(fg_color="transparent", text_color=TEXT)
        if key == "dashboard":
            self._refresh_dashboard()

    # ---- reusable widgets --------------------------------------------------
    @staticmethod
    def _card(parent):
        c = ctk.CTkFrame(parent, fg_color=CARD, border_width=1, border_color=BORDER,
                         corner_radius=12)
        c.grid_columnconfigure(0, weight=1)
        return c

    @staticmethod
    def _h1(parent, text):
        return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=24, weight="bold"),
                            anchor="w", justify="left")

    @staticmethod
    def _muted(parent, text, size=13, wrap=620):
        return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=size),
                            text_color=MUTED, anchor="w", justify="left", wraplength=wrap)

    # ===================================================================== PAGES
    def _page_dashboard(self, page):
        # Calm & premium: one eyebrow, a big purpose statement, a guided spine,
        # a quiet status checklist, and exactly one primary action — all reactive
        # to how far setup has progressed (see _refresh_dashboard).
        self.dash_eyebrow = ctk.CTkLabel(page, text="", font=ctk.CTkFont(size=12, weight="bold"),
                                         text_color=ACCENT_TEXT, anchor="w")
        self.dash_eyebrow.grid(row=0, column=0, sticky="w")
        self.dash_title = ctk.CTkLabel(page, text="", font=ctk.CTkFont(size=26, weight="bold"),
                                       justify="left", anchor="w")
        self.dash_title.grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.dash_sub = ctk.CTkLabel(page, text="", font=ctk.CTkFont(size=14),
                                     text_color=MUTED, justify="left", anchor="w", wraplength=520)
        self.dash_sub.grid(row=2, column=0, sticky="w", pady=(10, 26))

        self.spine = ctk.CTkFrame(page, fg_color="transparent")
        self.spine.grid(row=3, column=0, sticky="ew", pady=(0, 26))
        for i in range(3):
            self.spine.grid_columnconfigure(i, weight=1, uniform="step")

        panel = self._card(page)
        panel.grid(row=4, column=0, sticky="w", pady=(0, 24))
        ctk.CTkLabel(panel, text="What's connected", font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=MUTED, anchor="w").grid(row=0, column=0, sticky="w",
                                                        padx=20, pady=(16, 10))
        rows = ctk.CTkFrame(panel, fg_color="transparent")
        rows.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))
        rows.grid_columnconfigure(0, minsize=360)
        for i, (key, label) in enumerate([("email", "Email inbox"),
                                          ("bitwarden", "Bitwarden"), ("nordpass", "NordPass")]):
            r = ctk.CTkFrame(rows, fg_color="transparent")
            r.grid(row=i, column=0, sticky="ew", pady=5)
            r.grid_columnconfigure(1, weight=1)
            dot = ctk.CTkLabel(r, text="○", font=ctk.CTkFont(size=15), text_color=GREY, width=18)
            dot.grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(r, text=label, font=ctk.CTkFont(size=13), anchor="w").grid(
                row=0, column=1, sticky="w", padx=8)
            st = ctk.CTkLabel(r, text="…", font=ctk.CTkFont(size=12), text_color=MUTED)
            st.grid(row=0, column=2, sticky="e")
            self.checklist[key] = (dot, st)

        self.dash_cta = ctk.CTkButton(page, text="", height=46, width=260,
                                      font=ctk.CTkFont(size=15, weight="bold"))
        self.dash_cta.grid(row=5, column=0, sticky="w")
        self.dash_hint = ctk.CTkLabel(page, text="Everything stays in your device's keychain.",
                                      font=ctk.CTkFont(size=12), text_color=MUTED, anchor="w")
        self.dash_hint.grid(row=6, column=0, sticky="w", pady=(12, 0))
        self._refresh_dashboard()

    def _build_spine(self, current: int):
        for w in self.spine.winfo_children():
            w.destroy()
        steps = [("Connect", "Link email & your vaults"),
                 ("Scan", "Find compromised accounts"),
                 ("Fix", "Rotate & store in both")]
        for i, (title, sub) in enumerate(steps):
            n = i + 1
            col = ctk.CTkFrame(self.spine, fg_color="transparent")
            col.grid(row=0, column=i, sticky="w")
            head = ctk.CTkFrame(col, fg_color="transparent")
            head.grid(row=0, column=0, sticky="w")
            done = n < current
            active = n == current
            circle = ctk.CTkLabel(head, text=("✓" if done else str(n)), width=30, height=30,
                                  corner_radius=15, font=ctk.CTkFont(size=13, weight="bold"),
                                  fg_color=(GREEN if done else (ACCENT_BG if active else "transparent")),
                                  text_color=("#ffffff" if (done or active) else GREY))
            if not (done or active):
                circle.configure(fg_color=("#eceef2", "#26262c"))
            circle.grid(row=0, column=0)
            ctk.CTkLabel(head, text=title, font=ctk.CTkFont(size=14, weight="bold"),
                         text_color=(TEXT if active or done else MUTED)).grid(row=0, column=1, padx=10)
            ctk.CTkLabel(col, text=sub, font=ctk.CTkFont(size=12), text_color=MUTED,
                         anchor="w").grid(row=1, column=0, sticky="w", padx=(40, 0), pady=(6, 0))

    def _refresh_dashboard(self):
        if not hasattr(self, "dash_cta"):
            return
        accounts = bool(self.engine.cfg.accounts)
        flagged = len(self.signals)
        if not accounts:
            step = 1
            eyebrow = "GETTING STARTED"
            title = "Find the accounts that are at risk —\nand fix them in a few clicks."
            sub = ("RPHE reads your inbox for breach and suspicious-login alerts, helps you "
                   "set a strong new password, and saves it to Bitwarden and NordPass. Three steps.")
            cta, cmd = "Connect your inbox to begin", lambda: self.show_page("connect")
        elif not self._scanned:
            step = 2
            eyebrow = "READY TO SCAN"
            title = "You're set up.\nScan your inbox whenever you're ready."
            sub = "RPHE will look through recent mail for accounts that may be compromised."
            cta, cmd = "Scan my accounts", lambda: (self.show_page("scan"), self.on_scan())
        elif flagged:
            step = 3
            eyebrow = "ACTION NEEDED"
            title = f"{flagged} account{'s' if flagged != 1 else ''} need attention."
            sub = "Review each one and rotate to a strong new password stored in both vaults."
            cta, cmd = (f"Review {flagged} at-risk account{'s' if flagged != 1 else ''}",
                        lambda: self.show_page("scan"))
        else:
            step = 3
            eyebrow = "ALL CLEAR"
            title = "No at-risk accounts found."
            sub = "You're in good shape. Scan again any time, or audit your whole vault."
            cta, cmd = "Scan again", lambda: (self.show_page("scan"), self.on_scan())
        self.dash_eyebrow.configure(text=eyebrow)
        self.dash_title.configure(text=title)
        self.dash_sub.configure(text=sub)
        self.dash_cta.configure(text=cta, command=cmd)
        self._build_spine(step)
        self._refresh_checklist()

    def _set_check(self, key, state, text):
        pair = self.checklist.get(key)
        if not pair:
            return
        dot, st = pair
        glyph, color = {"ok": ("●", GREEN), "todo": ("○", GREY),
                        "warn": ("●", AMBER)}.get(state, ("○", GREY))
        dot.configure(text=glyph, text_color=color)
        st.configure(text=text, text_color=(color if state != "todo" else MUTED))

    def _refresh_checklist(self):
        self._set_check("email", "ok" if self.engine.cfg.accounts else "todo",
                        "Connected" if self.engine.cfg.accounts else "Not connected")
        self._set_check("nordpass", "ok", "Ready (CSV)")

        def done(stt):
            s = stt.get("status", "unknown")
            mapping = {"unlocked": ("ok", "Unlocked"), "locked": ("warn", "Locked — unlock to use"),
                       "unauthenticated": ("todo", "Not logged in"),
                       "missing-cli": ("todo", "CLI not found")}
            state, txt = mapping.get(s, ("todo", "Unknown"))
            self._set_check("bitwarden", state, txt)
            # Keep the Connect-page Bitwarden pill in sync too, if it exists.
            if "bitwarden" in getattr(self, "_connect_cards", {}):
                pill = {"unlocked": ("ok", "Connected"), "locked": ("warn", "Locked"),
                        "missing-cli": ("warn", "Missing")}.get(s, ("todo", "Not connected"))
                self._set_conn_status("bitwarden", *pill)
        self._async(self.engine.bitwarden_status, done, "")

    # ---- Connect -----------------------------------------------------------
    def _page_connect(self, page):
        self._h1(page, "Connect your services").grid(row=0, column=0, sticky="w")
        self._muted(page, "Connect these one at a time. Everything you enter is stored "
                    "in your device's keychain — never sent to us.", wrap=720).grid(
            row=1, column=0, sticky="w", pady=(6, 18))
        self._connect_cards = {}

        b = self._conn_card(page, "email", "✉", "Email inbox",
                            "The mailbox RPHE scans for alerts", 2)
        self._email_body(b)
        b = self._conn_card(page, "bitwarden", "🔑", "Bitwarden",
                            "Where your strong new passwords are saved", 3)
        self._bw_body(b)
        b = self._conn_card(page, "hibp", "🔎", "Breach check  ·  optional",
                            "Look up your email in known breaches", 4)
        self._hibp_body(b)
        b = self._conn_card(page, "nordpass", "🗂", "NordPass",
                            "Kept in sync with a CSV you import", 5)
        self._nordpass_body(b)

        self._refresh_bw_body()            # set the Bitwarden pill from live status
        self._toggle_card("email")         # open the first card by default

    # ---- collapsible card scaffold ----------------------------------------
    def _conn_card(self, parent, key, icon, title, subtitle, row):
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        card.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=14)
        header.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(header, text=icon, font=ctk.CTkFont(size=18), width=24).grid(
            row=0, column=0, rowspan=2, padx=(0, 12))
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=15, weight="bold"),
                     anchor="w").grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(header, text=subtitle, font=ctk.CTkFont(size=12), text_color=MUTED,
                     anchor="w").grid(row=1, column=1, sticky="w")
        pill = ctk.CTkLabel(header, text="…", font=ctk.CTkFont(size=12), text_color=MUTED,
                            fg_color=("#eceef2", "#26262c"), corner_radius=12)
        pill.grid(row=0, column=3, rowspan=2, padx=10, ipadx=8, ipady=3)
        toggle = ctk.CTkButton(header, text="Open", width=74, height=30,
                               fg_color="transparent", border_width=1,
                               command=lambda k=key: self._toggle_card(k))
        toggle.grid(row=0, column=4, rowspan=2)
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))
        body.grid_columnconfigure(0, weight=1)
        body.grid_remove()
        self._connect_cards[key] = {"body": body, "toggle": toggle, "pill": pill, "open": False}
        return body

    def _toggle_card(self, key):
        for k, c in self._connect_cards.items():       # accordion: one open at a time
            if k != key and c["open"]:
                c["body"].grid_remove(); c["open"] = False; c["toggle"].configure(text="Open")
        c = self._connect_cards[key]
        if c["open"]:
            c["body"].grid_remove(); c["open"] = False; c["toggle"].configure(text="Open")
        else:
            c["body"].grid(); c["open"] = True; c["toggle"].configure(text="Close")
            if key == "bitwarden":
                self._refresh_bw_body()

    def _set_conn_status(self, key, state, text):
        c = self._connect_cards.get(key)
        if not c:
            return
        palette = {"ok": (GREEN, ("#e6f4ea", "#10331f")),
                   "warn": (AMBER, ("#fdf0dd", "#3a2a10")),
                   "ready": (ACCENT_TEXT, ("#e8eefc", "#16264e")),
                   "todo": (MUTED, ("#eceef2", "#26262c"))}
        fg, bg = palette.get(state, palette["todo"])
        c["pill"].configure(text=text, text_color=fg, fg_color=bg)

    @staticmethod
    def _open_url(url):
        import webbrowser
        if url:
            webbrowser.open(url)

    # ---- Email card --------------------------------------------------------
    def _email_body(self, body):
        self.account_list = ctk.CTkFrame(body, fg_color="transparent")
        self.account_list.grid(row=0, column=0, sticky="ew")
        self.account_list.grid_columnconfigure(0, weight=1)
        self._refresh_account_list()

        form = ctk.CTkFrame(body, fg_color=("#f6f7f9", "#191920"), corner_radius=10)
        form.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        form.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(form, text="Add an inbox", font=ctk.CTkFont(size=13, weight="bold")
                     ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        inner = ctk.CTkFrame(form, fg_color="transparent")
        inner.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12))
        inner.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(inner, text="Your email address", font=ctk.CTkFont(size=12),
                     text_color=MUTED, anchor="w").grid(row=0, column=0, sticky="w")
        self.in_address = ctk.CTkEntry(inner, placeholder_text="you@gmail.com")
        self.in_address.grid(row=1, column=0, sticky="ew", pady=(2, 2))
        self.in_address.bind("<KeyRelease>", lambda e: self._on_email_detect())
        self.detect_lbl = ctk.CTkLabel(inner, text="", font=ctk.CTkFont(size=12),
                                       text_color=GREEN, anchor="w")
        self.detect_lbl.grid(row=2, column=0, sticky="w", pady=(0, 6))

        ctk.CTkLabel(inner, text="App password", font=ctk.CTkFont(size=12),
                     text_color=MUTED, anchor="w").grid(row=3, column=0, sticky="w")
        self.in_app_pw = ctk.CTkEntry(inner, placeholder_text="paste an app password", show="•")
        self.in_app_pw.grid(row=4, column=0, sticky="ew", pady=(2, 2))
        self.apppw_link = ctk.CTkButton(inner, text="How do I get an app password?",
                                        fg_color="transparent", hover=False, anchor="w",
                                        text_color=ACCENT_TEXT,
                                        command=lambda: self._open_url(
                                            getattr(self, "_apppw_url", "")
                                            or "https://support.google.com/accounts/answer/185833"))
        self.apppw_link.grid(row=5, column=0, sticky="w", pady=(0, 6))
        self.in_imap_host = ctk.CTkEntry(inner, placeholder_text="IMAP host (filled automatically)")
        self.in_imap_host.grid(row=6, column=0, sticky="ew", pady=(0, 10))

        btns = ctk.CTkFrame(inner, fg_color="transparent")
        btns.grid(row=7, column=0, sticky="w")
        ctk.CTkButton(btns, text="Connect inbox", command=self.on_add_inbox).pack(side="left")
        self.oauth_alt = ctk.CTkButton(btns, text="", fg_color="transparent", hover=False,
                                       text_color=ACCENT_TEXT, command=self._oauth_connect)
        self.oauth_alt.pack(side="left", padx=12)
        self.oauth_alt.pack_forget()
        ctk.CTkLabel(inner, text="🔒 Stored in your device keychain, never sent to us.",
                     font=ctk.CTkFont(size=11), text_color=MUTED, anchor="w").grid(
            row=8, column=0, sticky="w", pady=(8, 0))
        self._set_conn_status("email", "ok" if self.engine.cfg.accounts else "todo",
                              "Connected" if self.engine.cfg.accounts else "Not connected")

    def _on_email_detect(self):
        from .providers import detect_provider
        info = detect_provider(self.in_address.get())
        self._detected = info
        self._apppw_url = info.app_password_url
        if info.imap_host:
            self.in_imap_host.delete(0, "end")
            self.in_imap_host.insert(0, info.imap_host)
            self.detect_lbl.configure(text=f"{info.name} detected — we'll use {info.imap_host}",
                                      text_color=GREEN)
        else:
            self.detect_lbl.configure(text=(info.note or ""), text_color=MUTED)
        if info.oauth:
            self.oauth_alt.configure(text=f"Advanced: connect with {info.name} (read-only) →")
            self.oauth_alt.pack(side="left", padx=12)
        else:
            self.oauth_alt.pack_forget()

    def _oauth_connect(self):
        info = getattr(self, "_detected", None)
        if info and info.oauth == "gmail":
            self.on_connect_gmail()
        elif info and info.oauth == "graph":
            self.on_connect_graph()

    def _refresh_account_list(self):
        for w in self.account_list.winfo_children():
            w.destroy()
        accounts = self.engine.cfg.accounts
        if not accounts:
            self._muted(self.account_list, "No inboxes yet — add one below.").grid(
                row=0, column=0, sticky="w", padx=4, pady=4)
            return
        for i, a in enumerate(accounts):
            row = ctk.CTkFrame(self.account_list, fg_color=("#f0f1f4", "#191920"), corner_radius=8)
            row.grid(row=i, column=0, sticky="ew", pady=3)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=f"{a.label}  ·  {a.provider}  ·  {a.address or '—'}",
                         anchor="w").grid(row=0, column=0, sticky="w", padx=12, pady=6)
            ctk.CTkButton(row, text="Remove", width=70, height=26, fg_color="transparent",
                          border_width=1, text_color=RED,
                          command=lambda lbl=a.label: self.on_remove_inbox(lbl)).grid(
                row=0, column=1, padx=8)

    # ---- Bitwarden card (adapts to login/lock state) ----------------------
    def _bw_body(self, body):
        self.bw_body_inner = ctk.CTkFrame(body, fg_color="transparent")
        self.bw_body_inner.grid(row=0, column=0, sticky="ew")
        self.bw_body_inner.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.bw_body_inner, text="Checking…", text_color=MUTED, anchor="w").grid(
            row=0, column=0, sticky="w")

    def _refresh_bw_body(self):
        self._async(self.engine.bitwarden_status, self._render_bw, "")

    def _render_bw(self, st):
        inner = self.bw_body_inner
        for w in inner.winfo_children():
            w.destroy()
        s = st.get("status", "unknown")
        email = st.get("userEmail") or ""
        if s == "unlocked":
            ctk.CTkLabel(inner, text=f"Connected ✓   {email}", text_color=GREEN,
                         anchor="w").grid(row=0, column=0, sticky="w")
            ctk.CTkButton(inner, text="Lock vault", fg_color="transparent", border_width=1,
                          command=self.on_lock).grid(row=1, column=0, sticky="w", pady=8)
            self._set_conn_status("bitwarden", "ok", "Connected")
        elif s == "locked":
            ctk.CTkLabel(inner, text=f"Signed in{(' as ' + email) if email else ''} — "
                         "unlock to use it.", text_color=MUTED, anchor="w").grid(
                row=0, column=0, sticky="w")
            ctk.CTkButton(inner, text="Unlock vault", command=self.on_unlock).grid(
                row=1, column=0, sticky="w", pady=8)
            self._set_conn_status("bitwarden", "warn", "Locked")
        elif s == "missing-cli":
            ctk.CTkLabel(inner, text="Bitwarden CLI not found on this system.",
                         text_color=AMBER, anchor="w").grid(row=0, column=0, sticky="w")
            self._set_conn_status("bitwarden", "warn", "Missing")
        else:
            ctk.CTkLabel(inner, text="Sign in with a Bitwarden API key "
                         "(bitwarden.com → Settings → Security → Keys).", text_color=MUTED,
                         anchor="w", wraplength=520, justify="left").grid(
                row=0, column=0, sticky="w")
            self.bw_cid = ctk.CTkEntry(inner, placeholder_text="client_id")
            self.bw_cid.grid(row=1, column=0, sticky="ew", pady=(8, 4))
            self.bw_secret = ctk.CTkEntry(inner, placeholder_text="client_secret", show="•")
            self.bw_secret.grid(row=2, column=0, sticky="ew", pady=(0, 4))
            ctk.CTkButton(inner, text="Sign in", command=self.on_bw_login).grid(
                row=3, column=0, sticky="w", pady=8)
            ctk.CTkButton(inner, text="Where do I find this?", fg_color="transparent",
                          hover=False, text_color=ACCENT_TEXT,
                          command=lambda: self._open_url(
                              "https://bitwarden.com/help/personal-api-key/")).grid(
                row=4, column=0, sticky="w")
            self._set_conn_status("bitwarden", "todo", "Not connected")

    # ---- Breach + NordPass cards ------------------------------------------
    def _hibp_body(self, body):
        present = self.engine.store.get(self.engine.store.hibp_api_key()) is not None
        ctk.CTkLabel(body, text=("A key is saved ✓" if present else
                     "Optional — the free password check needs no key. Add a HIBP key to "
                     "also look up which breaches your email appears in."),
                     text_color=(GREEN if present else MUTED), anchor="w",
                     wraplength=520, justify="left").grid(row=0, column=0, sticky="w")
        self.hibp_key = ctk.CTkEntry(body, placeholder_text="HIBP API key", show="•")
        self.hibp_key.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        ctk.CTkButton(body, text="Save key", command=self.on_save_hibp).grid(
            row=2, column=0, sticky="w", pady=4)
        self._set_conn_status("hibp", "ok" if present else "todo",
                              "Connected" if present else "Optional")

    def _nordpass_body(self, body):
        ctk.CTkLabel(body, text="NordPass has no write API, so RPHE keeps it in sync via a "
                     "CSV you import (NordPass → Settings → Import). Bitwarden is the "
                     "automated source of truth.", text_color=MUTED, anchor="w",
                     wraplength=520, justify="left").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(body, text="Show import steps", fg_color="transparent", border_width=1,
                      command=self.on_nordpass).grid(row=1, column=0, sticky="w", pady=8)
        self._set_conn_status("nordpass", "ready", "Ready")

    # ---- Scan & Fix --------------------------------------------------------
    def _page_scan(self, page):
        self._h1(page, "Scan & Fix").grid(row=0, column=0, sticky="w")
        self._muted(page, "Scan your inboxes for at-risk accounts, then rotate the "
                    "ones that need it.", wrap=720).grid(row=1, column=0, sticky="w", pady=(4, 14))
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkButton(bar, text="🔍  Scan inboxes", command=self.on_scan).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bar, text="🔎  Breach report", fg_color="transparent", border_width=1,
                      command=self.on_breach_report).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="📋  Pending rotations", fg_color="transparent", border_width=1,
                      command=self.on_pending).pack(side="left", padx=8)
        self.findings = ctk.CTkFrame(page, fg_color="transparent")
        self.findings.grid(row=3, column=0, sticky="ew")
        self.findings.grid_columnconfigure(0, weight=1)
        self._empty_findings()

    def _empty_findings(self):
        for w in self.findings.winfo_children():
            w.destroy()
        card = self._card(self.findings)
        card.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(card, text="🗂️", font=ctk.CTkFont(size=34)).grid(row=0, column=0, pady=(22, 0))
        ctk.CTkLabel(card, text="No scan yet", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=1, column=0)
        self._muted(card, "Click 'Scan inboxes' to look for compromised accounts.").grid(
            row=2, column=0, pady=(2, 22))

    def _render_findings(self, signals):
        for w in self.findings.winfo_children():
            w.destroy()
        if not signals:
            card = self._card(self.findings)
            card.grid(row=0, column=0, sticky="ew")
            ctk.CTkLabel(card, text="✅  You're clear", font=ctk.CTkFont(size=16, weight="bold")
                         ).grid(row=0, column=0, padx=16, pady=(18, 2), sticky="w")
            self._muted(card, "No at-risk accounts found in the scanned mail.").grid(
                row=1, column=0, padx=16, pady=(0, 18), sticky="w")
            return
        for i, s in enumerate(signals):
            self._finding_card(s, i).grid(row=i, column=0, sticky="ew", pady=5)

    def _finding_card(self, s, idx):
        card = self._card(self.findings)
        card.grid_columnconfigure(1, weight=1)
        sev = SEV_COLOR.get(s.severity.name, GREY)
        strip = ctk.CTkFrame(card, width=6, fg_color=sev, corner_radius=0)
        strip.grid(row=0, column=0, rowspan=3, sticky="nsw")
        ctk.CTkLabel(card, text=s.service_name, font=ctk.CTkFont(size=16, weight="bold"),
                     anchor="w").grid(row=0, column=1, sticky="w", padx=14, pady=(12, 0))
        ctk.CTkLabel(card, text=s.severity.name, fg_color=sev, corner_radius=10,
                     text_color="#ffffff", font=ctk.CTkFont(size=11, weight="bold"),
                     padx=10, pady=2).grid(row=0, column=2, padx=10, pady=(12, 0))
        self._muted(card, f"{s.kind.value.replace('_', ' ')} — {s.rationale}", wrap=560).grid(
            row=1, column=1, columnspan=2, sticky="w", padx=14, pady=(2, 2))
        badges = ctk.CTkFrame(card, fg_color="transparent")
        badges.grid(row=2, column=1, sticky="w", padx=10, pady=(0, 12))
        if s.reset_url and not s.reset_url_trusted:
            ctk.CTkLabel(badges, text="⚠ phishing link", fg_color=RED, text_color="#fff",
                         corner_radius=10, font=ctk.CTkFont(size=11), padx=8, pady=2).pack(side="left", padx=3)
        if s.reset_url and s.reset_url_trusted:
            ctk.CTkLabel(badges, text="reset link", fg_color=("#e0e7ff", "#1e3a8a"),
                         corner_radius=10, font=ctk.CTkFont(size=11), padx=8, pady=2).pack(side="left", padx=3)
        ctk.CTkButton(card, text="Rotate…", width=90, command=lambda sig=s: self.on_rotate(sig)).grid(
            row=2, column=2, padx=10, pady=(0, 10))
        return card

    # ---- Vault Health ------------------------------------------------------
    def _page_health(self, page):
        self._h1(page, "Vault Health").grid(row=0, column=0, sticky="w")
        self._muted(page, "Audit every password stored in Bitwarden and keep NordPass "
                    "in sync.", wrap=720).grid(row=1, column=0, sticky="w", pady=(4, 14))
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkButton(bar, text="🔑  Audit all passwords", command=self.on_vault_audit).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bar, text="🔄  Sync verify", fg_color="transparent", border_width=1,
                      command=self.on_sync).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="📤  NordPass import", fg_color="transparent", border_width=1,
                      command=self.on_nordpass).pack(side="left", padx=8)
        self.health_area = ctk.CTkFrame(page, fg_color="transparent")
        self.health_area.grid(row=3, column=0, sticky="ew")
        self.health_area.grid_columnconfigure(0, weight=1)
        self._muted(self.health_area, "Run an audit to see weak, reused or breached "
                    "passwords across your vault.").grid(row=0, column=0, sticky="w", pady=8)

    # ---- Settings ----------------------------------------------------------
    def _page_settings(self, page):
        self._h1(page, "Settings").grid(row=0, column=0, sticky="w")

        sec = self._card(page)
        sec.grid(row=1, column=0, sticky="ew", pady=(14, 12))
        ctk.CTkLabel(sec, text="🔒  Security", font=ctk.CTkFont(size=16, weight="bold"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))
        row = ctk.CTkFrame(sec, fg_color="transparent"); row.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 14))
        ctk.CTkLabel(row, text="Auto-lock after").pack(side="left")
        self.lock_min = ctk.CTkEntry(row, width=60)
        self.lock_min.insert(0, str(getattr(self.engine.cfg, "auto_lock_minutes", 15)))
        self.lock_min.pack(side="left", padx=8)
        ctk.CTkLabel(row, text="minutes idle (0 = never)").pack(side="left")
        ctk.CTkButton(row, text="Save", width=70, command=self.on_save_security).pack(side="left", padx=12)

        sch = self._card(page)
        sch.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(sch, text="⏰  Scheduled background scan",
                     font=ctk.CTkFont(size=16, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 6))
        self.sched_status = ctk.CTkLabel(sch, text="", anchor="w", text_color=MUTED)
        self.sched_status.grid(row=1, column=0, sticky="w", padx=16)
        srow = ctk.CTkFrame(sch, fg_color="transparent"); srow.grid(row=2, column=0, sticky="w", padx=16, pady=(4, 14))
        ctk.CTkLabel(srow, text="Every").pack(side="left")
        self.sched_hours = ctk.CTkEntry(srow, width=60); self.sched_hours.insert(0, "6")
        self.sched_hours.pack(side="left", padx=8)
        ctk.CTkLabel(srow, text="hours").pack(side="left")
        ctk.CTkButton(srow, text="Install", width=80, command=self.on_sched_install).pack(side="left", padx=(12, 4))
        ctk.CTkButton(srow, text="Remove", width=80, fg_color="transparent", border_width=1,
                      command=self.on_sched_uninstall).pack(side="left", padx=4)

        misc = self._card(page)
        misc.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(misc, text="ℹ️  About & logs", font=ctk.CTkFont(size=16, weight="bold"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))
        mrow = ctk.CTkFrame(misc, fg_color="transparent"); mrow.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 14))
        ctk.CTkButton(mrow, text="About RPHE", command=self.on_about).pack(side="left", padx=(0, 8))
        ctk.CTkButton(mrow, text="View audit log", fg_color="transparent", border_width=1,
                      command=self.on_audit_log).pack(side="left", padx=8)
        self.after(300, self._refresh_sched_status)

    # ===================================================================== ACTIONS
    def _async(self, fn: Callable, on_done: Callable, busy: str = ""):
        if busy:
            self.status.configure(text=busy)
        self._busy += 1
        if self._busy == 1:
            self.progress.start()

        def worker():
            try:
                self._results_q.put(("ok", on_done, fn()))
            except Exception as exc:
                self._results_q.put(("err", on_done, exc))
        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                kind, on_done, payload = self._results_q.get_nowait()
                self._busy = max(0, self._busy - 1)
                if self._busy == 0:
                    self.progress.stop()
                    self.progress.set(0)
                if kind == "ok":
                    on_done(payload)
                else:
                    self.status.configure(text=f"Error: {payload}")
                    messagebox.showerror("RPHE", str(payload))
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    def refresh_status(self):
        # The dashboard is the single source of truth for connection state.
        self._refresh_dashboard()

    # ---- connect actions ---
    def _save_account(self, acct):
        accts = [a for a in self.engine.cfg.accounts if a.label != acct.label]
        accts.append(acct)
        self.engine.cfg.accounts = accts
        self.engine.save(self.engine.cfg)
        self._refresh_account_list()
        self._set_conn_status("email", "ok", "Connected")
        self.refresh_status()

    def on_add_inbox(self):
        from .providers import suggested_label
        email = self.in_address.get().strip()
        if not email:
            messagebox.showinfo("RPHE", "Enter your email address first.")
            return
        host = self.in_imap_host.get().strip()
        if not host:
            messagebox.showinfo("RPHE", "Enter your provider's IMAP host "
                                "(it usually fills in automatically).")
            return
        label = suggested_label(email)
        acct = EmailAccount(label=label, provider="imap", address=email, imap_host=host)
        pw = self.in_app_pw.get()
        if pw:
            self.engine.set_imap_app_password(label, pw)
        self._save_account(acct)
        self.in_app_pw.delete(0, "end")
        self.status.configure(text=f"Inbox '{label}' connected.")

    def on_remove_inbox(self, label):
        self.engine.cfg.accounts = [a for a in self.engine.cfg.accounts if a.label != label]
        self.engine.save(self.engine.cfg)
        self.engine.store.delete(self.engine.store.imap_password_key(label))
        self._refresh_account_list()
        self._set_conn_status("email", "ok" if self.engine.cfg.accounts else "todo",
                              "Connected" if self.engine.cfg.accounts else "Not connected")
        self.refresh_status()

    def on_connect_gmail(self):
        from .providers import suggested_label
        email = self.in_address.get().strip()
        if not email:
            messagebox.showinfo("RPHE", "Enter your Gmail address first.")
            return
        label = suggested_label(email)
        self._save_account(EmailAccount(label=label, provider="gmail", address=email))
        path = filedialog.askopenfilename(title="Select client_secret.json",
                                          filetypes=[("JSON", "*.json")])
        if not path:
            return
        self._async(lambda: self.engine.connect_gmail(label, path),
                    lambda email_addr: self.status.configure(text=f"Gmail connected: {email_addr}"),
                    "Opening browser for Gmail consent…")

    def on_connect_graph(self):
        from .providers import suggested_label
        email = self.in_address.get().strip()
        if not email:
            messagebox.showinfo("RPHE", "Enter your Outlook address first.")
            return
        cid = self._ask_secret("Connect Outlook", "Entra app client ID:", show="")
        if not cid:
            return
        label = suggested_label(email)
        self._save_account(EmailAccount(label=label, provider="graph", address=email))

        def show_msg(text):
            self.after(0, lambda: messagebox.showinfo("Connect Outlook", text))
        self._async(lambda: self.engine.connect_graph(label, cid, show_msg),
                    lambda _: self.status.configure(text=f"Outlook connected for {label}."),
                    "Starting Microsoft device-code sign-in…")

    def on_bw_login(self):
        cid, sec = self.bw_cid.get().strip(), self.bw_secret.get().strip()
        if not (cid and sec):
            messagebox.showinfo("RPHE", "Enter both client_id and client_secret.")
            return
        self._async(lambda: self.engine.bitwarden_login_apikey(cid, sec),
                    lambda _: (self._refresh_bw_body(),
                               self.status.configure(text="Signed in — now unlock your vault.")),
                    "Signing in to Bitwarden…")

    def on_unlock(self):
        pw = self._ask_secret("Unlock Bitwarden", "Bitwarden master password:")
        if not pw:
            return
        self._async(lambda: self.engine.unlock_bitwarden(pw),
                    lambda _: (self._refresh_bw_body(), self.refresh_status(),
                               self.status.configure(text="Bitwarden unlocked.")),
                    "Unlocking Bitwarden…")

    def on_save_hibp(self):
        key = self.hibp_key.get().strip()
        if not key:
            return
        self.engine.set_hibp_key(key)
        self.hibp_key.delete(0, "end")
        self._set_conn_status("hibp", "ok", "Connected")
        self.refresh_status()
        self.status.configure(text="HIBP key saved to keychain.")

    # ---- scan / rotate ---
    def on_scan(self):
        if not self.engine.cfg.accounts:
            messagebox.showinfo("RPHE", "Add an inbox on the Connect page first.")
            self.show_page("connect")
            return

        def done(signals):
            self.signals = signals
            self._scanned = True
            self._render_findings(signals)
            self.status.configure(text=f"Scan complete — {len(signals)} account(s) flagged.")
        self._async(lambda: self.engine.scan(Severity.MEDIUM), done, "Scanning inboxes…")

    def on_breach_report(self):
        emails = sorted({a.address for a in self.engine.cfg.accounts if a.address})
        if self.engine.store.get(self.engine.store.hibp_api_key()) is None:
            messagebox.showwarning("Breach report", "Add a HIBP API key on the Connect "
                                   "page to look up email breaches.")
            return
        if not emails:
            messagebox.showinfo("Breach report", "No inbox email addresses configured.")
            return

        def done(results):
            lines = []
            for r in results:
                lines.append((f"⚠  {r.name}: {', '.join(r.breach_titles[:8])}") if r.breached
                             else f"✓  {r.name}: no known breaches")
            self._show_text("Breach report (Have I Been Pwned)", "\n".join(lines))
            self.status.configure(text="Breach report complete.")
        self._async(lambda: self.engine.check_accounts_breached(emails), done,
                    "Checking Have I Been Pwned…")

    def on_rotate(self, signal):
        RotateDialog(self, self.engine, signal)

    def on_pending(self):
        PendingDialog(self, self.engine)

    # ---- vault health ---
    def on_vault_audit(self):
        def done(report):
            for w in self.health_area.winfo_children():
                w.destroy()
            head = self._card(self.health_area); head.grid(row=0, column=0, sticky="ew", pady=4)
            ctk.CTkLabel(head, text=f"Scanned {report['scanned']} logins · "
                         f"{len(report['findings'])} need attention",
                         font=ctk.CTkFont(size=15, weight="bold"), anchor="w").grid(
                row=0, column=0, sticky="w", padx=16, pady=12)
            if not report["findings"]:
                self._muted(head, "✅ No weak, reused or breached passwords.").grid(
                    row=1, column=0, sticky="w", padx=16, pady=(0, 12))
            for i, f in enumerate(report["findings"], start=1):
                c = self._card(self.health_area); c.grid(row=i, column=0, sticky="ew", pady=4)
                ctk.CTkLabel(c, text=f"{f['name']}  ·  {f['username']}",
                             font=ctk.CTkFont(size=14, weight="bold"), anchor="w").grid(
                    row=0, column=0, sticky="w", padx=14, pady=(10, 0))
                bf = ctk.CTkFrame(c, fg_color="transparent"); bf.grid(row=1, column=0, sticky="w", padx=10, pady=(2, 10))
                for issue in f["issues"]:
                    col = RED if "breached" in issue else (AMBER if "weak" in issue else ("#7c3aed", "#a78bfa"))
                    ctk.CTkLabel(bf, text=issue, fg_color=col, text_color="#fff", corner_radius=10,
                                 font=ctk.CTkFont(size=11), padx=8, pady=2).pack(side="left", padx=3)
            self.status.configure(text="Vault audit complete.")
        self._async(self.engine.audit_vault, done,
                    "Auditing every vault login (local, k-anonymity)…")

    def on_sync(self):
        def done(r):
            txt = (f"In both vaults: {len(r.in_both)}\nOnly in Bitwarden: "
                   f"{len(r.only_in_bitwarden)}\nOnly in NordPass CSV: "
                   f"{len(r.only_in_nordpass)}\nPassword drift: {len(r.password_drift)}\n\n"
                   + ("✓ Vaults are consistent." if r.is_consistent
                      else "⚠ Drift — re-import the NordPass CSV."))
            self._show_text("Sync verify", txt)
        self._async(self.engine.sync_report, done, "Comparing vaults…")

    def on_nordpass(self):
        self._show_text("NordPass import", self.engine.nordpass().import_instructions())

    # ---- settings ---
    def on_save_security(self):
        try:
            self.engine.cfg.auto_lock_minutes = int(self.lock_min.get() or 15)
        except ValueError:
            self.engine.cfg.auto_lock_minutes = 15
        self.engine.save(self.engine.cfg)
        self.status.configure(text="Security settings saved.")

    def _refresh_sched_status(self):
        def done(s):
            self.sched_status.configure(text=f"Status: {s}")
        self._async(self._sched_status, done)

    @staticmethod
    def _sched_status():
        from . import schedule as sch
        return sch.status()

    def on_sched_install(self):
        try:
            hours = float(self.sched_hours.get() or 6)
        except ValueError:
            hours = 6.0

        def work():
            from . import schedule as sch
            return sch.install(hours, data_dir=str(self.engine.cfg.resolved_data_dir))
        self._async(work, lambda msg: (self.status.configure(text=msg),
                                       self._refresh_sched_status()), "Installing schedule…")

    def on_sched_uninstall(self):
        def work():
            from . import schedule as sch
            return sch.uninstall()
        self._async(work, lambda msg: (self.status.configure(text=msg),
                                       self._refresh_sched_status()), "Removing schedule…")

    def on_audit_log(self):
        def done(events):
            if not events:
                self._show_text("Audit log", "No audit events yet.")
                return
            lines = [f"{e.get('ts','')}  {e.get('action','')}  "
                     f"{str({k: v for k, v in e.items() if k not in ('ts', 'action')})[:120]}"
                     for e in events[-200:]]
            self._show_text("Audit log (redacted, last 200)", "\n".join(lines))
        self._async(self.engine.audit.read_all, done, "Reading audit log…")

    def on_about(self):
        def gather():
            import keyring
            from .config import default_config_dir
            from .vaults.bitwarden import find_bw
            bw = find_bw()
            bwver = "not found"
            if bw:
                try:
                    import subprocess
                    bwver = subprocess.run([bw, "--version"], capture_output=True, text=True,
                                           timeout=20).stdout.strip() or bw
                except Exception:
                    bwver = bw
            try:
                backend = keyring.get_keyring().__class__.__name__
            except Exception:
                backend = "unknown"
            return (f"RPHE — Recovery & Password-Hygiene Engine\nVersion {__version__}\n\n"
                    f"Bitwarden CLI: {bwver}\nKeychain backend: {backend}\n"
                    f"Config: {default_config_dir()}\nData: {self.engine.cfg.resolved_data_dir}\n"
                    f"Auto-lock: {self.engine.cfg.auto_lock_minutes} min idle\n\n"
                    "Secrets live only in your OS keychain; passwords are never logged "
                    "or sent to any third party.")
        self._async(gather, lambda t: self._show_text("About RPHE", t), "Gathering info…")

    def on_lock(self):
        self._async(self.engine.lock_bitwarden, lambda _: (self.refresh_status(),
                    self.status.configure(text="Vault locked.")), "Locking…")

    # ---- helpers ---
    def _ask_secret(self, title, prompt, show="•"):
        dlg = ctk.CTkToplevel(self)
        dlg.title(title)
        dlg.geometry("400x180")
        dlg.transient(self)
        dlg.after(50, dlg.grab_set)
        ctk.CTkLabel(dlg, text=prompt, wraplength=360, anchor="w").pack(padx=18, pady=(18, 8), anchor="w")
        ent = ctk.CTkEntry(dlg, show=show, width=340)
        ent.pack(padx=18)
        ent.after(120, ent.focus)
        res = {"v": None}

        def ok():
            res["v"] = ent.get()
            dlg.destroy()
        btns = ctk.CTkFrame(dlg, fg_color="transparent")
        btns.pack(pady=16)
        ctk.CTkButton(btns, text="OK", width=100, command=ok).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Cancel", width=100, fg_color="transparent",
                      border_width=1, command=dlg.destroy).pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: ok())
        self.wait_window(dlg)
        return res["v"]

    def _show_text(self, title, body):
        top = ctk.CTkToplevel(self)
        top.title(title)
        top.geometry("660x460")
        top.after(50, top.lift)
        box = ctk.CTkTextbox(top, wrap="word", font=ctk.CTkFont(size=13))
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", body)
        box.configure(state="disabled")

    # ---- auto-lock ---
    def _mark_active(self, _e=None):
        self._last_activity = time.monotonic()
        self._locked_by_idle = False

    def _check_idle(self):
        minutes = getattr(self.engine.cfg, "auto_lock_minutes", 15)
        if minutes and not self._locked_by_idle:
            if time.monotonic() - self._last_activity >= minutes * 60:
                self._locked_by_idle = True
                threading.Thread(target=self.engine.lock_bitwarden, daemon=True).start()
                self.status.configure(text=f"Vault auto-locked after {minutes} min idle.")
                self.refresh_status()
        self.after(30_000, self._check_idle)

    def _on_close(self):
        try:
            self.engine.lock_bitwarden()
        except Exception:
            pass
        self.destroy()

    def run(self):
        self.mainloop()


class RotateDialog(ctk.CTkToplevel if ctk else object):
    """Pick one of 5 breach-vetted passwords, store to both vaults, guide the reset."""

    def __init__(self, parent, engine: Engine, signal, on_close=None):
        super().__init__(parent)
        self.engine = engine
        self.signal = signal
        self.on_close_cb = on_close
        self._closed = False
        self.candidates = []
        self.choice = ctk.StringVar()

        self.title(f"Rotate — {signal.service_name}")
        self.geometry("620x520")
        self.transient(parent)
        self.after(60, self.lift)
        self.protocol("WM_DELETE_WINDOW", self._close)

        ctk.CTkLabel(self, text=signal.service_name, font=ctk.CTkFont(size=20, weight="bold")
                     ).pack(anchor="w", padx=20, pady=(18, 0))
        ctk.CTkLabel(self, text=f"{signal.severity.name} · {signal.kind.value.replace('_', ' ')}",
                     text_color=MUTED).pack(anchor="w", padx=20)
        if signal.reset_url and not signal.reset_url_trusted:
            ctk.CTkLabel(self, text=f"⚠ Possible phishing — {signal.reset_url_note}",
                         text_color=RED, wraplength=560, justify="left").pack(
                anchor="w", padx=20, pady=(8, 0))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=12)
        ctk.CTkLabel(row, text="Username / email").pack(side="left")
        self.username = ctk.CTkEntry(row, width=300)
        self.username.insert(0, signal.account_hint or "")
        self.username.pack(side="left", padx=10)

        ctk.CTkButton(self, text="Generate 5 vetted passwords", command=self.on_generate
                      ).pack(anchor="w", padx=20)
        self.options = ctk.CTkScrollableFrame(self, height=180, fg_color=("#f4f5f7", "#191920"))
        self.options.pack(fill="both", expand=True, padx=20, pady=10)
        self.info = ctk.CTkLabel(self, text="", text_color=MUTED, anchor="w")
        self.info.pack(anchor="w", padx=20)

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=14)
        ctk.CTkButton(btns, text="Apply & store in both vaults", command=self.on_apply
                      ).pack(side="right")
        ctk.CTkButton(btns, text="Cancel", fg_color="transparent", border_width=1,
                      command=self._close).pack(side="right", padx=8)

    def on_generate(self):
        self.info.configure(text="Generating and breach-checking candidates…")

        def worker():
            try:
                cands = self.engine.password_candidates(n=5, vet_pwned=True)
                self.after(0, lambda: self._show(cands))
            except Exception as exc:
                self.after(0, lambda exc=exc: self.info.configure(text=f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _show(self, cands):
        for w in self.options.winfo_children():
            w.destroy()
        self.candidates = cands
        if cands:
            self.choice.set(cands[0])
        bits = estimate_strength(self.engine.cfg.policy)
        for pw in cands:
            ctk.CTkRadioButton(self.options, text=f"{pw}      (~{bits:.0f} bits · not in any breach ✓)",
                               variable=self.choice, value=pw,
                               font=ctk.CTkFont(family="monospace", size=13)).pack(
                anchor="w", pady=5, padx=6)
        self.info.configure(text=f"{len(cands)} candidates ready — pick one and Apply.")

    def on_apply(self):
        pw = self.choice.get()
        if not pw:
            messagebox.showinfo("RPHE", "Generate and select a password first.")
            return
        username = self.username.get().strip()
        if not username:
            messagebox.showinfo("RPHE", "Enter the username/email for this account.")
            return
        url = f"https://{self.signal.sender_domain}" if self.signal.sender_domain else None
        self.info.configure(text="Storing in Bitwarden + NordPass…")

        def worker():
            try:
                res = self.engine.rotate(service_name=self.signal.service_name,
                                         username=username, password=pw, url=url,
                                         kind=self.signal.kind.value)
                self.after(0, lambda: self._done(res))
            except Exception as exc:
                self.after(0, lambda exc=exc: self.info.configure(text=f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, res):
        from .passkeys import render as render_pk
        from .reset import ResetOrchestrator
        plan = ResetOrchestrator().build_plan(self.signal)
        lines = [
            f"Bitwarden: {'stored & verified ✓' if res.verified else 'stored'}"
            + (f"  (id {res.bitwarden_id})" if res.bitwarden_id else ""),
            f"NordPass CSV: {'staged ✓' if res.nordpass_staged else 'FAILED'}",
            "Status: PENDING — Confirm from 'Pending rotations' once the reset works, "
            "or Revert to roll back.", "",
            "Complete the reset on the website:", plan.render(), "",
            render_pk(res.passkey), "",
            "Then import the NordPass CSV (Vault Health → NordPass import).",
        ]
        if res.error:
            lines.insert(0, f"⚠ {res.error}")
        top = ctk.CTkToplevel(self)
        top.title(f"Rotation complete — {res.service_name}")
        top.geometry("660x520")
        top.after(60, top.lift)
        box = ctk.CTkTextbox(top, wrap="word")
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", "\n".join(lines))
        box.configure(state="disabled")
        self._close()

    def _close(self):
        if self._closed:
            return
        self._closed = True
        cb = self.on_close_cb
        try:
            self.destroy()
        finally:
            if cb:
                cb()


class PendingDialog(ctk.CTkToplevel if ctk else object):
    """Confirm / revert rotations that haven't been verified yet."""

    def __init__(self, parent, engine: Engine):
        super().__init__(parent)
        self.engine = engine
        self.title("Pending rotations")
        self.geometry("560x420")
        self.transient(parent)
        self.after(60, self.lift)
        ctk.CTkLabel(self, text="Pending rotations", font=ctk.CTkFont(size=18, weight="bold")
                     ).pack(anchor="w", padx=20, pady=(18, 2))
        ctk.CTkLabel(self, text="Confirm once a new password works on the site, or "
                     "Revert to roll back to the previous one.", text_color=MUTED,
                     wraplength=500, justify="left").pack(anchor="w", padx=20)
        self.area = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.area.pack(fill="both", expand=True, padx=16, pady=12)
        self.msg = ctk.CTkLabel(self, text="Loading…", text_color=MUTED)
        self.msg.pack(anchor="w", padx=20, pady=(0, 10))
        self._reload()

    def _reload(self):
        for w in self.area.winfo_children():
            w.destroy()

        def worker():
            try:
                items = self.engine.list_pending()
                self.after(0, lambda: self._render(items))
            except Exception as exc:
                self.after(0, lambda exc=exc: self.msg.configure(text=f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _render(self, items):
        if not items:
            ctk.CTkLabel(self.area, text="No pending rotations.").pack(anchor="w", pady=8)
            self.msg.configure(text="")
            return
        for it in items:
            row = ctk.CTkFrame(self.area, fg_color=("#f0f1f4", "#191920"), corner_radius=8)
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=f"{it.name}  ·  {it.username}", anchor="w").pack(
                side="left", padx=12, pady=8)
            ctk.CTkButton(row, text="Revert", width=70, fg_color="transparent", border_width=1,
                          command=lambda i=it: self._act("revert", i)).pack(side="right", padx=8)
            ctk.CTkButton(row, text="Confirm", width=80,
                          command=lambda i=it: self._act("confirm", i)).pack(side="right", padx=2)
        self.msg.configure(text=f"{len(items)} pending.")

    def _act(self, kind, item):
        def worker():
            try:
                if kind == "confirm":
                    self.engine.confirm_rotation(item.item_id)
                    res = "confirmed"
                else:
                    res = "reverted" if self.engine.revert_rotation(item.item_id) \
                        else "no previous password to revert to"
                self.after(0, lambda: (self.msg.configure(text=f"{item.name}: {res}"),
                                       self._reload()))
            except Exception as exc:
                self.after(0, lambda exc=exc: self.msg.configure(text=f"Error: {exc}"))
        threading.Thread(target=worker, daemon=True).start()


def launch():
    _require_ctk()
    RpheApp().run()


if __name__ == "__main__":
    launch()
