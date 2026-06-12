"""Password-reset orchestrator.

Philosophy: **guided-first**. Fully automating a password reset is risky:
  * Reset links are single-use — a failed automation can burn the link and lock
    you out.
  * Most reset flows include CAPTCHA, MFA, or "was this you?" interstitials that
    are *designed* to stop automation (and that's a good thing).
  * UI selectors break constantly; a wrong click could change unrelated settings.
  * Many sites' ToS forbid automated interaction.

So the default mode produces a precise, ordered **manual workflow** for each
account and opens the reset page in a real browser the user controls. The
optional `--automate` mode uses Playwright to *open the page and pre-fill the new
password fields* but always **pauses for the human** to solve CAPTCHA/MFA and to
click the final submit — it never blindly completes the reset.

Playwright is launched in *headed, non-persistent* mode so the user sees exactly
what happens and can take over at any point.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import BreachSignal, GeneratedCredential


@dataclass
class ResetStep:
    order: int
    text: str
    manual_required: bool = False  # True == human MUST do this (CAPTCHA/MFA)


@dataclass
class ResetPlan:
    service_name: str
    reset_url: Optional[str]
    severity: str
    steps: list = field(default_factory=list)
    automatable: bool = False

    def render(self) -> str:
        lines = [f"== {self.service_name}  (severity: {self.severity}) =="]
        if self.reset_url:
            lines.append(f"Reset page: {self.reset_url}")
        else:
            lines.append("No reset link found in the email — start from the site's "
                         "login page → 'Forgot password'.")
        for s in sorted(self.steps, key=lambda x: x.order):
            flag = "  [YOU]" if s.manual_required else ""
            lines.append(f"  {s.order}. {s.text}{flag}")
        return "\n".join(lines)


# Domains where, by policy, we NEVER automate (high blast radius / explicit ToS).
_NEVER_AUTOMATE = {
    "google.com", "accounts.google.com", "apple.com", "icloud.com",
    "microsoft.com", "live.com", "paypal.com", "coinbase.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com",
}


class ResetOrchestrator:
    def __init__(self, automate: bool = False, headless: bool = False,
                 nav_timeout_ms: int = 30000):
        self.automate = automate
        self.headless = headless
        self.nav_timeout_ms = nav_timeout_ms

    # --- plan building (always available, no browser needed) ----------------
    def build_plan(self, signal: BreachSignal) -> ResetPlan:
        domain = signal.sender_domain
        automatable = (
            self.automate
            and bool(signal.reset_url)
            and domain not in _NEVER_AUTOMATE
        )
        steps = [
            ResetStep(1, "Confirm this alert is genuine: check the sender domain "
                         f"({domain or 'unknown'}) and that the URL host matches the "
                         "real service. If anything looks off, STOP and go to the "
                         "site by typing its address yourself.", manual_required=True),
            ResetStep(2, "Open the reset page and begin 'Forgot password'."),
            ResetStep(3, "When prompted, paste the new password RPHE generated "
                         "(already copied to clipboard / written to Bitwarden draft)."),
            ResetStep(4, "Solve any CAPTCHA and complete MFA / email-code "
                         "verification.", manual_required=True),
            ResetStep(5, "Submit the reset and confirm the success screen.",
                      manual_required=True),
            ResetStep(6, "Sign in once with the new password to verify it works."),
            ResetStep(7, "Review active sessions / devices and sign out anything "
                         "you don't recognize.", manual_required=True),
            ResetStep(8, "If the service supports it, enable/rotate MFA now."),
        ]
        return ResetPlan(
            service_name=signal.service_name,
            reset_url=signal.reset_url,
            severity=signal.severity.name,
            steps=steps,
            automatable=automatable,
        )

    # --- optional assisted automation --------------------------------------
    def assist(self, plan: ResetPlan, cred: GeneratedCredential) -> str:
        """Open the reset page and pre-fill password fields, then hand control to
        the human. Returns a status string. Requires `playwright` + browsers.

        This NEVER auto-submits. It fills fields that *look* like new-password
        inputs and then blocks, printing instructions, until the user closes the
        browser. If the page structure is unfamiliar, it simply opens the page.
        """
        if not plan.automatable or not plan.reset_url:
            return "skipped: not automatable (guided steps printed instead)"

        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Assisted reset needs Playwright.\n"
                "Install: pip install playwright && python -m playwright install chromium"
            ) from exc

        filled = 0
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(self.nav_timeout_ms)
            page.goto(plan.reset_url, wait_until="domcontentloaded")

            # Best-effort: fill inputs that look like "new password" + "confirm".
            selectors = [
                'input[type="password"][name*="new" i]',
                'input[type="password"][id*="new" i]',
                'input[type="password"][autocomplete="new-password"]',
                'input[type="password"]',
            ]
            for sel in selectors:
                try:
                    fields = page.query_selector_all(sel)
                except Exception:
                    fields = []
                if fields:
                    for f in fields[:2]:  # new + confirm, at most
                        try:
                            f.fill(cred.secret)
                            filled += 1
                        except Exception:
                            continue
                    if filled:
                        break

            # Hand off to the human. We block until they close the window.
            print("\n>>> Browser is open. RPHE pre-filled "
                  f"{filled} password field(s).")
            print(">>> Solve CAPTCHA/MFA, then click the site's own Submit button.")
            print(">>> Close the browser window when you're done to continue.\n")
            try:
                page.wait_for_event("close", timeout=0)  # wait indefinitely
            except Exception:
                pass
            try:
                context.close()
                browser.close()
            except Exception:
                pass
        return f"assisted: pre-filled {filled} field(s); human completed the reset"
