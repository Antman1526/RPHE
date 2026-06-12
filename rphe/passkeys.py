"""Passkey advisor.

A passkey (WebAuthn/FIDO2) is a per-site public/private key pair created and held
by your platform authenticator — iCloud Keychain / Touch ID on your Mac and
iPhone, Windows Hello, an Android device, a hardware key, or a password manager
like Bitwarden. **RPHE never creates, holds, or syncs a passkey** — that would
defeat its security model. Instead, after a password rotation, this advisor tells
you whether the service supports passkeys and how to enroll one yourself.

The support list is a curated set of well-known services that offer passkeys
(non-exhaustive; passkey adoption is growing fast). For unknown services we give
generic guidance to look in the account's Security settings.
"""
from __future__ import annotations

from dataclasses import dataclass

# Domains (or domain stems) known to support passkeys for personal accounts.
_PASSKEY_DOMAINS = {
    "google.com": "Google", "gmail.com": "Google", "apple.com": "Apple",
    "icloud.com": "Apple", "microsoft.com": "Microsoft", "live.com": "Microsoft",
    "github.com": "GitHub", "amazon.com": "Amazon", "paypal.com": "PayPal",
    "coinbase.com": "Coinbase", "ebay.com": "eBay", "nintendo.com": "Nintendo",
    "best buy.com": "Best Buy", "bestbuy.com": "Best Buy", "tiktok.com": "TikTok",
    "x.com": "X", "twitter.com": "X", "linkedin.com": "LinkedIn",
    "shopify.com": "Shopify", "dashlane.com": "Dashlane", "okta.com": "Okta",
    "yahoo.com": "Yahoo", "adobe.com": "Adobe", "kayak.com": "Kayak",
    "robinhood.com": "Robinhood", "docusign.com": "DocuSign", "uber.com": "Uber",
    "instacart.com": "Instacart", "cloudflare.com": "Cloudflare",
    "discord.com": "Discord", "synology.com": "Synology", "binance.com": "Binance",
}


@dataclass
class PasskeyAdvice:
    service_name: str
    domain: str
    supported: bool          # known to support passkeys
    confidence: str          # "known" | "unknown"
    steps: list


def _domain_supports(domain: str) -> "tuple[bool, str]":
    d = (domain or "").lower()
    for stem, name in _PASSKEY_DOMAINS.items():
        if stem in d:
            return True, name
    return False, ""


def advise(service_name: str, domain: str) -> PasskeyAdvice:
    """Return passkey enrollment guidance for a given service."""
    supported, known_name = _domain_supports(domain)
    name = known_name or service_name

    if supported:
        steps = [
            f"Sign in to {name} with your NEW password.",
            "Open account Security settings → 'Passkeys' (or 'Sign in with "
            "passkey' / 'Security keys').",
            "Choose 'Add a passkey'. When prompted, pick where to store it:",
            "  • Your iPhone/Mac (iCloud Keychain) or Android — syncs to your "
            "phone automatically.",
            "  • Bitwarden — if you want it in your vault across devices.",
            "Approve with Touch ID / Face ID / Windows Hello / device PIN.",
            "Keep your strong password as a backup until you've tested the "
            "passkey sign-in once.",
        ]
        confidence = "known"
    else:
        steps = [
            f"Check whether {name} supports passkeys: account Security settings "
            "→ look for 'Passkeys', 'Passwordless', or 'Security keys'.",
            "If available, choose 'Add a passkey' and store it on your phone/"
            "device or in Bitwarden, approving with biometrics.",
            "If not available yet, enable an authenticator-app (TOTP) second "
            "factor instead, and keep the strong password.",
        ]
        confidence = "unknown"

    return PasskeyAdvice(service_name=name, domain=domain, supported=supported,
                         confidence=confidence, steps=steps)


def render(advice: PasskeyAdvice) -> str:
    head = (f"Passkey: {advice.service_name} "
            + ("supports passkeys ✓" if advice.supported
               else "— check support (Security settings)"))
    lines = [head] + [f"  • {s}" if not s.startswith("  ") else s
                      for s in advice.steps]
    return "\n".join(lines)
