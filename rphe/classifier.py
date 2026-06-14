"""Rule-based breach-signal classifier.

Given a raw email (subject, sender, body), decide whether it indicates a
compromised / at-risk account and, if so, classify the kind + severity and
extract a self-service reset link.

Why rules first (not an LLM): the classification has to run locally, be
auditable, be deterministic, and never ship email bodies to a third party.
The signal patterns for these alerts are stable and well-known. An optional
LLM second-pass hook is provided for ambiguous cases (disabled by default and
explicitly local-only), but the default path needs no network and no API key.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

from .models import BreachSignal, Severity, SignalKind

# --- Keyword banks. Tuned for precision; extend freely in config later. ---
_BREACH = re.compile(
    r"\b(data breach|was breached|security breach|your data was|exposed in a breach|"
    r"involved in a (data )?(breach|incident)|leaked|compromised account)\b", re.I)
_SUSPICIOUS_LOGIN = re.compile(
    r"\b(suspicious (sign[- ]?in|login|activity)|unusual (sign[- ]?in|activity|login)|"
    r"unrecognized (device|login)|we(?:'| )?ve detected|someone (?:may have )?(?:signed|logged) in|"
    r"sign[- ]?in attempt|access(?:ed)? from)\b", re.I)
_NEW_DEVICE = re.compile(
    r"\b(new (sign[- ]?in|device|login)|signed in on a new|new device|"
    r"your account was accessed from)\b", re.I)
_RESET_PROMPT = re.compile(
    r"\b(reset your password|password reset|change your password|"
    r"forgot(?: your)? password|create a new password|set a new password)\b", re.I)
_MFA = re.compile(
    r"\b(verification code|one[- ]?time (?:code|password|passcode)|otp|"
    r"two[- ]?factor|2fa|authentication code|security code)\b", re.I)
_LEAK = re.compile(
    r"\b(your password (?:was|has been) (?:found|exposed)|found on the dark web|"
    r"dark web (?:monitoring|alert|report)|credentials? (?:were )?exposed)\b", re.I)

# A reset link tends to live on the sending domain and contain a token-ish path.
_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_RESET_PATH_HINT = re.compile(
    r"(reset|recover|password|verify|confirm|unlock|account|security|token|code)", re.I)

# Senders we should never treat as breach alerts about an *external* service
# (these are the password managers / the tool itself).
_SELF_DOMAINS = {"bitwarden.com", "nordpass.com", "nordsecurity.com"}


def _sender_domain(from_header: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", from_header or "")
    return (m.group(1).lower().rstrip(".") if m else "").strip()


def _guess_service_name(domain: str, subject: str) -> str:
    """Human-friendly service name from the registrable domain."""
    if not domain:
        # Fall back to a capitalized word from the subject.
        m = re.search(r"\b([A-Z][a-zA-Z]{2,})\b", subject or "")
        return m.group(1) if m else "Unknown service"
    # Strip common mail subdomains then take the second-level label.
    parts = domain.split(".")
    for noise in ("mail", "email", "e", "notifications", "notify", "account",
                  "accounts", "security", "no-reply", "noreply", "info"):
        if parts and parts[0] == noise:
            parts = parts[1:]
    core = parts[-2] if len(parts) >= 2 else parts[0]
    return core.capitalize()


def _extract_reset_url(body: str, sender_domain: str) -> Optional[str]:
    """Pick the most plausible self-service reset link from the body.

    Preference order: a URL on the sender's domain whose path looks reset-y,
    then any reset-y URL. We deliberately do NOT auto-follow it — the
    orchestrator decides what to do, and the audit log only keeps the host.
    """
    candidates = _URL.findall(body or "")
    if not candidates:
        return None
    # Match on the registrable domain of the URL *host* (not a naive substring of
    # the whole URL), so 'apple.com.evil.test' / '?ref=apple.com' don't qualify
    # as the sender's domain.
    from urllib.parse import urlparse

    from .linksafety import registrable_domain
    sender_rd = registrable_domain(sender_domain or "")
    same_domain = [u for u in candidates
                   if sender_rd and registrable_domain(urlparse(u).hostname or "") == sender_rd]
    resetish = [u for u in (same_domain or candidates) if _RESET_PATH_HINT.search(u)]
    chosen = (resetish or same_domain or candidates)
    return chosen[0] if chosen else None


def classify(
    *,
    message_id: str,
    from_header: str,
    subject: str,
    body: str,
    received_at: datetime,
) -> Optional[BreachSignal]:
    """Return a BreachSignal if the email looks security-relevant, else None."""
    domain = _sender_domain(from_header)
    haystack = f"{subject}\n{body}"

    kind = SignalKind.UNKNOWN
    severity = Severity.INFO
    rationale_bits: list[str] = []

    if _LEAK.search(haystack):
        kind, severity = SignalKind.DATA_LEAK, Severity.CRITICAL
        rationale_bits.append("dark-web/credential-exposure language")
    elif _BREACH.search(haystack):
        kind, severity = SignalKind.BREACH_NOTICE, Severity.CRITICAL
        rationale_bits.append("explicit breach language")
    elif _SUSPICIOUS_LOGIN.search(haystack):
        kind, severity = SignalKind.SUSPICIOUS_LOGIN, Severity.HIGH
        rationale_bits.append("suspicious-login language")
    elif _NEW_DEVICE.search(haystack):
        kind, severity = SignalKind.NEW_DEVICE_LOGIN, Severity.MEDIUM
        rationale_bits.append("new-device sign-in")
    elif _RESET_PROMPT.search(haystack):
        kind, severity = SignalKind.PASSWORD_RESET_PROMPT, Severity.MEDIUM
        rationale_bits.append("password-reset prompt")
    elif _MFA.search(haystack):
        kind, severity = SignalKind.MFA_CHALLENGE, Severity.LOW
        rationale_bits.append("MFA/verification code")
    else:
        return None  # nothing security-relevant detected

    # An unsolicited MFA code or reset you didn't request escalates risk —
    # someone may be trying to get into the account right now.
    if kind in (SignalKind.MFA_CHALLENGE, SignalKind.PASSWORD_RESET_PROMPT) and \
            re.search(r"\b(didn'?t (?:you|request)|not you|wasn'?t you|if this wasn'?t)\b",
                      haystack, re.I):
        severity = max(severity, Severity.HIGH)
        rationale_bits.append("'was this you?' challenge")

    reset_url = _extract_reset_url(body, domain)
    snippet = re.sub(r"\s+", " ", (body or "")[:240]).strip()

    # Anti-phishing: assess the reset link before anyone acts on it.
    from .linksafety import assess
    link = assess(reset_url, domain)
    if reset_url and not link.trusted:
        rationale_bits.append("UNVERIFIED reset link")
        severity = max(severity, Severity.HIGH)

    return BreachSignal(
        message_id=message_id,
        service_name=_guess_service_name(domain, subject),
        sender_domain=domain,
        subject=(subject or "").strip()[:200],
        received_at=received_at,
        kind=kind,
        severity=severity,
        reset_url=reset_url,
        account_hint=None,
        rationale="; ".join(rationale_bits),
        raw_snippet=snippet,
        reset_url_trusted=link.trusted,
        reset_url_note=link.reason,
    )


def classify_many(messages: Iterable[dict]) -> list[BreachSignal]:
    """Convenience: classify an iterable of {message_id, from, subject, body, date}."""
    out: list[BreachSignal] = []
    for m in messages:
        sig = classify(
            message_id=m["message_id"],
            from_header=m.get("from", ""),
            subject=m.get("subject", ""),
            body=m.get("body", ""),
            received_at=m["received_at"],
        )
        if sig is not None:
            out.append(sig)
    # Most urgent first; within a severity, newest first.
    out.sort(key=lambda s: (s.severity, s.received_at), reverse=True)
    return out
