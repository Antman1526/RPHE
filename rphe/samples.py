"""Synthetic sample emails for `rphe demo`.

These are hand-written, realistic-but-fake security emails covering each signal
class. They let a new user see *exactly* what RPHE flags, with zero setup and no
inbox access. They also double as a stable corpus for eyeballing the classifier
after editing the rules.

All addresses/links here are illustrative and non-functional.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _ago(days: int) -> datetime:
    # Fixed reference point so demo output is deterministic across runs.
    base = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    return base - timedelta(days=days)


SAMPLE_MESSAGES: list[dict] = [
    {
        "message_id": "demo-breach-1",
        "from": "Dropbox Security <no-reply@dropbox.com>",
        "subject": "Important: your account was involved in a data breach",
        "body": ("We're writing to let you know your data was exposed in a "
                 "breach affecting a third-party service. Please reset your "
                 "password now: https://www.dropbox.com/password_reset?token=ZZZ "
                 "and review recent activity."),
        "received_at": _ago(1),
    },
    {
        "message_id": "demo-darkweb-1",
        "from": "NordPass <noreply@nordpass.com>",
        "subject": "Data breach alert: your password was found on the dark web",
        "body": ("Dark web monitoring found one of your passwords exposed. "
                 "We recommend changing it immediately on the affected site."),
        "received_at": _ago(2),
    },
    {
        "message_id": "demo-login-1",
        "from": "GitHub <noreply@github.com>",
        "subject": "A new sign-in to your account from an unrecognized device",
        "body": ("We detected a sign-in to your account from a new device in "
                 "a location you don't usually use. If this wasn't you, secure "
                 "your account: https://github.com/settings/security"),
        "received_at": _ago(3),
    },
    {
        "message_id": "demo-reset-1",
        "from": "Reddit <noreply@redditmail.com>",
        "subject": "Reset your Reddit password",
        "body": ("Someone requested a password reset. If this was you, click "
                 "https://www.reddit.com/resetpassword?token=ABC123. If this "
                 "wasn't you, you can ignore this email."),
        "received_at": _ago(4),
    },
    {
        "message_id": "demo-mfa-1",
        "from": "Coinbase <no-reply@coinbase.com>",
        "subject": "Your Coinbase verification code",
        "body": ("Your one-time code is 884213. If you didn't request this, "
                 "someone may be trying to access your account — change your "
                 "password and contact support."),
        "received_at": _ago(5),
    },
    {
        "message_id": "demo-newdevice-1",
        "from": "Netflix <info@account.netflix.com>",
        "subject": "New sign-in to your Netflix account",
        "body": ("Your account was accessed from a new device. If this was "
                 "you, no action is needed."),
        "received_at": _ago(6),
    },
    {
        "message_id": "demo-marketing-1",  # should NOT be flagged
        "from": "Spotify <news@spotify.com>",
        "subject": "Your Discover Weekly is ready 🎵",
        "body": "Fresh tracks picked just for you. Open the app to listen.",
        "received_at": _ago(2),
    },
    {
        "message_id": "demo-receipt-1",  # should NOT be flagged
        "from": "Amazon <auto-confirm@amazon.com>",
        "subject": "Your order has shipped",
        "body": "Your package is on the way and will arrive Thursday.",
        "received_at": _ago(3),
    },
]
