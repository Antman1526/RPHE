"""Anti-phishing assessment of password-reset links.

A security tool must never become a phishing assist. Before RPHE shows, opens,
or autofills a reset link, it checks that the link is plausibly legitimate:

  * HTTPS only.
  * No punycode/IDN homoglyph hosts (xn-- ...), a classic look-alike trick.
  * The link's registrable domain (eTLD+1) matches the *sender's* registrable
    domain, OR is on a small allow-list of the service's known domains.

A mismatch doesn't prove phishing, but it's exactly when the human should slow
down — so untrusted links are flagged loudly and are NEVER auto-opened/filled.

Dependency-free: registrable-domain extraction uses a heuristic plus a small set
of well-known multi-part public suffixes. This isn't the full Public Suffix List,
so it can be imperfect on exotic TLDs — it errs toward "untrusted" (safe).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

# Common multi-label public suffixes so we don't treat "co.uk" as the domain.
_MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "go.jp", "com.br", "com.cn", "com.mx",
    "co.in", "co.za", "com.sg", "com.hk", "com.tr", "co.kr", "com.ar",
}

# A few services whose reset links live on a different registrable domain than
# the sender (so a strict sender-match would false-positive). Extend as needed.
_SERVICE_ALT_DOMAINS = {
    "amazon.com": {"amazon.com"},
    "google.com": {"google.com", "accounts.google.com"},
    "microsoft.com": {"microsoft.com", "live.com", "microsoftonline.com"},
    "reddit.com": {"reddit.com", "redditmail.com"},
    "netflix.com": {"netflix.com"},
}


@dataclass
class LinkAssessment:
    trusted: bool
    reason: str
    https: bool
    host: str

    @property
    def warning(self) -> str:
        return "" if self.trusted else f"⚠ Possible phishing — {self.reason}"


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 (e.g. 'mail.example.co.uk' -> 'example.co.uk')."""
    host = (host or "").lower().strip().rstrip(".")
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def assess(reset_url: str | None, sender_domain: str | None,
           service_name: str | None = None) -> LinkAssessment:
    """Judge whether a reset link is safe to act on."""
    if not reset_url:
        return LinkAssessment(True, "no link present", True, "")

    parsed = urlparse(reset_url)
    host = (parsed.hostname or "").lower()
    https = parsed.scheme == "https"

    if not host:
        return LinkAssessment(False, "link has no host", https, host)
    if "xn--" in host:
        return LinkAssessment(False, f"punycode/look-alike host '{host}'", https, host)
    if not https:
        return LinkAssessment(False, f"link is not HTTPS ('{parsed.scheme}')", https, host)

    rd_link = registrable_domain(host)
    rd_sender = registrable_domain(sender_domain or "")

    if rd_sender and rd_link == rd_sender:
        return LinkAssessment(True, f"link host matches sender ({rd_sender})", https, host)

    allow = _SERVICE_ALT_DOMAINS.get(rd_sender) or _SERVICE_ALT_DOMAINS.get(rd_link)
    if allow and rd_link in allow:
        return LinkAssessment(True, f"known domain for the service ({rd_link})", https, host)

    return LinkAssessment(
        False,
        f"link host '{rd_link}' does not match the sender '{rd_sender or 'unknown'}'. "
        "Don't click it — go to the site by typing its address yourself.",
        https, host)
