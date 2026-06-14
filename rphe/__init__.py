"""RPHE — Recovery & Password-Hygiene Engine.

A local-first, cross-platform (macOS + Windows) tool that:
  1. Scans email inboxes for breach / compromise signals.
  2. Guides or (optionally) automates password resets.
  3. Generates strong unique credentials.
  4. Writes them to Bitwarden (source of truth) and bridges to NordPass via CSV.
  5. Verifies the two vaults stay consistent.

Security stance: secrets live only in the OS keystore; plaintext passwords are
never written to disk or logs. See SECURITY in README.md.
"""

__version__ = "0.7.6"
__all__ = ["__version__"]
