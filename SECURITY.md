# Security

RPHE handles credentials, so its own security matters. This is how it's protected
and how you can verify it.

## Design posture

- **Local-first.** RPHE talks only to *your* providers (your mailbox, Bitwarden,
  Have I Been Pwned). It never sends your data to us — there is no RPHE server.
- **Secrets stay in the OS keychain** (macOS Keychain / Windows Credential
  Manager) via `keyring` — never in config files, never in logs.
- **Passwords are structurally unloggable** — the audit log only ever records
  fingerprints (sha256[:8]) and host-only URLs; a redaction pass scrubs every
  line. Generated secrets carry `repr=False`.
- **HTTPS only** — all network calls refuse non-`https://` URLs (blocks
  `file://`/scheme abuse).
- **Anti-phishing** — reset links are verified against the sender's domain before
  anything is opened or auto-filled.

## Supply-chain protection

Every push and pull request runs, and must pass, automated checks
(`.github/workflows/`):

- **Semgrep** static analysis (`p/python` + `p/security-audit`) — fails the build
  on insecure code patterns.
- **pip-audit** — fails the build if any dependency has a known CVE
  (also runs weekly to catch newly-disclosed advisories).
- **Test gate** — installers are only built after the full test suite passes.
- **Dependabot** keeps dependencies and GitHub Actions patched.

The bundled **Bitwarden CLI** is pinned to a specific version and its download is
**SHA-256-verified** against GitHub's published digest at build time
(`packaging/fetch_bw.py`).

## Verifying your download

Each release includes **`SHA256SUMS.txt`**. Confirm your installer matches before
running it:

```bash
# macOS
shasum -a 256 RPHE.dmg          # compare against SHA256SUMS.txt
# Windows (PowerShell)
Get-FileHash .\RPHE.exe -Algorithm SHA256
```

If the hash doesn't match the release's `SHA256SUMS.txt`, **do not run it** — the
file was modified or corrupted in transit.

## Antivirus / SmartScreen note

The installers are **not code-signed** (that needs paid Apple/Windows certs), so:

- macOS Gatekeeper says "unidentified developer" → right-click → **Open** once.
- Windows SmartScreen warns → **More info → Run anyway**.
- Some antivirus engines heuristically flag *any* PyInstaller-built `.exe`. This
  is a known false positive for the packaging tool, not evidence of malware — the
  full source is in this repo and the `SHA256SUMS.txt` lets you confirm the file
  matches what CI built from that source. You can also upload the file to
  [VirusTotal](https://www.virustotal.com/) to cross-check across engines.

## Reporting a vulnerability

Found a security issue? Please open a **private** report via GitHub Security
Advisories (repo → Security → Report a vulnerability), or email the maintainer.
Don't file public issues for vulnerabilities.
