# Gmail setup

Two ways to connect Gmail. **Use the first one** unless you specifically want
least-privilege API access — it needs no Google Cloud project and no JSON file.

## Easiest: app password (recommended)

Gmail no longer allows your normal password in apps, so it uses an **app
password** — a 16-character token that replaces your password for IMAP. Creating
one requires 2-Step Verification.

1. Turn on **2-Step Verification**:
   <https://myaccount.google.com/signinoptions/twosv>
2. Create an app password at <https://myaccount.google.com/apppasswords>, name it
   "RPHE", and copy the 16-character code.
3. In RPHE → **Connect → Email inbox**: type your Gmail address (the IMAP host
   fills in automatically), paste the app password, choose how far back to scan
   (and leave **Include spam/junk** on — alerts often get filtered there), then
   **Connect inbox**.
4. Click **Scan** — RPHE reads your mailbox over IMAP. That's it.

The app password lives only in your OS keychain, and you can revoke it anytime
from the same Google page. (The CLI equivalent: `rphe secrets set
imap.<label>.app_password`.)

> **Just want to test first?** Run `rphe demo`, or drop a few exported `.eml`
> files in a folder — see [Offline option](#offline-option). No account needed.

---

## Advanced: read-only OAuth API (optional)

Prefer a read-only API token (`gmail.readonly`) that never touches your password?
This path is more locked-down but **requires creating a Google Cloud OAuth client
and downloading a `client_secret.json`** — most people don't need it.

### 1. Create a Google Cloud project
1. Go to <https://console.cloud.google.com/> and create a new project
   (e.g. `rphe-personal`).
2. **APIs & Services → Library →** search **Gmail API → Enable**.

### 2. Configure the OAuth consent screen
1. **APIs & Services → OAuth consent screen.**
2. User type: **External** → Create.
3. Fill app name (e.g. `RPHE`), your email for support + developer contact.
4. **Scopes:** you can leave this empty here — RPHE requests the scope at
   runtime. (If you add one, add `.../auth/gmail.readonly`.)
5. **Test users:** click **+ Add users** and add **your own Gmail address**.
   This is the step people miss — without it you'll get *"Error 403:
   access_denied / app is being tested."*
6. Save. You do **not** need to publish or get verified for personal use; a
   testing-mode app works fine for your own test-user account.

### 3. Create the OAuth client (Desktop app)
1. **APIs & Services → Credentials → + Create credentials → OAuth client ID.**
2. Application type: **Desktop app** → name it → Create.
3. **Download JSON.** Save it somewhere private, e.g.
   `~/.config/rphe/client_secret.json`. **Never commit this file** (it's in
   `.gitignore`).

### 4. Authorize RPHE (one time)
```bash
rphe auth gmail personal-gmail ~/.config/rphe/client_secret.json
```
- Your browser opens; pick your account and approve **read-only** access.
- You may see *"Google hasn't verified this app"* → **Advanced → Go to RPHE
  (unsafe)**. This warning is expected for an unverified personal app that you
  built; you're approving your own client.
- On success the refresh token is saved to the keystore and RPHE immediately
  self-checks:
  ```
  ✓ Verified: signed in as you@gmail.com (48213 messages, scope=gmail.readonly).
  ```

### 5. Add the account to your config
`rphe init` already includes this block — make sure `address` is your real
Gmail and the label matches what you used above:
```yaml
accounts:
  - label: "personal-gmail"
    provider: "gmail"
    address: "you@gmail.com"
    lookback_days: 30
```

### 6. Scan
```bash
rphe auth gmail-check personal-gmail   # re-validate any time (no scan)
rphe scan --dry-run                    # fetch + classify, write nothing
rphe scan                              # the real thing
```
RPHE issues a **server-side Gmail search** so it only downloads recent messages
whose subject/body look security-related, then classifies them locally.

---

## Offline option

Validate the classifier on your actual mail without granting anything:

1. In Gmail (web), open a suspicious message → **⋮ (More) → Download message**
   (saves a `.eml`). Repeat for a few alerts. Or **⋮ → Show original → Download
   Original**.
2. Put them in a folder, e.g. `~/Desktop/suspicious-emails/`.
3. Add this account block (already commented in the template):
   ```yaml
   - label: "exported"
     provider: "eml"
     address: ""
     folders: ["~/Desktop/suspicious-emails"]
     lookback_days: 3650
   ```
4. `rphe scan` — it classifies the files locally; nothing leaves your machine.

Or skip files entirely and see canned examples:
```bash
rphe demo          # classifier on built-in synthetic samples, zero setup
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `access_denied` / "app is being tested" | Add your Gmail as a **Test user** on the OAuth consent screen (§2.5). |
| "Google hasn't verified this app" | Expected for a personal app → **Advanced → Go to RPHE (unsafe)**. It's your own client. |
| `client_secret file not found` | Pass the correct path to the downloaded JSON; it must be an **OAuth client ID → Desktop app** credential, not an API key or service account. |
| `redirect_uri_mismatch` | You created a "Web application" client instead of **Desktop app**. Recreate as Desktop app. |
| Token "works then stops after ~7 days" | Apps in **testing** mode issue refresh tokens that expire in 7 days. For long-lived use, **publish** the consent screen (still no verification needed for `gmail.readonly` with only you as user) — or just re-run `rphe auth gmail`. |
| `invalid_grant` on scan | Token revoked/expired → re-run `rphe auth gmail personal-gmail <json>`. |
| Want to revoke access entirely | <https://myaccount.google.com/permissions> → remove RPHE; then `rphe secrets del oauth.personal-gmail.token_json`. |

### Privacy / least-privilege notes
- Scope is **`gmail.readonly`** — the strongest read-only guarantee Google
  offers; it structurally cannot modify your mailbox.
- RPHE never uploads message content anywhere. Classification is local regex.
- The audit log records only the **sender host** and severity, never bodies,
  tokens, or full reset URLs.
