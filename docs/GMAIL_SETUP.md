# Gmail end-to-end setup

This walks you from zero to `rphe scan` pulling real security alerts from your
Gmail — using a **read-only** OAuth scope (`gmail.readonly`). The token can never
send, delete, or modify mail, and it's stored in your OS keystore, never on disk.

> **Don't want to grant any access yet?** Skip to
> [§B Offline first (no OAuth)](#b-offline-first-no-oauth) — you can validate the
> classifier on your real emails by exporting them as `.eml` files, with zero
> account access.

---

## A. The OAuth path (recommended for ongoing scanning)

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

## B. Offline first (no OAuth)

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
