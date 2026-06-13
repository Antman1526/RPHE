# Third-party notices

RPHE itself is MIT-licensed. The packaged macOS `.dmg` and Windows `.exe`
**bundle** the following third-party program, shipped unmodified:

## Bitwarden CLI (`bw`)

- **Project:** Bitwarden CLI — https://github.com/bitwarden/clients
- **License:** GNU General Public License v3.0 (GPL-3.0)
- **How it is used:** RPHE invokes `bw` as a **separate process** via the command
  line (subprocess). RPHE does not link against, modify, or derive from the
  Bitwarden CLI source. Under the GPL this is "mere aggregation" — distributing
  two separate programs together on the same medium — so RPHE's own MIT license
  is unaffected.
- **Source:** the complete corresponding source for the bundled `bw` binary is
  publicly available at the project URL above (the exact version is recorded in
  `packaging/vendor/BW_VERSION.txt` at build time and shown in the app's
  self-test output).
- **Obtaining/replacing the binary:** the binary is downloaded at build time by
  `packaging/fetch_bw.py` from the official Bitwarden GitHub releases. You may
  substitute your own trusted `bw` build by setting the `RPHE_BW_PATH`
  environment variable, or by replacing `packaging/vendor/bw` before building.

If you redistribute the RPHE installers, you must also make the Bitwarden CLI
source available (a link to the official repository at the bundled version
satisfies GPL-3.0 §6 for an unmodified binary).

## Other dependencies

The Python libraries RPHE depends on (Typer, Rich, PyYAML, keyring, and the
optional google-api-python-client / google-auth-oauthlib / msal) are distributed
under their own permissive licenses (MIT / BSD / Apache-2.0 / PSF). See each
project for details.
