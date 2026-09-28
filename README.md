# Hermes GWS OAuth

Multi-account OAuth login and scope management for the [Google Workspace CLI (`gws`)](https://github.com/googleworkspace/cli) in Hermes Agent.

The plugin keeps each account inside the active Hermes profile, exposes `gws` without adding a command denylist, and lets a user finish the otherwise-local OAuth callback from a private gateway chat. It does not share tokens across profiles or modify Hermes core.

## Prerequisites

- **Node.js 18+** — required only when installing `gws` through npm. You can instead download a pre-built binary from [Google Workspace CLI releases](https://github.com/googleworkspace/cli/releases) or use another supported package manager.
- **A Google Cloud project** — required for OAuth credentials. Create one through the [Google Cloud Console](https://console.cloud.google.com/), the `gcloud` CLI, or `gws auth setup`.
- **A Google account with access to Google Workspace.**
- **Hermes Agent** with a private-chat gateway platform.

Install `gws` using one of its supported methods. For npm:

```bash
npm install -g @googleworkspace/cli

gws --version
```

## Install

Install and enable the plugin in the desired Hermes profile:

```bash
hermes plugins install anpicasso/hermes-gws-oauth --enable
```

For a named profile:

```bash
hermes --profile <name> plugins install anpicasso/hermes-gws-oauth --enable
```

Authorized accounts always remain profile-scoped. The OAuth client may be shared from the native `gws` configuration or overridden by one Hermes profile. Repeat the installation for every profile that should expose the tools.

### Configure the OAuth client manually

For security, the plugin **never accepts, downloads, or installs `client_secret.json` through chat**. Plugin activation creates `$HERMES_HOME/gws-oauth/` with mode `0700`. Installation with `--enable` reloads a running gateway immediately; if no gateway is running, start or restart it once after installation.

`gws_login` selects the OAuth client in this order:

1. `$HERMES_HOME/gws-oauth/client_secret.json` — optional profile override.
2. The native global `gws` client, normally `~/.config/gws/client_secret.json`.

If `gws auth login` already works from its native client file, no second copy is required. Setups that rely on `GOOGLE_WORKSPACE_CLI_CLIENT_ID`, `GOOGLE_WORKSPACE_CLI_CLIENT_SECRET`, or `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` still need one of the files above because the plugin deliberately clears inherited Google credential overrides. The login flow creates neither file.

`gws auth status` reports the exact native path as `client_config` if your platform uses a legacy location.

1. Configure the required Workspace APIs and OAuth consent screen in Google Cloud.
2. Create an OAuth client of type **Desktop app**. If the consent screen is in *Testing*, add every account under *Test users*.
3. Download the client JSON and install it globally for native `gws`:

```bash
install -d -m 700 "$HOME/.config/gws"
install -m 600 /secure/path/client_secret.json \
  "$HOME/.config/gws/client_secret.json"
```

   Or override it for one Hermes profile:

```bash
export HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
install -m 600 /secure/path/client_secret.json \
  "$HERMES_HOME/gws-oauth/client_secret.json"
```

The profile override location is:

```text
$HERMES_HOME/gws-oauth/client_secret.json
```

Do not paste this file into a chat, commit it, or place it inside the plugin directory. The selected client must be a regular file, not a symbolic link. Only the client may be shared; authorized accounts and their tokens remain under the active Hermes profile.

If the gateway cannot find `gws`, set an absolute binary path:

```bash
hermes config set plugins.entries.gws-oauth.settings.gws_bin /absolute/path/to/gws
```

After installation, run `hermes gateway restart` from an external shell and begin a new private session.

## Use

Ask Hermes in a private gateway chat:

> Connect `person@example.com` to Google Workspace with read-only access.

Hermes calls `gws_login` with one of the native `gws` permission modes:

- `default`
- `readonly`
- `full` (default)
- `custom` with explicit OAuth scopes

Open the returned Google URL and grant access. When the browser fails while opening `localhost`, copy the **complete URL from the address bar** and paste it into the same private chat. The plugin sends the one-time code only to the waiting local `gws` process and rewrites the message before it reaches the agent.

A login expires after five minutes. Only one attempt may run for the same user and chat, while different users may authorize concurrently. The Google identity returned by `gws` must match the requested account.

## Tools

- `gws_login(account, scope_mode="full", scopes=[])` — starts OAuth for one account. Available only in a private gateway chat with a user identity.
- `gws_accounts()` — lists the account labels stored in the active profile without revealing credentials.
- `gws_api(account, args)` — executes `gws` for one explicit account and passes `args` verbatim. Example: `args=["drive", "files", "list", "--params", "{\"pageSize\":5}"]`.

Authorized accounts are stored under:

```text
$HERMES_HOME/gws-oauth/accounts/<account>/
```

Each account receives its own `GOOGLE_WORKSPACE_CLI_CONFIG_DIR`.

## Security and limitations

- `gws auth login` 0.22.5 uses a random loopback callback without PKCE or `state`. The plugin correlates the live process, exact port, profile, chat, and sender; this mitigates confusion but does not replace PKCE.
- The pasted callback is not end-to-end secret on a messaging platform. The plugin rewrites recognized callbacks and attempts best-effort deletion, but platform servers, notifications, or devices may retain copies. Never send the OAuth client JSON, exported credentials, or refresh tokens through chat.
- Paste the callback before the five-minute deadline. After expiry the temporary hook is gone and Hermes may receive the message normally.
- Login completion works only in the same gateway process and private chat that started it. CLI, TUI, Desktop, and API-server sessions in another process are rejected.
- Account separation is logical per Hermes profile, not an operating-system security boundary against other processes running as the same user. A native global OAuth client may be shared, but authorized account tokens are never shared by this plugin.
- `gws_api` preserves native `gws` capabilities, including local file access and remote mutations. The plugin adds no sandbox, denylist, or approval layer; the user is responsible for reviewing each operation.
- `--full` may exceed the scope limit of an unverified external application. Use `default`, `readonly`, or `custom` when necessary.

## Verify

From a checkout:

```bash
python -m unittest discover -s tests -v
hermes plugins doctor . --ci
hermes plugins validate .
```

The offline suite uses a fake local `gws` process; it does not contact Google or prove a live OAuth authorization.

## Remove

```bash
hermes plugins disable gws-oauth
hermes plugins remove gws-oauth
```

Plugin removal does not delete `$HERMES_HOME/gws-oauth/`. Remove that state separately only when you intentionally want to discard all authorized accounts and the OAuth client.

See [docs/implementation.md](docs/implementation.md) for the flow and security decisions.
