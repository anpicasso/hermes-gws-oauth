# Manual OAuth client setup required

Plugin activation creates the private directory:

```text
$HERMES_HOME/gws-oauth/
```

Installation with `--enable` reloads a running gateway immediately. For CLI, TUI, Desktop or API use, load the updated plugin in the frontend's agent process and open a fresh session; no messaging gateway is required.

Before calling `gws_login`, configure a Google Desktop OAuth client in either location:

```text
~/.config/gws/client_secret.json                 # native global gws client
$HERMES_HOME/gws-oauth/client_secret.json        # optional profile override
```

The profile file wins when both exist. Set file permissions to `0600`. Do not paste or upload the JSON through chat, and do not store it inside the plugin directory. Authorized accounts remain profile-scoped even when the client is global.

To renew an account that is already configured, call `gws_login` with `reauthorize=true` after this version is installed. The previous credentials stay in place until the new browser flow reports the requested identity. A mismatch, cancellation, or timeout leaves them intact; a failed replacement attempts to restore them. Avoid simultaneous native commands during the brief swap. See README for crash-recovery limitations. Use `gws_accounts(check_health=true)` for an optional live check that distinguishes stored credentials from a session confirmed by native `gws`.

Run `gws auth status` to inspect the exact native `client_config` path on systems using a legacy location.
