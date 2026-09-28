# Manual OAuth client setup required

Plugin activation creates the private directory:

```text
$HERMES_HOME/gws-oauth/
```

Installation with `--enable` reloads a running gateway immediately. If no gateway is running, start or restart it once so the plugin activates and creates the directory.

Before calling `gws_login`, configure a Google Desktop OAuth client in either location:

```text
~/.config/gws/client_secret.json                 # native global gws client
$HERMES_HOME/gws-oauth/client_secret.json        # optional profile override
```

The profile file wins when both exist. Set file permissions to `0600`. Do not paste or upload the JSON through chat, and do not store it inside the plugin directory. Authorized accounts remain profile-scoped even when the client is global.

Run `gws auth status` to inspect the exact native `client_config` path on systems using a legacy location.
