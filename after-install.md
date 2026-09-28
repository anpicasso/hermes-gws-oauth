# Manual OAuth client setup required

Plugin activation creates the private directory:

```text
$HERMES_HOME/gws-oauth/
```

Installation with `--enable` reloads a running gateway immediately. If no gateway is running, start or restart it once so the plugin activates and creates the directory.

Before calling `gws_login`, manually place your Google Desktop OAuth client at:

```text
$HERMES_HOME/gws-oauth/client_secret.json
```

Set file permissions to `0600`. Do not paste or upload the JSON through chat, and do not store it inside the plugin directory.
