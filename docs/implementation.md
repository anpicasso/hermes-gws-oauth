# Implementation and verification

Plugin activation creates the profile-local `$HERMES_HOME/gws-oauth/` directory with mode `0700`. The plugin keeps a `LoginManager` inside the Hermes process that executes `gws_login`. For each login attempt it:

1. Resolves `get_hermes_home()` for the active profile. It uses `gws-oauth/client_secret.json` when present; otherwise it asks `gws auth status` for the native global client path (normally `~/.config/gws/client_secret.json`). The profile client is therefore an override. Login never creates either file.
2. Creates a private temporary directory, copies the selected client with mode `0600`, and launches `gws auth login` with the chosen native mode (`--readonly`, `--full`, `--scopes ...`, or the default). Inherited `GOOGLE_WORKSPACE_CLI_*` and `GOOGLE_APPLICATION_CREDENTIALS` values are removed, and `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file` is set. Only the client is shared; account credentials are still committed under the active Hermes profile.
3. Reads the authorization URL printed by `gws` and extracts its `redirect_uri=http://localhost:<port>`. Gateway attempts temporarily register `pre_gateway_dispatch` through `ctx.register_hook()`; CLI/TUI attempts register no hook.
4. Accepts callbacks only from the profile, platform, chat, and sender associated with the live attempt. A protocol-less `localhost:<port>/...` copied by mobile Safari is normalized to `http://` before parsing. URL parsing still requires the exact host, port, and path plus one valid `code`. The plugin sends only that code to `127.0.0.1:<port>`; it never fetches a user-selected URL.
5. Waits for `gws`, verifies the returned Google identity and `credentials.enc`, then atomically moves the temporary directory to `accounts/<account>/`.
6. Returns a rewritten status message containing no authorization code. Completion, failure, timeout, and plugin unload terminate the process, remove temporary files, and dispose the hook when no attempts remain. Platform-message deletion is bounded and best effort.

`gws_api` selects the chosen account through `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` and executes `[gws_bin, *args]` without a shell or semantic filtering. Command policy, local file access, and remote mutations remain the user's responsibility, exactly as when using `gws` from a terminal.

## Important boundaries

The hook runs before the gateway authorization check, so binding every attempt to its profile, platform, chat, and sender is mandatory. A recognized callback must be rewritten even when parsing or authorization fails, because an unhandled hook error could otherwise allow the original message to continue.

`pre_gateway_dispatch` has no automatic timeout. The manager therefore enforces its own five-minute lease and bounded local network operations. A busy adapter may enqueue a message before the hook processes it; the plugin cannot control copies already retained by the messaging provider. Pending attempts are not restored after a gateway process stops.

The dynamic hook exists only in the process that started `gws_login`. Gateway callbacks must come from the same chat, sender, and profile. CLI/TUI chats use `HERMES_SESSION_SOURCE` when no gateway platform is bound, and bind attempts to the active home, terminal surface, and the host-dispatched `session_id` (falling back to `HERMES_SESSION_ID`). The agent passes the pasted callback through `gws_login(account, callback_url=...)`; `LoginManager.finish()` selects that exact pending attempt and uses the same callback-code validation, identity check, commit, and cleanup as the gateway. It never fetches the pasted URL itself. No CLI command, ingress interceptor, or core change is added. CLI/TUI callbacks intentionally reach the model, logs, and chat history; the plugin does not redact or delete them. Desktop and API-server sessions remain unsupported.

## Offline verification

Run from the plugin root:

```bash
python -m unittest discover -s tests -v
hermes plugins doctor . --ci
hermes plugins validate .
```

The tests launch a fake `gws` executable that listens on a real loopback socket. They cover fragmented authorization output, protocol-less mobile Safari callbacks, gateway callback rewriting without code leakage, sender and profile binding, terminal session binding and completion without hooks, malformed terminal callbacks, timeout cleanup, account identity verification, custom scopes, global-client fallback, profile-client precedence, and per-profile credential selection.

A real Google authorization still requires the user's Desktop OAuth client and consent; offline tests cannot prove that external flow.
