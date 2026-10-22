# Implementation and verification

Plugin activation creates the profile-local `$HERMES_HOME/gws-oauth/` directory with mode `0700`. The plugin keeps a `LoginManager` inside the Hermes process that executes `gws_login`. For each login attempt it:

1. Resolves `get_hermes_home()` for the active profile. It uses `gws-oauth/client_secret.json` when present; otherwise it asks `gws auth status` for the native global client path (normally `~/.config/gws/client_secret.json`). The profile client is therefore an override. Login never creates either file.
2. Creates a private temporary directory, copies the selected client with mode `0600`, and launches `gws auth login` with the chosen native mode (`--readonly`, `--full`, `--scopes ...`, or the default). Inherited `GOOGLE_WORKSPACE_CLI_*` and `GOOGLE_APPLICATION_CREDENTIALS` values are removed, and `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file` is set. Only the client is shared; account credentials are still committed under the active Hermes profile.
3. Reads the authorization URL printed by `gws` and extracts its `redirect_uri=http://localhost:<port>`. Attempts with a gateway chat identity temporarily register `pre_gateway_dispatch` through `ctx.register_hook()`; other frontend sessions register no hook.
4. Accepts callbacks only from the profile, platform, chat, and sender associated with the live attempt. A protocol-less `localhost:<port>/...` copied by mobile Safari is normalized to `http://` before parsing. URL parsing still requires the exact host, port, and path plus one valid `code`. The plugin sends only that code to `127.0.0.1:<port>`; it never fetches a user-selected URL.
5. Waits for `gws`, verifies the returned Google identity and `credentials.enc`, then commits under a per-profile cross-process lock. A new account is moved into `accounts/<account>/` atomically. For `reauthorize=true`, the existing directory is first renamed to a hidden backup, the validated staging directory is moved into place, and only then is the backup removed; if the second rename fails, restoration is attempted. Cancellation, timeout, and identity mismatch preserve old credentials, even if already expired. This is not crash-atomic: a crash or rollback failure may require local recovery from the hidden backup. Plugin API calls and health checks hold the same lock until completion, preventing token-cache writes during replacement. Independent CLI processes do not participate and must not run against the account during the swap.
6. Returns a rewritten status message containing no authorization code. Completion, failure, timeout, and plugin unload terminate the process, remove temporary files, and dispose the hook when no attempts remain. Platform-message deletion is bounded and best effort.

`gws_accounts(check_health=true)` runs native `gws auth status` with the same filtered environment and account-local config directory used by `gws_api`. It returns a fixed summary: `stored` shows the account files exist, `valid` is `true` only when native `gws` confirms a live session, and `state` is `valid`, `invalid`, `stored`, or `unreadable`. The plugin never decrypts credentials and never refreshes tokens itself; native `gws` owns that behavior, so a health check may update its token cache.

`gws_api` classifies native failures by exit code and an allowlist of safe signals (`invalid_grant`, `invalid_rapt`, permission markers, validation markers, HTTP status). It returns `error_code`, `category`, `action`, `reauth_required`, and `exit_code` with a fixed message. Raw stdout/stderr are never returned: they may contain request bodies, local paths, or token fragments. Auth failures point to `gws_login(..., reauthorize=true)`; permission failures point to scopes or API enablement; syntax and non-auth API failures do not suggest reauthorization.

`gws_api` selects the chosen account through `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` and executes `[gws_bin, *args]` without a shell or semantic filtering. Command policy, local file access, and remote mutations remain the user's responsibility, exactly as when using `gws` from a terminal.

## Important boundaries

The hook runs before the gateway authorization check, so binding every attempt to its profile, platform, chat, and sender is mandatory. A recognized callback must be rewritten even when parsing or authorization fails, because an unhandled hook error could otherwise allow the original message to continue.

`pre_gateway_dispatch` has no automatic timeout. The manager therefore enforces its own five-minute lease and bounded local network operations. A busy adapter may enqueue a message before the hook processes it; the plugin cannot control copies already retained by the messaging provider. Pending attempts are not restored after a gateway process stops.

The dynamic hook exists only in the process that started `gws_login`. Gateway callbacks must come from the same chat, sender, and profile. Without a gateway chat identity, any frontend binds attempts to the active home, actual surface, and host-dispatched `session_id` (falling back to `HERMES_SESSION_ID`), retaining a host user identity when available. The agent can pass the pasted callback through `gws_login(account, callback_url=...)` on every platform; `LoginManager.finish()` selects that exact pending attempt and uses the same callback-code validation, identity check, commit, and cleanup as the gateway. It never fetches the pasted URL itself. No CLI command, extra ingress interceptor, or core change is added. Explicit callbacks intentionally reach the model, logs, and chat history; the plugin does not redact or delete them. CLI, TUI, Desktop, API server and other frontend names are supported without a platform allowlist. A stateless API request cannot complete another request's attempt unless its host preserves the same bound identity and process.

## Offline verification

Run from the plugin root:

```bash
python -m unittest discover -s tests -v
hermes plugins doctor . --ci
hermes plugins validate .
```

The tests launch a fake `gws` executable that listens on a real loopback socket. They cover fragmented authorization output, protocol-less mobile Safari callbacks, gateway callback rewriting without code leakage, sender and profile binding, CLI/TUI/Desktop/API/custom surface binding and completion without hooks, malformed explicit callbacks, timeout cleanup, account identity verification, custom scopes, global-client fallback, profile-client precedence, and per-profile credential selection. Additional cases cover sanitized `invalid_grant`/`invalid_rapt`/permission/syntax/non-auth failures, optional live health states, explicit reauthorization, successful replacement, identity mismatch, cancellation, timeout, commit rollback, and overlapping reauthorization. The reauthorization tests assert that old credentials remain unchanged until a validated commit and are restored after a failed swap.

A real Google authorization still requires the user's Desktop OAuth client and consent; offline tests cannot prove that external flow.
