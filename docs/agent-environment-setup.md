# Editor And Agent Environment Setup

This guide is for using `via` from editors, IDEs, AI agents, scheduled jobs, and
other tools that spawn their own command processes.

## Recommended Pattern

Install `via` and the configured secret-provider CLI in directories the spawned
process can find on `PATH`. For the 1Password provider, that means the process
must be able to run both:

```sh
via --version
op --version
```

Use 1Password desktop app integration for the `op` CLI. Classic `op signin`
session tokens are shell-local; `via login` can run `op signin`, but it cannot
export that shell-local session token into future processes created by an
editor, agent, task runner, or daemon. With desktop app integration enabled, any
`via` process can call `op read` as long as the 1Password app is running,
unlocked, and allowed to service CLI requests.

1. Open and unlock the 1Password desktop app.
2. Enable CLI integration:
   - macOS or Windows: Settings > Developer > Integrate with 1Password CLI.
   - Linux: Settings > Security > Unlock using system authentication, then
     Settings > Developer > Integrate with 1Password CLI.
3. If multiple 1Password accounts are available, set the provider account in
   `via.toml`:

   ```toml
   [providers.onepassword]
   type = "1password"
   cache = "daemon"
   account = "<account-id-or-sign-in-address>"
   ```

4. From the same kind of process your editor or agent will spawn, verify:

   ```sh
   command -v via
   command -v op
   op whoami
   via config doctor
   ```

Do not put `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN`, OAuth client secrets,
access tokens, refresh tokens, or other secret values in editor settings. Those
settings are not a secret store.

## PATH Setup

If the tool works in your normal terminal but fails inside an editor or agent,
the spawned process usually has a different `PATH`. Fix that by launching the
editor from a configured shell, or by adding a non-secret PATH override to the
editor's terminal/task/agent environment.

For example, if `via` is installed in `~/.local/bin` and `op` is available in a
system or package-manager directory:

```json
{
  "terminal": {
    "env": {
      "PATH": "$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
    }
  }
}
```

On NixOS, `op` may be exposed through `/run/wrappers/bin` and system packages
through `/run/current-system/sw/bin`, so include those paths in editor-spawned
tool environments when needed.

If 1Password desktop integration needs to be forced on for spawned shells, set:

```json
{
  "terminal": {
    "env": {
      "OP_BIOMETRIC_UNLOCK_ENABLED": "true"
    }
  }
}
```

## Zed Notes

Zed inherits environment variables when launched from the `zed` CLI. When
launched from a window manager, Dock, or app launcher, Zed builds an environment
from login shells and then passes that environment to terminals, tasks, language
servers, and agent terminal tools.

For Zed, either launch with:

```sh
zed .
```

from a shell where `command -v via` and `command -v op` both work, or add the
needed PATH entries under `terminal.env` in Zed settings.

## Why Repeated Login Prompts Happen

Repeated prompts usually mean one of these is true:

- The editor or agent was launched without an environment that can find the same
  `op` and `via` binaries as the user's terminal.
- 1Password desktop app integration is not enabled, so `op signin` relies on a
  shell-local session token that separate tool processes do not share.
- The 1Password desktop app is locked, not running, or cannot service CLI
  integration prompts.
- Multiple 1Password accounts are configured and `via.toml` does not pin the
  provider `account`.

`via`'s daemon helps by caching resolved 1Password secrets and OAuth token state
in memory, but the daemon still needs `op read` on cache misses. Keep
`cache = "daemon"` enabled for editor and agent workflows, and use
`via daemon status` to confirm the daemon remains warm during a session.

On Linux and macOS, `via` auto-starts the daemon through the user service
manager when possible: `systemd-run --user` on Linux and `launchctl` on macOS.
That keeps the daemon alive after a one-shot editor task or agent command exits,
so later `via` invocations can reuse the same daemon cache. If the service
manager is unavailable, `via` falls back to a detached direct spawn.

## References

- Zed environment model: <https://zed.dev/docs/environment>
- Zed terminal environment settings: <https://zed.dev/docs/terminal>
- Zed Agent terminal tools: <https://zed.dev/docs/ai/agent-panel>
- 1Password CLI desktop app integration:
  <https://www.1password.dev/cli/app-integration>
