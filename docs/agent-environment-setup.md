# Editor And Agent Environment Setup

Use this guide when an editor, agent, task runner, or scheduled job starts
`via` in a separate process.

Each process must find `via` and the configured provider CLI on `PATH`. For
1Password, each process must run both commands:

```sh
via --version
op --version
```

## Use Cross-Process 1Password Authentication

Use 1Password desktop app integration for processes that do not share a shell.
A classic `op signin` session token applies only to its current shell.

`via login` can start `op signin`. It cannot export that shell-local token to
future processes from an editor, agent, task runner, or daemon.

With desktop integration, `op read` can authenticate through the unlocked
1Password app. The app must allow CLI requests.

1. Open and unlock the 1Password desktop app.
2. Enable **Settings > Developer > Integrate with 1Password CLI**.
3. On Linux, first enable **Settings > Security > Unlock using system authentication**.
4. If you use multiple accounts, set the provider account in `via.toml`:

   ```toml
   [providers.onepassword]
   type = "1password"
   account = "<account-id-or-sign-in-address>"
   ```

5. Open the same process type that will run `via`.
6. Run these checks from that process:

   ```sh
   command -v via
   command -v op
   op whoami
   via config doctor
   ```

On PowerShell, replace the first two checks with:

```powershell
Get-Command via
Get-Command op
```

CAUTION: Do not put credentials in editor or agent settings. These settings are
not a secret store and can expose their contents to child processes.

Credentials include `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN`, OAuth client
secrets, access tokens, and refresh tokens.

## Configure `PATH`

If commands work in a terminal but fail in a tool, compare the tool's `PATH`
with the terminal's `PATH`.

Use one of these methods:

- Start the editor from a configured shell.
- Add only required executable directories to the tool environment.
- Configure the editor's terminal, task, or agent environment.

For example, add these paths to a tool that expands `$HOME` and `$PATH`:

```json
{
  "terminal": {
    "env": {
      "PATH": "$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
    }
  }
}
```

On NixOS, `op` can be in `/run/wrappers/bin`. System packages can be in
`/run/current-system/sw/bin`.

Add those directories only when the spawned process requires them.

If the process must enable desktop integration explicitly, set:

```json
{
  "terminal": {
    "env": {
      "OP_BIOMETRIC_UNLOCK_ENABLED": "true"
    }
  }
}
```

## Configure Zed

When you start Zed with `zed`, Zed inherits the calling shell environment:

```sh
zed .
```

Run that command from a shell where `command -v via` and `command -v op`
succeed.

When a window manager, Dock, or app launcher starts Zed, Zed builds its
environment from login shells. It passes the applicable environment to
terminals, tasks, language servers, and agent terminal tools.

If required, add executable directories under `terminal.env` in Zed settings.
See [Zed Agent Setup](zed-agent-setup.md) for the focused procedure.

## Understand Daemon Caching

On Unix-like systems, keep `cache = "daemon"` enabled for editor and agent
workflows. This platform default caches 1Password values and OAuth token state
in memory.

On Windows, keep the default `cache = "off"`. The daemon and OAuth
authentication are unavailable until via has a Windows named-pipe backend.

The daemon still runs `op read` after a cache miss. Therefore, the daemon also
needs a valid `PATH` and working desktop integration.

On Linux and macOS, `via` tries to start the daemon through the user service
manager. It uses `systemd-run --user` on Linux and `launchctl` on macOS.

If the service manager is unavailable, `via` starts a detached daemon process.
Check the current state with:

```sh
via daemon status
```

See [Daemon Architecture](daemon-architecture.md) for cache behavior and
security boundaries.

## Troubleshoot From Observable Results

| Result | Cause to check | Corrective action |
| --- | --- | --- |
| `via` or `op` is not found | The spawned process has a different `PATH`. | Start the tool from a configured shell or update its non-secret `PATH`. |
| `op whoami` reports no session | Desktop integration is disabled, or the app is unavailable. | Unlock 1Password and enable CLI integration. |
| Authentication prompts repeat | Independent processes rely on shell-local `op signin` state. | Use 1Password desktop app integration. |
| The wrong account is selected | Multiple accounts are available without a pinned provider account. | Set `[providers.onepassword] account` in `via.toml`. |
| The first request works but later requests fail | The app locked, exited, or stopped servicing CLI requests. | Unlock or restart 1Password, then rerun `op whoami`. |
| Daemon cache misses always occur | The daemon restarts or exits between commands. | Run `via daemon status`, then review the daemon setup guide. |

After each correction, rerun:

```sh
op whoami
via config doctor
```

A healthy result identifies the intended 1Password account and reports no
provider error.

## References

- Zed environment model: <https://zed.dev/docs/environment>
- Zed terminal environment settings: <https://zed.dev/docs/terminal>
- Zed Agent terminal tools: <https://zed.dev/docs/ai/agent-panel>
- 1Password CLI desktop app integration:
  <https://www.1password.dev/cli/app-integration>
