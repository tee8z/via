# Zed Agent Setup

Configure Zed so its terminals, tasks, and agent terminal tools can run `via`
and the selected provider CLI.

This guide uses the 1Password provider. For the shared authentication model,
see [Editor And Agent Environment Setup](agent-environment-setup.md).

## 1. Prepare 1Password

Open and unlock the 1Password desktop app. Enable **Settings > Developer >
Integrate with 1Password CLI**.

On Linux, also enable system authentication under **Settings > Security**.

If several accounts are available, pin the intended account in `via.toml`:

```toml
[providers.onepassword]
type = "1password"
account = "<account-id-or-sign-in-address>"
```

This omission uses the platform cache default. Unix-like systems use the
daemon. Windows uses `cache = "off"`; OAuth authentication is unavailable
there because it requires the daemon.

Do not put session tokens, service-account tokens, or OAuth credentials in Zed
settings.

## 2. Give Zed The Required `PATH`

The simplest method is to start Zed from a configured shell:

```sh
command -v via
command -v op
zed .
```

Both lookup commands must print the intended executable path before you start
Zed.

When a window manager, Dock, or launcher starts Zed, Zed reads its environment
from login shells. It also builds a project environment in the project
directory.

If those environments omit required paths, add them to Zed settings:

```json
{
  "terminal": {
    "env": {
      "PATH": "$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
    }
  }
}
```

Use directories that contain your installed `via` and `op` binaries. On
NixOS, you might also need these directories:

```text
/run/wrappers/bin
/run/current-system/sw/bin
```

If the spawned shell must explicitly enable 1Password app integration, add:

```json
{
  "terminal": {
    "env": {
      "OP_BIOMETRIC_UNLOCK_ENABLED": "true"
    }
  }
}
```

## 3. Verify Inside Zed

Open a new Zed terminal and run:

```sh
command -v via
command -v op
op whoami
via config doctor
via daemon status
```

In a PowerShell terminal, use `Get-Command via` and `Get-Command op` for the
first two checks.

Then ask the Zed agent to run this non-secret check through its terminal tool:

```text
Run `via capabilities` and summarize the available capability names.
```

A healthy setup has these results:

- Zed finds the intended `via` and `op` binaries.
- `op whoami` identifies the intended account.
- `via config doctor` reports no provider error.
- The agent can run `via capabilities` without a shell-local `op signin` token.

## Troubleshoot From Observable Results

| Result | Cause to check | Corrective action |
| --- | --- | --- |
| Zed cannot find `via` or `op` | Zed started with a different `PATH`. | Start Zed with `zed .` from a configured shell or update `terminal.env`. |
| The Zed terminal works but the agent fails | The agent can have an older or separate environment. | Start a new thread. If failure continues, restart Zed from the configured shell. |
| `op whoami` fails in Zed | The app is locked or CLI integration is disabled. | Unlock 1Password, enable integration, and rerun the check. |
| Zed selects the wrong 1Password account | The provider does not pin an account. | Set `[providers.onepassword] account` in `via.toml`. |
| Authentication repeats for each command | Zed processes rely on shell-local `op signin` state. | Use 1Password desktop app integration. |
| `via daemon status` returns `stopped` after a provider-backed command | Caching is off, unsupported, or unable to start. | Confirm `cache = "daemon"` on macOS or Linux, then run `via config doctor`. |

## References

- [Editor And Agent Environment Setup](agent-environment-setup.md)
- [Daemon Architecture](daemon-architecture.md)
- Zed environment model: <https://zed.dev/docs/environment>
- Zed terminal settings: <https://zed.dev/docs/terminal>
- Zed Agent tools: <https://zed.dev/docs/ai/agent-panel>
