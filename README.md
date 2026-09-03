# via

[![crates.io](https://img.shields.io/crates/v/via-cli.svg)](https://crates.io/crates/via-cli)
[![docs.rs](https://docs.rs/via-cli/badge.svg)](https://docs.rs/via-cli)

via runs configured commands, SSH sessions, and API requests with credentials
from a secret provider. It does not expose those credentials to the caller's
shell.

For credential fields, store only `op://` references in the config. via
resolves each required value at runtime and applies the selected execution
boundary.

via is an early project. It currently supports 1Password through the official
1Password CLI and SSH agent. The crates.io package is `via-cli`; the installed
binary is `via`.

## Choose an execution mode

Each capability uses one execution mode:

| Mode | Use it for | Credential boundary |
| --- | --- | --- |
| `rest` | Supported HTTP APIs | via sends the request. The resolved secret stays in the via process. |
| `delegated` | A trusted binary whose native behavior is required | The child process receives only its configured secrets. via redacts known secret values from captured output. |
| `ssh` | Direct SSH sessions and remote commands | OpenSSH receives one selected public identity and its agent endpoint. The private key remains in 1Password. |

Prefer `rest` for AI agents when the service provides a suitable API. Use
`delegated` only when you trust the configured child binary.

REST mode does not pass a resolved secret to a shell, child process,
environment variable, argument, or temporary file. A delegated child can
transform, store, transmit, or pass an injected secret to another process.

SSH mode restricts the remote user, port, identity, authentication methods,
and destination hosts. It disables agent forwarding and caller-supplied local
OpenSSH options.

via selects trusted OpenSSH executables from fixed absolute paths. It does not
select these executables from the caller's `PATH`.

via does not insert a local shell between itself and a configured program. An
SSH server can still use the remote user's shell for a remote command.

## Install via

On macOS or Linux, install the latest prebuilt release:

```sh
curl -fsSL https://raw.githubusercontent.com/tee8z/via/master/scripts/install-release.sh | bash
```

To install a specific release, set `VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/tee8z/via/master/scripts/install-release.sh | VERSION=v0.2.0 bash
```

The script selects the correct macOS or Linux asset. It installs `via` to
`${INSTALL_DIR:-$HOME/.local/bin}` and reports a required `PATH` change.

When a release includes `SHA256SUMS`, the script verifies the downloaded
archive. Set `VERIFY=required` to require signed checksum verification. See
[Release Signing](docs/release-signing.md) for the verification modes.

For a manual install, download an asset from the
[latest release](https://github.com/tee8z/via/releases/latest):

| Platform | Asset |
| --- | --- |
| Linux x86_64 | `via-linux-x86_64.tar.gz` |
| Linux arm64 | `via-linux-arm64.tar.gz` |
| macOS Intel | `via-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `via-macos-arm64.tar.gz` |
| Windows x86_64 | `via-windows-x86_64.zip` |
| Windows arm64 | `via-windows-arm64.zip` |

Extract the archive. Put `via` or `via.exe` in a directory on `PATH`.

Verify the installation:

```sh
via --help
```

If Rust is installed, install from crates.io:

```sh
cargo install via-cli
```

## Set up 1Password

Before you configure via, prepare these components:

| Component | Requirement |
| --- | --- |
| 1Password CLI | Install it and authenticate through `via login`. |
| 1Password desktop app | Enable the CLI integration. |
| Secrets | Store them in 1Password and reference them with `op://` URIs. |
| SSH support | Install `ssh` and `ssh-add`. Enable the 1Password SSH agent and selected key. |

Install the 1Password CLI:

```sh
# macOS
brew install --cask 1password-cli

# Windows
winget install -e --id AgileBits.1Password.CLI
```

On Linux, use the official
[1Password CLI installation guide](https://developer.1password.com/docs/cli/get-started/).

If necessary, install the 1Password desktop app:

```sh
# macOS
brew install --cask 1password

# Windows
winget install -e --id AgileBits.1Password
```

On Linux, use the official
[1Password desktop installation guide](https://support.1password.com/install-linux/).

Verify the CLI:

```sh
op --version
```

Open and unlock the desktop app. Add the required account, then enable
**Settings > Developer > Integrate with 1Password CLI**.

If the CLI lists multiple accounts, use the account that contains the
configured vault. List available accounts:

```sh
op account list
```

If necessary, pin the account in `via.toml`:

```toml
[providers.onepassword]
type = "1password"
account = "<account-id-or-sign-in-address>"
```

For SSH access, also enable the 1Password SSH agent. Follow the
[1Password SSH Agent Setup](docs/ssh-agent-setup.md) guide to select one key
and restrict its destinations.

## Create and verify a config

Run the interactive setup:

```sh
via config
```

The setup creates a generic service config from your answers. It does not
assume GitHub or another specific service.

The interactive setup does not create SSH profiles. For SSH mode, start with
[examples/ssh.toml](examples/ssh.toml) and follow the
[SSH setup guide](docs/ssh-agent-setup.md).

After the config exists, authenticate and run the doctor:

```sh
via login
via config doctor
```

`via login` starts the provider's official interactive login flow. For
1Password, it runs `op signin` and passes the configured account when present.

The doctor checks providers, references, delegated tools, and SSH profiles. It
verifies resolved values without printing them.

## Discover and run capabilities

Every capability uses this command shape:

```sh
via <service> <capability> [args...]
```

Inspect the active config and its capabilities:

```sh
via config path
via login
via config doctor
via capabilities
via capabilities --json
via skill print
```

`via skill print` generates concise instructions for an AI agent from the
current config.

### Run a REST capability

Pass a path, and optionally an HTTP method and request options:

```sh
via github api /installation/repositories
via github api GET /repos/OWNER/REPO/issues --query state=open
via github api POST /repos/OWNER/REPO/pulls --json @pull-request.json
```

### Run a delegated capability

Pass remaining arguments to the configured trusted binary:

```sh
via github gh issue list --repo OWNER/REPO --state open --limit 10 --json number,title,url
```

### Run an SSH capability

Pass one allowed host. Add remote-command arguments after the host:

```sh
via example shell server-01.example.com
via example shell server-01.example.com uptime
```

Pass only a hostname or IP address. Do not pass an OpenSSH option,
`user@host`, or `host:port` value.

## Configuration examples

### REST API

Create `via.toml`:

```toml
version = 1

[providers.onepassword]
type = "1password"

[services.github]
description = "GitHub REST API access through a GitHub App installation"
hint = "via github api /installation/repositories"
provider = "onepassword"

[services.github.secrets]
app = "op://Private/Example GitHub App/metadata"
private_key = "op://Private/Example GitHub App/github-app.private-key.pem"

[services.github.commands.api]
description = "Call the GitHub REST API. Prefer this for agents."
mode = "rest"
base_url = "https://api.github.com"
method_default = "GET"

[services.github.commands.api.auth]
type = "github_app"
credential = "app"
private_key = "private_key"

[services.github.commands.api.headers]
Accept = "application/vnd.github+json"
X-GitHub-Api-Version = "2022-11-28"
```

A REST capability accepts paths within its configured `base_url`. That base
URL is the service trust boundary.

If authenticated files use another host, add exact names to `asset_hosts`:

```toml
[services.linear.commands.api]
mode = "rest"
base_url = "https://api.linear.app"
asset_hosts = ["uploads.linear.app"]
```

via accepts absolute URLs only for listed asset hosts. For an absolute asset
URL, use `--output`. This prevents binary response data from printing in the
terminal.

```sh
via linear api GET "https://uploads.linear.app/WORKSPACE/OBJECT/FILE" --output /tmp/hero.jpg
```

The optional service-level `hint` appears in `via capabilities` and
`via skill print`. Use a safe, minimal command that contains no secrets.

### SSH through the 1Password agent

Configure a reusable profile and an SSH capability:

```toml
version = 1

[providers.onepassword]
type = "1password"

[ssh_profiles.example]
provider = "onepassword"
public_key = "op://Private/Example SSH Key/public key"

[services.example]
description = "SSH access to example servers"
hint = "via example shell server-01.example.com"
provider = "onepassword"

[services.example.commands.shell]
description = "Open a public-key-only SSH session as deploy."
mode = "ssh"
profile = "example"
user = "deploy"
hosts = ["server-*.example.com", "192.0.2.10"]
port = 22
```

The private key remains in 1Password. via resolves the selected public key and
requires its exact identity from the agent before any SSH network connection.

via uses `IdentitiesOnly=yes`, preserves host-key verification, and does not
increase the server's `MaxAuthTries` value. See the
[complete example](examples/ssh.toml) and
[SSH setup guide](docs/ssh-agent-setup.md).

## Provider cache

On macOS and Linux, `cache = "daemon"` is the default. via automatically starts
a per-user daemon and caches resolved 1Password secrets in memory for a short
time-to-live (TTL).

No separate service installation is necessary. Manage the daemon with:

```sh
via daemon status
via daemon clear
via daemon stop
```

The next command that needs daemon caching starts a stopped daemon. Set
`cache = "off"` to call `op read` for every resolution. See
[Daemon Architecture](docs/daemon-architecture.md) for the data flow and
verification procedures.

Each daemon-backed provider resolution registers the current config's allowed
references. Config changes do not require a daemon restart.

Discovery commands show config-only changes immediately. After a value behind
a daemon-cached `op://` reference changes, run `via daemon clear`. To restart
the daemon, run `via daemon stop` and invoke via again.

GitHub App installation tokens can use a separate disk cache when a supported
cache directory is available. `via daemon clear` does not remove those tokens;
via stops reusing each token near its GitHub expiry.

On Windows, the cache defaults to `off`. The daemon does not yet have a Windows
named-pipe backend. The same provider setting can enable caching after that
backend is implemented.

## Authentication recipes

### GitHub App installation tokens

Store the app metadata and private key as separate 1Password fields:

```toml
[services.github.secrets]
app = "op://Private/Example GitHub App/metadata"
private_key = "op://Private/Example GitHub App/github-app.private-key.pem"

[services.github.commands.api.auth]
type = "github_app"
credential = "app"
private_key = "private_key"
```

The metadata must be valid JSON with `type`, numeric `app_id`, and
`installation_id`. Store the PEM as a 1Password file attachment to avoid JSON
escaping.

Follow the complete [GitHub App Setup](docs/github-app-setup.md) guide.

### OAuth

OAuth authentication requires the local via daemon. It works on Unix-like
platforms and is unavailable on Windows.

Store the OAuth credential bundle in 1Password:

```toml
[services.service.secrets]
oauth = "op://Private/OAuth/credential"

[services.service.commands.api.auth]
type = "oauth"
credential = "oauth"
```

An OAuth bundle uses `type = "service_oauth"`, the service's REST OAuth
`token_url`, and its required grant fields. Prefer `client_credentials` for a
bot, agent, service account, or app actor when the service supports it.

For Linear, use this bundle shape:

```json
{
  "type": "service_oauth",
  "token_url": "https://api.linear.app/oauth/token",
  "grant_type": "client_credentials",
  "client_id": "client_id",
  "client_secret": "client_secret",
  "scope": "read,issues:create"
}
```

The local daemon mints OAuth access tokens through the configured OAuth token
endpoint. It keeps access tokens and refresh-token state only in memory.

via does not write OAuth exchange data to disk. Use `refresh_token` only when
the service requires user-actor OAuth and cannot issue bot or app credentials.

For Linear client-credentials tokens, via retries once with a fresh token after
a `401 Unauthorized` response. Follow the
[Linear OAuth Setup](docs/linear-oauth-setup.md) guide.

### Bearer tokens by environment

For bearer-token APIs, such as Grafana service account tokens, configure one
service per environment:

```toml
[services.grafana-staging.secrets]
token = "op://Private/Example Grafana Staging/service-account-token"

[services.grafana-staging.commands.api.auth]
type = "bearer"
secret = "token"

[services.grafana-prod.secrets]
token = "op://Private/Example Grafana Prod/service-account-token"

[services.grafana-prod.commands.api.auth]
type = "bearer"
secret = "token"
```

Follow the [Grafana Service Account Setup](docs/grafana-service-account-setup.md)
guide. It includes Loki and PostgreSQL queries through Grafana's
`/api/ds/query` endpoint.

### Secret-backed headers

Map one or more secrets to fixed request headers:

```toml
[services.example.secrets]
api_key = "op://Private/Example/api-key"
tenant = "op://Private/Example/tenant"

[services.example.commands.api.auth]
type = "headers"

[services.example.commands.api.auth.headers.Authorization]
secret = "api_key"
prefix = "Token "

[services.example.commands.api.auth.headers.X-Tenant]
secret = "tenant"
```

## Editors and AI agents

Ensure that a spawned tool process can find both `via` and the provider CLI on
`PATH`. For example, the process must find `op` for 1Password-backed services.

Prefer 1Password desktop integration to shell-local `op signin` session
tokens. Separate tool processes can then authenticate without repeated login
prompts.

See [Agent Environment Setup](docs/agent-environment-setup.md) for environment
requirements.

Agents that use via must follow these rules:

- Start with `via capabilities --json`.
- Prefer configured `rest` capabilities.
- Use a `delegated` capability only when its configured binary is required.
- For SSH, pass a configured host as the first capability argument.
- Never ask the user for a token, password, or SSH private key.
- Never call the underlying secret provider directly.
- Never print credentials or the complete process environment.
- If a service fails, run `via config doctor <service>`.
