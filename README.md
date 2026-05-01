# via

[![crates.io](https://img.shields.io/crates/v/via-cli.svg)](https://crates.io/crates/via-cli)
[![docs.rs](https://docs.rs/via-cli/badge.svg)](https://docs.rs/via-cli)

via is a secure CLI for running commands and API requests with credentials from your secret provider without exposing secrets to your shell.

Define services in a config file, store only `op://` secret references, and let via resolve credentials at runtime. 1Password is supported today; more providers can be added behind the same config-driven model.

## Status

via is early and currently focuses on 1Password-backed credentials.

The first provider backend is the 1Password CLI. via uses the official local CLI instead of an unofficial Rust SDK wrapper so the core CLI stays small, portable, and compatible with normal 1Password desktop/CLI auth flows.

The crates.io package is `via-cli`; the installed binary is `via`.

## Human Setup Requirements

- 1Password CLI installed and signed in.
- Secrets stored in 1Password and referenced by `op://...` URIs.

Install 1Password CLI:

```sh
# macOS CLI
brew install --cask 1password-cli

# Windows CLI
winget install -e --id AgileBits.1Password.CLI
```

For Linux, follow the official 1Password CLI install guide for APT, YUM, Alpine, NixOS, or manual installation: <https://developer.1password.com/docs/cli/get-started/>.

Install the 1Password desktop app if it is not already installed:

```sh
# macOS desktop app
brew install --cask 1password

# Windows desktop app
winget install -e --id AgileBits.1Password
```

For Linux desktop app setup, follow the official 1Password Linux install guide: <https://support.1password.com/install-linux/>.

Then verify:

```sh
op --version
```

Open and unlock the 1Password desktop app, add your account if needed, then enable the CLI integration in Settings > Developer > Integrate with 1Password CLI.

Sign in to the CLI session:

```sh
op signin
op whoami
```

If `op signin` lists multiple accounts, choose the account that contains the configured vault. To see which accounts the CLI can access:

```sh
op account list
```

If needed, pin via to a specific account:

```toml
[providers.onepassword]
type = "1password"
account = "<account-id-or-sign-in-address>"
```

Run the guided setup:

```sh
via config
```

`via config` creates a generic service config from values you type in. It does not assume GitHub or any other specific service.

Run:

```sh
via config doctor
```

to check that the secret provider, configured secret references, and any delegated tools are available. `via config doctor` verifies that secrets are readable by via, but never prints secret values.

## Security Model

via has two execution modes:

`rest`

via makes the HTTP request itself. The resolved secret stays inside the via process and is not passed to a shell, child process, environment variable, argv, or temp file. This is the preferred mode for AI agents.

`delegated`

via runs a configured trusted binary, injects configured secrets only into that child process, captures stdout/stderr, redacts known secret values, and then forwards the sanitized output. This is higher risk than `rest`: the child binary receives the secret and must be trusted not to write it elsewhere, transform it before printing, send it over the network, or spawn other processes with it.

Use delegated capabilities only when the binary's native behavior is required. Prefer REST APIs when practical.

via never invokes configured commands through a shell.

## Usage

The command shape is:

```sh
via <service> <capability> [args...]
```

For example, with the config below:

```sh
via github api /user
via github api GET /repos/OWNER/REPO/issues --query state=open
via github api POST /repos/OWNER/REPO/pulls --json @pull-request.json
```

If the configured capability delegates to a trusted CLI, everything after the capability name is passed to that binary:

```sh
via github gh issue list --repo OWNER/REPO --state open --limit 10 --json number,title,url
```

Discover what is configured:

```sh
via config path
via config doctor
via capabilities
via capabilities --json
via skill print
```

`via skill print` emits concise instructions an AI agent can use for the current config.

## Example Config

Create `via.toml`:

```toml
version = 1

[providers.onepassword]
type = "1password"

[services.github]
description = "GitHub REST API access through a GitHub App installation"
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

REST capabilities accept paths, not arbitrary absolute URLs. The configured `base_url` is the trust boundary for that service.

For GitHub App installation-token auth, store the app metadata and private key as separate 1Password secrets and use:

```toml
[services.github.secrets]
app = "op://Private/Example GitHub App/metadata"
private_key = "op://Private/Example GitHub App/github-app.private-key.pem"

[services.github.commands.api.auth]
type = "github_app"
credential = "app"
private_key = "private_key"
```

See [docs/github-app-setup.md](docs/github-app-setup.md) for the full GitHub App setup flow.

The GitHub App metadata field must be valid JSON with `type`, numeric `app_id`, and `installation_id`. Store the PEM as a 1Password file attachment so it does not need JSON escaping.

For APIs that need one or more secret-backed headers:

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

## Agent Rules

Agents using via should:

- Start with `via capabilities --json`.
- Prefer configured `rest` capabilities.
- Use delegated capabilities only when the configured binary is needed.
- Never ask the user for tokens or passwords.
- Never call the underlying secret provider directly.
- Never print environment variables or credentials.
- Run `via config doctor <service>` when a service fails.
