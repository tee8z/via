# via

via is a lightweight CLI for running configured service capabilities with credentials stored in 1Password.

Define services in a config file, store only `op://` secret references, and let via resolve credentials at runtime. The goal is to make authenticated tools safe and easy for humans and AI agents without asking them to handle raw tokens.

## Status

via is early and currently focuses on 1Password-backed credentials.

The first provider backend is the 1Password CLI (`op`). via intentionally uses `op read` instead of an unofficial Rust SDK wrapper so the core CLI stays small, portable, and compatible with normal 1Password desktop/CLI auth flows.

The crates.io package is `via-cli`; the installed binary is `via`.

## Requirements

- 1Password CLI (`op`) installed and signed in.
- A `via.toml` config file.
- Secrets stored in 1Password and referenced by `op://...` URIs.

Run:

```sh
via doctor
```

to check that `op` and any configured delegated tools are available.

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
via github gh api /user
```

Discover what is configured:

```sh
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
description = "GitHub API and CLI access"
provider = "onepassword"

[services.github.secrets]
token = "op://Private/GitHub/token"

[services.github.commands.api]
description = "Call the GitHub REST API. Prefer this for agents."
mode = "rest"
base_url = "https://api.github.com"
method_default = "GET"

[services.github.commands.api.auth]
type = "bearer"
secret = "token"

[services.github.commands.api.headers]
Accept = "application/vnd.github+json"
X-GitHub-Api-Version = "2022-11-28"

[services.github.commands.gh]
description = "Run the GitHub CLI with GH_TOKEN injected."
mode = "delegated"
program = "gh"
check = ["--version"]

[services.github.commands.gh.inject.env.GH_TOKEN]
secret = "token"
```

REST capabilities accept paths, not arbitrary absolute URLs. The configured `base_url` is the trust boundary for that service.

## Agent Rules

Agents using via should:

- Start with `via capabilities --json`.
- Prefer configured `rest` capabilities.
- Use delegated capabilities only when the configured binary is needed.
- Never ask the user for tokens or passwords.
- Never run `op read` directly.
- Never print environment variables or credentials.
- Run `via doctor <service>` when a service fails.
