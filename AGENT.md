# Agent Notes

`via` is a small Rust CLI for commands, SSH sessions, and API requests that
need secret-provider credentials. It keeps those credentials out of the
caller's shell.

The current provider is 1Password through its official local CLI and SSH
agent. The crates.io package is `via-cli`. The library crate and installed
binary are both named `via`.

## Product contract

via lets humans and AI agents use configured resources without copying
credentials into prompts, shell history, config files, argv, or long-lived
environment variables.

All capability invocations use this shape:

```sh
via <service> <capability> [args...]
```

Before an invocation, discover the configured boundary:

```sh
via capabilities --json
via skill print
```

Keep service behavior config-driven. Add a service-specific Rust module only
when the generic execution model cannot represent the required behavior.

Add a runtime dependency only when it improves security, protocol correctness,
or package support enough to justify its cost.

## Security boundaries

Config files contain secret references, such as `op://...`. They never contain
plaintext secrets or SSH private keys.

| Mode | Credential boundary | Required control |
| --- | --- | --- |
| `rest` | The resolved secret stays in via. | via constructs and sends the HTTP request. |
| `delegated` | One configured child receives each injected secret. | Trust that binary with the injected values. |
| `ssh` | The private key stays in the 1Password SSH agent. | via selects one public identity and limits the destination. |

Prefer `rest` when the service provides the required API. The resolved secret
stays inside the via process and does not enter a child process.

Use `delegated` only for trusted binaries. via captures output and redacts
known secret values, but the child can still transform, store, or transmit a
secret.

Use `ssh` for direct agent-backed access. Preserve its fixed user, port,
identity, authentication policy, and host allowlist.

SSH mode must never resolve a private key. It must disable agent forwarding
and reject caller-supplied local OpenSSH options.

For security-sensitive inputs, validate the capability boundary before secret
resolution or network access. Add focused tests for each rejection path.

## Architecture

Keep `src/main.rs` small. It calls the library entry point and contains no
business logic.

| Module | Responsibility |
| --- | --- |
| `src/app.rs` | Coordinate top-level commands. |
| `src/cli.rs` | Parse CLI input with clap. |
| `src/config.rs` | Load and validate TOML configuration. |
| `src/providers/` | Provide secret-provider abstractions and the 1Password CLI backend. |
| `src/executor/rest.rs` | Execute brokered HTTP requests. |
| `src/executor/delegated.rs` | Execute trusted child processes and redact their output. |
| `src/executor/ssh.rs` | Execute scoped OpenSSH sessions with one selected agent identity. |
| `src/redaction.rs` | Redact resolved secret values. |
| `src/skill.rs` | Generate instructions for AI agents. |
| `src/tls.rs` | Install the rustls cryptography provider. |

## Verification

Before merging, run all required checks:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Add focused tests for security-sensitive behavior. Cover config validation,
secret-resolution boundaries, REST headers, delegated redaction, SSH identity
selection, destination restrictions, and error handling.

## Release process

The manual **Prepare Release** input accepts a version with or without a leading
`v`. A tag trigger must use `v<version>`.

The workflow opens a `release/v<version>` pull request against `master`.

After that pull request merges, the workflow performs these actions:

1. Validate the merged `Cargo.toml` and `Cargo.lock` version.
2. Create the matching `v<version>` tag on the merge commit.
3. Dispatch the crate-publish and binary-build workflows for that tag.

The crate-publish workflow checks out the tag and runs
`cargo publish --locked`. Make `CARGO_REGISTRY_TOKEN` available to its
`crates-io` GitHub Actions environment.

The binary-build workflow produces release archives for Linux, macOS, and
Windows. It builds x86_64 and arm64 artifacts for each supported operating
system.
