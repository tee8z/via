# Agent Notes

`via` is a small Rust CLI for running commands and API requests with credentials from a secret provider without exposing secrets to the shell. The current provider target is 1Password through its official local CLI.

The crates.io package name is `via-cli` because `via` is already taken. The library crate and installed binary are both named `via`.

## Product Shape

The goal is to let humans and AI agents use configured resources without copying tokens into prompts, shell history, config files, argv, or long-lived environment variables.

The CLI shape is:

```sh
via <service> <capability> [args...]
```

Agents should discover capabilities with:

```sh
via capabilities --json
via skill print
```

## Security Model

Config files must contain secret references only, such as `op://...`, never plaintext secrets.

Prefer `rest` capabilities. In REST mode, `via` resolves the secret and sends the HTTP request itself, so the secret stays inside the `via` process and is not exposed to a child process.

Use `delegated` capabilities only for trusted binaries. In delegated mode, `via` injects configured secrets into one child process, captures stdout/stderr, redacts known secret values, and forwards sanitized output. The child binary still receives the secret, so it must be trusted.

Do not add service-specific Rust modules for each integration. Service behavior should stay config-driven unless there is a strong reason to extend the generic execution model.

Do not add dependencies casually. New runtime dependencies should pay for themselves clearly, especially on security, protocol correctness, or package manager support.

## Architecture

`src/main.rs` should stay tiny. It should call into the library entry point and avoid business logic.

The core modules are:

- `src/app.rs`: top-level command coordination.
- `src/cli.rs`: CLI parsing with clap.
- `src/config.rs`: TOML config loading and validation.
- `src/providers/`: secret provider abstraction and 1Password local CLI backend.
- `src/executor/rest.rs`: brokered HTTP execution.
- `src/executor/delegated.rs`: trusted child-process execution with redaction.
- `src/redaction.rs`: output redaction for resolved secret values.
- `src/skill.rs`: generated instructions for AI agents.
- `src/tls.rs`: rustls crypto provider setup.

## Development Checks

Run these before merging:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Security-sensitive behavior should have focused tests. Keep coverage high around config validation, secret resolution boundaries, REST header construction, delegated redaction, and error handling.

## Release Process

Release PRs should either:

- use a branch named `release/<version>`, or
- carry the `release` label.

When a release PR is merged into `main`, the publish workflow checks out the merge commit and runs `cargo publish --locked`. The version published is the version in `Cargo.toml` at that merge commit.

The repository must define `CARGO_REGISTRY_TOKEN` as a GitHub Actions secret for crates.io publishing.

The binary build workflow produces release artifacts for Linux, macOS, and Windows on x86_64 and arm64 runners.
