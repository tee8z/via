# Daemon Architecture

`via` can cache 1Password reads in a small per-user daemon. The daemon is an
implementation detail of the CLI: users do not install or configure a separate
service.

On macOS and Linux, `cache = "daemon"` is the default for the 1Password
provider. On Windows, the default is `cache = "off"` until the daemon has a
named-pipe backend.

```toml
[providers.onepassword]
type = "1password"
cache = "daemon"
cache_ttl_seconds = 300
```

Set `cache = "off"` to make every CLI invocation call `op read` directly.

## Flow

```text
first via invocation
  |
  | auto-starts, if needed
  v
via daemon serve
  |
  | REGISTER { config_hash, allowed_refs }
  v
daemon memory
  - allowlist: config_hash -> ref_id -> op:// reference
  - cache:     config_hash + ref_id -> secret value, expires_at

normal secret resolve
  |
  | RESOLVE { config_hash, ref_id }
  v
daemon memory
  |
  | cache miss only
  v
op read op://...
  |
  v
daemon cache
  |
  | secret value
  v
via command
```

The normal hot path sends only `config_hash` and `ref_id` over the socket. Raw
`op://` references are sent during registration so the daemon can enforce the
allowlist and perform `op read` on cache misses.

## Socket And Lifetime

The daemon listens on a Unix domain socket. The socket path is resolved in this
order:

1. `VIA_DAEMON_SOCKET`
2. `$XDG_RUNTIME_DIR/via/daemon.sock`
3. `/tmp/via-$UID/daemon.sock`

The socket directory is created with mode `0700`, and the socket file is set to
`0600`. The daemon exits automatically after 15 minutes without activity.

The cache is memory-only. Nothing is written to disk. Cache entries expire after
`cache_ttl_seconds`, defaulting to 300 seconds.

## Commands

```sh
via daemon status
```

Shows whether the daemon is running. If it is running, this also prints the
number of cached secret values.

```sh
via daemon clear
```

Clears cached secret values and registered allowlists. The daemon remains
running. The next command invocation registers its configured refs again and
repopulates the cache on demand.

```sh
via daemon stop
```

Stops the daemon. The next command that needs daemon caching auto-starts it
again.

`via daemon serve` is an internal command used by auto-start. It is hidden from
normal help output.

## Verifying Clear And Restart

Warm the daemon:

```sh
VIA_TIMING=1 via github api GET /repos/example-org/example-repo >/tmp/via.json
VIA_TIMING=1 via github api GET /repos/example-org/example-repo >/tmp/via.json
```

The second run should show `1password daemon resolve cache=hit` timing lines.

Clear cached data without stopping the daemon:

```sh
via daemon clear
via daemon status
VIA_TIMING=1 via github api GET /repos/example-org/example-repo >/tmp/via.json
```

After `clear`, `status` should show zero cached secrets. The next command should
re-register refs and repopulate the cache.

Stop and auto-start:

```sh
via daemon stop
via daemon status
VIA_TIMING=1 via github api GET /repos/example-org/example-repo >/tmp/via.json
via daemon status
```

After `stop`, `status` should report that the daemon is stopped. The next
command that needs daemon caching starts it again.

## Security Notes

The daemon reduces repeated `op read` latency and avoids writing resolved
1Password secrets to disk. Plaintext secrets still pass between the daemon and
the requesting `via` process over the local socket because `via` needs the value
to build headers, generate GitHub App tokens, or inject delegated command
environment variables.

The socket permissions restrict access to the same local user. This is intended
to protect against other users on the machine, not against malicious processes
already running as the same user. The registration handshake protects normal
operation by preventing arbitrary unregistered refs from being resolved through
the hot path.

If you run agents that should not share secret access, run them under separate
OS users, containers, or another sandbox with a separate `via` config and
1Password session. A process running as the same OS user can usually talk to the
daemon socket directly, read local files available to that user, or invoke
`op read` directly if the 1Password CLI session allows it. For untrusted
same-user work, set `cache = "off"` or stop the daemon with `via daemon stop`
before handing over execution.
