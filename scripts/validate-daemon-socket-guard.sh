#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "${VIA_BIN:-}" ]]; then
  via_bin="$VIA_BIN"
elif [[ -x "$repo_root/target/release/via" ]]; then
  via_bin="$repo_root/target/release/via"
elif [[ -x "$repo_root/target/debug/via" ]]; then
  via_bin="$repo_root/target/debug/via"
else
  via_bin="via"
fi

if [[ -n "${VIA_DAEMON_SOCKET:-}" ]]; then
  socket_path="$VIA_DAEMON_SOCKET"
elif [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
  socket_path="$XDG_RUNTIME_DIR/via/daemon.sock"
else
  uid="${UID:-$(id -u 2>/dev/null || printf unknown)}"
  socket_path="/tmp/via-$uid/daemon.sock"
fi

if [[ ! -S "$socket_path" ]]; then
  cat >&2 <<EOF
via daemon socket is not running at:
  $socket_path

Start it with a via command that uses daemon caching, then rerun this script.
Use VIA_DAEMON_SOCKET to point at a non-default socket.
EOF
  exit 2
fi

if ! "$via_bin" daemon status >/dev/null; then
  cat >&2 <<EOF
via could not talk to the daemon with:
  $via_bin daemon status

Set VIA_BIN to the same via binary that started the daemon.
EOF
  exit 2
fi

echo "via binary: $via_bin"
echo "daemon socket: $socket_path"
echo "probing daemon as a raw non-via socket client"

python3 - "$socket_path" <<'PY'
import json
import socket
import sys

socket_path = sys.argv[1]

probes = [
    ("status", {"type": "status"}),
    (
        "unregistered resolve",
        {
            "type": "resolve",
            "config_hash": "via-daemon-socket-guard-probe",
            "ref_id": "probe",
            "ttl_seconds": 1,
        },
    ),
]


def request(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(socket_path)
        client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        return client.recv(65536).decode("utf-8", "replace").strip()


failed = False
for name, payload in probes:
    try:
        raw = request(payload)
    except OSError as error:
        print(f"FAIL {name}: raw client could not complete probe: {error}", file=sys.stderr)
        failed = True
        continue

    try:
        response = json.loads(raw)
    except json.JSONDecodeError:
        print(f"FAIL {name}: daemon returned non-JSON response: {raw!r}", file=sys.stderr)
        failed = True
        continue

    error = str(response.get("error", ""))
    rejected_by_guard = (
        response.get("ok") is False
        and "client verification failed" in error
        and "executable other than via" in error
        and "value" not in response
    )
    if rejected_by_guard:
        print(f"PASS {name}: raw client rejected by executable guard")
        continue

    print(
        f"FAIL {name}: raw client reached daemon protocol or received unexpected response: {response}",
        file=sys.stderr,
    )
    failed = True

if failed:
    sys.exit(1)
PY

"$via_bin" daemon status >/dev/null

echo "PASS daemon still responds to via after raw-client probes"
