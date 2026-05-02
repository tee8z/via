#!/usr/bin/env bash
set -euo pipefail

repo="tee8z/via"
version="${VERSION:-latest}"
install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
verify="${VERIFY:-auto}"
default_minisign_public_key="RWQXl6EUeJDLanxitNIsR9gTrHZOPicg4+a2V1tZF8l8dBargQRKt/wq"
release_minisign_public_key="${VIA_RELEASE_MINISIGN_PUBLIC_KEY:-$default_minisign_public_key}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

need curl
need install
need tar
need mktemp
need awk

case "$verify" in
  auto | required | off) ;;
  *)
    echo "error: VERIFY must be auto, required, or off" >&2
    exit 1
    ;;
esac

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="macos" ;;
  *)
    echo "error: unsupported OS: $(uname -s)" >&2
    echo "Download a release asset manually from https://github.com/$repo/releases" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *)
    echo "error: unsupported architecture: $(uname -m)" >&2
    echo "Download a release asset manually from https://github.com/$repo/releases" >&2
    exit 1
    ;;
esac

asset="via-$os-$arch.tar.gz"
if [[ "$version" == "latest" ]]; then
  release_url="https://github.com/$repo/releases/latest/download"
else
  release_url="https://github.com/$repo/releases/download/$version"
fi
url="$release_url/$asset"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "Downloading $url"
curl -fsSL "$url" -o "$tmpdir/$asset"

sha256_file="$tmpdir/SHA256SUMS"
signature_file="$tmpdir/SHA256SUMS.minisig"

download_optional() {
  local name="$1"
  local target="$2"

  curl -fsSL "$release_url/$name" -o "$target" 2>/dev/null
}

sha256_digest() {
  local file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo "error: required command not found: sha256sum or shasum" >&2
    exit 1
  fi
}

verify_checksum() {
  local expected
  local actual

  expected="$(awk -v asset="$asset" '$2 == asset { print $1 }' "$sha256_file")"
  if [[ -z "$expected" ]]; then
    echo "error: SHA256SUMS does not contain $asset" >&2
    exit 1
  fi

  actual="$(sha256_digest "$tmpdir/$asset")"
  if [[ "$actual" != "$expected" ]]; then
    echo "error: checksum mismatch for $asset" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi

  echo "Verified SHA256 checksum for $asset"
}

verify_signature() {
  if [[ -z "$release_minisign_public_key" ]]; then
    if [[ "$verify" == "required" ]]; then
      echo "error: release signature verification requires VIA_RELEASE_MINISIGN_PUBLIC_KEY" >&2
      exit 1
    fi

    echo "Release signature verification skipped: no minisign public key configured" >&2
    return
  fi

  if ! command -v minisign >/dev/null 2>&1; then
    if [[ "$verify" == "required" ]]; then
      echo "error: release signature verification requires minisign" >&2
      exit 1
    fi

    echo "Release signature verification skipped: minisign is not installed" >&2
    return
  fi

  minisign -Vm "$sha256_file" -x "$signature_file" -P "$release_minisign_public_key"
}

verify_release() {
  if [[ "$verify" == "off" ]]; then
    echo "Release verification disabled by VERIFY=off" >&2
    return
  fi

  if ! download_optional SHA256SUMS "$sha256_file"; then
    if [[ "$verify" == "required" ]]; then
      echo "error: release does not provide SHA256SUMS" >&2
      exit 1
    fi

    echo "Release checksums are not available; continuing without checksum verification" >&2
    return
  fi

  if download_optional SHA256SUMS.minisig "$signature_file"; then
    verify_signature
  elif [[ "$verify" == "required" ]]; then
    echo "error: release does not provide SHA256SUMS.minisig" >&2
    exit 1
  else
    echo "Release signature is not available; verifying checksum only" >&2
  fi

  verify_checksum
}

verify_release

tar -xzf "$tmpdir/$asset" -C "$tmpdir"
if [[ ! -x "$tmpdir/via" ]]; then
  echo "error: release archive did not contain executable via binary" >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$tmpdir/via" "$install_dir/via"

echo "Installed via to $install_dir/via"
if ! command -v via >/dev/null 2>&1; then
  cat <<EOF

Add this directory to PATH if it is not already there:
  export PATH="$install_dir:\$PATH"
EOF
fi

if "$install_dir/via" --version >/dev/null 2>&1; then
  "$install_dir/via" --version
elif "$install_dir/via" version >/dev/null 2>&1; then
  "$install_dir/via" version
else
  "$install_dir/via" --help >/dev/null
  echo "Verified via starts successfully. Try: via --help"
fi
