# Release Signing

`via` releases publish platform archives plus release verification metadata:

- `SHA256SUMS`
- `SHA256SUMS.minisig`, when `VIA_MINISIGN_SECRET_KEY` is configured

The install script downloads the selected archive, verifies `SHA256SUMS.minisig`
with minisign using the public key pinned in `scripts/install-release.sh`, then
verifies the selected archive against `SHA256SUMS`.

## Signing Key Setup

Generate the release signing key once:

```sh
minisign -G -W -s via-release-minisign.key -p via-release-minisign.pub
```

Store the private key as a GitHub Actions secret:

```sh
gh secret set VIA_MINISIGN_SECRET_KEY < via-release-minisign.key
```

Keep `via-release-minisign.key` private. Commit or publish only the public key.
The public key file contains a comment line and a key line beginning with `RW`.
Use that `RW...` key as the installer trust anchor.

The release public key is pinned as `default_minisign_public_key` in
`scripts/install-release.sh`. For testing or key rotation, callers can override
that key explicitly:

```sh
VERIFY=required VIA_RELEASE_MINISIGN_PUBLIC_KEY=RW... ./scripts/install-release.sh
```

## Verification Modes

`scripts/install-release.sh` accepts:

- `VERIFY=auto`, the default. Verify checksums when available and signatures
  when `minisign` plus a public key are available.
- `VERIFY=required`. Fail unless `SHA256SUMS`, `SHA256SUMS.minisig`,
  `minisign`, and a trusted public key are all available.
- `VERIFY=off`. Skip release verification.

Older releases may not have `SHA256SUMS` or `SHA256SUMS.minisig`, so use
`VERIFY=required` only for releases built after this signing flow is enabled.
