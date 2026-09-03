# Release Signing

`via` releases include archive checksums and can include a minisign signature.
The installer uses this metadata before it installs an archive.

Each release publishes:

- Platform archives.
- `SHA256SUMS` for all archives.
- `SHA256SUMS.minisig` when `VIA_MINISIGN_SECRET_KEY` is configured.

The installer verifies the signature on `SHA256SUMS` first. It then compares
the selected archive with its SHA-256 digest.

## Create The Signing Key

Generate one release signing key pair:

```sh
minisign -G -W -s via-release-minisign.key -p via-release-minisign.pub
```

WARNING: Keep `via-release-minisign.key` private. Anyone with this key can sign
release metadata that the configured public key trusts.

Store the complete private key as a GitHub Actions secret:

```sh
gh secret set VIA_MINISIGN_SECRET_KEY < via-release-minisign.key
```

Commit or publish only `via-release-minisign.pub`. Its key line starts with
`RW`; use that complete line as the installer trust anchor.

The release workflow creates `SHA256SUMS` for all `.tar.gz` and `.zip`
archives. When the secret exists, it signs that file with minisign.

## Configure The Installer Trust Anchor

The installer pins the release public key in
`scripts/install-release.sh` as `default_minisign_public_key`.

For a test or key rotation, override the pinned key for one invocation:

```sh
VERIFY=required VIA_RELEASE_MINISIGN_PUBLIC_KEY=RW... ./scripts/install-release.sh
```

Use the complete `RW...` key. A required verification must succeed before you
replace the pinned key.

## Select A Verification Mode

Set `VERIFY` when you run `scripts/install-release.sh`:

| Mode | Behavior |
| --- | --- |
| `auto` | Default. Verify checksums when present. Verify their signature when the signature, `minisign`, and a public key are available. |
| `required` | Stop unless checksums, a signature, `minisign`, and a trusted public key are available and valid. |
| `off` | Skip signature and checksum verification. |

In `auto` mode, a missing `SHA256SUMS` file permits installation without
verification. A missing signature permits checksum-only verification.

If a signature exists but `minisign` is unavailable, `auto` mode skips the
signature and still checks the archive digest.

`required` mode is the recommended mode for automation that must fail closed:

```sh
VERIFY=required ./scripts/install-release.sh
```

Older releases might not include `SHA256SUMS` or
`SHA256SUMS.minisig`. `VERIFY=required` rejects those releases.

## Troubleshoot From Installer Output

| Result | Meaning | Corrective action |
| --- | --- | --- |
| `release does not provide SHA256SUMS` | Required checksum metadata is absent. | Select a signed release or use `auto` only when unverified installation is acceptable. |
| `release does not provide SHA256SUMS.minisig` | Required signature metadata is absent. | Select a signed release or repair the release workflow. |
| `release signature verification requires minisign` | The host cannot run `minisign`. | Install minisign and rerun the installer. |
| Minisign reports an invalid signature | The checksum file does not match the trusted signer. | Stop the installation and verify the release source and public key. |
| `SHA256SUMS does not contain <archive>` | The checksum manifest omits the selected asset. | Repair and republish the release metadata. |
| `checksum mismatch for <archive>` | The downloaded archive differs from the manifest. | Stop the installation and investigate the release asset. |

Do not use `VERIFY=off` to bypass an unexpected signature or checksum failure.
