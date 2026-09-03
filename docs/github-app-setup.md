# GitHub App Setup

Use this guide to give `via` GitHub REST API access to one repository.
The local config stores only 1Password references.

`via` reads two values from 1Password:

- A JSON field that contains GitHub App metadata.
- A file attachment that contains the private key.

At runtime, `via` signs a JSON Web Token (JWT) and requests an installation
access token. Do not create or store an installation token yourself.

## Before You Start

Confirm that you can create a GitHub App for the target organization or user.
Confirm that you can install the app on the target repository.

You also need a working `via` and 1Password CLI setup.

## 1. Create The GitHub App

Create the app under the organization or user that must own it.

Use these starting values:

| Setting | Suggested value |
| --- | --- |
| App name | `Via GitHub Broker` |
| Homepage URL | `https://github.com/<owner>/<via-repo>` |
| Webhook | Disabled |
| Only on this account | Enabled when installation must stay in one account |

Grant only the repository permissions that the workflow needs.
For a blog publishing workflow, start with these permissions:

| Repository permission | Access |
| --- | --- |
| Contents | Read and write |
| Pull requests | Read and write |
| Metadata | Read-only |

Do not grant Issues, Actions, Deployments, Checks, or Administration without a
workflow requirement.

## 2. Install The App

Open the app installation page:

```text
https://github.com/apps/<app-slug>/installations/new
```

Select the target organization. Then select only the required repository:

```text
Only select repositories
example-org/example-repo
```

After installation, select **Configure** for the installed app.
The browser URL has this form:

```text
https://github.com/organizations/example-org/settings/installations/<installation_id>
```

Record the trailing number as `installation_id`.

## 3. Generate The Private Key

Generate a private key in the GitHub App settings.
GitHub downloads the key as a `.pem` file.

> **WARNING:** Store the downloaded PEM in 1Password immediately. Do not put
> the key in `via.toml`, source control, shell history, issue comments, or
> prompts. Exposed key material can let another party authenticate as the app.

## 4. Store The Credential In 1Password

Create an item in a vault that `via` can read.
This guide uses these example names:

| 1Password location | Example name | Content |
| --- | --- | --- |
| Vault | `Private` | Credential vault |
| Item | `Example GitHub App` | GitHub App credential |
| Field | `metadata` | Non-secret app metadata |
| Attachment | `github-app.private-key.pem` | Downloaded private key |

Put this JSON in the `metadata` field:

```json
{
  "type": "github_app",
  "app_id": 123456,
  "client_id": "Iv1.xxxxxxxxxxxxxxxxxxxx",
  "installation_id": 12345678
}
```

Use these field rules:

- Set `app_id` to the numeric App ID from the GitHub App settings. `via` uses it
  as the JWT issuer.
- Set `installation_id` to the number from the installation URL.
- Keep `client_id` only if the metadata is useful elsewhere. `via` does not use it.
- Store the private key as the `.pem` attachment, not in the JSON field.

The resulting references have this form:

```text
op://Private/Example GitHub App/metadata
op://Private/Example GitHub App/github-app.private-key.pem
```

## 5. Configure `via`

Add this service to `via.toml`:

```toml
version = 1

[providers.onepassword]
type = "1password"

[services.github]
description = "GitHub API access"
provider = "onepassword"

[services.github.secrets]
app = "op://Private/Example GitHub App/metadata"
private_key = "op://Private/Example GitHub App/github-app.private-key.pem"

[services.github.commands.api]
description = "Call the GitHub REST API with a GitHub App installation token."
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

On macOS and Linux, `cache = "daemon"` is the default.
The local daemon keeps resolved 1Password secrets in memory for a short
time-to-live (TTL). Normal use does not require a separate service installation.

Set `cache = "off"` to make each invocation call `op read` directly.
On Windows, the default is `off` until the daemon has a named-pipe backend.

See [Daemon Architecture](daemon-architecture.md) for daemon commands and
verification steps.

### Understand Installation-Token Caching

GitHub App installation tokens use a separate disk cache. via selects the
first available location:

1. `$VIA_CACHE_DIR/github-app`
2. `$XDG_CACHE_HOME/via/github-app`
3. `$HOME/.cache/via/github-app`

Without one of those base directories, via exchanges a new token instead of
caching it on disk. On Unix, via sets the cache directory to mode `0700` and
token files to mode `0600`.

`via daemon clear` does not clear this disk cache. via stops reusing each token
near the expiry that GitHub returned. Revoke the installation access token
through GitHub when access must end immediately.

For GitHub Enterprise Server, replace `base_url` with the server REST API URL.
The URL usually has this form:

```text
https://<hostname>/api/v3
```

## 6. Verify The Setup

Authenticate to 1Password and inspect the service:

```sh
via login
via config doctor github
via capabilities
```

A healthy doctor result confirms that `via` can read both values.
It also confirms that the metadata and private key form a valid credential.

Test the configured repository:

```sh
via github api GET /repos/example-org/example-repo
```

A successful request returns the repository response from GitHub.
The request also verifies the app installation and repository permissions.

## Troubleshooting

### Doctor Reports An Invalid GitHub App Credential

Confirm these auth settings:

```text
type = "github_app"
credential = "<the secret name pointing to the 1Password metadata field>"
private_key = "<the secret name pointing to the 1Password PEM attachment>"
```

Confirm that the JSON contains `type`, numeric `app_id`, and `installation_id`.
Confirm that `private_key` selects the PEM attachment.
Then run `via config doctor github` again.

### GitHub Rejects The Token Exchange

Confirm that `app_id` belongs to the app that generated the private key.
Confirm that `installation_id` identifies the selected app installation.
Generate a replacement key if the configured PEM was revoked.

### GitHub Returns A Permission Error

Confirm that the app is installed on `example-org/example-repo`.
Confirm that the app has the repository permission required by the request.
Update only the missing permission, then approve the installation change.

## References

- [Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
- [Managing private keys for GitHub Apps](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
- [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
