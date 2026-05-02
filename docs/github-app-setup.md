# GitHub App Setup

This guide configures a GitHub App credential for a single repository. The local via config contains no secret values: it points to one 1Password field for GitHub App metadata and one 1Password file attachment for the private key.

## 1. Create The GitHub App

Create the app under the organization or user that should own it.

Suggested fields:

```text
App name: Via GitHub Broker
Homepage URL: https://github.com/<owner>/<via-repo>
Webhook: disabled
Only on this account: enabled, if the app should only install under one org
```

For repository permissions, start with the smallest set the workflow needs. For the blog publishing workflow:

```text
Contents: Read and write
Pull requests: Read and write
Metadata: Read-only
```

Do not add Issues, Actions, Deployments, Checks, or Administration unless a configured workflow actually needs them.

## 2. Install The App On The Repository

Open the app install page:

```text
https://github.com/apps/<app-slug>/installations/new
```

Choose the organization, then select:

```text
Only select repositories
example-org/example-repo
```

After installation, click Configure for the installed app. The browser URL should look like:

```text
https://github.com/organizations/example-org/settings/installations/<installation_id>
```

Save the trailing number as `installation_id`.

## 3. Create The Private Key

In the GitHub App settings, generate a private key. Treat the downloaded `.pem` as a secret.

Do not store the private key in the via config file. Put it in 1Password.

## 4. Store The Credential In 1Password

Create a 1Password item in the vault you want via to read from, for example:

```text
Vault: Private
Item: Example GitHub App
Field: metadata
Attachment: github-app.private-key.pem
```

Put only non-secret metadata in the `metadata` field:

```json
{
  "type": "github_app",
  "app_id": 123456,
  "client_id": "Iv1.xxxxxxxxxxxxxxxxxxxx",
  "installation_id": 12345678
}
```

Notes:

- `app_id` is the numeric App ID shown in the GitHub App settings. via uses this as the JWT issuer.
- `client_id` is optional metadata. It is safe to include, but via does not use it for the token exchange.
- `installation_id` is the trailing number from the installation Configure URL.
- The private key must be stored as the `.pem` file attachment, not inside the JSON field.
- Do not store the short-lived GitHub installation token. via mints it at runtime.

The 1Password references should look like:

```text
op://Private/Example GitHub App/metadata
op://Private/Example GitHub App/github-app.private-key.pem
```

## 5. Configure via

Use this local config shape:

```toml
version = 1

[providers.onepassword]
type = "1password"
cache = "daemon"

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

`cache = "daemon"` is the default on macOS and Linux and keeps resolved 1Password secrets in a local memory-only daemon for a short TTL. There is no separate service to install. Set `cache = "off"` if you want every invocation to call `op read` directly. On Windows, via defaults to `cache = "off"` until the daemon has a named-pipe backend. See [daemon-architecture.md](daemon-architecture.md) for the daemon flow, commands, and verification steps.

For GitHub Enterprise Server, use that server's REST API base URL instead, usually:

```text
https://<hostname>/api/v3
```

## 6. Verify

Check local setup:

```sh
via config doctor github
via capabilities
```

Test GitHub API access:

```sh
via github api GET /repos/example-org/example-repo
```

If the request fails, first confirm:

```text
base_url = "https://api.github.com"
type = "github_app"
credential = "<the secret name pointing to the 1Password metadata field>"
private_key = "<the secret name pointing to the 1Password PEM attachment>"
```
