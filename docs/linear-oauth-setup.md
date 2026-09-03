# Linear OAuth App-Actor Setup

Use this guide to give `via` app-actor access to the Linear API.
The local config stores one 1Password reference, not OAuth tokens or secrets.

OAuth authentication requires the local via daemon and therefore works only
on Unix-like platforms. It is unavailable on Windows.

`via` uses two Linear endpoints for different purposes:

| Purpose | Method and endpoint |
| --- | --- |
| Mint or refresh an OAuth token | `POST https://api.linear.app/oauth/token` |
| Query or change workspace data | `POST https://api.linear.app/graphql` |

OAuth token requests use `application/x-www-form-urlencoded` content.
Workspace requests use Linear's GraphQL API.

The capability uses `mode = "rest"` because `via` sends HTTP requests.
The mode name does not change Linear's GraphQL workspace API.

## Before You Start

Confirm that you can create and configure a Linear OAuth2 application.
Choose whether the workflow must act as the app or as a specific user.

Use client credentials for an app actor.
Use the refresh-token fallback only for a user actor.

## 1. Create The Linear OAuth App

Create an OAuth2 application in Linear.
Enable client credentials tokens in the application settings.

Client credentials produce an app-actor token.
Actions performed with that token appear as the app, not a user.

Grant the smallest scope set that covers the workflow:

| Scope | Use |
| --- | --- |
| `read` | Read workspace data |
| `write` | Write workspace data |
| `issues:create` | Create issues and their attachments |
| `comments:create` | Create issue comments |
| `timeSchedule:write` | Create or change time schedules |
| `admin` | Access admin-level endpoints |

Do not grant `admin` unless the workflow requires admin-level access.

## 2. Store The App Credential In 1Password

Create a 1Password item in a vault that `via` can read.
This guide uses these example names:

| 1Password location | Example name |
| --- | --- |
| Vault | `Private` |
| Item | `Example Linear OAuth` |
| Field | `credential` |

Store this JSON in the `credential` field:

```json
{
  "type": "service_oauth",
  "token_url": "https://api.linear.app/oauth/token",
  "grant_type": "client_credentials",
  "client_id": "lin_client_id",
  "client_secret": "lin_client_secret",
  "scope": "read,issues:create"
}
```

The reference has this form:

```text
op://Private/Example Linear OAuth/credential
```

> **WARNING:** Keep `client_secret` and all OAuth tokens out of `via.toml`,
> source control, shell history, issue comments, and prompts. Exposed material
> can grant the configured Linear access.

This client-credentials bundle does not contain a refresh token.
The local `via` daemon mints and caches the access token in memory.
If the daemon loses that token, it can mint another from the same credential.

Linear allows multiple active client-credentials tokens when their scopes match.
Requesting a token with different scopes revokes existing app-actor tokens.
If Linear returns `401 Unauthorized`, `via` retries once with a fresh token.

## 3. Configure `via`

Add this service to `via.toml`:

```toml
version = 1

[providers.onepassword]
type = "1password"
cache = "daemon"

[services.linear]
description = "Linear app-actor API access through OAuth"
hint = "via linear api POST /graphql --json '{\"query\":\"{ viewer { id name } }\"}'"
provider = "onepassword"

[services.linear.secrets]
oauth = "op://Private/Example Linear OAuth/credential"

[services.linear.commands.api]
description = "Call configured Linear API endpoints with an app-actor OAuth bearer token."
mode = "rest"
base_url = "https://api.linear.app"
asset_hosts = ["uploads.linear.app"]
method_default = "GET"

[services.linear.commands.api.auth]
type = "oauth"
credential = "oauth"
```

The `oauth` auth type performs these operations:

1. Resolve the credential bundle from 1Password.
2. Ask the local `via` daemon for an access token.
3. Mint or reuse a token through Linear's OAuth endpoint.
4. Send the API request with `Authorization: Bearer <access-token>`.

The `asset_hosts` setting permits absolute URLs only for
`uploads.linear.app`. `via` can send the same OAuth bearer token to this
allowlisted host without exposing the token to the caller.

## 4. Verify The App Actor

Authenticate to 1Password and inspect the service:

```sh
via login
via config doctor linear
via capabilities
```

A healthy doctor result confirms that `via` can read and parse the OAuth bundle.

Query the authenticated actor:

```sh
via linear api POST /graphql --json '{"query":"{ viewer { id name } }"}'
```

A successful response contains the Linear app actor in `data.viewer`.
Also inspect the response for a GraphQL `errors` array.

## 5. Download Linear Files

Linear stores private uploads on `uploads.linear.app`.
The configured `asset_hosts` entry allows authenticated downloads from that
exact host.

Write a private upload to a local file:

```sh
via linear api GET "https://uploads.linear.app/<workspace>/<object>/<file>" --output /tmp/linear-upload.bin
```

Linear can also return signed temporary file URLs in GraphQL responses.
Add this static header when a workflow needs those URLs:

```toml
[services.linear.commands.api.headers]
"public-file-urls-expire-in" = "300"
```

The value is the signature lifetime in seconds.
Download a signed URL with an unauthenticated client outside this capability
to avoid forwarding the OAuth bearer token. The configured via capability
adds OAuth authentication to every request, including allowlisted asset URLs.

## User-Actor Fallback

Use this fallback only when the workflow must act as a specific user.
Complete Linear's authorization-code flow outside `via`.

Store the resulting refresh-token bundle in the same 1Password field:

```json
{
  "type": "service_oauth",
  "token_url": "https://api.linear.app/oauth/token",
  "grant_type": "refresh_token",
  "client_id": "lin_client_id",
  "client_secret": "lin_client_secret",
  "refresh_token": "linear_refresh_token"
}
```

Linear rotates refresh tokens.
`via` keeps the newest access and refresh tokens in daemon memory.
It does not write OAuth tokens to disk.

The daemon loses this state after a clear, stop, idle timeout, restart, or
machine reboot. If Linear already rotated the stored refresh token, complete
the authorization flow again. Then update the 1Password field.

## Troubleshooting

### Doctor Reports An Invalid OAuth Bundle

Confirm that the JSON contains these fields:

```text
type = "service_oauth"
token_url = "https://api.linear.app/oauth/token"
grant_type = "client_credentials" or "refresh_token"
client_id = "<Linear OAuth client ID>"
```

For client credentials, also confirm `client_secret` and `scope`.
For a refresh grant, also confirm `refresh_token`.
Then run `via config doctor linear` again.

### Linear Continues To Return `401 Unauthorized`

`via` already retries one request with a fresh token.
If the retry fails, confirm the client ID and client secret in 1Password.
Check whether the client secret or requested scopes changed.

### GraphQL Returns HTTP `200` With An `errors` Array

Treat the operation as incomplete or failed.
Read each GraphQL error and correct the query, variables, or app scopes.

### `via` Rejects A Linear Upload URL

Confirm that the URL host is exactly `uploads.linear.app`.
Confirm that `asset_hosts = ["uploads.linear.app"]` is in the command config.

### A Signed File URL No Longer Works

Request the GraphQL data again to get a new signed URL.
Increase `public-file-urls-expire-in` only when the workflow needs more time.

## References

- [Linear OAuth 2.0 authentication](https://linear.app/developers/oauth-2-0-authentication)
- [Linear GraphQL API](https://linear.app/developers/graphql)
- [Linear file storage authentication](https://linear.app/developers/file-storage-authentication)
