# Linear OAuth Setup

This guide configures Linear OAuth for a via REST capability. The local via config contains no secret values: it points to one 1Password field that stores the OAuth client and token material.

via uses Linear's REST OAuth token endpoint:

```text
POST https://api.linear.app/oauth/token
Content-Type: application/x-www-form-urlencoded
```

via does not use GraphQL for OAuth token refresh.

## 1. Create The Linear OAuth App

Create an OAuth2 application in Linear and configure the callback URL used by your app or setup script.

Choose the smallest scope set the workflow needs. Linear supports scopes such as:

```text
read
write
issues:create
comments:create
timeSchedule:write
admin
```

Avoid `admin` unless the configured workflow actually needs admin-level API access.

## 2. Get The Initial OAuth Token

Complete Linear's authorization-code flow outside via. The authorization URL uses:

```text
https://linear.app/oauth/authorize
```

Exchange the returned code using Linear's REST token endpoint and URL-encoded form data:

```text
POST https://api.linear.app/oauth/token
grant_type=authorization_code
code=<authorization-code>
redirect_uri=<same-redirect-uri>
client_id=<client-id>
client_secret=<client-secret>
```

The response includes a short-lived `access_token` and a rotating `refresh_token`. Store the refresh token in 1Password as described below; do not store it in `via.toml`.

For server-to-server app-actor access, Linear also supports `grant_type=client_credentials` if that grant is enabled on the OAuth app. That flow uses `client_id`, `client_secret`, and `scope`, and does not return a refresh token.

## 3. Store The Credential In 1Password

Create a 1Password item in the vault you want via to read from, for example:

```text
Vault: Private
Item: Linear OAuth
Field: credential
```

For a refresh-token grant, store JSON like:

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

For a client-credentials grant, store JSON like:

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

The 1Password reference should look like:

```text
op://Private/Linear OAuth/credential
```

Linear refresh tokens rotate. via keeps the newest access token and refresh token only in daemon memory while the daemon is running so future invocations can keep working after the original 1Password refresh token has been consumed. OAuth tokens are not written to disk. If the daemon idles out, is stopped, cleared, restarted, or the machine reboots after a refresh token has rotated, complete the Linear OAuth flow again and update the 1Password field with a fresh credential bundle.

## 4. Configure via

Use this local config shape:

```toml
version = 1

[providers.onepassword]
type = "1password"
cache = "daemon"

[services.linear]
description = "Linear API access through OAuth"
provider = "onepassword"

[services.linear.secrets]
oauth = "op://Private/Linear OAuth/credential"

[services.linear.commands.api]
description = "Call configured Linear API endpoints with an OAuth bearer token."
mode = "rest"
base_url = "https://api.linear.app"
method_default = "GET"

[services.linear.commands.api.auth]
type = "oauth"
credential = "oauth"
```

The `oauth` auth type resolves the configured credential bundle, asks the local via daemon to refresh or mint an access token through Linear's REST OAuth endpoint, then sends the request with:

```text
Authorization: Bearer <access-token>
```

## 5. Verify

Check local setup:

```sh
via login
via config doctor linear
via capabilities
```

If doctor reports an invalid OAuth bundle, fix the JSON stored in 1Password. Do not paste OAuth tokens, client secrets, or refresh tokens into terminal output, issue comments, or prompts.
