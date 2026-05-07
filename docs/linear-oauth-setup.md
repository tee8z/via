# Linear OAuth App-Actor Setup

This guide configures Linear OAuth for a via capability. The local via config contains no secret values: it points to one 1Password field that stores the OAuth client and token material.

via uses Linear's REST OAuth token endpoint:

```text
POST https://api.linear.app/oauth/token
Content-Type: application/x-www-form-urlencoded
```

via does not use GraphQL for OAuth token minting or refresh.

Linear's documented public workspace API is GraphQL. via still models the Linear command as `mode = "rest"` because it sends plain HTTP requests, but normal Linear operations are expected to call `POST /graphql`. The REST-only requirement here applies to OAuth token minting and refresh, not to Linear's workspace API shape.

## 1. Create The Linear OAuth App

Create an OAuth2 application in Linear. For coding agents and bots, enable client credentials tokens on the OAuth app so Linear issues an app-actor token instead of a user-actor token.

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

## 2. Store The Credential In 1Password

Create a 1Password item in the vault you want via to read from, for example:

```text
Vault: Private
Item: Example Linear OAuth
Field: credential
```

Store JSON like:

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
op://Private/Example Linear OAuth/credential
```

This setup does not store or require a refresh token. via asks the daemon to mint an access token from the Linear REST `/oauth/token` endpoint, then keeps that access token only in daemon memory until it expires or the daemon exits. If the daemon loses the token, via can mint another one from the same 1Password client credentials without touching Linear setup again.

Linear allows one active client-credentials token per OAuth app. If another machine or daemon mints a token for the same app and Linear returns `401 Unauthorized` for the previous token, via retries the REST request once with a freshly minted daemon token.

## 3. Optional User-Actor Fallback

Use a refresh-token credential only when the workflow must act as a specific user rather than the Linear app. Complete Linear's authorization-code flow outside via, then store JSON like:

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

Linear refresh tokens rotate. via keeps the newest access token and refresh token only in daemon memory while the daemon is running so future invocations can keep working after the original 1Password refresh token has been consumed. OAuth tokens are not written to disk. If the daemon idles out, is stopped, cleared, restarted, or the machine reboots after a refresh token has rotated, complete the Linear OAuth flow again and update the 1Password field with a fresh credential bundle.

## 4. Configure via

Use this local config shape:

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
method_default = "GET"

[services.linear.commands.api.auth]
type = "oauth"
credential = "oauth"
```

The `oauth` auth type resolves the configured credential bundle, asks the local via daemon to mint or refresh an access token through Linear's REST OAuth endpoint, then sends the request with:

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

Then make a small authenticated Linear API request:

```sh
via linear api POST /graphql --json '{"query":"{ viewer { id name } }"}'
```

This verifies that via can read the 1Password credential bundle, mint a Linear `client_credentials` token through the REST `/oauth/token` endpoint, attach it as a bearer token, and have Linear accept it as the app actor.

If doctor reports an invalid OAuth bundle, fix the JSON stored in 1Password. Do not paste OAuth tokens, client secrets, or refresh tokens into terminal output, issue comments, or prompts.
