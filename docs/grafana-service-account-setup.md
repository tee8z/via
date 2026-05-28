# Grafana Service Account Setup

This guide configures a Grafana HTTP API capability for via. The local via config contains no secret values: it points to one 1Password field that stores a Grafana service account token.

Grafana service account tokens authenticate to the Grafana HTTP API with:

```text
Authorization: Bearer <service-account-token>
```

That matches via's existing `bearer` REST auth type. No Grafana-specific auth code is needed.

## 1. Create The Grafana Service Account

In Grafana, create a service account and add a token:

1. Open Administration.
2. Open Users and access.
3. Open Service accounts.
4. Add a service account, then add a service account token.

Use the smallest permissions that cover the workflow.

For read-only datasource queries, start with a `Viewer` organization role when that is acceptable for the Grafana instance. In Grafana Enterprise or Grafana Cloud, use datasource permissions or RBAC if you need tighter access. The token must be allowed to read and query the target datasource UIDs.

## 2. Store The Token In 1Password

Create a 1Password item in the vault you want via to read from, for example:

```text
Vault: Private
Item: Example Grafana
Field: service-account-token
```

The 1Password reference should look like:

```text
op://Private/Example Grafana/service-account-token
```

Do not store the token in `via.toml`, shell history, issue comments, prompts, or checked-in files.

## 3. Configure via

Use one service per Grafana environment. Keep staging and production on separate Grafana service accounts and separate 1Password token fields:

```toml
version = 1

[providers.onepassword]
type = "1password"
cache = "daemon"

[services.grafana-staging]
description = "Staging Grafana HTTP API access through a service account token"
hint = "via grafana-staging api /api/org"
provider = "onepassword"

[services.grafana-staging.secrets]
token = "op://Private/Example Grafana Staging/service-account-token"

[services.grafana-staging.commands.api]
description = "Call the staging Grafana HTTP API with a service account token."
mode = "rest"
base_url = "https://staging.grafana.example.com"
method_default = "GET"

[services.grafana-staging.commands.api.auth]
type = "bearer"
secret = "token"

[services.grafana-staging.commands.api.headers]
Accept = "application/json"

[services.grafana-prod]
description = "Production Grafana HTTP API access through a service account token"
hint = "via grafana-prod api /api/org"
provider = "onepassword"

[services.grafana-prod.secrets]
token = "op://Private/Example Grafana Prod/service-account-token"

[services.grafana-prod.commands.api]
description = "Call the production Grafana HTTP API with a service account token."
mode = "rest"
base_url = "https://grafana.example.com"
method_default = "GET"

[services.grafana-prod.commands.api.auth]
type = "bearer"
secret = "token"

[services.grafana-prod.commands.api.headers]
Accept = "application/json"
```

For Grafana Cloud, set each `base_url` to that environment's stack URL, for example:

```toml
[services.grafana-staging.commands.api]
base_url = "https://example-staging.grafana.net"

[services.grafana-prod.commands.api]
base_url = "https://example.grafana.net"
```

If you need to address a specific Grafana organization in a multi-org instance, add the optional organization header:

```toml
[services.grafana-prod.commands.api.headers]
Accept = "application/json"
X-Grafana-Org-Id = "2"
```

## 4. Verify

Check local setup:

```sh
via login
via config doctor grafana-staging
via config doctor grafana-prod
via capabilities
```

Then make a small authenticated Grafana API request to each environment:

```sh
via grafana-staging api /api/org
via grafana-prod api /api/org
```

This verifies that via can read the 1Password token, attach it as a bearer token, and have Grafana accept it.

## 5. Query Grafana Data Sources

Grafana exposes datasource management endpoints such as:

```sh
via grafana-staging api /api/datasources
via grafana-prod api /api/datasources
via grafana-staging api /api/datasources/uid/<datasource-uid>
via grafana-prod api /api/datasources/uid/<datasource-uid>
via grafana-staging api /api/datasources/uid/<datasource-uid>/health
via grafana-prod api /api/datasources/uid/<datasource-uid>/health
```

To query backend data sources through Grafana, call:

```text
POST /api/ds/query
```

The body is Grafana's datasource query model. Each query includes the target datasource UID and datasource-specific properties. Grafana's docs recommend using the browser Developer Tools network panel against Explore or a panel query to capture the exact `/api/ds/query` payload for a specific datasource plugin.

### Loki Example

Create a local request body such as `loki-query.json`:

```json
{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "uid": "loki_uid"
      },
      "expr": "{job=\"api\"} |= \"error\"",
      "queryType": "range",
      "maxLines": 100,
      "intervalMs": 1000,
      "maxDataPoints": 1000
    }
  ],
  "from": "now-15m",
  "to": "now"
}
```

Run:

```sh
via grafana-staging api POST /api/ds/query --json @loki-query.json
via grafana-prod api POST /api/ds/query --json @loki-query.json
```

### PostgreSQL Example

Create a local request body such as `postgres-query.json`:

```json
{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "uid": "postgres_uid"
      },
      "format": "table",
      "rawSql": "select now() as time, current_database() as database_name",
      "rawQuery": true,
      "intervalMs": 1000,
      "maxDataPoints": 100
    }
  ],
  "from": "now-5m",
  "to": "now"
}
```

Run:

```sh
via grafana-staging api POST /api/ds/query --json @postgres-query.json
via grafana-prod api POST /api/ds/query --json @postgres-query.json
```

Keep SQL read-only unless the Grafana datasource and database account are intentionally scoped for writes. via protects the Grafana service token, but Grafana and the underlying datasource still decide what the query is allowed to do.

## Notes

- Grafana is deprecating legacy `/api` endpoints in favor of newer `/apis` endpoints, but the datasource query endpoint is still documented under the legacy API and remains available.
- Direct Loki HTTP API access is a different setup. A Grafana service account token authenticates to Grafana, not necessarily to Loki itself. Querying Loki through `/api/ds/query` lets Grafana use the configured Loki datasource and its permissions.
- If Grafana returns `403`, inspect the service account permissions and datasource permissions. The token needs permission to query the selected datasource UID.

## References

- Grafana HTTP API authentication: <https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/>
- Grafana service accounts: <https://grafana.com/docs/grafana/latest/administration/service-accounts/>
- Grafana datasource HTTP API: <https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/data_source/>
- Grafana datasource permissions: <https://grafana.com/docs/grafana/latest/permissions/datasource_permissions/>
