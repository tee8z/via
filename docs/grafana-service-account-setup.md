# Grafana Service Account Setup

Use this guide to give `via` access to the Grafana HTTP API.
The local config stores a 1Password reference, not the service account token.

Grafana accepts the token in this header:

```text
Authorization: Bearer <service-account-token>
```

This header uses `via`'s existing `bearer` REST authentication.
No Grafana-specific authentication code is required.

## Before You Start

Identify each Grafana environment that the workflow can access.
Use a separate service account and token for each environment.

Confirm that you can create service accounts in each Grafana organization.

## 1. Create A Grafana Service Account

Create the service account in the Grafana user interface:

1. Open **Administration**.
2. Open **Users and access**.
3. Open **Service accounts**.
4. Add a service account.
5. Add a token to the new service account.

Grant the smallest permissions that cover the workflow.
For read-only datasource queries, start with the `Viewer` organization role
when that role is acceptable.

Grafana Enterprise and Grafana Cloud support tighter datasource permissions or
role-based access control (RBAC). The account must have query access to each
target datasource unique identifier (UID).

## 2. Store The Token In 1Password

Create a 1Password item in a vault that `via` can read.
This guide uses these example names:

| 1Password location | Example name |
| --- | --- |
| Vault | `Private` |
| Item | `Example Grafana` |
| Field | `service-account-token` |

The reference has this form:

```text
op://Private/Example Grafana/service-account-token
```

> **WARNING:** Do not store the token in `via.toml`, shell history, source
> control, issue comments, or prompts. An exposed token grants its service
> account permissions until the token expires or is revoked.

## 3. Configure `via`

Keep staging and production in separate services.
Use separate 1Password items or fields for their tokens.

Add this configuration to `via.toml`:

```toml
version = 1

[providers.onepassword]
type = "1password"

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

Omitting `cache` uses the platform default. Unix-like systems use the daemon,
while Windows resolves each 1Password reference directly.

### Grafana Cloud URLs

For Grafana Cloud, set each `base_url` to its stack URL:

```toml
[services.grafana-staging.commands.api]
base_url = "https://example-staging.grafana.net"

[services.grafana-prod.commands.api]
base_url = "https://example.grafana.net"
```

### Multi-Organization Instances

If a request must target one Grafana organization, add its organization header:

```toml
[services.grafana-prod.commands.api.headers]
Accept = "application/json"
X-Grafana-Org-Id = "2"
```

## 4. Verify The Setup

Authenticate to 1Password and inspect both services:

```sh
via login
via config doctor grafana-staging
via config doctor grafana-prod
via capabilities
```

A healthy doctor result confirms that `via` can resolve each token reference.

Make a small authenticated request to each environment:

```sh
via grafana-staging api /api/org
via grafana-prod api /api/org
```

Successful responses confirm the base URLs, tokens, and organization access.

## 5. Inspect Grafana Data Sources

Use these read requests to find and inspect datasource UIDs:

```sh
via grafana-staging api /api/datasources
via grafana-prod api /api/datasources
via grafana-staging api /api/datasources/uid/<datasource-uid>
via grafana-prod api /api/datasources/uid/<datasource-uid>
via grafana-staging api /api/datasources/uid/<datasource-uid>/health
via grafana-prod api /api/datasources/uid/<datasource-uid>/health
```

## 6. Query A Data Source

Send backend datasource queries to this endpoint:

```text
POST /api/ds/query
```

The JSON body uses Grafana's datasource query model.
Each query identifies a datasource UID and adds plugin-specific properties.

For an exact payload, run the query in Explore or a panel.
Then inspect the `/api/ds/query` request in browser Developer Tools.

### Loki Example

Create `loki-query.json`:

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

Run the query against the intended environment:

```sh
via grafana-staging api POST /api/ds/query --json @loki-query.json
via grafana-prod api POST /api/ds/query --json @loki-query.json
```

### PostgreSQL Example

Create `postgres-query.json`:

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

Run the query against the intended environment:

```sh
via grafana-staging api POST /api/ds/query --json @postgres-query.json
via grafana-prod api POST /api/ds/query --json @postgres-query.json
```

> **CAUTION:** Keep SQL read-only unless the datasource and database account
> intentionally permit writes. Grafana and the database enforce query access;
> `via` protects only the Grafana service token.

## API Compatibility Notes

Grafana is moving legacy `/api` endpoints to newer `/apis` endpoints.
The legacy endpoints remain available, but Grafana no longer updates them.
Grafana still documents `/api/ds/query` for backend datasource queries.

A Grafana service account token authenticates to Grafana.
It does not necessarily authenticate directly to Loki or another datasource.
Using `/api/ds/query` lets Grafana apply the configured datasource credentials.
Direct Loki HTTP API access requires a separate setup.

## Troubleshooting

### Grafana Returns `401 Unauthorized`

Confirm that the token belongs to the configured Grafana environment.
Confirm that the token has not expired or been revoked.
Update the 1Password field after rotating the token.

### Grafana Returns `403 Access Denied`

Inspect the service account and datasource permissions.
Confirm that the account can query the selected datasource UID.
For multi-organization instances, confirm `X-Grafana-Org-Id`.

### Grafana Returns `404 Not Found`

Confirm the service `base_url` and datasource UID.
Confirm that the target datasource plugin is available in that environment.

### `/api/ds/query` Returns `400 Bad Request`

Compare the JSON body with a working browser request.
Check the content type, datasource UID, time range, and plugin-specific fields.

### Doctor Cannot Resolve A Token

Confirm the vault, item, and field in the `op://` reference.
Run `via login`, then run the doctor command again.

## References

- Grafana HTTP API authentication: <https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/>
- Grafana service accounts: <https://grafana.com/docs/grafana/latest/administration/service-accounts/>
- Grafana datasource HTTP API: <https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/data_source/>
- Grafana datasource permissions: <https://grafana.com/docs/grafana/latest/permissions/datasource_permissions/>
