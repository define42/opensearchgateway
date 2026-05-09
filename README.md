# OpenSearchGateway

[![codecov](https://codecov.io/gh/define42/OpenSearchGateway/graph/badge.svg?token=FUNK8UEA7N)](https://codecov.io/gh/define42/OpenSearchGateway)
[![Go Report Card](https://goreportcard.com/badge/github.com/define42/opensearchgateway)](https://goreportcard.com/report/github.com/define42/opensearchgateway)
[![Build Status](https://github.com/define42/opensearchgateway/actions/workflows/build.yml/badge.svg)](https://github.com/define42/opensearchgateway/actions/)

OpenSearchGateway is an opinionated tenancy and ingest gateway for OpenSearch.
It turns LDAP group membership into OpenSearch Security roles, OpenSearch Dashboards tenants, and namespace-scoped ingest permissions.

The central idea is that users do not get arbitrary OpenSearch access.
They are forced into one or more namespace tenants, and every namespace comes from LDAP.
A namespace controls:

- which Dashboards tenant the user can open
- which index patterns the user can see
- which ingest paths the user can write to
- which OpenSearch Security role the gateway creates for the user

For example, LDAP group `team10_r` gives read-only access to the `team10` namespace.
LDAP group `team10_rw` gives read and write access to `team10`, including ingest paths such as `POST /ingest/team10-hello`.

## Opinionated Access Model

LDAP groups are the source of truth.
The gateway reads group names from `LDAP_GROUP_ATTRIBUTE`, keeps only groups matching `LDAP_GROUP_PREFIX`, and maps suffixes to permissions:

| LDAP group | Namespace | Dashboards tenant | OpenSearch index pattern | Ingest |
| --- | --- | --- | --- | --- |
| `<namespace>_r` | `<namespace>` | tenant access | read on `<namespace>-*` | no |
| `<namespace>_rd` | `<namespace>` | tenant access | read and delete on `<namespace>-*` | no |
| `<namespace>_rw` | `<namespace>` | tenant access | read and write on `<namespace>-*` | yes |
| `<namespace>_rwd` | `<namespace>` | tenant access | read, write, and delete on `<namespace>-*` | yes |

When a user logs in, the gateway provisions the matching OpenSearch resources:

- Dashboards tenant named exactly like the namespace, such as `team10`
- Dashboards data view for the namespace, such as `team10-*`
- OpenSearch Security role named `gateway_<namespace>_<mode>`
- OpenSearch internal user for the login session
- built-in `kibana_user` role plus the generated namespace roles

Multiple groups mean multiple namespaces.
A user in `team10_r` and `team20_rw` can browse both tenants, can write to `team20-*`, and cannot write to `team10-*`.
If two namespaces could match the same ingest path, the longest namespace wins, so `team10_rw` is preferred over `team_rw` for `/ingest/team10-hello`.

Duplicate groups for the same namespace collapse to the strongest permission.
For example, `team10_r` plus `team10_rw` becomes write-capable access to `team10`.

## Opinionated Ingest Model

All writes use the same route shape:

```text
POST /ingest/<namespace>-<index>
```

The namespace prefix is not decoration.
It is the authorization boundary.
The gateway accepts an ingest request only when the authenticated user has write-capable LDAP access for the namespace at the front of the path.

Every document must contain top-level UTC `event_time`.
That timestamp controls the daily rollover alias:

```text
<namespace>-<index>-YYYYMMDD-rollover
```

For:

```text
POST /ingest/team10-hello
event_time = 2024-12-30T10:11:12Z
```

the gateway creates or uses:

```text
tenant:        team10
data view:     team10-hello-*
write alias:   team10-hello-20241230-rollover
backing index: team10-hello-20241230-rollover-000001
```

## How It Works

At startup, the gateway bootstraps shared OpenSearch resources:

- ISM policy `generic-rollover-100m`
- index template `gateway-rollover-template`
- template index pattern `*-*-rollover-*`
- `event_time` mapping as an OpenSearch `date`
- hard-coded template shard settings of `2` shards and `2` replicas

At login, the gateway:

1. binds to LDAP with the submitted credentials
2. looks up the LDAP user and group memberships
3. maps matching LDAP groups to namespace access
4. upserts one OpenSearch Security role per namespace and mode
5. ensures a Dashboards tenant and namespace-level data view
6. creates or replaces an OpenSearch internal user for that username
7. generates a random per-login OpenSearch password for that internal user
8. stores an encrypted, signed gateway session cookie
9. proxies `/dashboards` with the generated internal-user Basic auth header

The LDAP password is not stored in OpenSearch. The internal OpenSearch user gets a generated password for the current login session.

At ingest time, the gateway:

1. validates the route as `/ingest/<namespace>-<index>`
2. authenticates with Basic auth or an existing gateway session
3. checks that the user can write to the namespace prefix
4. requires `Content-Type: application/json`
5. decodes exactly one JSON object
6. validates `event_time`
7. ensures the Dashboards tenant and data view
8. ensures the daily rollover alias exists
9. repairs ISM policy attachment on existing write aliases when needed
10. indexes the document through the alias

## HTTP API

### `GET /`

Redirects to `/login`.

### `GET /login`

Renders the login page. If the request already has a valid session cookie, it redirects to `/dashboards/app/home`.

### `POST /login`

Authenticates against LDAP, provisions OpenSearch and Dashboards resources, sets the session cookie, and redirects to Dashboards.

Common responses:

| Status | Meaning |
| --- | --- |
| `303` | login succeeded |
| `401` | missing or invalid credentials |
| `403` | LDAP user is valid but has no gateway namespace access, or the matching OpenSearch internal user is reserved or hidden |
| `502` | LDAP, OpenSearch, or Dashboards provisioning failed |

### `POST /logout`

Clears the session cookie and forgets this instance's cached ingest credentials for the logged-in user.

### `/dashboards`

### `/dashboards/*`

Reverse proxies OpenSearch Dashboards. A valid gateway session is required. All Dashboards HTTP methods are passed through to the upstream service.

The bundled Dashboards config uses `server.basePath: /dashboards`, which matches this proxy route.

### `GET /demo`

Serves a small browser form for sending test ingest requests.

### `POST /ingest/<namespace>-<index>`

Writes one JSON document to OpenSearch.

Authentication can be either:

- HTTP Basic auth with LDAP credentials
- a gateway session cookie from `POST /login`

If an `Authorization` header is present, it must be valid Basic auth. If no `Authorization` header is present, the gateway falls back to the session cookie.

Successful Basic-auth LDAP lookups are cached in memory for 5 minutes. Cache entries are keyed by a SHA-256 hash of `username:password`, and active callers refresh the TTL on cache hits.

## Ingest Contract

Valid paths look like this:

```text
/ingest/team10-hello
/ingest/team10-hello/
```

Invalid paths include:

```text
/ingest
/ingest/
/ingest/team10/hello
/ingest/Team10-hello
```

The path segment after `/ingest/` must:

- start with a lowercase letter or digit
- contain only lowercase letters, digits, `-`, and `_`
- include the namespace prefix followed by `-`
- stay within OpenSearch's 255-byte index name limit after alias expansion

The request body must be exactly one JSON object:

```json
{
  "event_time": "2024-12-30T10:11:12Z",
  "message": "payment received",
  "amount": 123.45
}
```

`event_time` rules:

- required
- string only
- valid RFC3339
- UTC only
- must end in `Z`

The gateway normalizes `event_time` back to canonical UTC RFC3339 before indexing.

Successful writes return `201 Created`:

```json
{
  "result": "created",
  "write_alias": "team10-hello-20241230-rollover",
  "document_id": "abc123",
  "bootstrapped": true
}
```

Common ingest errors:

| Status | Meaning |
| --- | --- |
| `400` | bad path, malformed JSON, missing `event_time`, invalid timestamp, or generated name too long |
| `401` | missing or invalid LDAP credentials/session |
| `403` | user does not have write access to the target namespace |
| `405` | unsupported method |
| `415` | request is not `application/json` |
| `502` | LDAP, Dashboards, OpenSearch bootstrap, or OpenSearch indexing failed |

## Namespace Access

LDAP groups drive all namespace permissions.

The gateway reads group values from `LDAP_GROUP_ATTRIBUTE` and extracts the leading `cn=` or `ou=` value when the group value is a DN.
Only group names that start with `LDAP_GROUP_PREFIX` are considered. The default prefix is `team`.

Recognized suffixes:

| Group suffix | OpenSearch access | Ingest writes |
| --- | --- | --- |
| `<namespace>_r` | read | no |
| `<namespace>_rd` | read, delete | no |
| `<namespace>_rw` | read, write | yes |
| `<namespace>_rwd` | read, write, delete | yes |

Namespace names may contain lowercase letters, digits, and `_`. They may not contain `-`, because `-` separates the namespace from the index family in ingest paths.

Examples:

- `team10_r` can browse the `team10` tenant but cannot ingest.
- `team10_rw` can browse `team10` and ingest to paths such as `/ingest/team10-hello`.
- `team10_rw` cannot ingest to `/ingest/team20-hello`.
- A user in both `team10_rw` and `team20_rw` can write to both namespaces.
- If memberships overlap, such as `team_rw` and `team10_rw`, the longest matching namespace wins for ingest paths.

Duplicate memberships for the same namespace are merged to the strongest access.

## OpenSearch And Dashboards Resources

The gateway creates deterministic resource names.

For:

```text
POST /ingest/team10-hello
event_time = 2024-12-30T10:11:12Z
```

it uses:

| Resource | Name |
| --- | --- |
| Tenant | `team10` |
| Data view ID | `gateway-index-pattern-team10-hello` |
| Data view title | `team10-hello-*` |
| Time field | `event_time` |
| Write alias | `team10-hello-20241230-rollover` |
| First backing index | `team10-hello-20241230-rollover-000001` |

New backing indices are created with:

- alias `is_write_index: true`
- `plugins.index_state_management.rollover_alias`
- `plugins.index_state_management.policy_id`

For aliases that already exist, the gateway resolves the concrete write backing index and calls OpenSearch's ISM add-policy API for that index.
The add-policy response is decoded, and `failures: true` is treated as a failed repair rather than cached as success.

## Configuration

Configuration is environment based.

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | Gateway bind address |
| `OPENSEARCH_URL` | `https://localhost:9200` | OpenSearch API URL |
| `OPENSEARCH_USERNAME` | `admin` | OpenSearch admin/API username |
| `OPENSEARCH_PASSWORD` | `OPENSEARCH_ADMIN_PASSWORD` or empty | OpenSearch admin/API password |
| `OPENSEARCH_ADMIN_PASSWORD` | empty | Convenience fallback used by Docker Compose and password defaults |
| `OPENSEARCH_SKIP_TLS_VERIFY` | `false` | Disable OpenSearch TLS verification |
| `DASHBOARDS_URL` | `http://localhost:5601` | OpenSearch Dashboards URL |
| `DASHBOARDS_USERNAME` | `OPENSEARCH_USERNAME` or `admin` | Dashboards API username |
| `DASHBOARDS_PASSWORD` | `OPENSEARCH_PASSWORD`, `OPENSEARCH_ADMIN_PASSWORD`, or empty | Dashboards API password |
| `DASHBOARDS_TENANT` | `admin_tenant` | Default tenant for generic Dashboards API calls |
| `LDAP_URL` | `ldaps://ldap:389` | LDAP server URL |
| `LDAP_BASE_DN` | `dc=glauth,dc=com` | LDAP search base |
| `LDAP_USER_FILTER` | `(mail=%s)` | User lookup filter; `%s` receives the login email |
| `LDAP_GROUP_ATTRIBUTE` | `memberOf` | Attribute containing group memberships |
| `LDAP_GROUP_PREFIX` | `team` | Prefix required for gateway-managed groups |
| `LDAP_USER_DOMAIN` | `@example.com` | Domain appended to usernames without `@` before LDAP bind/search |
| `LDAP_STARTTLS` | `false` | Start TLS after connecting to `ldap://` URLs |
| `LDAP_SKIP_TLS_VERIFY` | `true` | Disable LDAP TLS verification |

Production notes:

- Set `LDAP_SKIP_TLS_VERIFY=false` with trusted LDAP certificates.
- Set `OPENSEARCH_SKIP_TLS_VERIFY=false` outside local self-signed development.
- Run the gateway behind HTTPS so session cookies are sent with the `Secure` flag.
- The session cookie codec uses random per-process keys. Restarting the gateway invalidates existing sessions.
- Multiple gateway instances need shared cookie keys, but this repository does not currently expose shared-key configuration.
- The gateway needs OpenSearch permissions to manage ISM policies, index templates, tenants, roles, internal users, and indices.

## Local Docker Demo

The repository includes a Compose stack for trying the gateway with OpenSearch, OpenSearch Dashboards, and GLAuth:

```bash
docker compose up --build
```

Or use the make target:

```bash
make run
```

The local stack exposes:

| Service | URL |
| --- | --- |
| Gateway | `http://localhost:8080` |
| OpenSearch | `https://localhost:9200` |
| OpenSearch Dashboards | `http://localhost:5601/dashboards` |
| GLAuth LDAP | `ldaps://localhost:389` |

The local OpenSearch admin password defaults to:

```text
Cedar7!FluxOrbit29
```

Override it before starting the stack:

```bash
export OPENSEARCH_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

The bundled LDAP fixture includes users that demonstrate the permission suffixes:

| Username | Password | Groups | Result |
| --- | --- | --- | --- |
| `testuser` | `dogood` | `team1_rwd`, `team2_rw`, `team10_r` | multiple tenants with mixed permissions |
| `ingestuser` | `dogood` | `team10_rw` | can write to `team10-*` ingest targets |
| `johndoe` | `dogood` | `team10_r` | can browse `team10`, cannot ingest |

Example write using the write-capable demo user:

```bash
curl -i http://localhost:8080/ingest/team10-hello \
  -u ingestuser:dogood \
  -H 'Content-Type: application/json' \
  -d '{
    "event_time": "2024-12-30T10:11:12Z",
    "message": "hello from the gateway",
    "customer_id": 42
  }'
```

## Running Without Docker

Run directly:

```bash
go run .
```

If you are using the Compose OpenSearch, Dashboards, and LDAP services from the host, set host-facing URLs:

```bash
export OPENSEARCH_URL=https://localhost:9200
export OPENSEARCH_USERNAME=admin
export OPENSEARCH_PASSWORD='Cedar7!FluxOrbit29'
export OPENSEARCH_SKIP_TLS_VERIFY=true
export DASHBOARDS_URL=http://localhost:5601
export DASHBOARDS_USERNAME=admin
export DASHBOARDS_PASSWORD='Cedar7!FluxOrbit29'
export LDAP_URL=ldaps://localhost:389
export LISTEN_ADDR=:8080

go run .
```

## Development

Useful commands:

```bash
go test ./...
go test ./... -short
make test
make lint
make gosec
```

The LDAP integration tests use Docker for GLAuth and skip automatically when Docker is unavailable. Use `go test ./... -short` to skip Docker-backed tests explicitly.

The repository layout is intentionally small:

| Path | Purpose |
| --- | --- |
| `main.go` | startup, shared OpenSearch bootstrap, HTTP server lifecycle |
| `internal/config` | environment-backed runtime config |
| `internal/ldap` | LDAP bind/search and group-to-access mapping |
| `internal/authz` | namespace authorization semantics |
| `internal/ingest` | ingest path parsing, document validation, auth cache |
| `internal/opensearch` | OpenSearch, Security API, ISM, and Dashboards clients |
| `internal/server` | HTTP routes, login flow, sessions, Dashboards proxy |
| `internal/server/templates` | embedded login and demo pages |
| `docker-compose.yml` | local OpenSearch, Dashboards, gateway, and LDAP stack |
| `opensearch_dashboards.yml` | local Dashboards base-path and proxy header config |
| `testldap/default-config.cfg` | local LDAP users and groups |

## Limitations

- Ingest is single-document only; there is no bulk API.
- Session keys are generated at process start and are not configurable yet.
- Shard and replica counts are currently hard-coded in the gateway config.
- Dashboards resource setup is synchronous; failed tenant or data-view creation fails the ingest before writing the document.
- The service is built for namespace-prefixed index families, not arbitrary OpenSearch indexing.
