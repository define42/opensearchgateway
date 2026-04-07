# OpenSearchGateway

OpenSearchGateway is a small Go web server that sits in front of an OpenSearch cluster and turns simple JSON HTTP writes into rollover-friendly OpenSearch documents.

It is designed for a very specific ingestion model:

- clients send JSON to `POST /ingest/<index>`
- every document must contain a top-level `event_time`
- the gateway derives a daily write alias from that timestamp
- OpenSearch writes go through rollover aliases and backing indices
- OpenSearch Dashboards gets a per-index tenant and a matching data view automatically

In short, this project gives you a thin HTTP ingest layer in front of OpenSearch, with just enough bootstrap logic to make daily rollover-based indexing and Dashboards discovery work without manual setup for each new index family.

## What It Does

When the gateway starts, it bootstraps shared cluster resources:

- ensures the ISM policy `generic-rollover-100m` exists
- ensures a shared index template exists for rollover backing indices
- starts an HTTP server on `LISTEN_ADDR` (default `:8080`)

When a client sends a document to `POST /ingest/<index>`, the gateway:

1. validates the path and index name
2. requires `Content-Type: application/json`
3. parses the body as a single JSON object
4. requires top-level `event_time` as a UTC RFC3339 string ending in `Z`
5. derives the write alias as:

```text
<index>-YYYYMMDD-rollover
```

6. ensures an OpenSearch Security tenant named exactly `<index>`
7. ensures an OpenSearch Dashboards data view inside that tenant with pattern:

```text
<index>-*
```

8. checks whether the daily write alias exists
9. if missing, creates the first backing index:

```text
<index>-YYYYMMDD-rollover-000001
```

10. attaches the rollover alias and ISM policy
11. indexes the document through the alias
12. returns a compact JSON response describing the write

## Why This Exists

This gateway is useful when you want:

- a very simple HTTP ingest interface instead of exposing OpenSearch directly
- deterministic daily alias naming based on an event timestamp
- rollover-compatible index creation
- automatic Dashboards setup for each logical index family
- a lightweight developer stack you can run locally with Docker Compose

It is especially handy for internal tools, demos, prototypes, and ingestion pipelines where producers should not need to know OpenSearch index template, alias, tenant, or Dashboards setup details.

## HTTP Interface

### `GET /`

Serves a small demo page where you can:

- enter an index name
- paste a JSON document
- submit it directly to the gateway from the browser

### `POST /ingest/<index>`

Primary ingest endpoint.

Accepted path examples:

```text
/ingest/orders
/ingest/orders/
```

Rejected path examples:

```text
/ingest/
/ingest/orders/extra
/ingest/Orders
```

Index names must:

- start with a lowercase letter or digit
- only contain lowercase letters, digits, `-`, and `_`

The generated alias and first backing index must also fit within OpenSearch index naming limits.

### Required document shape

The request body must be a single JSON object with a top-level `event_time`.

Example:

```json
{
  "event_time": "2024-12-30T10:11:12Z",
  "message": "hello",
  "customer_id": 42,
  "status": "received"
}
```

Rules for `event_time`:

- must be present
- must be a string
- must be valid RFC3339
- must be UTC and end in `Z`

The gateway preserves the rest of the JSON body and normalizes `event_time` back into canonical UTC RFC3339 before indexing.

### Success response

Successful writes return `201 Created`.

Example:

```json
{
  "result": "created",
  "write_alias": "orders-20241230-rollover",
  "document_id": "abc123",
  "bootstrapped": true
}
```

### Error behavior

- `400` for request validation errors
- `405` for wrong HTTP methods
- `415` for non-JSON requests
- `502` when OpenSearch or Dashboards setup/indexing fails

The gateway is strict about Dashboards setup for indexed families. If tenant or data-view creation fails, the request fails before any document is written.

## OpenSearch Naming Model

For an ingest request like:

```text
POST /ingest/orders
```

with:

```json
{
  "event_time": "2024-12-30T10:11:12Z"
}
```

the gateway produces:

- tenant: `orders`
- Dashboards data view pattern: `orders-*`
- write alias: `orders-20241230-rollover`
- first backing index: `orders-20241230-rollover-000001`

Writes always go through the alias, not directly to the backing index.

## Dashboards Behavior

For every new index family, the gateway creates:

- an OpenSearch Security tenant named exactly after the index family
- an OpenSearch Dashboards data view inside that tenant

That means:

- `orders` data goes with the `orders` tenant
- the Dashboards data view is created with title `orders-*`
- the time field is set to `event_time`

This keeps data-view organization aligned with the ingest namespace.

Current behavior is admin-focused:

- the gateway creates tenants and data views using the configured admin credentials
- it does not create roles or role mappings for non-admin users

## Local Development Stack

The repository includes a full local stack in [docker-compose.yml](/home/define42/git/OpenSearchGateway/docker-compose.yml):

- OpenSearch
- OpenSearch Dashboards
- OpenSearchGateway

### Start the stack

```bash
docker compose up --build
```

Or with the included [makefile](/home/define42/git/OpenSearchGateway/makefile):

```bash
make
```

The compose stack exposes:

- OpenSearch: `https://localhost:9200`
- OpenSearch Dashboards: `http://localhost:5601`
- OpenSearchGateway: `http://localhost:8080`

Default admin password in the local stack:

```text
Cedar7!FluxOrbit29
```

You can override it with:

```bash
export OPENSEARCH_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

## Running the Gateway Without Docker

Run it directly with Go:

```bash
go run .
```

Useful environment variables:

- `LISTEN_ADDR`
- `OPENSEARCH_URL`
- `OPENSEARCH_USERNAME`
- `OPENSEARCH_PASSWORD`
- `DASHBOARDS_URL`
- `DASHBOARDS_USERNAME`
- `DASHBOARDS_PASSWORD`
- `DASHBOARDS_TENANT`

Current defaults in the code:

- `LISTEN_ADDR=:8080`
- `OPENSEARCH_URL=https://localhost:9200`
- `DASHBOARDS_URL=http://localhost:5601`
- username defaults to `admin`

Note that per-index data views are created in tenants named after the index, so `DASHBOARDS_TENANT` is not used for those auto-created views. It remains available as the default tenant value for generic Dashboards requests.

## Example Ingest

```bash
curl -X POST http://localhost:8080/ingest/orders \
  -H 'Content-Type: application/json' \
  -d '{
    "event_time": "2024-12-30T10:11:12Z",
    "message": "order received",
    "customer_id": 42
  }'
```

## Project Files

- [main.go](/home/define42/git/OpenSearchGateway/main.go): gateway server, bootstrap logic, OpenSearch client helpers, demo page
- [main_test.go](/home/define42/git/OpenSearchGateway/main_test.go): request flow and bootstrap tests
- [docker-compose.yml](/home/define42/git/OpenSearchGateway/docker-compose.yml): local OpenSearch, Dashboards, and gateway stack
- [Dockerfile](/home/define42/git/OpenSearchGateway/Dockerfile): container image for the gateway
- [makefile](/home/define42/git/OpenSearchGateway/makefile): local compose convenience target

## Development Notes

- the HTTP client disables TLS verification for OpenSearch, which is convenient for local development but not production-safe
- the gateway does not include authentication or authorization on its ingest endpoint
- batching is not implemented; each request indexes one JSON document
- the index template and ISM policy are shared, global bootstrap resources
- the tenant and data-view setup is demand-driven and happens per index family on first ingest

## Testing

Run the test suite with:

```bash
go test ./...
```

## Summary

This project is a narrow, purpose-built ingest gateway for OpenSearch. It accepts JSON over HTTP, validates and routes documents by `event_time`, creates rollover-friendly daily aliases and backing indices, and automatically prepares matching Dashboards tenants and data views so newly ingested data is easier to discover.
