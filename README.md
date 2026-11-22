# Service Health

For the infrastructure agent, start with the [integration handoff](docs/integration.md):
it names the three runtime roles, minimal pod/node RBAC, Homepage and ingress
mapping, persistent paths, first-deployment checks, and upgrade/rollback limits.
The checked-in configuration and RBAC examples are synthetic; infrastructure
owns the real runtime files and deployment.

This application serves a persistent SQLite cache through a read-only HTTP API and
simple findings page. One-shot inventory and release commands populate the cache;
offline tests inject Kubernetes objects, release responses, and scanner reports.
Structured upstream OSV advisory collection is available for configured components.
Service and overall aggregation now reconcile those cached results across every
mapped component; see [aggregate signals](docs/aggregation.md). The recurring
collector and expiry policy are in [freshness](docs/freshness.md).

The inventory slice now resolves active registry services to explicit regular and
init container mappings, including deployed image IDs, digests, and platform when
the Kubernetes API provides them. See [inventory input and collection](docs/inventory.md)
for the non-secret catalog, one-shot in-cluster command, and required read-only RBAC.
Release checks use configured public GitHub releases and reliable annotated
application versions. See [release checks](docs/releases.md). Same-tag image
checks compare the deployed platform manifest with the current tag; see
[image checks](docs/images.md). Scheduled or one-shot digest-bound Trivy checks
and externally supplied reports for local images are described in
[scanner checks](docs/scanner.md). See [upstream advisory checks](docs/advisories.md) for structured package mappings, one-shot collection, and coverage limits.

The recurring worker can optionally read a dedicated GitHub token from
`--github-token-file PATH`; anonymous release checks remain supported. The
token file is operator-managed at runtime and must not enter the repository,
catalog, image, SQLite backup, or HTTP process. See the
[v0.1.0 collection migration](docs/integration.md#v010-collection-repair-migration)
for the schema change, private-registry limits, and worker sizing checks.

## Local development

Python 3.14 is pinned in `.python-version`. Runtime dependencies are Python's
standard library and locked in `uv.lock`. Ruff is pinned separately in
`requirements-dev.txt`. Use `uv` 0.6.9 or newer to create the environment:

```sh
uv sync --locked
uv pip install -r requirements-dev.txt
PYTHONPATH=src uv run --no-sync python -m service_health --db /tmp/service-health.db
PYTHONPATH=src uv run --no-sync python -m unittest discover -s tests -v
uv run --no-sync ruff check src tests
uv run --no-sync ruff format --check src tests
```

By default the server binds `127.0.0.1:8080`. Use `--host` and `--port` to change
the listener. The SQLite path is created on startup and must be on persistent storage
in deployment. This source tree uses four-space indentation, snake_case names for
modules/functions/fields, and Ruff's formatter and E/F/I lint rules.

## Container

Build the `linux/amd64` image and run the synthetic local container smoke test:

```sh
docker build --platform linux/amd64 -t service-health:local .
python tests/container_smoke.py service-health:local
```

See [container runtime and integration](docs/container.md) for the exact
server/worker commands, persistent SQLite and Trivy cache mounts, runtime
catalogs, resource expectations, and first-deployment/upgrade checks. The image
includes only generic application code and Trivy; real catalogs and any
operator-managed credentials are supplied at runtime.

Pull requests run tests, style checks, and an amd64 image build. Explicit stable
version tags prepare a GHCR release with SBOM and provenance; see
[image release workflow](docs/releases-image.md) for package visibility,
digest-pinned deployment, and release prerequisites. No image is published by
local development commands.

## Empty-cache contract

Readiness means the SQLite state opened and the HTTP process can answer requests;
it does **not** mean an assessment has run. At initial startup, `/readyz` returns
HTTP 200 with `{"status":"ready","cache_state":"empty"}`. `/healthz` returns
HTTP 200 with `{"status":"alive"}`.

`/api/v1/summary` reports `cache_state: "empty"`, `checked_at: null`,
`service_count: 0`, `update_status: "unknown"`,
`security_status: "incomplete coverage"`, and `coverage_complete: false`.
`/api/v1/services` contains an empty `services` array with the same cache state
and null check time. A missing service path returns HTTP 404. The root page says
that no collection has completed. An empty result does not mean there are no
active services or no findings.

After a fixture collection succeeds, the service list is cached in SQLite and
survives restart. Fields with no evidence remain null or unknown. HTTP requests
only read the cache and never invoke the collection provider. The fixture seam is
`service_health.collection.collect_once(store, provider, clock)`; the provider
returns non-secret service dictionaries, and a failed provider leaves the previous
snapshot intact. The offline test sends HTTP request bytes through the real request handler
without binding a socket, so it can run in environments that prohibit loopback.

Initial routes: `/healthz`, `/readyz`, `/api/v1/summary`, `/api/v1/services`,
`/api/v1/services/{id}`, `/api/v1/services/{id}/homepage`, `/`, and
`/services/{id}`. The Homepage representation uses null versions until known,
`unknown` update status, `incomplete coverage` security status, and explicit
coverage state. Counts of zero on an unassessed service are placeholders and must
be read with `coverage_complete: false`; they do not assert a clean scan.
