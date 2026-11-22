# Inventory input and collection

The runtime registry snapshot and component catalog are non-secret JSON files mounted
at runtime. `examples/active-registry.json` and `examples/inventory-catalog.json`
show their shape with fictional services. Infrastructure owns the real files and
must generate the registry snapshot from active entries in its `services.yml`.
Each registry item has a stable `id`, display `name`, and explicit `active` boolean.
Inactive entries are omitted from results. Every active ID must have exactly one
catalog entry with at least one component. A missing mapping rejects the whole
cycle and leaves the previous SQLite snapshot intact.

Each component selector gives an exact namespace, one or more pod labels, container
name, and `kind` (`regular` or `init`). Label values are matched exactly. Give each
separately assessed container its own component; this includes sidecars and init
containers. The collector uses all matching nonterminal pods, including multiple
replicas, and records container status image, raw image ID, digest, node, platform,
and pod name. A missing status, digest, node, or platform remains null/unknown.
It does not infer application versions from tags. A component may declare a
`version_annotation` only when that pod annotation is a reliable application
version; absent or disagreeing replica values yield a null current version.
For a multicomponent service, the service-level `current_version` stays null until
the update aggregation contract is defined; component versions remain visible.

Run a single cycle in a pod with read-only service account mounts and the two
JSON files:

```sh
PYTHONPATH=src python -m service_health \
  --inventory-once \
  --db /var/lib/service-health/state.db \
  --registry /etc/service-health/active-registry.json \
  --catalog /etc/service-health/inventory-catalog.json
```

The command uses the cluster service host/HTTPS port environment, service account
token, and service account CA by default. `--kube-api`, `--token-file`, and
`--ca-file` allow explicit paths. It lists pods and nodes with pagination and a
10-second request timeout, then atomically merges the observed inventory into
the cached snapshot. It does not write to Kubernetes, exec into pods, inspect
Secrets, or log the token. The HTTP process itself never calls Kubernetes.

The command fetches inventory and then takes the same nonblocking collection
lock as the recurring release and security worker. Under that lock it merges
against the latest SQLite snapshot, so a concurrent job cannot overwrite the
refresh. If the lock is busy, retry the command. An unchanged component retains
release/advisory evidence only when its verified application version, configured
source, prerelease policy, and selector match. An unchanged deployment retains
image/scan evidence only when its image reference, running digest, and platform
all match. Changed or incomplete identities drop old evidence and return to
unknown or missing coverage until the respective job runs again. A failed
refresh leaves the previous snapshot intact and marks inventory stale in JSON,
Homepage, and the findings page. Its error and last successful refresh time are
recorded in the SQLite job table and exposed under `jobs` in the summary.
Existing caches written before identity fields were introduced conservatively
lose release/advisory evidence on their first refresh. Run this command before
starting the recurring collector, then arrange regular refreshes through the
infrastructure supervisor or timer.

Minimal cluster-wide RBAC for this collector is `list` on core `pods` and `nodes`.
It needs no access to Secrets, ConfigMaps, workloads, pod logs, or
exec. A namespace-scoped Role can replace cluster-wide pod listing only if the
collector is later configured to query each selected namespace separately.

`GET /api/v1/services` and Homepage include compact `components` metadata without
finding arrays. The detail endpoint carries complete components and findings.
The Homepage endpoint retains flat status fields and `component_count`.
The root and service detail pages render each component with observed image,
running digest, platform, and known version. A
null digest means the runtime did not provide a trustworthy `sha256` image ID;
`localhost/...:latest` stays an image reference, not a verified version. Inventory
is evidence of deployment only: update and security statuses remain unknown and
incomplete until their respective collectors run.
