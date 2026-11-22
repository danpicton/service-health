# Same-tag image checks

Run this one-shot check after inventory has populated the SQLite cache:

```sh
PYTHONPATH=src python -m service_health --images-once --db /var/lib/service-health/state.db
```

The collector uses each observed image reference, running `sha256` digest, and
node platform from the cached inventory. It queries the image's public OCI
registry over HTTPS with a 10-second request timeout. Anonymous Bearer
challenges are supported. It compares the platform manifest behind the current
tag with the platform manifest behind the running digest. An OCI index digest
and its matching platform manifest digest can differ while the image is still
up to date. A changed platform manifest is reported as `image rebuild available`.

`image_status` is independent of application `update_status`. A rebuild makes
no claim about a newer application version or a security fix. Service and
component image status aggregate deployment results: an available rebuild
takes precedence, then `check failed`, `unknown`, and `up to date`.
`image_coverage_complete` is false if any deployment cannot be compared.
Homepage JSON exposes the service image status, checked time, candidate platform
digest, coverage, and stale state. Detail JSON and pages expose each deployment's
running and resolved platform digests, the current tag's platform digest, and
any error or unknown reason. On a registry failure, prior candidate evidence is
retained and marked stale.

A digest-only pin has no mutable tag to compare and reports `unknown`. Missing
running digests or platforms also report `unknown`. Registry errors, inaccessible
running digests, unsupported manifest types, and ambiguous platform variants
report `check failed`; they never establish a rebuild. For multiple replicas or
components, the flat candidate digest is null because a single digest would be
misleading. The per-deployment values remain in detail JSON. The registry
client currently supports public anonymous pulls only; private registry
authentication is future work. Collection is one-shot; recurring scheduling
and freshness expiry are later slices. HTTP requests only read cached SQLite.
