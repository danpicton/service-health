# Local container and runtime contract

The `linux/amd64` image contains Python 3.14.10, the application modules, and
Trivy 0.76.2. Its Python base is selected by OCI index digest; the Trivy release
tarball is checked against a fixed SHA-256 during the build. It contains no
catalog, registry snapshot, SQLite database, scan cache, kubeconfig, or report.
The Docker build context admits only `Dockerfile` and `src/service_health/*.py`.
Review the Dockerfile and `.dockerignore` before building after a packaging
change. BuildKit is required for `ADD --checksum`.

```sh
docker build --platform linux/amd64 -t service-health:local .
python tests/container_smoke.py service-health:local
```

The smoke test creates a disposable named volume, injects one synthetic cached
service with network disabled, starts the HTTP process bound to a random
localhost port, checks liveness, summary JSON, Homepage JSON, and both findings
pages, and removes its container and volume. It also checks the packaged Trivy
binary and prints image bytes and a point-in-time memory reading when the local
container runtime supports them. It neither calls Kubernetes nor scans an image.

## Persistent paths and processes

Mount `/var/lib/service-health` for the SQLite database and its collection and
inventory lock files.
Mount `/var/cache/service-health` for Trivy vulnerability databases, image
layers, and other scanner cache files. Both are writable by UID/GID 65532. The
image starts as that unprivileged user, serves port 8080, and defaults to
`--db /var/lib/service-health/state.db --host 0.0.0.0 --port 8080`. Supply
the two paths as persistent writable volumes in deployment. Mount `/tmp` as a
writable tmpfs if using a read-only root filesystem; scanner report handling
uses temporary files. Keep external reports, if used, on a separate read-only
mount. The scanner does not prune its cache automatically, so monitor disk use
and set a retention/quota policy.

The same image runs either the HTTP process (default command) or collection
commands. The server only reads cached evidence on requests. A scheduled worker
needs a cached inventory and a non-secret runtime catalog:

```sh
docker volume create service-health-state
docker volume create service-health-cache
docker run --rm --name service-health-web --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount type=volume,src=service-health-state,dst=/var/lib/service-health \
  --mount type=volume,src=service-health-cache,dst=/var/cache/service-health \
  --publish 127.0.0.1:8080:8080 service-health:local
```

For a local worker after inventory has been populated, add a bind mount for a
**generic, non-secret** catalog and override the image command:

```sh
docker run --rm --name service-health-worker --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount type=volume,src=service-health-state,dst=/var/lib/service-health \
  --mount type=volume,src=service-health-cache,dst=/var/cache/service-health \
  --mount type=bind,src="$(pwd)/examples/inventory-catalog.json",dst=/etc/service-health/catalog.json,readonly \
  service-health:local --scheduled --db /var/lib/service-health/state.db \
  --catalog /etc/service-health/catalog.json \
  --trivy-cache /var/cache/service-health/trivy
```

The checked-in catalog is synthetic and cannot discover real workloads. The
operator supplies the actual service registry snapshot and component catalog
at runtime, then runs `--inventory-once` with read-only Kubernetes access as
described in [inventory](inventory.md). The collector needs network access to
its configured public providers and Trivy DB/remote image registries. For a
local, unpullable image, mount externally supplied reports read-only and pass
`--external-reports`; see [scanner reports](scanner.md). Do not put credentials,
catalogs, or reports in image build arguments or the build context.

The server and worker share one SQLite volume. Collection uses a lock to avoid
overlapping cycles. Run one scheduler per database. The worker can be restarted
independently while the server retains the last cached result. The HTTP process
does not launch collection. Startup with an empty database is ready to serve but
reports an empty, unassessed cache; see [README](../README.md#empty-cache-contract).

## Resource and integration notes

The operator built and smoke-tested the `linux/amd64` image on a container-capable
workstation. The image measured **303,129,933 bytes**, and the running smoke
container reported **22.93 MB** of memory at one point in time. The restricted
development sandbox could not create a rootless container namespace; these
measurements come from the operator's workstation. Initial deployment sizing
estimates are 128 MiB for the
idle Python server and 1 GiB for the scanner worker, with 2 GiB of scanner
cache disk space; adjust from measured workload and Trivy DB behavior. A
full image scan can use more memory and disk than the idle process. The scanner
limits concurrent image scans to two by default and rejects reports above 20
MiB, but the cache needs operator-managed retention.

The infrastructure repository owns the selected immutable image digest,
Deployment/Service, PVC, runtime files, read-only RBAC, network policy, ingress,
backup, and Homepage wiring. The app does not need pod exec, a runtime socket,
privileged mounts, or cluster write access. For first deployment, mount empty
state/cache volumes, start the server, verify `/healthz` and empty-cache
`/readyz`, run inventory, then start the scheduled worker and verify cached
summary, a service Homepage route, findings, and check times. For an upgrade,
back up the SQLite volume first, change the pinned image digest deliberately,
restart server and worker, verify both endpoints and a completed collector
cycle, and retain the prior image. Reverting an image alone does not reverse a
database migration; restore a compatible backup if a schema change requires
rollback.

The pinned Python base and Trivy archive should be refreshed deliberately for
security updates, followed by a rebuilt image and smoke test. Upstream Trivy
release metadata documents the [0.76.2 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2),
and the [official Python image](https://hub.docker.com/_/python) provides the
base runtime. This image build is local only; publishing and deployment are
separate, operator-authorized steps.
