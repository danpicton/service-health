# Infrastructure integration handoff

## v0.1.0 collection repair migration

The next image automatically adds `jobs.state` and the credential-free
`github_cache` table to the existing SQLite database. Back up the database and
runtime catalog together before changing the pinned image digest. The HTTP and
worker roles must continue sharing the same writable database and collection
lock. No catalog format change is required. GitHub responses are shared by
case-normalized `owner/repository`, cached for six hours, and revalidated with
ETag after expiry. Rate-limit headers and `Retry-After` gate further requests
for 60 to 3,600 seconds. A failed component is retried without refreshing
successful release/image checks in the same retry series.

Anonymous GitHub access remains the default. For a higher GitHub API quota,
the operator may mount a dedicated, read-only token file **only in the worker**
and append `--github-token-file /run/secrets/service-health/github-token` to
its `--scheduled` command. The file must contain a token with only the needed
repository read permission. Do not put the token in the catalog, SQLite,
environment dump, image, HTTP container, or Homepage configuration. This token
is for GitHub releases only. Kubernetes imagePullSecrets authenticate kubelet;
they do not authenticate the application image comparison client. That client
still supports anonymous public OCI registries only. A private registry 401/403
is reported as unknown with an authentication-required reason. Trivy private
image scans may use operator-managed Trivy credentials, or a fresh validated
external report; those credentials are independent of this flag.

The worker now marks jobs running before collection, commits each validated
scan result under the existing collection lock, and marks a job interrupted
when the worker disappears. A restarted worker resumes pending scans while
retaining completed checks whose inventory identity remains unchanged. The
first security cycle needs enough time and temporary disk to assess the full
configured inventory. Measure peak `/tmp`, scanner cache use, memory, and
cycle duration to size the worker.

Follow [image releases](releases-image.md) to publish and select an immutable
image digest. Deployment is managed in the infrastructure repository.

## Ownership and runtime layout

This repository owns source, tests, the image and release workflow, API schema,
and generic examples. The infrastructure repository owns the selected image
digest, namespace, service registry entry, manifests, runtime catalog and active
registry snapshot, PVCs, backups, optional credentials, ingress, and Homepage
configuration. Add the service there on a feature branch and pull request under
that repository's rules. The operator chooses repository and GHCR package
visibility separately, authorizes publication/deployment, and performs any
secret operation personally. Keep GitHub Actions limited to building and
publishing; it needs no kubeconfig, SSH key, or deployment credential.

Use one image in three roles against the **same** persistent SQLite state:

| Role | Command after image entrypoint | Kubernetes API access |
| --- | --- | --- |
| HTTP | `--db /var/lib/service-health/state.db --host 0.0.0.0 --port 8080` | none |
| Inventory, initially and periodically | `--inventory-once --db /var/lib/service-health/state.db --registry /etc/service-health/active-registry.json --catalog /etc/service-health/inventory-catalog.json` | service account, list pods and nodes |
| One long-lived worker | `--scheduled --db /var/lib/service-health/state.db --catalog /etc/service-health/inventory-catalog.json --trivy-cache /var/cache/service-health/trivy` | none |

Run one HTTP process and one scheduler per database. Arrange an initial inventory
run **before** starting the worker and periodic inventory refresh afterward, for
example with a single scheduled Job. Retry a busy collection lock; do not add a
second scheduler or run the legacy `--scans-scheduled` concurrently. The worker
starts release/image checks every six hours and scanner/advisory checks daily;
`--release-interval` and `--security-interval` are seconds. Defaults are two
concurrent Trivy scans, a 300-second scan timeout, 60-to-3,600-second retry
backoff, 12-hour release/image maximum age, and 48-hour security maximum age.
The HTTP process computes expiry from cached timestamps and never calls a
provider. See [freshness](freshness.md) for all flags and failure behavior.

Expose only port **8080** through a ClusterIP Service, such as
`http://service-health.example.invalid:8080` in documentation examples. Use the
actual internal Service URL in the deployment. `/healthz` is
process liveness. `/readyz` returns 200 even when the cache is empty; check
`cache_state` and summary `jobs` before treating collection as successful.
Start with a single replica: local-path SQLite and a single scheduler are not a
multi-writer, multi-node design. The HTTP and worker containers and inventory
Job need the same writable `/var/lib/service-health` PVC for the SQLite file
and lock. Give the worker a persistent writable `/var/cache/service-health`
volume for Trivy DB/image cache; monitor and prune it under an operator policy.
Both paths must be writable by UID/GID 65532. A read-only root filesystem is
appropriate with a writable `/tmp` tmpfs (64 MiB is the local example).
Mount catalog and registry JSON read-only under `/etc/service-health`.
External Trivy reports, if used, get a separate read-only mount and
`--external-reports /etc/service-health/reports` on the worker. Reports may
contain package inventory and must stay out of images and public artifacts.

Initial sizing **estimates**, pending real scans: HTTP request 64 MiB and limit
128 MiB; worker request 256 MiB and limit 1 GiB. Size temporary storage from a
full scan cycle and size the persistent scanner cache separately.
Raise worker memory or lower `--scan-workers` if measured scans exceed the
limit. Retain enough PVC space for the SQLite database and backups. Keep this
single-node workload on the node with its local-path PVC; a rollout must not
start competing schedulers against that database.

## Inventory and access

Generate a non-secret `active-registry.json` from **active** entries in the
infrastructure repository's service registry. Directories absent from that
registry are not automatically in scope. Keep stable service IDs and map every active
service to explicit regular and init-container selectors in
`inventory-catalog.json`. [Synthetic registry](../examples/active-registry.json)
and [catalog](../examples/inventory-catalog.json) show the accepted JSON shape.
A missing mapping rejects the inventory cycle and retains prior evidence;
version annotations must be trustworthy, because tags alone do not establish
bundled application versions. Runtime files belong in infrastructure, never
in image layers. Review every active service and sidecar before first run.

The inventory command lists **all pods and nodes** via the core API. The
[illustrative RBAC](../examples/inventory-rbac.yaml) grants exactly `list` on
those two resource kinds cluster-wide to a dedicated inventory service account.
The current client requests cluster-wide `/api/v1/pods` and `/api/v1/nodes`;
namespace Roles alone will not work. Mount its standard token and CA only in
the inventory Job. Give the HTTP and scheduler pods no API token; neither needs
Kubernetes access. Do not grant get/list on Secrets, pod exec/logs, workload
writes, privileged host mounts, or container-runtime socket access. Constrain
network egress to the Kubernetes API for inventory and to configured public
release/advisory/registry/Trivy DB sources for the worker as local policy allows.

Public providers need no application credential. The current image comparison
client supports **anonymous public registry access only**; injecting a private
registry credential does not add authentication to that check. Trivy may need
operator-managed registry authentication for private images; if configured,
inject it only into the worker at runtime through infrastructure-owned secret
mounts or environment references, following Trivy's supported mechanism. Never
copy credentials into catalog JSON, image build arguments, logs, or CI. No
credential is needed for this application's HTTP API. If private image checks
cannot be authenticated, keep image status/scan coverage unknown or missing,
or supply a validated external report; do not silently call it clean.

## Homepage and browser route

Use the [Homepage v1.10.1 example](../examples/homepage-services.yaml) in the
infrastructure `services.yaml`. Its per-service `widgets` array retains an
illustrative activity widget and adds separate Custom API widgets for updates
and security. Replace the fictional service and ID with each real stable
catalog ID, retaining each existing activity widget. The summary tile reads
`/api/v1/summary`. Homepage fetches widget URLs **server-side** through the
ClusterIP Service. Set the server-side `url` and browser-facing `href` to
their respective internal and ingress routes.

For detail navigation, optionally route
`/service-health/` on each Homepage host to the reporter's port 8080,
stripping `/service-health` before forwarding. Redirect the prefix without a
trailing slash to `/service-health/`; the HTML's relative links then resolve
under each host. Example `href` values are `/service-health/` and
`/service-health/services/{id}`. An alternative dedicated host is possible if
the `href` and ingress agree. There is no application authentication; apply the
same access policy at ingress as the dashboard. Do not expose the internal
ClusterIP address as a browser link. The [API contract](api-v1.md) defines null,
status, coverage, freshness, and error meanings. In Homepage v1.10.1 the
Custom API widget has no block highlighting; the text fields are the signal.

## First deployment verification

1. In the infrastructure feature branch, select an explicitly published
   `linux/amd64` image **digest**, review package visibility and pull access,
   and retain the previous digest for future upgrades. Create the runtime
   registry/catalog, RBAC, state/cache PVCs, workload, Service, backup entry,
   and Homepage fragment. Keep runtime data and credentials outside the image.
2. Follow the infrastructure repository's deployment and backup procedures.
   Review any deployment script for secret handling before executing it.
3. Confirm the HTTP process serves `/healthz` and `/readyz`. On an empty cache,
   `readyz` is 200 with `cache_state: empty`; summary has zero assessed services,
   unknown update status, and incomplete security coverage. This is expected
   until inventory and collection succeed.
4. Run inventory using the dedicated service account. Check that every active
   registry ID appears in `/api/v1/services`, with its expected components,
   regular/init containers, running digest and platform where reported. A
   missing digest or verified version remains null; inspect `jobs.inventory`
   and `inventory_stale` for errors.
5. Start the single scheduled worker. Confirm release, image, scan, and
   advisory job attempt/success times in `/api/v1/summary`; inspect a service
   detail and Homepage JSON for independent update/security fields,
   `coverage_complete`, `stale`, and successful-check timestamps. Confirm a
   failed or missing check stays visible and zero findings never imply clean
   coverage. Validate Trivy cache/PVC growth and worker memory under a real
   cycle before keeping the sizing limits.
6. From each Homepage host, check the summary tile, separate widgets beside an
   existing activity widget, and a browser detail link including its source
   links. If Homepage config is mounted with `subPath`, restart its Deployment
   after changing the ConfigMap, per infrastructure guidance. Check the detail
   route's trailing-slash redirect and relative navigation.

## Upgrade and rollback verification

1. Before changing the pinned digest, record current image and SQLite schema
   version, and take a consistent backup of the state PVC. Stop or quiesce the
   HTTP/worker/inventory processes for a simple SQLite file copy, or use
   SQLite's online backup facility while they run. Back up the runtime catalog
   and external reports separately under infrastructure policy. Verify the
   backup can be restored to a disposable location; a cache backup alone is
   insufficient for reconstructing runtime mappings.
2. Read release/schema migration notes and test the new image against a copy
   of the database. If compatibility is uncertain, plan a maintenance window.
   Change the image **digest** in infrastructure, keeping the previous image
   available.
3. Verify `/healthz`, `/readyz`, cached service count, job attempts/successes,
   freshness, Homepage fields, detail pages, PVC writes, and one completed
   collector cycle. Recheck resource use and backup integration.
4. If rollback is necessary, stop the new processes. Reverting the image alone
   may not undo a schema migration. Restore the compatible pre-upgrade SQLite
   backup with the prior image and matching runtime catalog, then verify the
   API and collector again. Do not overwrite the only backup while testing.

## Known limits

- OSV structured mappings do not cover every upstream advisory; an unsupported
  source or uncertain affected range is an explicit coverage gap or possible
  finding. Trivy's vulnerability DB and package inventory also cannot prove
  complete CVE coverage. See [advisories](advisories.md) and [scanner](scanner.md).
- Local `localhost/...` and other unpullable images require a fresh external
  digest/platform-matched report. Missing, stale, or mismatched reports remain
  missing coverage. There is no node runtime export or arbitrary pod exec.
- A mutable tag can change without an application version change. Image rebuild
  detection compares platform manifests where public registry access works;
  digest-only pins, private registries, missing runtime digests/platforms, and
  ambiguous manifests may leave image status unknown or failed. A rebuild does
  not establish that a vulnerability was fixed.
- Tags such as `redis:7-alpine` and custom `latest` images may not reveal their
  bundled application version. Leave that value unknown without reliable
  version metadata. A current release can still have findings, and an update
  can have none.
