# Trivy image scans

The one-shot scanner reads the cached inventory, refreshes Trivy's vulnerability
DB, and scans each observed pullable image at its **running digest** and node
platform. Run after inventory:

```sh
PYTHONPATH=src python -m service_health --scans-once \
  --db /var/lib/service-health/state.db \
  --trivy-cache /var/cache/service-health/trivy
```

For a long-lived daily worker, use `--scans-scheduled` instead. It runs immediately
and then every 86,400 seconds by default; `--scan-interval` configures the interval
(minimum 60 seconds). `--scan-workers` defaults to 2 and accepts 1–4; `--scan-timeout`
defaults to 300 seconds per Trivy subprocess. Trivy itself uses one parallel worker
per image and a 2 GB maximum image size. A nonblocking lock beside the SQLite file
prevents overlapping scan cycles across processes. Run one scheduler per database;
other release and inventory jobs remain separate. The Trivy binary must be installed
in the runtime image or supplied in `PATH` by the operator.

Trivy uses only its remote image source, with `--scanners vuln`,
`--skip-db-update` after the explicit DB refresh, `--skip-java-db-update`,
`--platform`, a persistent cache directory, and an immutable `image@sha256:…`
target. It does not use pod exec, container runtime sockets, or Kubernetes write
permissions. The runtime cache directory needs a writable volume and an operator
set disk quota/retention policy; the application limits a single JSON report to
20 MiB but does not yet prune Trivy's downloaded image/DB cache. Private registries
may require operator managed credentials; no credentials are read from the cluster
by this collector.

Each deployment has `scan_coverage` (`complete`, `missing`, or `failed`),
`scan_error`, `scan_findings`, `scan_digest`, `scan_platform`, `scan_checked_at`,
and `scan_stale`. Findings carry ID, severity, affected package, installed and fixed
versions where known, Trivy source URL, and the assessed digest/platform. The service
and component aggregate these fields; `scan_coverage` is complete only when every
observed deployment has an accepted report. A failed scan retains prior findings
for the same digest/platform and marks them stale. Missing digests, platforms, or
pullable references remain coverage gaps. A report with a different digest or
platform is rejected. Every scheduled cycle refreshes the vulnerability DB and
rescans unchanged digests, so DB updates can change findings without an image update.

An empty Trivy report establishes only scanner coverage. Overall
`coverage_complete` remains false and `security_status` remains `incomplete coverage`
until the separate upstream advisory collector has assessed its sources; see [upstream advisory checks](advisories.md). Scanner
findings are shown with a `Trivy finding` label on the service page. The API and
Homepage fields are cached and HTTP reads never launch scans.

Trivy flags and JSON identity fields were checked against the official
[image CLI reference](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/)
and [JSON reporting guide](https://www.trivy.dev/docs/latest/guide/configuration/reporting/).

## External reports for local or private images

Supply a read-only directory of non-secret JSON report envelopes with
`--external-reports /etc/service-health/reports`. The scan job reads at most 128
directory entries and 20 MiB per report. The default maximum report age is 48
hours; set `--external-report-max-age SECONDS` to match the report producer's
schedule. The directory is operator supplied at runtime and must not be copied
into the container image. Reports can include image/package inventories and
should be treated as operational data, even when they contain no credentials.

Each `.json` file has this shape (the `report` value is the complete Trivy JSON
output, shown here with an empty result):

```json
{
  "image": "localhost/example-app:latest",
  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "platform": "linux/amd64",
  "scanned_at": "2026-11-22T00:00:00Z",
  "report": {
    "SchemaVersion": 2,
    "ArtifactName": "localhost/example-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "Metadata": {"ImageConfig": {"os": "linux", "architecture": "amd64"}},
    "Results": []
  }
}
```

The `image` must exactly equal the observed deployment image reference,
including its tag. The envelope digest and platform must equal the observed
running digest and platform; the embedded Trivy report must independently state
that digest and platform. The report producer must scan the running image or an
equivalent exported artifact whose identity is verified against that digest and
platform. A mutable tag alone is insufficient evidence. Reports must have a
timezone-aware scan time, must not be more than five minutes in the future, and
must be within the configured maximum age. Two matching files are ambiguous and
both are rejected. Invalid, missing, old, and mismatched reports yield
`scan_coverage: missing` for a local image; previously accepted findings for the
same digest/platform remain visible with `scan_stale: true`. No mutable tag is
pulled as a fallback. Pullable images can use a matching external report too;
otherwise the collector continues its immutable remote digest scan.

Accepted reports expose `scan_source: external` and `scan_reported_at` on each
deployment and finding. Homepage includes `scan_sources` and existing counts;
the detail page shows the external provenance. The directory path is not exposed
in API responses. The operator remains responsible for producing and rotating
reports, and for verifying the exported artifact's digest before creating an
envelope. There is no automatic local image export or access to the node's
container runtime.
