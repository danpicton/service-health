# Collection schedule and freshness

After the inventory command has populated SQLite, run one long-lived collection
worker and one HTTP process against the **same** persistent database:

```sh
PYTHONPATH=src python -m service_health --scheduled --db /var/lib/service-health/state.db --catalog /etc/service-health/inventory-catalog.json --trivy-cache /var/cache/service-health/trivy
PYTHONPATH=src python -m service_health --db /var/lib/service-health/state.db --host 0.0.0.0 --port 8080
```

Run one scheduler per database. It runs release plus image checks every six hours,
and Trivy plus advisory checks daily. `--release-interval` and
`--security-interval` set independent intervals in seconds. `--retry-initial`
defaults to 60 seconds and `--retry-max` to 3,600 seconds; each failed job
retries with exponential backoff, capped at the maximum. The next due time is
recovered from the SQLite job table after restart. Each job has an exclusive
nonblocking file lock beside the database, shared with the legacy
`--scans-scheduled` command, so those cycles cannot overlap. The scheduler runs
jobs serially. The Trivy work pool is bounded by `--scan-workers` (1–4, default
2). Trivy subprocesses have `--scan-timeout` (default 300 seconds). GitHub,
registry, OSV, and Kubernetes requests have their existing 10-second per-request
timeouts; OSV pagination is bounded. An operator should configure an external
process supervisor to restart a crashed worker.

The HTTP server uses `--release-max-age` (default 43,200 seconds) for release
and image evidence, and `--security-max-age` (default 172,800 seconds) for scans
and advisories. Both must be positive. On expiry, candidate versions and prior
findings remain visible as old evidence. The corresponding status becomes
`unknown` or `incomplete coverage`, and its stale flag is true. Confirmed
findings remain the security headline even if other coverage expires. A failed
provider marks its field `check failed` immediately; a previous success keeps
its check time and evidence with `stale: true`. A first failure has no previous
successful check time and is not labeled as retained stale evidence. A failed
whole job preserves the prior SQLite snapshot and records an error and attempt
time in `/api/v1/summary` under `jobs`; the detail page shows the same job
failure and last successful job time. Partial provider failures commit the
healthy results, retain failed provider evidence, and retry the affected job.
If the first job runs before inventory exists, the summary remains `empty`
and `unknown`/`incomplete coverage`, with the job error visible in summary JSON
and on the root page.

The flat Homepage JSON includes `release_stale`, `image_stale`, `scan_stale`,
`advisory_stale`, aggregate `stale`, last successful check timestamps, and
provider error arrays. Service detail JSON carries component and deployment
errors. `/api/v1/summary` exposes persisted `jobs` entries with `attempted_at`,
`succeeded_at`, `error`, and `failures`. The root and service pages show stale
and failure wording. HTTP requests only read SQLite and calculate expiry from
timestamps; they never invoke a collector or modify the cached snapshot.

The legacy one-shot commands and `--scans-scheduled` remain available. Inventory
refresh takes a separate short-lived `.inventory.lock` commit slot and observes
Kubernetes only after acquiring it. It waits up to 120 seconds, then records a
visible inventory job error and leaves the prior snapshot intact. The worker
keeps `.collection.lock` across its cycle to prevent overlapping jobs, but takes
`.inventory.lock` only while publishing progress and final results. If pod
identity changes during a scan, the worker retains only matching evidence,
records a retryable job error, and never restores the old deployment identity.
Inventory retains evidence only for unchanged component/deployment identities;
see [inventory](inventory.md). A failed inventory refresh marks the retained
inventory stale immediately. The unified
`--scheduled` worker should replace separate scanner scheduling in a new
deployment to avoid duplicate scan work. Inventory remains a separate one-shot
input; recurring refresh should be arranged by the infrastructure agent.
