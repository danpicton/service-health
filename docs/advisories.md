# Upstream application advisories

Configure an OSV ecosystem package for each component whose **deployed application version** is reliably known. The package identity is independent of its container image and release source:

```json
{
  "id": "server",
  "advisory_source": {
    "type": "osv",
    "ecosystem": "PyPI",
    "package": "example-app",
    "version_policy": "semver",
    "current_prefix": "v"
  }
}
```

The package and ecosystem must exactly identify the upstream application in OSV. Do not map a container image to an OSV package unless its version annotation proves the bundled application version. `current_prefix` removes a literal prefix from the verified version. The original version remains in the display. Only exact SemVer versions and OSV `SEMVER` ranges are compared; `ECOSYSTEM` and `GIT` ranges, unrecognized versions, and conflicting records become possible findings or coverage gaps. This avoids treating arbitrary version text or prose as a verified range. A component without a supported structured source is a coverage gap, including when OSV does not cover that application. An empty successful OSV response can establish advisory coverage only for a reliable deployed version and configured package; it cannot establish complete security coverage without a complete scanner check.

Run after inventory, independently of release and scanner jobs:

```sh
PYTHONPATH=src python -m service_health --advisories-once \
  --db /var/lib/service-health/state.db \
  --catalog /etc/service-health/inventory-catalog.json
```

The provider requests all pages of public structured OSV records for the configured package, with a 10-second request timeout and 20-page bound. The job writes SQLite; HTTP requests read cached results only. An OSV failure retains the previous advisory evidence, marks it stale, and sets `advisory_coverage: failed`. The collector does not use credentials or query cluster secrets. A production scheduler should call this one-shot command daily; recurring advisory scheduling and freshness expiry are later work.

`advisory_findings` on each component and service distinguish `match: confirmed` from `match: possible`. Each finding has the OSV ID and aliases, severity when OSV supplies a recognized categorical severity, fixed versions from range events, and a `provenance` array containing source IDs, OSV links, and structured affected ranges. Aliased records count once; a conflicting group is possible and excluded from confirmed severity counts. `advisory_coverage`, `advisory_gap`, `advisory_error`, `advisory_checked_at`, and `advisory_stale` explain uncertainty and failure. The Homepage response includes advisory coverage and possible count. A `findings` headline can coexist with incomplete coverage; `no known findings` requires both scanner and advisory coverage complete.

OSV's [query API](https://google.github.io/osv.dev/post-v1-query/) and [vulnerability schema](https://ossf.github.io/osv-schema/) define the structured input and range events. OSV's categorical `database_specific.severity` is optional, so `unknown` severity is retained rather than inferred from a CVSS vector. No-CVE OSV IDs are accepted. This source covers only packages represented in OSV, not every upstream repository advisory.
