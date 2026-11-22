# Application release checks

Each component can have a `release_source` in the non-secret runtime catalog:

```json
{
  "type": "github_releases",
  "repository": "example/example-photos",
  "version_policy": "semver",
  "tag_prefix": "v",
  "current_prefix": "",
  "track_prereleases": false
}
```

`tag_prefix` and `current_prefix` remove literal prefixes before comparison;
displayed versions retain their original text. `track_prereleases` can instead be
set on the service catalog entry for all its release sources. A source-level value
overrides it. The provider requests up to 100 recent releases from the public GitHub
API with a 10-second timeout; it ignores drafts, releases without an HTTPS source
link, and prereleases unless opted in. API rate limits or outages produce
`check failed` and retain previous candidate evidence as stale. No credentials are
read from the catalog. Private or unsupported sources need a future provider.

`semver` accepts exact `major.minor.patch` versions, optional `v`, prerelease,
and build metadata. `numeric` accepts exact 2–4 part numeric versions such as
`2026.11`; segment counts must match. Numeric segments compare in order and the
first segment is treated as the major boundary. Version ranges, partial SemVer,
floating image tags, and unrecognized formats produce `unknown`; they are never
treated as verified application versions. A candidate without a reliable current
version is shown, but its update status remains `unknown`. An empty eligible
release set is also `unknown`, not `up to date`.

Run after inventory has populated the SQLite cache:

```sh
PYTHONPATH=src python -m service_health \
  --releases-once \
  --db /var/lib/service-health/state.db \
  --catalog /etc/service-health/inventory-catalog.json
```

The command updates cached component and service results. HTTP requests read only
SQLite. `candidate_version`, `update_status`, `update_kind`, `release_source_url`,
`release_checked_at`, `release_error`, `release_stale`, and `update_reason` expose
the comparison and its evidence. Service `candidate_version` and `update_kind` are
flat only for one-component services; multi-component details remain in
`components`. `update_coverage_complete` is false if any component is unknown or
failed, even when another component has an available update. A release does not
establish that security findings are fixed. Image rebuild checks, recurring jobs,
and release freshness expiry are separate later work.
