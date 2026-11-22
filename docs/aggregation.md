# Aggregate signals

Each service combines all explicitly mapped components. `update_status` and
`image_status` have their own precedence: an available application update or
image rebuild takes the headline, then a failed check, an unknown check, and an
up-to-date check. `update_coverage_complete` and `image_coverage_complete` stay
false if any component remains unknown or failed. An update candidate and a
security finding are independent evidence; a newer release does not establish a
security fix.

`security_status` is `findings` whenever a confirmed scanner finding or upstream
advisory exists, even if another component has missing or failed coverage.
`coverage_complete` is true only if every component has both complete scanner and
upstream advisory checks. With no confirmed findings, failed checks produce
`check failed`, missing checks produce `incomplete coverage`, and complete checks
produce `no known findings`. The overall summary applies the same rule across
services. The separate `scan_coverage`, `advisory_coverage`, and
`coverage_gap_service_count` fields explain a findings headline with incomplete
assessment.

`confirmed_findings` groups matching IDs and aliases **within each affected
component**, so the same issue reported by Trivy and OSV counts once for that
component. Each group retains `component_id`, aliases, severity, fix evidence,
and its `sources` array with the original scanner and advisory records. The same
issue affecting two distinct components counts twice because each deployed
component needs attention. `confirmed_finding_count`, `critical_count`,
`high_count`, and `fix_available_count` count these groups. Ambiguous upstream
matches remain in `advisory_findings` with `match: possible`; they contribute to
`possible_finding_count` only and prevent complete advisory coverage.

The service detail JSON and `/api/v1/services` include those fields. The flat
Homepage JSON includes the counts, statuses, coverage flags, and stale flags.
`/api/v1/summary` sums service finding counts, exposes `security_counts` by
service headline, and counts services with a coverage gap. The root and service
pages show the same counts and retain each source's details and links. Counts of
zero on an unassessed service are placeholders and require the coverage fields
for interpretation.

Scanner and advisory jobs can run in either order. Both recalculate aggregate
security fields from cached component evidence after their own check, while
release and image checks leave security evidence untouched. HTTP requests only
read the persisted snapshot.
