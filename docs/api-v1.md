# Service Health API v1

All JSON routes are read only and return cached SQLite evidence. The schema is
[`api-v1.schema.json`](api-v1.schema.json); select `$defs.summary`,
`$defs.serviceList`, `$defs.serviceDetail`, or `$defs.homepage` for each route. The
synthetic responses in [`examples`](../examples/) are complete responses from
one offline assessment: `api-v1-summary.json`, `api-v1-services.json`,
`api-v1-detail.json`, and `api-v1-homepage.json`. The directory also contains
`api-v1-empty-summary.json`, `api-v1-homepage-stale.json`, and
`api-v1-error.json` for first startup, a retained failed check, and HTTP 404.
Fields may be added within v1.
Consumers should ignore fields they do not use.

The services list and Homepage response now omit `scan_findings`,
`advisory_findings`, and `confirmed_findings` at service, component, and
deployment level. Their `components` still carry identity, status, coverage,
timestamps, counts, and error fields. Fetch `/api/v1/services/{id}` or
`/services/{id}` for the complete finding tree. This coordinated v1 response
reduction keeps the 42 commonly polled dashboard widgets small; consumers that
used list or Homepage findings arrays must use the detail route.

| Route | Success | Body |
| --- | --- | --- |
| `GET /healthz` | 200 | `{"status":"alive"}`: process liveness only |
| `GET /readyz` | 200 | `status: ready`, `cache_state: empty\|populated` |
| `GET /api/v1/summary` | 200 | Overall service counts, coverage, freshness, jobs |
| `GET /api/v1/services` | 200 | `cache_state`, `checked_at`, compact `services` array |
| `GET /api/v1/services/{id}` | 200 | Service and component evidence plus `checked_at` |
| `GET /api/v1/services/{id}/homepage` | 200 | Stable flat fields for Custom API widgets |
| `GET /` and `/services/{id}` | 200 | HTML findings pages |

An unknown service ID or path returns HTTP 404 JSON
`{"error":"not found"}`. IDs are stable catalog IDs, not display names;
percent encode them as URL path segments. All JSON responses use
`application/json; charset=utf-8`. The HTML pages use `text/html; charset=utf-8`.
No API request runs collection. There is no pagination or authentication in the
application; access control belongs to the ingress.

## State meanings

`/readyz` intentionally returns 200 while the cache is empty: the process can
serve a truthful unassessed response. On that first startup, summary and list
have `cache_state: empty`, `checked_at: null`, zero services, `unknown` update
and `incomplete coverage` security. A failed first job is visible in `jobs`.
Readiness is therefore not proof that an assessment exists.

`checked_at` is the last snapshot write, **not** proof that all checks succeeded
then. `release_checked_at`, `image_checked_at`, `scan_checked_at`, and
`advisory_checked_at` record the oldest relevant successful check at service
level when available. `jobs.*.attempted_at` records the last whole-job attempt;
`succeeded_at` remains the last success after failure; `error` and `failures`
describe the current failure. Times are UTC RFC 3339 strings; `null` means no
known successful timestamp. `stale: true` means retained evidence survived a
failed check or exceeded configured maximum age. A first failure with no previous
success has no retained stale evidence, but its status and error still show the
failure. A zero finding count with incomplete or failed coverage is **not** a
clean assessment.

`jobs.*.state` is an additive v1 field: `running` means the worker holds the
collection lock and has started the job; `interrupted` means a prior running
worker lost that lock before completion; `completed` includes both successful
and failed finished attempts. During security collection, validated scans are
committed individually. `checked_at` can therefore advance before the job is
complete. Check `jobs.security.state`, per-deployment coverage, and the four
successful-check timestamps before interpreting a partial result. HTTP routes
only read this state and never trigger collection.

| Field | Values and interpretation |
| --- | --- |
| `update_status` | `update available`, `up to date`, `unknown`, `check failed` |
| `update_kind` | `patch`, `minor`, `major migration`, or `null`; see components when service has several |
| `image_status` | `image rebuild available`, `up to date`, `unknown`, `check failed`; independent of application updates |
| `security_status` | `findings`, `no known findings`, `incomplete coverage`, `check failed` |
| `scan_coverage`, `advisory_coverage` | `complete`, `missing`, `failed`; independent of a findings headline |
| `coverage_complete` | True only when all components have complete scanner and advisory checks |
| `update_coverage_complete`, `image_coverage_complete` | True only when all component comparisons completed |
| `current_version`, `candidate_version`, `candidate_image_digest` | `null` when unknown or no single representative value exists; inspect components/deployments |
| `inventory_status`, `inventory_stale`, `inventory_error` | Observation/failure evidence for the registry and pod inventory |
| `release_stale`, `image_stale`, `scan_stale`, `advisory_stale` | Evidence age/failure by collector; aggregate `stale` includes any of these and inventory |

Summary `*_counts` objects count **services** by headline, not individual
components. `coverage_gap_service_count` counts services with any security
coverage gap, even if their headline is `findings`. Severity and fix counts
count confirmed finding groups across affected components. The same scanner and
upstream advisory issue on one component is one group with multiple `sources`;
the same issue on two affected components counts twice. `possible_finding_count`
is separate and excluded from confirmed severity counts. `fix_available_count`
reflects source fix evidence; a newer release alone does not imply a fix.

The flat Homepage response includes `id`, `detail_path`,
`component_count`, `components`, all independent statuses and coverage flags,
four successful-check timestamps, collector error arrays, the five finding
counts, `checked_at`, and stale flags. `detail_path` is the API's root-relative
route. Homepage should use a browser-facing `href` matching its ingress path;
the server-side widget `url` is a separate ClusterIP address. The HTML pages
use relative links (`services/{id}`, `../`), so both hub hostnames work. If an
ingress mounts the reporter under a path prefix, it must strip that prefix for
the app and redirect the prefix without a trailing slash to one with a slash.
The detail-page route must be reachable from the viewer's browser.
Homepage may render a `null` version as an empty value; map the accompanying
status and coverage fields so an empty version never reads as “up to date” or
“no known findings.”
The additive scalar `update_reason`, `image_reason`, and `security_reason`
fields show one actionable cause for a widget; `update_reasons`,
`image_reasons`, `advisory_gaps`, and the existing error arrays preserve all
component/deployment causes. Examples include GitHub rate limited with a
retry time, GitHub authentication required, missing verified application
version, private registry authentication required, unsupported local image,
and missing structured advisory mapping. These reasons do not change the
existing v1 status enums; unknown and incomplete remain distinct from clean.

## Homepage v1.10.1 integration example

The example in [`homepage-services.yaml`](../examples/homepage-services.yaml) is
an illustrative `services.yaml` fragment. Keep each real service's existing
activity widget in `widgets`; append the update and security Custom API widgets.
Use the actual stable catalog ID in both server-side URLs. The sample also has
an overall summary tile. Replace the fictional service names, existing widget,
ClusterIP service name, and browser ingress path in infrastructure configuration.
Do not point the widget at a hub hostname: Homepage fetches its data server-side
through the internal service URL. No API credentials are required by this app.

This mapping syntax and the `widgets` array are verified against the
[Homepage v1.10.1 Custom API docs](https://github.com/gethomepage/homepage/blob/v1.10.1/docs/widgets/services/customapi.md)
and [v1.10.1 service configuration](https://github.com/gethomepage/homepage/blob/v1.10.1/docs/configs/services.md).
The v1.10.1 implementation reads string `field` paths and its block display
shows at most four mappings; the example uses `display: list` for more fields
([source](https://github.com/gethomepage/homepage/blob/v1.10.1/src/widgets/customapi/component.jsx)).
Kubernetes ingress annotations cannot express multiple widgets in that version;
place this example in `services.yaml`. Custom API has no block highlighting in
that release, so the text statuses and counts carry the signal.
