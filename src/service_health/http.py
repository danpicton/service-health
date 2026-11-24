"""Read-only HTTP presentation of the latest SQLite snapshot."""

import html
import json
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore
from urllib.parse import quote, unquote, urlsplit

from service_health.freshness import DEFAULT_INVENTORY_MAX_AGE, project
from service_health.store import Store


def _summary(snapshot: dict | None) -> dict:
    services = snapshot["services"] if snapshot else []
    statuses = {item.get("update_status", "unknown") for item in services}
    update_status = next(
        (
            status
            for status in ("update available", "check failed", "unknown", "up to date")
            if status in statuses
        ),
        "unknown",
    )
    return {
        "cache_state": "populated"
        if snapshot and not snapshot.get("empty")
        else "empty",
        "checked_at": snapshot["checked_at"] if snapshot else None,
        "jobs": snapshot.get("jobs", {}) if snapshot else {},
        "stale": any(item.get("stale", False) for item in services),
        "service_count": len(services),
        "update_status": update_status,
        "update_coverage_complete": bool(services)
        and all(item.get("update_coverage_complete", False) for item in services),
        "image_status": next(
            (
                status
                for status in (
                    "image update available",
                    "check failed",
                    "unknown",
                    "up to date",
                )
                if status in {item.get("image_status", "unknown") for item in services}
            ),
            "unknown",
        ),
        "image_counts": {
            status: sum(
                item.get("image_status", "unknown") == status for item in services
            )
            for status in (
                "image update available",
                "up to date",
                "unknown",
                "check failed",
            )
        },
        "update_counts": {
            status: sum(
                item.get("update_status", "unknown") == status for item in services
            )
            for status in ("update available", "up to date", "unknown", "check failed")
        },
        "security_status": next(
            (
                status
                for status in (
                    "findings",
                    "check failed",
                    "incomplete coverage",
                    "no known findings",
                )
                if status
                in {
                    item.get("security_status", "incomplete coverage")
                    for item in services
                }
            ),
            "incomplete coverage",
        ),
        "coverage_complete": bool(services)
        and all(item.get("coverage_complete", False) for item in services),
        "coverage_gap_service_count": sum(
            not item.get("coverage_complete", False) for item in services
        ),
        "security_counts": {
            status: sum(
                item.get("security_status", "incomplete coverage") == status
                for item in services
            )
            for status in (
                "findings",
                "no known findings",
                "incomplete coverage",
                "check failed",
            )
        },
        "scan_coverage": "complete"
        if services
        and all(item.get("scan_coverage") == "complete" for item in services)
        else (
            "failed"
            if any(item.get("scan_coverage") == "failed" for item in services)
            else "missing"
        ),
        "critical_count": sum(item.get("critical_count", 0) for item in services),
        "high_count": sum(item.get("high_count", 0) for item in services),
        "confirmed_finding_count": sum(
            item.get("confirmed_finding_count", 0) for item in services
        ),
        "fix_available_count": sum(
            item.get("fix_available_count", 0) for item in services
        ),
        "possible_finding_count": sum(
            item.get("possible_finding_count", 0) for item in services
        ),
        "advisory_coverage": "complete"
        if services
        and all(item.get("advisory_coverage") == "complete" for item in services)
        else "failed"
        if any(item.get("advisory_coverage") == "failed" for item in services)
        else "missing",
        "message": (
            "No cached collection has completed; services have not been assessed."
            if not snapshot or snapshot.get("empty")
            else "Cached aggregate assessment across active services."
        ),
    }


def _homepage(service: dict, checked_at: str | None) -> dict:
    components = service.get("components", [])
    deployments = [
        d for component in components for d in component.get("deployments", [])
    ]

    def first(values):
        return next((value for value in values if value), None)

    return {
        "id": service["id"],
        "detail_path": "/services/" + quote(service["id"], safe=""),
        "inventory_status": service.get("inventory_status", "unknown"),
        "inventory_error": service.get("inventory_error"),
        "inventory_stale": service.get("inventory_stale", False),
        "component_count": len(service.get("components", [])),
        "components": components,
        "current_version": service.get("current_version"),
        "candidate_version": service.get("candidate_version"),
        "update_status": service.get("update_status", "unknown"),
        "update_reason": first(
            c.get("release_error") or c.get("update_reason") for c in components
        ),
        "update_kind": service.get("update_kind"),
        "image_status": service.get("image_status", "unknown"),
        "image_reason": first(
            d.get("image_reason") or d.get("image_error") for d in deployments
        ),
        "candidate_image_digest": service.get("candidate_image_digest"),
        "image_coverage_complete": service.get("image_coverage_complete", False),
        "image_checked_at": service.get("image_checked_at"),
        "image_stale": service.get("image_stale", False),
        "image_errors": [
            deployment["image_error"]
            for component in service.get("components", [])
            for deployment in component.get("deployments", [])
            if deployment.get("image_error")
        ],
        "image_reasons": [
            deployment["image_reason"]
            for component in service.get("components", [])
            for deployment in component.get("deployments", [])
            if deployment.get("image_reason")
        ],
        "update_coverage_complete": service.get("update_coverage_complete", False),
        "release_stale": service.get("release_stale", False),
        "release_checked_at": service.get("release_checked_at")
        or next(
            (
                component.get("release_checked_at")
                for component in service.get("components", [])
                if component.get("release_checked_at")
            ),
            None,
        ),
        "release_errors": [
            component["release_error"]
            for component in service.get("components", [])
            if component.get("release_error")
        ],
        "update_reasons": [
            component["update_reason"]
            for component in service.get("components", [])
            if component.get("update_reason")
        ],
        "security_status": service.get("security_status", "incomplete coverage"),
        "security_reason": first(
            [d.get("scan_error") for d in deployments]
            + [c.get("advisory_error") or c.get("advisory_gap") for c in components]
        ),
        "scan_coverage": service.get("scan_coverage", "missing"),
        "scan_sources": service.get("scan_sources", []),
        "scan_checked_at": service.get("scan_checked_at"),
        "scan_stale": service.get("scan_stale", False),
        "scan_errors": [
            deployment["scan_error"]
            for component in service.get("components", [])
            for deployment in component.get("deployments", [])
            if deployment.get("scan_error")
        ],
        "advisory_coverage": service.get("advisory_coverage", "missing"),
        "advisory_checked_at": service.get("advisory_checked_at"),
        "advisory_stale": service.get("advisory_stale", False),
        "advisory_errors": [
            component["advisory_error"]
            for component in service.get("components", [])
            if component.get("advisory_error")
        ],
        "advisory_gaps": [
            component["advisory_gap"]
            for component in service.get("components", [])
            if component.get("advisory_gap")
        ],
        "possible_finding_count": service.get("possible_finding_count", 0),
        "confirmed_finding_count": service.get("confirmed_finding_count", 0),
        "coverage_complete": service.get("coverage_complete", False),
        "critical_count": service.get("critical_count", 0),
        "high_count": service.get("high_count", 0),
        "fix_available_count": service.get("fix_available_count", 0),
        "checked_at": checked_at,
        "stale": service.get("stale", False)
        or service.get("inventory_stale", False)
        or service.get("release_stale", False)
        or service.get("image_stale", False)
        or service.get("scan_stale", False)
        or service.get("advisory_stale", False),
    }


def _job_markup(name, job):
    label = html.escape(name) + " job"
    state = job.get("state")
    if state in ("running", "interrupted"):
        yield f"<p>{label} {html.escape(state)}.</p>"
    elif state == "partial":
        yield f"<p>{label} completed with coverage gaps.</p>"
    if job.get("error") and state != "interrupted":
        error = html.escape(job["error"])
        succeeded = html.escape(job.get("succeeded_at") or "never")
        yield f"<p>{label} failed: {error}; last successful: {succeeded}</p>"
    if job.get("next_full_at"):
        full = html.escape(job["next_full_at"])
        retry = html.escape(job.get("next_retry_at") or "none scheduled")
        yield f"<p>Next full security scan: {full}; next retry: {retry}</p>"


def _page(snapshot: dict | None, service: dict | None = None) -> str:
    home_href = "../" if service is not None else "./"
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        "<title>Service health</title></head><body>",
        f'<header><h1><a href="{home_href}">Service health</a></h1></header><main>',
    ]
    jobs = snapshot.get("jobs", {}) if snapshot else {}
    if service is not None:
        parts.append(f"<h2>{html.escape(service.get('name', service['id']))}</h2>")
        if service.get("stale"):
            parts.append("<p>Previous result is stale.</p>")
        if service.get("inventory_error"):
            parts.append(
                "<p>Inventory refresh failed: "
                + html.escape(service["inventory_error"])
                + "</p>"
            )
        elif service.get("inventory_stale"):
            parts.append("<p>Inventory observation expired.</p>")
        for name in ("release", "security"):
            parts.extend(_job_markup(name, jobs.get(name, {})))
        parts.append(
            f"<p>Update: {html.escape(service.get('update_status', 'unknown'))}</p>"
        )
        if not service.get("update_coverage_complete"):
            parts.append("<p>Incomplete component update checks.</p>")
        parts.append(
            f"<p>Image: {html.escape(service.get('image_status', 'unknown'))}</p>"
        )
        parts.append(
            "<p>Security: "
            + html.escape(service.get("security_status", "incomplete coverage"))
            + "</p>"
        )
        parts.append(
            "<p>Confirmed findings: "
            + str(service.get("confirmed_finding_count", 0))
            + "; critical: "
            + str(service.get("critical_count", 0))
            + "; high: "
            + str(service.get("high_count", 0))
            + "; possible findings: "
            + str(service.get("possible_finding_count", 0))
            + "; coverage complete: "
            + str(bool(service.get("coverage_complete", False))).lower()
            + "</p>"
        )
        parts.append(
            "<p>Scanner coverage: "
            + html.escape(service.get("scan_coverage", "missing"))
            + "; checked: "
            + html.escape(service.get("scan_checked_at") or "never")
            + ("; previous result is stale" if service.get("scan_stale") else "")
            + "</p>"
        )
        parts.append(
            "<p>Upstream advisory coverage: "
            + html.escape(service.get("advisory_coverage", "missing"))
            + "; checked: "
            + html.escape(service.get("advisory_checked_at") or "never")
            + ("; previous result is stale" if service.get("advisory_stale") else "")
            + "</p>"
        )
        if service.get("scan_coverage", "missing") == "missing":
            parts.append("<p>Detailed findings have not been assessed.</p>")
        parts.extend(_component_markup(service))
    elif snapshot is None or snapshot.get("empty"):
        parts.append(
            "<p>No cached collection has completed. "
            "Services have not been assessed.</p>"
        )
        for name, job in jobs.items():
            parts.extend(_job_markup(name, job))
    elif not snapshot["services"]:
        parts.append(
            "<p>The cached catalog is empty. No services have been assessed.</p>"
        )
        for name, job in jobs.items():
            parts.extend(_job_markup(name, job))
    else:
        summary = _summary(snapshot)
        if summary["stale"]:
            parts.append("<p>Some previous results are stale.</p>")
        for name, job in jobs.items():
            parts.extend(_job_markup(name, job))
        parts.append(
            "<p>Overall update: "
            + html.escape(summary["update_status"])
            + "; security: "
            + html.escape(summary["security_status"])
            + "; confirmed findings: "
            + str(summary["confirmed_finding_count"])
            + "; possible findings: "
            + str(summary["possible_finding_count"])
            + "; services with coverage gaps: "
            + str(summary["coverage_gap_service_count"])
            + "</p>"
        )
        parts.append("<p>Cached services; unassessed fields remain unknown.</p><ul>")
        for item in snapshot["services"]:
            service_path = html.escape(quote(item["id"], safe=""), quote=True)
            name = html.escape(item.get("name", item["id"]))
            parts.append(f'<li><a href="services/{service_path}">{name}</a>')
            parts.append(
                "; update: "
                + html.escape(item.get("update_status", "unknown"))
                + "; security: "
                + html.escape(item.get("security_status", "incomplete coverage"))
                + "; confirmed findings: "
                + str(item.get("confirmed_finding_count", 0))
                + "; possible findings: "
                + str(item.get("possible_finding_count", 0))
                + "; coverage complete: "
                + str(bool(item.get("coverage_complete", False))).lower()
            )
            if not item.get("update_coverage_complete"):
                parts.append("; incomplete component update checks")
            parts.extend(_component_markup(item))
            parts.append("</li>")
        parts.append("</ul>")
    parts.append("</main></body></html>")
    return "".join(parts)


def _version_markup(record):
    parts = []
    source = record["source"]
    identity = source.get("url") or source.get("repository") or source.get("key")
    parts.append(
        "<p>Version source "
        + html.escape(source["type"])
        + " ("
        + html.escape(identity or "unknown")
        + "), scope "
        + html.escape(record["scope"])
        + ", "
        + html.escape(record["outcome"])
        + ". Reported "
        + html.escape(record["reported"] or "unknown")
        + ", normalized "
        + html.escape(record["normalized"] or "unknown")
        + ", checked "
        + html.escape(record["checked_at"] or "never")
    )
    if source["type"] == "image_metadata":
        parts.append(
            ". Application label "
            + html.escape(source["identity_label"])
            + " = "
            + html.escape(source["identity_value"])
            + ", version label "
            + html.escape(source["version_label"])
        )
        if record.get("config_digest"):
            parts.append(
                ", manifest "
                + html.escape(record["manifest_digest"])
                + ", config "
                + html.escape(record["config_digest"])
            )
    if record.get("limitation"):
        parts.append(". " + html.escape(record["limitation"]))
    if record.get("reason"):
        parts.append(". " + html.escape(record["reason"]))
    previous = record.get("last_success")
    if previous and record["outcome"] != "success":
        parts.append(
            ". Last successful version "
            + html.escape(previous["normalized"])
            + " at "
            + html.escape(previous["checked_at"])
        )
        prior_identity = previous.get("assessed_identity") or {}
        prior_source = previous.get("source") or prior_identity.get(
            "version_source", {}
        )
        if prior_source.get("url"):
            parts.append(" from " + html.escape(prior_source["url"]))
        for deployment in prior_identity.get("deployments", []):
            parts.append(
                "; previously assessed "
                + html.escape(" ".join(str(value) for value in deployment if value))
            )
    parts.append("</p>")
    return parts


def _component_markup(service: dict) -> list[str]:
    components = service.get("components", [])
    if not components:
        return []
    parts = ["<ul>"]
    for component in components:
        name = html.escape(component.get("name", component["id"]))
        kind = html.escape(component.get("kind", "unknown"))
        version = html.escape(component.get("current_version") or "unknown")
        parts.append(f"<li><strong>{name}</strong> ({kind}); version: {version}")
        if component.get("version_evidence"):
            parts.append(" (" + html.escape(component["version_evidence"]) + ")")
        for record in component.get("version_observations", []):
            parts.extend(_version_markup(record))
        status = html.escape(component.get("update_status", "unknown"))
        update_kind = html.escape(component.get("update_kind") or "unknown")
        checked = html.escape(component.get("release_checked_at") or "never")
        parts.append(f"; update: {status}; release checked: {checked}")
        if "release_candidates" in component:
            for group in ("routine", "major", "unclassified"):
                candidate = component["release_candidates"].get(group)
                if candidate:
                    label = "previous " if component.get("release_stale") else ""
                    tag = html.escape(candidate["version"])
                    url = candidate["source_url"]
                    if url.startswith("https://"):
                        tag = f'<a href="{html.escape(url, quote=True)}">{tag}</a>'
                    parts.append(f"; {label}{group} release: {tag}")
        elif component.get("candidate_version"):
            parts.append(
                "; latest eligible release: "
                + html.escape(component["candidate_version"])
            )
        if component.get("update_kind"):
            parts.append(f"; change: {update_kind}")
        image_status = html.escape(component.get("image_status", "unknown"))
        parts.append(f"; image: {image_status}")
        parts.append(
            "; scanner coverage: "
            + html.escape(component.get("scan_coverage", "missing"))
        )
        parts.append(
            "; upstream advisory coverage: "
            + html.escape(component.get("advisory_coverage", "missing"))
        )
        if component.get("advisory_gap"):
            parts.append("; advisory gap: " + html.escape(component["advisory_gap"]))
        if component.get("advisory_reason"):
            parts.append(
                "; advisory reason: " + html.escape(component["advisory_reason"])
            )
        if component.get("advisory_error"):
            parts.append(
                "; advisory check failed: " + html.escape(component["advisory_error"])
            )
        if component.get("advisory_stale"):
            parts.append("; previous advisory evidence is stale")
        for finding in component.get("advisory_findings", []):
            label = (
                "Possible upstream advisory"
                if finding["match"] == "possible"
                else "Upstream advisory"
            )
            parts.append("<p>" + label + ": " + html.escape(finding["id"]))
            parts.append(
                "; severity: " + html.escape(finding.get("severity", "unknown"))
            )
            parts.append(
                "; aliases: " + html.escape(", ".join(finding.get("aliases", [])))
            )
            if finding.get("fixed_versions"):
                parts.append(
                    "; fixed versions: "
                    + html.escape(", ".join(finding["fixed_versions"]))
                )
            assessments = component.get("advisory_candidate_assessments", {}).get(
                finding["id"], {}
            )
            for group, assessment in assessments.items():
                version = html.escape(assessment["version"])
                status = html.escape(assessment["status"])
                reason = html.escape(assessment["reason"])
                parts.append(
                    f"; {html.escape(group)} release {version} ({status}). {reason}"
                )
            for provenance in finding.get("provenance", []):
                url = provenance.get("url")
                if isinstance(url, str) and url.startswith("https://"):
                    parts.append(
                        '; <a href="'
                        + html.escape(url, quote=True)
                        + '">'
                        + html.escape(provenance["id"])
                        + " source</a>"
                    )
                if provenance.get("affected_versions"):
                    parts.append(
                        "; affected versions: "
                        + html.escape(", ".join(provenance["affected_versions"]))
                    )
                parts.append(
                    "; affected ranges: "
                    + html.escape(json.dumps(provenance.get("affected_ranges", [])))
                )
            parts.append("</p>")
        source = component.get("release_source_url")
        if source and source.startswith("https://"):
            parts.append(
                f'; <a href="{html.escape(source, quote=True)}">release source</a>'
            )
        if component.get("update_reason"):
            parts.append("; " + html.escape(component["update_reason"]))
        if component.get("release_error"):
            parts.append(
                "; release check failed: " + html.escape(component["release_error"])
            )
        if component.get("release_stale"):
            parts.append("; previous release evidence is stale")
        if not component.get("deployments"):
            parts.append("; no matching container observed")
        else:
            parts.append("<ul>")
            for deployment in component["deployments"]:
                pod = html.escape(deployment.get("pod") or "unknown")
                image = html.escape(deployment.get("image") or "unknown")
                digest = html.escape(deployment.get("digest") or "unknown")
                platform = html.escape(deployment.get("platform") or "unknown")
                candidate_image = html.escape(
                    deployment.get("candidate_image_digest") or "unknown"
                )
                deployed_platform = html.escape(
                    deployment.get("deployed_platform_digest") or "unknown"
                )
                image_state = html.escape(deployment.get("image_status", "unknown"))
                parts.append(
                    f"<li>{pod}: image {image}; running digest {digest}; "
                    f"platform {platform}; image check {image_state}; "
                    f"deployed platform digest {deployed_platform}; "
                    f"current tag platform digest {candidate_image}"
                )
                for record in deployment.get("version_observations", []):
                    parts.extend(_version_markup(record))
                if deployment.get("image_update_kind") == "verified rebuild":
                    parts.append("; verified rebuild")
                if deployment.get("image_reason"):
                    parts.append("; " + html.escape(deployment["image_reason"]))
                if deployment.get("image_error"):
                    parts.append(
                        "; image check failed: "
                        + html.escape(deployment["image_error"])
                    )
                if deployment.get("image_stale"):
                    parts.append("; previous image evidence is stale")
                    history = deployment.get("image_update_history")
                    if history:
                        parts.append(
                            "; previous classification: "
                            + html.escape(history["image_update_kind"])
                            + " ("
                            + html.escape(
                                history.get("image_checked_at") or "unknown time"
                            )
                            + ")"
                        )
                parts.append(
                    "; scanner coverage: "
                    + html.escape(deployment.get("scan_coverage", "missing"))
                )
                if deployment.get("scan_source"):
                    parts.append(
                        "; scan source: "
                        + html.escape(deployment["scan_source"])
                        + "; report scanned: "
                        + html.escape(deployment.get("scan_reported_at") or "unknown")
                    )
                if deployment.get("scan_error"):
                    parts.append("; scanner: " + html.escape(deployment["scan_error"]))
                if deployment.get("scan_reason"):
                    parts.append(
                        "; scan reason: " + html.escape(deployment["scan_reason"])
                    )
                if deployment.get("scan_stale"):
                    parts.append("; previous scan findings are stale")
                for finding in deployment.get("scan_findings", []):
                    label = ", ".join(
                        (
                            finding["id"],
                            finding["severity"],
                            finding["package"],
                            finding.get("installed_version") or "unknown version",
                        )
                    )
                    parts.append("<p>Trivy finding: " + html.escape(label))
                    if finding.get("fixed_version"):
                        parts.append(
                            "; fixed version: " + html.escape(finding["fixed_version"])
                        )
                    parts.append(
                        "; assessed "
                        + html.escape(finding["digest"])
                        + " on "
                        + html.escape(finding["platform"])
                    )
                    if finding.get("scan_source"):
                        parts.append(
                            "; scan provenance: " + html.escape(finding["scan_source"])
                        )
                    source_url = finding.get("source_url")
                    if isinstance(source_url, str) and source_url.startswith(
                        "https://"
                    ):
                        parts.append(
                            '; <a href="'
                            + html.escape(source_url, quote=True)
                            + '">source</a>'
                        )
                    parts.append("</p>")
                parts.append("</li>")
            parts.append("</ul>")
        parts.append("</li>")
    parts.append("</ul>")
    return parts


def make_handler(
    store: Store,
    clock=lambda: datetime.now(timezone.utc),
    release_max_age=None,
    security_max_age=None,
    inventory_max_age=DEFAULT_INVENTORY_MAX_AGE,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = unquote(urlsplit(self.path).path)
            if path == "/healthz":
                self._json(200, {"status": "alive"})
                return
            if path == "/readyz":
                try:
                    cache_state = store.cache_state()
                except sqlite3.Error:
                    self._json(503, {"status": "unready"})
                else:
                    self._json(200, {"status": "ready", "cache_state": cache_state})
                return
            api_prefix = "/api/v1/services/"
            html_prefix = "/services/"
            api_service = path.startswith(api_prefix)
            detail = api_service or path.startswith(html_prefix)
            remainder = path.removeprefix(api_prefix if api_service else html_prefix)
            homepage = api_service and remainder.endswith("/homepage")
            # A newer job result must not freshen older rows during a refresh.
            jobs = store.read_jobs()
            if detail:
                service_id = (
                    remainder.removesuffix("/homepage") if homepage else remainder
                )
                raw = store.read_service(service_id, compact=homepage)
            else:
                raw = store.read_compact()
            snapshot = project(
                raw,
                jobs,
                clock,
                release_max_age,
                security_max_age,
                compact=not detail or homepage,
                inventory_max_age=inventory_max_age,
            )
            if path == "/api/v1/summary":
                self._json(200, _summary(snapshot))
            elif path == "/api/v1/services":
                self._json(
                    200,
                    {
                        "cache_state": _summary(snapshot)["cache_state"],
                        "checked_at": snapshot["checked_at"] if snapshot else None,
                        "services": snapshot["services"] if snapshot else [],
                    },
                )
            elif path == "/":
                self._html(200, _page(snapshot))
            elif path.startswith("/api/v1/services/"):
                self._service_api(path, snapshot)
            elif path.startswith("/services/"):
                service_id = path.removeprefix("/services/")
                service = self._find(snapshot, service_id)
                if service:
                    self._html(200, _page(snapshot, service))
                else:
                    self._not_found()
            else:
                self._not_found()

        def _find(self, snapshot: dict | None, service_id: str) -> dict | None:
            return (
                next(
                    (item for item in snapshot["services"] if item["id"] == service_id),
                    None,
                )
                if snapshot
                else None
            )

        def _service_api(self, path: str, snapshot: dict | None) -> None:
            remainder = path.removeprefix("/api/v1/services/")
            homepage = remainder.endswith("/homepage")
            service_id = remainder.removesuffix("/homepage") if homepage else remainder
            service = self._find(snapshot, service_id)
            if service is None:
                self._not_found()
            elif homepage:
                self._json(200, _homepage(service, snapshot["checked_at"]))
            else:
                self._json(200, {**service, "checked_at": snapshot["checked_at"]})

        def _json(self, status: int, value: dict) -> None:
            body = json.dumps(value, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, status: int, value: str) -> None:
            body = value.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _not_found(self) -> None:
            self._json(404, {"error": "not found"})

    return Handler


def create_server(
    store: Store,
    host: str,
    port: int,
    release_max_age=43200,
    security_max_age=172800,
    inventory_max_age=DEFAULT_INVENTORY_MAX_AGE,
) -> ThreadingHTTPServer:
    class BoundedServer(ThreadingHTTPServer):
        def __init__(self, *args, **kwargs):
            self.request_slots = BoundedSemaphore(4)
            super().__init__(*args, **kwargs)

        def process_request(self, request, client_address):
            self.request_slots.acquire()
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.request_slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.request_slots.release()

    return BoundedServer(
        (host, port),
        make_handler(
            store,
            release_max_age=release_max_age,
            security_max_age=security_max_age,
            inventory_max_age=inventory_max_age,
        ),
    )
