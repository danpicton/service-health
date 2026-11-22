"""Project persisted evidence into a current, read-only freshness view."""

import copy
from datetime import datetime, timezone

from service_health.aggregation import aggregate_security


def _expired(value, now, limit):
    if not value or limit is None:
        return False
    try:
        checked = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return True
    return (now - checked.astimezone(timezone.utc)).total_seconds() > limit


def project(snapshot, jobs, clock, release_max_age=43200, security_max_age=172800):
    """Never write age changes to SQLite; a later success can clear them."""
    if snapshot is None:
        return {"checked_at": None, "services": [], "jobs": jobs, "empty": True}
    now = clock().astimezone(timezone.utc)
    view = copy.deepcopy(snapshot)
    view["jobs"] = jobs
    release_error = jobs.get("release", {}).get("error")
    security_error = jobs.get("security", {}).get("error")
    if jobs.get("release", {}).get("state") == "interrupted":
        release_error = None
    if jobs.get("security", {}).get("state") == "interrupted":
        security_error = None
    inventory_error = jobs.get("inventory", {}).get("error")
    if release_error and "one or more provider checks failed" in release_error:
        release_error = None
    if security_error and "one or more provider checks failed" in security_error:
        security_error = None
    for service in view["services"]:
        if inventory_error:
            service["inventory_error"] = inventory_error
            service["inventory_stale"] = True
            service["inventory_status"] = "check failed"
        components = service.get("components", [])
        changed = False
        for component in components:
            if release_error:
                changed = True
                component["release_error"] = release_error
                component["update_status"] = "check failed"
                component["release_stale"] = bool(component.get("release_checked_at"))
            elif _expired(component.get("release_checked_at"), now, release_max_age):
                changed = True
                component["release_stale"] = True
                component["update_status"] = "unknown"
                component["update_reason"] = "release result expired"
            for deployment in component.get("deployments", []):
                if release_error:
                    changed = True
                    deployment["image_error"] = release_error
                    deployment["image_status"] = "check failed"
                    deployment["image_stale"] = bool(deployment.get("image_checked_at"))
                elif _expired(deployment.get("image_checked_at"), now, release_max_age):
                    changed = True
                    deployment["image_stale"] = True
                    deployment["image_status"] = "unknown"
                    deployment["image_reason"] = "image result expired"
                if security_error:
                    changed = True
                    deployment["scan_error"] = security_error
                    deployment["scan_coverage"] = "failed"
                    deployment["scan_stale"] = bool(deployment.get("scan_checked_at"))
                elif _expired(deployment.get("scan_checked_at"), now, security_max_age):
                    changed = True
                    deployment["scan_coverage"] = "missing"
                    deployment["scan_stale"] = True
                    deployment["scan_error"] = "scan result expired"
            if security_error:
                changed = True
                component["advisory_error"] = security_error
                component["advisory_coverage"] = "failed"
                component["advisory_stale"] = bool(component.get("advisory_checked_at"))
            elif _expired(component.get("advisory_checked_at"), now, security_max_age):
                changed = True
                component["advisory_coverage"] = "missing"
                component["advisory_stale"] = True
                component["advisory_gap"] = "advisory result expired"
            if not changed:
                continue
            deployments = component.get("deployments", [])
            image_statuses = {d.get("image_status", "unknown") for d in deployments}
            component["image_status"] = next(
                (
                    s
                    for s in (
                        "image rebuild available",
                        "check failed",
                        "unknown",
                        "up to date",
                    )
                    if s in image_statuses
                ),
                "unknown",
            )
            component["image_coverage_complete"] = bool(
                deployments
            ) and image_statuses <= {"image rebuild available", "up to date"}
            component["image_stale"] = any(
                d.get("image_stale", False) for d in deployments
            )
            coverages = [d.get("scan_coverage", "missing") for d in deployments]
            component["scan_coverage"] = (
                "complete"
                if coverages and all(c == "complete" for c in coverages)
                else "failed"
                if "failed" in coverages
                else "missing"
            )
            component["scan_stale"] = any(
                d.get("scan_stale", False) for d in deployments
            )
        if not changed:
            stale = any(
                service.get(name, False)
                for name in (
                    "inventory_stale",
                    "release_stale",
                    "image_stale",
                    "scan_stale",
                    "advisory_stale",
                )
            )
            if stale:
                service["stale"] = True
            continue
        update_statuses = {c.get("update_status", "unknown") for c in components}
        service["update_status"] = next(
            (
                s
                for s in ("update available", "check failed", "unknown", "up to date")
                if s in update_statuses
            ),
            "unknown",
        )
        service["update_coverage_complete"] = bool(components) and update_statuses <= {
            "update available",
            "up to date",
        }
        service["release_stale"] = any(
            c.get("release_stale", False) for c in components
        )
        image_statuses = {c.get("image_status", "unknown") for c in components}
        service["image_status"] = next(
            (
                s
                for s in (
                    "image rebuild available",
                    "check failed",
                    "unknown",
                    "up to date",
                )
                if s in image_statuses
            ),
            "unknown",
        )
        service["image_coverage_complete"] = bool(components) and all(
            c.get("image_coverage_complete", False) for c in components
        )
        service["image_stale"] = any(c.get("image_stale", False) for c in components)
        service["scan_stale"] = any(c.get("scan_stale", False) for c in components)
        aggregate_security(service)
        service["stale"] = any(
            service.get(name, False)
            for name in (
                "inventory_stale",
                "release_stale",
                "image_stale",
                "scan_stale",
                "advisory_stale",
            )
        )
    return view
