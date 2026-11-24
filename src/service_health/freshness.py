"""Project persisted evidence into a current, read-only freshness view."""

from datetime import datetime, timezone

from service_health.advisories import candidate_assessments
from service_health.aggregation import (
    aggregate_security,
    coverage_state,
    security_status,
)
from service_health.images import retain_image_update_history

DEFAULT_INVENTORY_MAX_AGE = 7200


def _expired(value, now, limit):
    if not value or limit is None:
        return False
    try:
        checked = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return True
    return (now - checked.astimezone(timezone.utc)).total_seconds() > limit


def _compact_security(service):
    """Recalculate coverage without discarding stored finding counts."""
    components = service.get("components", [])
    for component in components:
        complete = (
            component.get("scan_coverage") == "complete"
            and component.get("advisory_coverage") == "complete"
        )
        component["coverage_complete"] = complete
        component["security_status"] = security_status(
            component.get("confirmed_finding_count", 0),
            component.get("scan_coverage"),
            component.get("advisory_coverage"),
            complete,
        )
    for name in ("scan", "advisory"):
        service[f"{name}_coverage"] = coverage_state(
            [component.get(f"{name}_coverage") for component in components]
        )
    service["coverage_complete"] = bool(components) and all(
        component["coverage_complete"] for component in components
    )
    service["advisory_stale"] = any(
        component.get("advisory_stale", False) for component in components
    )
    service["security_status"] = security_status(
        service.get("confirmed_finding_count", 0),
        service["scan_coverage"],
        service["advisory_coverage"],
        service["coverage_complete"],
    )


def _mark_inventory_stale(service, error, attempted_at):
    service["inventory_stale"] = True
    service["inventory_status"] = "check failed" if error else "unknown"
    service["inventory_error"] = error
    service["stale"] = True
    components = service.get("components", [])
    for record in [service, *components]:
        if record.get("update_status") in ("up to date", "update available"):
            record["update_status"] = "unknown"
            record["update_reason"] = error or "inventory observation expired"
        if record.get("release_checked_at"):
            record["release_stale"] = True
        if record.get("image_status") in ("up to date", "image update available"):
            record["image_status"] = "unknown"
        if record.get("security_status") == "no known findings":
            record["security_status"] = "incomplete coverage"
        record["update_coverage_complete"] = False
        record["image_coverage_complete"] = False
        record["coverage_complete"] = False
    service["current_version"] = None
    for component in components:
        component["current_version"] = None
        component["version_state"] = "unknown"
        component["version_evidence"] = error or "inventory observation expired"
        if "advisory_version" in component:
            component["advisory_version"] = None
        for owner in [component, *component.get("deployments", [])]:
            for observation in owner.get("version_observations", []):
                observation.update(
                    reported=None,
                    normalized=None,
                    outcome="check failed" if error else "expired",
                    reason=error or "inventory observation expired",
                )
                if error:
                    observation["checked_at"] = attempted_at
        for deployment in component.get("deployments", []):
            if deployment.get("image_status") == "image update available":
                retain_image_update_history(deployment)
                deployment.update(
                    image_status="unknown",
                    image_reason=error or "inventory observation expired",
                    image_stale=True,
                )
                component["image_stale"] = service["image_stale"] = True
            deployment["application_version"] = None
            deployment["version_state"] = "unknown"
            if deployment.get("image_status") == "up to date":
                deployment["image_status"] = "unknown"


def _project_security_check(record, prefix, job_error, now, max_age):
    coverage_key = f"{prefix}_coverage"
    error_key = f"{prefix}_error"
    stale_key = f"{prefix}_stale"
    checked = record.get(f"{prefix}_checked_at")
    coverage = record.get(coverage_key)
    known_gap = coverage == "missing" and record.get(f"{prefix}_outcome")
    if job_error and not known_gap:
        record[error_key] = record.get(error_key) or job_error
        record[coverage_key] = "failed"
        record[stale_key] = bool(checked)
        return True
    if _expired(checked, now, max_age):
        if coverage == "complete":
            record[coverage_key] = "missing"
            reason_key = "advisory_gap" if prefix == "advisory" else error_key
            record[reason_key] = f"{prefix} result expired"
        record[stale_key] = True
        return True
    return False


def project(
    snapshot,
    jobs,
    clock,
    release_max_age=43200,
    security_max_age=172800,
    compact=False,
    inventory_max_age=DEFAULT_INVENTORY_MAX_AGE,
):
    """Never write age changes to SQLite; a later success can clear them."""
    if snapshot is None:
        return {"checked_at": None, "services": [], "jobs": jobs, "empty": True}
    now = clock().astimezone(timezone.utc)
    # Store reads return fresh objects; projecting them does not mutate SQLite.
    view = snapshot
    view["jobs"] = jobs
    release_error = jobs.get("release", {}).get("error")
    security_error = jobs.get("security", {}).get("error")
    if jobs.get("release", {}).get("state") == "interrupted":
        release_error = None
    if jobs.get("security", {}).get("state") == "interrupted":
        security_error = None
    inventory = jobs.get("inventory", {})
    inventory_error = inventory.get("error")
    inventory_stale = inventory_error or _expired(
        inventory.get("succeeded_at"), now, inventory_max_age
    )
    if release_error and "one or more provider checks failed" in release_error:
        release_error = None
    if security_error and "one or more provider checks failed" in security_error:
        security_error = None
    for service in view["services"]:
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
                    retain_image_update_history(deployment)
                    deployment["image_stale"] = True
                    deployment["image_status"] = "unknown"
                    deployment["image_reason"] = "image result expired"
                if deployment.get("image_stale") and deployment.get(
                    "image_update_kind"
                ):
                    retain_image_update_history(deployment)
                    deployment["image_reason"] = (
                        deployment.get("image_error") or "image result expired"
                    )
                changed |= _project_security_check(
                    deployment, "scan", security_error, now, security_max_age
                )
            changed |= _project_security_check(
                component, "advisory", security_error, now, security_max_age
            )
            if not changed:
                continue
            deployments = component.get("deployments", [])
            image_statuses = {d.get("image_status", "unknown") for d in deployments}
            component["image_status"] = next(
                (
                    s
                    for s in (
                        "image update available",
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
            ) and image_statuses <= {"image update available", "up to date"}
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
                    "image update available",
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
        if compact:
            _compact_security(service)
        else:
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
    if inventory_stale:
        for service in view["services"]:
            _mark_inventory_stale(
                service, inventory_error, inventory.get("attempted_at")
            )
    if not compact:
        for service in view["services"]:
            for component in service.get("components", []):
                assessments = candidate_assessments(
                    component, service.get("inventory_stale")
                )
                if assessments:
                    component["advisory_candidate_assessments"] = assessments
    return view
