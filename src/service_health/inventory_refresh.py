"""Merge fresh deployment observations with identity-bound cached evidence."""

import fcntl
import time
from datetime import datetime, timezone
from pathlib import Path

from service_health.aggregation import aggregate_security

_RELEASE_FIELDS = (
    "update_status",
    "update_reason",
    "candidate_version",
    "update_kind",
    "release_source_url",
    "release_checked_at",
    "release_error",
    "release_stale",
)
_ADVISORY_FIELDS = (
    "advisory_coverage",
    "advisory_gap",
    "advisory_error",
    "advisory_stale",
    "advisory_findings",
    "advisory_checked_at",
    "advisory_identity",
)
_IMAGE_FIELDS = (
    "image_status",
    "image_reason",
    "image_error",
    "image_stale",
    "image_checked_at",
    "candidate_image_digest",
    "deployed_platform_digest",
)
_SCAN_FIELDS = (
    "scan_coverage",
    "scan_error",
    "scan_findings",
    "scan_digest",
    "scan_platform",
    "scan_checked_at",
    "scan_source",
    "scan_reported_at",
    "scan_stale",
)


def _copy_fields(target, previous, names):
    for name in names:
        if name in previous:
            target[name] = previous[name]


def _deployment_identity(deployment):
    identity = tuple(deployment.get(key) for key in ("image", "digest", "platform"))
    return identity if all(identity) else None


def _coverage(values):
    if values and all(value == "complete" for value in values):
        return "complete"
    return "failed" if "failed" in values else "missing"


def _status(values, precedence, default="unknown"):
    present = set(values)
    return next((value for value in precedence if value in present), default)


def merge_inventory(services, previous):
    """Carry evidence only when its assessed identity still matches."""
    old_services = {service["id"]: service for service in previous or []}
    for service in services:
        old_components = {
            component["id"]: component
            for component in old_services.get(service["id"], {}).get("components", [])
        }
        for component in service["components"]:
            old = old_components.get(component["id"], {})
            if component.get("release_identity") and (
                component["release_identity"] == old.get("release_identity")
            ):
                _copy_fields(component, old, _RELEASE_FIELDS)
            if component.get("advisory_source_identity") and (
                component["advisory_source_identity"]
                == old.get("advisory_source_identity")
            ):
                _copy_fields(component, old, _ADVISORY_FIELDS)
            old_deployments = {
                _deployment_identity(item): item
                for item in old.get("deployments", [])
                if _deployment_identity(item)
            }
            for deployment in component["deployments"]:
                identity = _deployment_identity(deployment)
                if identity and identity in old_deployments:
                    old_deployment = old_deployments[identity]
                    _copy_fields(deployment, old_deployment, _IMAGE_FIELDS)
                    _copy_fields(deployment, old_deployment, _SCAN_FIELDS)
                else:
                    deployment["image_status"] = "unknown"
                    deployment["scan_coverage"] = "missing"
            deployments = component["deployments"]
            component["update_status"] = component.get("update_status", "unknown")
            component["release_stale"] = component.get("release_stale", False)
            component["advisory_coverage"] = component.get(
                "advisory_coverage", "missing"
            )
            component["advisory_stale"] = component.get("advisory_stale", False)
            component["advisory_findings"] = component.get("advisory_findings", [])
            component["image_status"] = _status(
                (item.get("image_status", "unknown") for item in deployments),
                ("image rebuild available", "check failed", "unknown", "up to date"),
            )
            component["image_coverage_complete"] = bool(deployments) and all(
                item.get("image_status") in ("image rebuild available", "up to date")
                for item in deployments
            )
            component["image_stale"] = any(
                item.get("image_stale", False) for item in deployments
            )
            component["image_checked_at"] = min(
                (
                    item["image_checked_at"]
                    for item in deployments
                    if item.get("image_checked_at")
                ),
                default=None,
            )
            component["candidate_image_digest"] = (
                deployments[0].get("candidate_image_digest")
                if len(deployments) == 1
                else None
            )
            component["scan_coverage"] = _coverage(
                [item.get("scan_coverage", "missing") for item in deployments]
            )
            component["scan_stale"] = any(
                item.get("scan_stale", False) for item in deployments
            )
            component["scan_findings"] = [
                finding
                for item in deployments
                for finding in item.get("scan_findings", [])
            ]
        components = service["components"]
        service["update_status"] = _status(
            (item["update_status"] for item in components),
            ("update available", "check failed", "unknown", "up to date"),
        )
        service["update_coverage_complete"] = bool(components) and all(
            item["update_status"] in ("update available", "up to date")
            for item in components
        )
        service["release_stale"] = any(item["release_stale"] for item in components)
        service["release_checked_at"] = min(
            (
                item["release_checked_at"]
                for item in components
                if item.get("release_checked_at")
            ),
            default=None,
        )
        service["candidate_version"] = (
            components[0].get("candidate_version") if len(components) == 1 else None
        )
        service["update_kind"] = (
            components[0].get("update_kind") if len(components) == 1 else None
        )
        service["image_status"] = _status(
            (item["image_status"] for item in components),
            ("image rebuild available", "check failed", "unknown", "up to date"),
        )
        service["image_coverage_complete"] = bool(components) and all(
            item["image_coverage_complete"] for item in components
        )
        service["image_stale"] = any(item["image_stale"] for item in components)
        service["image_checked_at"] = min(
            (
                item["image_checked_at"]
                for item in components
                if item.get("image_checked_at")
            ),
            default=None,
        )
        service["candidate_image_digest"] = (
            components[0].get("candidate_image_digest")
            if len(components) == 1
            else None
        )
        service["scan_coverage"] = _coverage(
            [item["scan_coverage"] for item in components]
        )
        service["scan_stale"] = any(item["scan_stale"] for item in components)
        service["scan_checked_at"] = min(
            (
                deployment["scan_checked_at"]
                for item in components
                for deployment in item["deployments"]
                if deployment.get("scan_checked_at")
            ),
            default=None,
        )
        service["scan_sources"] = sorted(
            {
                deployment["scan_source"]
                for item in components
                for deployment in item["deployments"]
                if deployment.get("scan_source")
            }
        )
        service["advisory_checked_at"] = min(
            (
                item["advisory_checked_at"]
                for item in components
                if item.get("advisory_checked_at")
            ),
            default=None,
        )
        aggregate_security(service)
    return services


def refresh_inventory(
    store,
    collect,
    clock=lambda: datetime.now(timezone.utc),
    wait_seconds=120,
    monotonic=time.monotonic,
    sleep=time.sleep,
    cancelled=lambda: False,
):
    """Wait briefly for a commit slot, then observe and publish current pods."""
    attempted = clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        lock_path = Path(str(store.path) + ".inventory.lock")
        deadline = monotonic() + wait_seconds
        with lock_path.open("w") as lock:
            while True:
                if cancelled():
                    raise TimeoutError(
                        "inventory refresh cancelled while waiting for lock"
                    )
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise TimeoutError(
                            "inventory commit lock wait exceeded deadline"
                        )
                    sleep(min(0.25, remaining))
            fresh = collect()
            previous = store.read()
            merged = merge_inventory(fresh, previous["services"] if previous else None)
            succeeded = (
                clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            store.replace(succeeded, merged)
            store.record_job("inventory", succeeded, None)
    except Exception as error:
        store.record_job("inventory", attempted, f"{type(error).__name__}: {error}")
        raise
