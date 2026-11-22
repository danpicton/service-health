"""Independent, bounded collection jobs sharing one database-wide cycle lock."""

import fcntl
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from service_health.advisories import apply_advisory_checks
from service_health.github_cache import GitHubReleases
from service_health.images import apply_image_checks
from service_health.releases import apply_release_checks
from service_health.scanner import apply_scan_checks


def _stamp(clock):
    return clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def run_job(
    store,
    name,
    catalog_path,
    scanner=None,
    external_reports=None,
    scan_workers=2,
    clock=lambda: datetime.now(timezone.utc),
    github_token_file=None,
):
    """Run one cycle. A failed cycle retains the last committed snapshot."""
    if name not in ("release", "security"):
        raise ValueError("unknown collection job")
    lock_path = Path(str(store.path) + ".collection.lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempted = _stamp(clock)
        previous = store.read_jobs().get(name, {})
        retry_failed = bool(
            previous.get("error") and "provider checks failed" in previous["error"]
        )
        scan_retry = retry_failed or previous.get("state") in ("running", "interrupted")
        store.start_job(name, attempted)
        try:
            snapshot = store.read()
            if snapshot is None:
                raise ValueError("collection requires a cached inventory")
            catalog = json.loads(Path(catalog_path).read_text())
            if name == "release":
                releases = GitHubReleases(store, github_token_file, clock)
                services = apply_release_checks(
                    snapshot["services"],
                    catalog,
                    fetch_releases=releases,
                    clock=clock,
                    only_failed=retry_failed,
                )
                services = apply_image_checks(
                    services, clock=clock, only_failed=retry_failed
                )
            else:
                if scanner is None:
                    raise ValueError("security job requires a scanner")
                services = apply_scan_checks(
                    snapshot["services"],
                    scanner,
                    clock,
                    scan_workers,
                    external_reports,
                    progress=lambda partial: store.commit_evidence(
                        _stamp(clock), partial
                    ),
                    only_failed=scan_retry,
                )
                services = apply_advisory_checks(
                    services, catalog, clock=clock, only_failed=scan_retry
                )
            inventory_changed = store.commit_evidence(attempted, services)
            if inventory_changed:
                raise RuntimeError(
                    "inventory changed during collection; retry required"
                )
            failed = (
                any(
                    component.get("update_status") == "check failed"
                    or any(
                        deployment.get("image_status") == "check failed"
                        for deployment in component.get("deployments", [])
                    )
                    for service in services
                    for component in service.get("components", [])
                )
                if name == "release"
                else any(
                    component.get("scan_coverage") == "failed"
                    or component.get("advisory_coverage") == "failed"
                    for service in services
                    for component in service.get("components", [])
                )
            )
            if failed:
                raise RuntimeError(
                    "one or more provider checks failed; see component errors"
                )
        except Exception as error:
            store.record_job(name, attempted, f"{type(error).__name__}: {error}")
            raise
        else:
            store.record_job(name, attempted, None)


def run_schedule(
    store,
    catalog_path,
    scanner,
    external_reports=None,
    release_interval=21600,
    security_interval=86400,
    retry_initial=60,
    retry_max=3600,
    scan_workers=2,
    clock=lambda: datetime.now(timezone.utc),
    sleep=time.sleep,
    stop=lambda: False,
    github_token_file=None,
):
    """Run due jobs serially; failures back off exponentially per job."""
    if min(release_interval, security_interval, retry_initial, retry_max) < 1:
        raise ValueError("schedule intervals and retry delays must be positive")
    if retry_max < retry_initial:
        raise ValueError("maximum retry delay must meet the initial delay")
    intervals = {"release": release_interval, "security": security_interval}
    jobs = store.read_jobs()
    next_run = {}
    for name in intervals:
        state = jobs.get(name)
        if state and state["state"] == "interrupted":
            next_run[name] = 0
        elif state and state["attempted_at"]:
            attempted = datetime.fromisoformat(
                state["attempted_at"].replace("Z", "+00:00")
            )
            delay = (
                min(retry_max, retry_initial * 2 ** (state["failures"] - 1))
                if state["error"]
                else intervals[name]
            )
            next_run[name] = attempted.timestamp() + delay
        else:
            next_run[name] = 0
    while not stop():
        now = clock().timestamp()
        due = [name for name in intervals if next_run[name] <= now]
        if not due:
            sleep(min(max(0, min(next_run.values()) - now), 60))
            continue
        for name in due:
            if stop():
                break
            try:
                run_job(
                    store,
                    name,
                    catalog_path,
                    scanner,
                    external_reports,
                    scan_workers,
                    clock,
                    github_token_file,
                )
            except BlockingIOError:
                next_run[name] = clock().timestamp() + retry_initial
            except Exception:
                failures = store.read_jobs()[name]["failures"]
                next_run[name] = clock().timestamp() + min(
                    retry_max, retry_initial * 2 ** (failures - 1)
                )
            else:
                next_run[name] = clock().timestamp() + intervals[name]
