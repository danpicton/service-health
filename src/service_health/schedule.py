"""Independent, bounded collection jobs sharing one database-wide cycle lock."""

import fcntl
import json
import time
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path

from service_health.advisories import apply_advisory_checks
from service_health.github_cache import GitHubReleases
from service_health.images import apply_image_checks
from service_health.releases import apply_release_checks
from service_health.scanner import apply_scan_checks
from service_health.security_schedule import SecurityWork, job_time

_PROVIDER_FAILURE = "one or more provider checks failed; see component errors"


def _stamp(clock):
    return clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _full_at(job):
    if job.get("full_attempted_at"):
        return job["full_attempted_at"]
    if job.get("state") in ("running", "interrupted"):
        return job.get("attempted_at")
    return None


def _full_due(full_at, interval):
    return job_time(full_at) + interval if full_at else 0


def _time_stamp(timestamp):
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def run_job(
    store,
    name,
    catalog_path,
    scanner=None,
    external_reports=None,
    scan_workers=2,
    clock=lambda: datetime.now(timezone.utc),
    github_token_file=None,
    security_interval=86400,
    retry_initial=60,
    retry_max=3600,
):
    """Run one cycle. A failed cycle retains the last committed snapshot."""
    if name not in ("release", "security"):
        raise ValueError("unknown collection job")
    lock_path = Path(str(store.path) + ".collection.lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempted = _stamp(clock)
        previous = store.read_jobs().get(name, {})
        full_at = _full_at(previous) if name == "security" else None
        retry_failed = bool(
            previous.get("error") and "provider checks failed" in previous["error"]
        )
        if name == "release":
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
                now = job_time(attempted)
                full = now >= _full_due(full_at, security_interval)
                work = SecurityWork(
                    attempted if full else full_at,
                    now,
                    retry_initial,
                    retry_max,
                    full=full,
                )
                work.plan(snapshot["services"], catalog, scanner, external_reports)
                if not (
                    full
                    or work.scans
                    or work.advisories
                    or previous.get("state") == "failed"
                ):
                    return
                store.start_job(name, attempted, full_attempted_at=work.full_at)
                full_at = work.full_at
                services = apply_scan_checks(
                    snapshot["services"],
                    scanner,
                    clock,
                    scan_workers,
                    external_reports,
                    progress=lambda partial: store.commit_evidence(
                        _stamp(clock), partial
                    ),
                    select=work.select_scan,
                    on_checked=lambda deployment: work.record_scan(
                        deployment, clock().timestamp()
                    ),
                )
                services = apply_advisory_checks(
                    services, catalog, clock=clock, select=work.select_advisory
                )
                work.record_advisories(services, clock().timestamp())
            inventory_changed = store.commit_evidence(attempted, services)
            if inventory_changed:
                raise RuntimeError(
                    "inventory changed during collection; retry required"
                )
            if name == "release" and any(
                component.get("update_status") == "check failed"
                or any(
                    deployment.get("image_status") == "check failed"
                    for deployment in component.get("deployments", [])
                )
                for service in services
                for component in service.get("components", [])
            ):
                raise RuntimeError(_PROVIDER_FAILURE)
            if name == "security":
                full_due = _full_due(full_at, security_interval)
                retries = SecurityWork(
                    full_at, clock().timestamp(), retry_initial, retry_max, full=False
                )
                retries.plan(services, catalog, scanner, external_reports)
                store.record_job(
                    name,
                    attempted,
                    None,
                    state="completed"
                    if all(service.get("coverage_complete") for service in services)
                    else "partial",
                    security_deadlines=(
                        _time_stamp(full_due),
                        _time_stamp(retries.next_at)
                        if isfinite(retries.next_at) and retries.next_at < full_due
                        else None,
                    ),
                )
                return
        except Exception as error:
            deadlines = None
            if name == "security":
                retry_at = clock().timestamp() + _retry_delay(
                    {"failures": previous.get("failures", 0) + 1},
                    retry_initial,
                    retry_max,
                )
                retry_at = _security_backoff_until(
                    {"full_attempted_at": full_at},
                    job_time(attempted),
                    retry_at,
                    security_interval,
                )
                full_due = _full_due(full_at, security_interval)
                deadlines = (
                    _time_stamp(max(full_due, retry_at)),
                    _time_stamp(retry_at) if retry_at < full_due else None,
                )
            store.record_job(
                name,
                attempted,
                f"{type(error).__name__}: {error}",
                state="failed" if name == "security" else "completed",
                security_deadlines=deadlines,
            )
            raise
        else:
            store.record_job(name, attempted, None)


def _next_security_run(
    store,
    catalog_path,
    scanner,
    external_reports,
    interval,
    retry_initial,
    retry_max,
    now,
):
    job = store.read_jobs().get("security", {})
    full_at = _full_at(job)
    full_due = _full_due(full_at, interval)
    due = (
        min(full_due, job_time(job["next_retry_at"]))
        if job.get("state") == "failed" and job.get("next_retry_at")
        else full_due
    )
    if full_due <= now:
        return full_due
    snapshot = store.read_compact()
    if snapshot is None:
        return due
    try:
        catalog = json.loads(Path(catalog_path).read_text())
        work = SecurityWork(full_at, now, retry_initial, retry_max, full=False)
        work.plan(snapshot["services"], catalog, scanner, external_reports)
    except (OSError, ValueError, KeyError, AttributeError, TypeError):
        # Let the real cycle record catalog errors at its deadline.
        return due
    return min(due, work.next_at)


def _retry_delay(job, initial, maximum):
    failures = job.get("failures", 1)
    exponent = min(maximum.bit_length(), max(0, failures - 1))
    return min(maximum, initial * 2**exponent)


def _resume_time(job, interval, initial, maximum):
    if job.get("state") == "interrupted" or not job.get("attempted_at"):
        return 0
    delay = _retry_delay(job, initial, maximum) if job["error"] else interval
    return job_time(job["attempted_at"]) + delay


def _security_backoff_until(job, attempted_at, retry_at, interval):
    full_at = _full_at(job)
    if full_at:
        full_due = _full_due(full_at, interval)
        # A failed retry cannot defer the next cycle. A failure while starting
        # or running the full cycle itself still needs infrastructure backoff.
        if job_time(full_at) < attempted_at < full_due:
            return min(retry_at, full_due)
    return retry_at


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
    jobs = store.read_jobs()
    release_at = _resume_time(
        jobs.get("release", {}), release_interval, retry_initial, retry_max
    )
    security_blocked_until = 0
    security = jobs.get("security", {})
    if (
        security.get("error")
        and _PROVIDER_FAILURE not in security["error"]
        and security["state"] != "interrupted"
    ):
        published = security.get("next_retry_at") or security.get("next_full_at")
        resume_at = (
            job_time(published)
            if published
            else _resume_time(security, security_interval, retry_initial, retry_max)
        )
        security_blocked_until = _security_backoff_until(
            security,
            job_time(security["attempted_at"]),
            resume_at,
            security_interval,
        )
    while not stop():
        now = clock().timestamp()
        security_at = max(
            security_blocked_until,
            _next_security_run(
                store,
                catalog_path,
                scanner,
                external_reports,
                security_interval,
                retry_initial,
                retry_max,
                now,
            ),
        )
        if min(release_at, security_at) > now:
            sleep(min(min(release_at, security_at) - now, 60))
            continue
        name = "release" if release_at <= now else "security"
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
                security_interval,
                retry_initial,
                retry_max,
            )
        except BlockingIOError:
            delay = retry_initial
        except Exception:
            delay = _retry_delay(
                store.read_jobs().get(name, {}), retry_initial, retry_max
            )
        else:
            delay = release_interval if name == "release" else 0
        if name == "release":
            release_at = clock().timestamp() + delay
        elif delay:
            security_blocked_until = _security_backoff_until(
                store.read_jobs().get("security", {}),
                now,
                clock().timestamp() + delay,
                security_interval,
            )
        else:
            security_blocked_until = 0
