"""Choose full-cycle and retry work from identity-bound security evidence."""

import hashlib
import json
from datetime import datetime
from math import inf

from service_health.scanner import scan_identity
from service_health.security_outcomes import SecurityOutcome

MAX_SECURITY_RETRIES = 3


def job_time(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _scan_configuration(scanner, external_reports):
    return _fingerprint(
        [
            type(scanner).__name__,
            str(getattr(scanner, "binary", "")),
            str(getattr(scanner, "cache_dir", "")),
            getattr(scanner, "timeout", None),
            type(external_reports).__name__,
            str(getattr(external_reports, "directory", "")),
            getattr(external_reports, "max_age", None),
        ]
    )


class SecurityWork:
    """Track each target's first attempt and bounded retries within one full cycle."""

    def __init__(self, full_at, attempted_at, retry_initial, retry_max, *, full):
        self.full_at = full_at
        self.attempted_at = attempted_at
        self.retry_initial = retry_initial
        self.retry_max = retry_max
        self.full = full
        self.next_at = inf
        self.scans = {}
        self.advisories = {}

    def plan(self, services, catalog, scanner, external_reports):
        scan_config = _scan_configuration(scanner, external_reports)
        self.use_external_reports = external_reports is not None
        sources = {
            (service["id"], component["id"]): component.get("advisory_source")
            for service in catalog
            for component in service.get("components", [])
        }
        scan_groups = {}
        for service in services:
            for component in service.get("components", []):
                key = (service["id"], component["id"])
                config = _fingerprint(
                    [
                        sources.get(key),
                        component.get(
                            "advisory_version", component.get("current_version")
                        ),
                    ]
                )
                self._add(self.advisories, key, [component], "advisory", config)
                for deployment in component.get("deployments", []):
                    key = scan_identity(deployment, self.use_external_reports)
                    scan_groups.setdefault(key, []).append(deployment)
        for key, group in scan_groups.items():
            self._add(self.scans, key, group, "scan", scan_config)

    def _add(self, selected, key, group, prefix, config):
        if self.full:
            due_at, failures = 0, 0
        else:
            matches = [
                attempt
                for item in group
                if (attempt := item.get(f"{prefix}_attempt"))
                and attempt["full_at"] == self.full_at
                and attempt["configuration"] == config
            ]
            if matches:
                latest = max(matches, key=lambda item: (item["at"], item["failures"]))
                failures = latest["failures"]
                if not 0 < failures <= MAX_SECURITY_RETRIES:
                    return
                due_at = latest["at"] + min(
                    self.retry_max, self.retry_initial * 2 ** (failures - 1)
                )
            elif any(
                not item.get(f"{prefix}_attempt")
                and item.get(f"{prefix}_coverage") == "complete"
                and (checked_at := item.get(f"{prefix}_checked_at"))
                and job_time(checked_at) >= job_time(self.full_at)
                for item in group
            ):
                # A pre-upgrade worker may have persisted progress but no attempt.
                return
            else:
                due_at, failures = 0, 0
        self.next_at = min(self.next_at, due_at)
        if due_at <= self.attempted_at:
            selected[key] = {
                "full_at": self.full_at,
                "configuration": config,
                "failures": failures,
            }

    def select_scan(self, deployment):
        return scan_identity(deployment, self.use_external_reports) in self.scans

    def record_scan(self, deployment, completed_at):
        key = scan_identity(deployment, self.use_external_reports)
        self._record(deployment, "scan", self.scans[key], completed_at)

    def select_advisory(self, service, component):
        return (service["id"], component["id"]) in self.advisories

    def record_advisories(self, services, completed_at):
        for service in services:
            for component in service.get("components", []):
                attempt = self.advisories.get((service["id"], component["id"]))
                if attempt is not None:
                    self._record(component, "advisory", attempt, completed_at)

    @staticmethod
    def _record(item, prefix, attempt, completed_at):
        retryable = item.get(f"{prefix}_outcome") == SecurityOutcome.TRANSIENT_FAILURE
        item[f"{prefix}_attempt"] = {
            **attempt,
            "at": completed_at,
            "failures": attempt["failures"] + 1 if retryable else 0,
        }
