"""Scheduled Trivy vulnerability checks of observed, pullable image digests."""

import copy
import fcntl
import json
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from service_health.aggregation import aggregate_security
from service_health.security_outcomes import (
    SecurityCheckError,
    SecurityOutcome,
    provider_failure,
)
from service_health.trivy_command import TrivyFailure, run_trivy

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
_PLATFORM = re.compile(r"[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?$")
_MAX_REPORT_BYTES = 20 * 1024 * 1024


def _timestamp(clock):
    return clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _target(deployment):
    image, digest, platform = (
        deployment.get("image"),
        deployment.get("digest"),
        deployment.get("platform"),
    )
    if (
        not isinstance(image, str)
        or not isinstance(digest, str)
        or not isinstance(platform, str)
    ):
        return None
    if not _DIGEST.fullmatch(digest) or not _PLATFORM.fullmatch(platform):
        return None
    # Strip a mutable tag or existing digest; keep an explicit registry/repository.
    repository = image.split("@", 1)[0]
    tail = repository.rsplit("/", 1)[-1]
    if ":" in tail:
        repository = repository[: -(len(tail) - tail.rfind(":"))]
    host = repository.split("/", 1)[0]
    if not repository or host == "localhost" or host.startswith(("localhost:", "127.")):
        return None
    return f"{repository}@{digest}"


def scan_identity(deployment, use_external_reports=False):
    """Identify the inputs shared by remote checks and external report lookup."""
    if not use_external_reports and (target := _target(deployment)):
        return (target, deployment["platform"])
    return tuple(deployment.get(field) for field in ("image", "digest", "platform"))


class ExternalReports:
    """Read bounded, operator-supplied Trivy reports from a non-secret directory."""

    def __init__(self, directory, max_age=172800):
        if max_age < 1:
            raise ValueError("external report maximum age must be positive")
        self.directory = Path(directory)
        self.max_age = max_age

    def lookup(self, deployment, now):
        image = deployment.get("image")
        digest = deployment.get("digest")
        platform = deployment.get("platform")
        if not isinstance(image, str) or not image:
            return None, "deployed image identity unavailable"
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            return None, "deployed image digest unavailable"
        if not isinstance(platform, str) or not _PLATFORM.fullmatch(platform):
            return None, "deployed image platform unavailable"
        try:
            paths = sorted(self.directory.iterdir())
        except OSError:
            return None, "external report directory unavailable"
        if len(paths) > 128:
            return None, "external report directory exceeds 128 entries"
        candidates = []
        for path in paths:
            if path.suffix != ".json" or path.is_symlink() or not path.is_file():
                continue
            try:
                if path.stat().st_size > _MAX_REPORT_BYTES:
                    continue
                envelope = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                continue
            if isinstance(envelope, dict) and envelope.get("image") == image:
                candidates.append(envelope)
        matching = [
            item
            for item in candidates
            if item.get("digest") == digest and item.get("platform") == platform
        ]
        if len(matching) != 1:
            reason = (
                "ambiguous external reports for deployed image"
                if len(matching) > 1
                else "external report digest/platform differs from deployed image"
                if candidates
                else "no external report for deployed image"
            )
            return None, reason
        item = matching[0]
        scanned_at = item.get("scanned_at")
        if not isinstance(scanned_at, str):
            return None, "external report scan time unavailable"
        try:
            scan_time = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
            if scan_time.tzinfo is None:
                raise ValueError("timezone required")
            age = (now - scan_time.astimezone(timezone.utc)).total_seconds()
        except (ValueError, TypeError):
            return None, "external report scan time invalid"
        if age < -300 or age > self.max_age:
            return None, "external report is old or dated in the future"
        report = item.get("report")
        if not isinstance(report, dict):
            return None, "external Trivy report unavailable"
        return (report, scanned_at), None


class TrivyScanner:
    """Remote-only scanner with one shared cache and bounded subprocesses."""

    def __init__(self, cache_dir, binary="trivy", timeout=300):
        if timeout < 1:
            raise ValueError("timeout must be positive")
        self.cache_dir = Path(cache_dir)
        self.binary = binary
        self.timeout = timeout
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _run(self, args):
        run_trivy(
            [
                self.binary,
                "image",
                "--cache-dir",
                str(self.cache_dir),
                "--timeout",
                f"{self.timeout}s",
                "--disable-telemetry",
                *args,
            ],
            "db_refresh" if "--download-db-only" in args else "scan",
            self.timeout + 15,
        )

    def refresh_db(self):
        self._run(["--download-db-only"])

    def scan(self, target, platform):
        with tempfile.TemporaryDirectory(prefix="service-health-scan-") as directory:
            output = Path(directory) / "report.json"
            self._run(
                [
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--image-src",
                    "remote",
                    "--scanners",
                    "vuln",
                    "--parallel",
                    "1",
                    "--max-image-size",
                    "2GB",
                    "--platform",
                    platform,
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    target,
                ]
            )
            try:
                if output.stat().st_size > _MAX_REPORT_BYTES:
                    raise TrivyFailure(
                        SecurityOutcome.MALFORMED,
                        "report_too_large",
                        "Report exceeds 20 MiB",
                        "report_parsing",
                        0,
                    )
                return json.loads(output.read_text(encoding="utf-8"))
            except (ValueError, OSError, RecursionError):
                raise TrivyFailure(
                    SecurityOutcome.MALFORMED,
                    "malformed_report",
                    "Could not read a valid JSON report",
                    "report_parsing",
                    0,
                ) from None


def _findings(report, target, platform, *, external=False):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("invalid Trivy JSON report")
    if report.get("ArtifactType", "container_image") != "container_image":
        raise ValueError("Trivy report artifact is not a container image")
    artifact = report.get("ArtifactName")
    if "ArtifactName" in report and not isinstance(artifact, str):
        raise ValueError("invalid Trivy report artifact name")
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("invalid Trivy report metadata")
    repo_digests = metadata.get("RepoDigests", [])
    if not isinstance(repo_digests, list) or not all(
        isinstance(value, str) for value in repo_digests
    ):
        raise ValueError("Trivy report RepoDigests must be an array of strings")
    digest = target.rsplit("@", 1)[1]
    # A tag or archive name can rely on RepoDigests. A digest in the scanned
    # artifact name must agree regardless of other reported repository names.
    _, separator, artifact_digest = (artifact or "").rpartition("@")
    if (
        separator
        and artifact_digest.startswith("sha256:")
        and artifact_digest != digest
    ):
        raise ValueError("Trivy report artifact digest differs from deployment")
    identities = [artifact, *repo_digests]
    if not any(
        isinstance(value, str) and value.endswith("@" + digest) for value in identities
    ):
        raise ValueError("Trivy report digest differs from deployed digest")
    if external and target not in identities:
        raise ValueError(
            "external Trivy report image identity differs from deployed image"
        )
    config = metadata.get("ImageConfig")
    platform_parts = platform.split("/")
    if (
        not isinstance(config, dict)
        or [config.get("os"), config.get("architecture")] != platform_parts[:2]
    ):
        raise ValueError("Trivy report platform differs from deployed platform")
    if len(platform_parts) == 3 and config.get("variant") != platform_parts[2]:
        raise ValueError("Trivy report platform variant differs from deployed platform")
    results = report.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy report Results must be an array")
    findings = []
    package_target = False
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("invalid Trivy result")
        name = result.get("Target")
        if (
            result.get("Class") in ("os-pkgs", "lang-pkgs")
            and isinstance(name, str)
            and name.strip()
        ):
            package_target = True
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy result Vulnerabilities must be an array")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("invalid Trivy vulnerability")
            issue = vulnerability.get("VulnerabilityID")
            package = vulnerability.get("PkgName")
            severity = vulnerability.get("Severity")
            if not all(
                isinstance(value, str) and value for value in (issue, package, severity)
            ):
                raise ValueError("Trivy vulnerability lacks required fields")
            findings.append(
                {
                    "id": issue,
                    "severity": severity.lower(),
                    "package": package,
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion") or None,
                    "source": "Trivy",
                    "source_url": vulnerability.get("PrimaryURL") or None,
                    "target": name,
                    "digest": digest,
                    "platform": platform,
                }
            )
    if not findings and not package_target:
        raise SecurityCheckError(
            SecurityOutcome.UNSUPPORTED,
            "no_supported_package_targets",
            "No supported package targets in Trivy report",
        )
    return findings


def apply_scan_checks(
    services,
    scanner,
    clock=lambda: datetime.now(timezone.utc),
    max_workers=2,
    external_reports=None,
    progress=None,
    only_failed=False,
    *,
    select=None,
    on_checked=None,
):
    """Refresh the DB and scans, retaining prior evidence on failure."""
    if max_workers < 1 or max_workers > 4:
        raise ValueError("max_workers must be between 1 and 4")
    checked_at = _timestamp(clock)
    now = clock().astimezone(timezone.utc)
    result = copy.deepcopy(services)
    deployments = [
        deployment
        for service in result
        for component in service.get("components", [])
        for deployment in component.get("deployments", [])
        if (not only_failed or deployment.get("scan_coverage") != "complete")
        and (select is None or select(deployment))
    ]
    groups = {}
    for deployment in deployments:
        key = scan_identity(deployment, external_reports is not None)
        groups.setdefault(key, []).append(deployment)
    db_error = None
    try:
        if any(_target(group[0]) for group in groups.values()):
            scanner.refresh_db()
    except TrivyFailure as error:
        db_error = error
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        failure = provider_failure(error)
        db_error = SecurityCheckError(
            failure.outcome,
            "database_refresh_failed",
            f"vulnerability DB refresh failed: {failure}",
        )

    def check(deployment):
        target = _target(deployment)
        if external_reports is not None:
            external, external_error = external_reports.lookup(deployment, now)
            if external is not None:
                report, scanned_at = external
                try:
                    image = deployment["image"].split("@", 1)[0]
                    tail = image.rsplit("/", 1)[-1]
                    if ":" in tail:
                        image = image[: -(len(tail) - tail.rfind(":"))]
                    reference = f"{image}@{deployment['digest']}"
                    findings = _findings(
                        report, reference, deployment["platform"], external=True
                    )
                    for finding in findings:
                        finding["scan_source"] = "external"
                        finding["scan_reported_at"] = scanned_at
                    return (
                        findings,
                        None,
                        "complete",
                        "external",
                        scanned_at,
                    )
                except SecurityCheckError as failure:
                    return None, failure, failure.coverage, None, None
                except (AttributeError, KeyError, TypeError, ValueError) as error:
                    failure = SecurityCheckError(
                        SecurityOutcome.MALFORMED, "malformed_report", str(error)
                    )
                    return None, failure, "missing", None, None
            if target is None:
                failure = SecurityCheckError(
                    SecurityOutcome.UNAVAILABLE,
                    "external_report_unavailable",
                    external_error,
                )
                return None, failure, "missing", None, None
        if target is None:
            failure = SecurityCheckError(
                SecurityOutcome.UNAVAILABLE,
                "image_not_pullable",
                "running image digest/platform or pullable registry unavailable",
            )
            return None, failure, "missing", None, None
        if db_error is not None:
            return None, db_error, db_error.coverage, None, None
        try:
            report = scanner.scan(target, deployment["platform"])
        except ValueError:
            failure = SecurityCheckError(
                SecurityOutcome.MALFORMED, "malformed_report", "Invalid scanner report"
            )
            return None, failure, "failed", None, None
        except (
            OSError,
            RuntimeError,
            KeyError,
            TypeError,
            subprocess.TimeoutExpired,
        ) as error:
            failure = provider_failure(error)
            return None, failure, failure.coverage, None, None
        try:
            findings = _findings(report, target, deployment["platform"])
        except SecurityCheckError as failure:
            return None, failure, failure.coverage, None, None
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            failure = TrivyFailure(
                SecurityOutcome.MALFORMED,
                "malformed_report",
                str(error),
                "report_parsing",
                0 if isinstance(scanner, TrivyScanner) else None,
            )
            return None, failure, "failed", None, None
        for finding in findings:
            finding["scan_source"] = "Trivy"
            finding["scan_reported_at"] = checked_at
        return findings, None, "complete", "Trivy", checked_at

    def update(deployment, findings, failure, coverage, source, scan_time):
        previous_identity = (
            deployment.get("scan_digest"),
            deployment.get("scan_platform"),
        )
        current_identity = (deployment.get("digest"), deployment.get("platform"))
        retained = previous_identity == current_identity and bool(
            deployment.get("scan_checked_at")
        )
        deployment["scan_outcome"] = (
            failure.outcome if failure else SecurityOutcome.SUCCESS
        )
        deployment["scan_reason"] = failure.reason if failure else None
        deployment["scan_failure_phase"] = getattr(failure, "phase", None)
        deployment["scan_exit_status"] = getattr(failure, "exit_status", None)
        deployment["scan_failed_at"] = checked_at if failure else None
        if coverage == "complete":
            deployment.update(
                scan_findings=findings,
                scan_coverage="complete",
                scan_error=None,
                scan_digest=current_identity[0],
                scan_platform=current_identity[1],
                scan_checked_at=checked_at,
                scan_source=source,
                scan_reported_at=scan_time,
                scan_stale=False,
            )
        else:
            deployment.update(
                scan_findings=deployment.get("scan_findings", []) if retained else [],
                scan_coverage=coverage,
                scan_error=str(failure),
                scan_digest=current_identity[0],
                scan_platform=current_identity[1],
                scan_stale=retained,
                scan_checked_at=deployment.get("scan_checked_at") if retained else None,
                scan_source=deployment.get("scan_source") if retained else None,
                scan_reported_at=deployment.get("scan_reported_at")
                if retained
                else None,
            )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, group[0]): group for group in groups.values()}
        for future in as_completed(futures):
            check_result = future.result()
            for deployment in futures[future]:
                update(deployment, *check_result)
                if on_checked is not None:
                    on_checked(deployment)
            if progress is not None:
                _aggregate_scans(result)
                progress(result)
    _aggregate_scans(result)
    return result


def _aggregate_scans(result):
    for service in result:
        service_findings = []
        coverages = []
        for component in service.get("components", []):
            items = component.get("deployments", [])
            component["scan_findings"] = [
                finding for item in items for finding in item.get("scan_findings", [])
            ]
            component["scan_coverage"] = (
                "complete"
                if items
                and all(item.get("scan_coverage") == "complete" for item in items)
                else (
                    "failed"
                    if any(item.get("scan_coverage") == "failed" for item in items)
                    else "missing"
                )
            )
            component["scan_stale"] = any(
                item.get("scan_stale", False) for item in items
            )
            service_findings.extend(component["scan_findings"])
            coverages.append(component["scan_coverage"])
        service["scan_findings"] = service_findings
        service["scan_sources"] = sorted(
            {
                item["scan_source"]
                for component in service.get("components", [])
                for item in component.get("deployments", [])
                if item.get("scan_coverage") == "complete" and item.get("scan_source")
            }
        )
        service["scan_coverage"] = (
            "complete"
            if coverages and all(value == "complete" for value in coverages)
            else ("failed" if "failed" in coverages else "missing")
        )
        successes = [
            item["scan_checked_at"]
            for component in service.get("components", [])
            for item in component.get("deployments", [])
            if item.get("scan_checked_at")
        ]
        service["scan_checked_at"] = min(successes, default=None)
        service["scan_stale"] = any(
            component.get("scan_stale", False)
            for component in service.get("components", [])
        )
        aggregate_security(service)


def scan_store_once(
    store,
    scanner,
    clock=lambda: datetime.now(timezone.utc),
    max_workers=2,
    external_reports=None,
):
    """Serialize cycles across processes sharing a SQLite database."""
    lock_path = Path(str(store.path) + ".collection.lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        snapshot = store.read()
        if snapshot is None:
            raise ValueError("scan requires a cached inventory")
        result = apply_scan_checks(
            snapshot["services"], scanner, clock, max_workers, external_reports
        )
        if store.commit_evidence(_timestamp(clock), result):
            raise RuntimeError("inventory changed during collection; retry required")
