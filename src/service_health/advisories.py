"""Structured OSV application advisories matched to verified component versions."""

import copy
import json
import re
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from service_health.aggregation import aggregate_security
from service_health.releases import _version
from service_health.security_outcomes import (
    SecurityCheckError,
    SecurityOutcome,
    provider_failure,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$")
_SEVERITIES = {"critical", "high", "medium", "low"}


def osv_advisories(source):
    """Fetch all OSV records for an explicitly configured ecosystem package."""
    if source.get("type") != "osv":
        raise ValueError("unsupported advisory source")
    ecosystem, name = source.get("ecosystem"), source.get("package")
    if not all(
        isinstance(value, str) and value and len(value) < 200
        for value in (ecosystem, name)
    ):
        raise ValueError("invalid OSV package identity")
    records, token = [], None
    for _ in range(20):
        payload = {"package": {"ecosystem": ecosystem, "name": name}}
        if token:
            payload["page_token"] = token
        request = Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "service-health",
            },
            method="POST",
        )
        with urlopen(request, timeout=10) as response:
            page = json.load(response)
        if not isinstance(page, dict) or not isinstance(page.get("vulns", []), list):
            raise ValueError("invalid OSV response")
        records.extend(page.get("vulns", []))
        token = page.get("next_page_token")
        if not token:
            return records
        if not isinstance(token, str):
            raise ValueError("invalid OSV page token")
    raise ValueError("OSV response exceeds 20 pages")


def _compare(left, right):
    if left[0] != right[0]:
        return (left[0] > right[0]) - (left[0] < right[0])
    a, b = left[1], right[1]
    if a is None or b is None:
        return (a is None) - (b is None)
    return (a > b) - (a < b)


def _intervals(events):
    """Read complete, ordered SemVer intervals. Reject ambiguous boundaries."""
    if not isinstance(events, list) or not events:
        return None
    intervals = []
    start = previous = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, value = next(iter(event.items()))
        boundary = (
            ((), None)
            if key == "introduced" and value == "0"
            else _version(value, "semver")
        )
        if boundary is None or (previous and _compare(boundary, previous) < 0):
            return None
        if key == "introduced" and start is None:
            start = boundary
        elif key in ("fixed", "last_affected", "limit") and start is not None:
            intervals.append((start, boundary, key, value))
            start = None
        else:
            return None
        previous = boundary
    if start is not None:
        intervals.append((start, None, None, None))
    return intervals


def _contains(interval, version):
    start, end, kind, _ = interval
    if _compare(version, start) < 0:
        return False
    if end is None:
        return True
    relation = _compare(version, end)
    return relation < 0 or (relation == 0 and kind == "last_affected")


def _range_match(events, current):
    intervals = _intervals(events)
    if intervals is None:
        return None, []
    return any(_contains(i, current) for i in intervals), [
        value for _, _, kind, value in intervals if kind == "fixed"
    ]


def _record_match(record, source, current):
    outcomes, ranges, fixes, exact_versions = [], [], [], []
    for affected in record.get("affected", []):
        package = affected.get("package", {}) if isinstance(affected, dict) else {}
        if (
            package.get("ecosystem") != source["ecosystem"]
            or package.get("name") != source["package"]
        ):
            continue
        if current is None:
            outcomes.append(None)
        versions = affected.get("versions", [])
        if not isinstance(versions, list) or any(
            not isinstance(v, str) for v in versions
        ):
            raise ValueError("invalid affected versions")
        exact_versions.extend(versions)
        if not versions and not affected.get("ranges"):
            outcomes.append(None)
        if versions and current is not None:
            parsed_versions = [_version(v, "semver") for v in versions]
            if current in parsed_versions:
                outcomes.append(True)
            else:
                outcomes.append(None if None in parsed_versions else False)
        for item in affected.get("ranges", []):
            ranges.append(item)
            if (
                not isinstance(item, dict)
                or item.get("type") != "SEMVER"
                or current is None
            ):
                outcomes.append(None)
            else:
                outcome, fixed = _range_match(item.get("events"), current)
                outcomes.append(outcome)
                fixes.extend(fixed)
    if not outcomes:
        return None, ranges, fixes, exact_versions
    if True in outcomes:
        return (None if None in outcomes else True), ranges, fixes, exact_versions
    if None in outcomes:
        return None, ranges, fixes, exact_versions
    return False, ranges, fixes, exact_versions


def _candidate_outcome(provenance, deployed, candidate):
    # Older snapshots did not retain OSV's explicit affected-version list.
    if "affected_versions" not in provenance:
        return "unknown"
    versions = [_version(v, "semver") for v in provenance["affected_versions"]]
    if candidate in versions:
        return "still affected"
    intervals = []
    for item in provenance.get("affected_ranges", []):
        if not isinstance(item, dict) or item.get("type") != "SEMVER":
            return "unknown"
        parsed = _intervals(item.get("events"))
        if parsed is None:
            return "unknown"
        intervals.extend(parsed)
    if any(_contains(interval, candidate) for interval in intervals):
        return "still affected"
    if None in versions:
        return "unknown"
    applicable = [interval for interval in intervals if _contains(interval, deployed)]
    intervening = [
        interval
        for interval in intervals
        if _compare(deployed, interval[0]) < 0 and _compare(interval[0], candidate) <= 0
    ]
    relevant = applicable + intervening
    if not applicable or any(interval[2] != "fixed" for interval in relevant):
        return "unknown"
    # An explicit affected release outside those intervals has no documented fix.
    for version in versions:
        if _compare(deployed, version) < 0 and _compare(version, candidate) < 0:
            if not any(_contains(interval, version) for interval in relevant):
                return "unknown"
    return "fixed"


def candidate_assessments(component, inventory_stale):
    """Join separately cached releases and OSV findings after freshness projection."""
    results = {}
    deployed_text = component.get("advisory_version", component.get("current_version"))
    source = (component.get("advisory_identity") or {}).get("source", {})
    prefix = source.get("current_prefix", "")
    deployed = _version(
        deployed_text.removeprefix(prefix)
        if isinstance(deployed_text, str) and isinstance(prefix, str)
        else None,
        "semver",
    )
    stale = (
        inventory_stale
        or component.get("advisory_stale")
        or component.get("release_stale")
    )
    for finding in component.get("advisory_findings", []):
        for group, release in component.get("release_candidates", {}).items():
            if group not in ("routine", "major"):
                continue
            candidate = _version(release.get("normalized_version"), "semver")
            status = "unknown"
            if (
                stale
                or component.get("update_status") != "update available"
                or component.get("advisory_error")
            ):
                reason = (
                    "Current release, inventory, or advisory evidence is unavailable."
                )
            elif (
                deployed is None
                or finding.get("match") != "confirmed"
                or finding.get("current_version") != deployed_text
                or component.get("version_state", "observed") != "observed"
            ):
                reason = (
                    "Advisory applicability is uncertain for the deployed replicas."
                )
            elif candidate is None or _compare(candidate, deployed) <= 0:
                reason = "The candidate lacks a comparable newer application version."
            else:
                outcomes = {
                    _candidate_outcome(p, deployed, candidate)
                    for p in finding.get("provenance", [])
                }
                if outcomes == {"fixed"}:
                    status, reason = "fixed", "The candidate includes the advisory fix."
                elif outcomes == {"still affected"}:
                    status, reason = (
                        "still affected",
                        "The advisory still covers this candidate.",
                    )
                else:
                    reason = "The advisory records do not establish a fixed candidate."
            results.setdefault(finding["id"], {})[group] = {
                **release,
                "status": status,
                "reason": reason,
            }
    return results


def _severity(record):
    details = record.get("database_specific") or {}
    value = details.get("severity") if isinstance(details, dict) else None
    return (
        value.lower()
        if isinstance(value, str) and value.lower() in _SEVERITIES
        else "unknown"
    )


def _groups(records):
    groups = []
    for item in records:
        ids = set(item["aliases"] + [item["id"]])
        overlapping = [group for group in groups if ids & group["ids"]]
        if overlapping:
            target = overlapping[0]
            for group in overlapping[1:]:
                target["ids"].update(group["ids"])
                target["items"].extend(group["items"])
                groups.remove(group)
            target["ids"].update(ids)
            target["items"].append(item)
        else:
            groups.append({"ids": ids, "items": [item]})
    return groups


def apply_advisory_checks(
    services,
    catalog,
    fetch_advisories=osv_advisories,
    clock=None,
    only_failed=False,
    *,
    select=None,
):
    """Return cached advisory evidence, retaining prior evidence on failures."""
    checked_at = (
        (clock or (lambda: datetime.now(timezone.utc)))()
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    result = copy.deepcopy(services)
    configured = {item["id"]: item for item in catalog}
    for service in result:
        mapping = {
            item["id"]: item
            for item in configured.get(service["id"], {}).get("components", [])
        }
        for component in service.get("components", []):
            if only_failed and component.get("advisory_coverage") == "complete":
                continue
            if select is not None and not select(service, component):
                continue
            source = mapping.get(component["id"], {}).get("advisory_source")
            if (
                not isinstance(source, dict)
                or source.get("type") != "osv"
                or not source.get("ecosystem")
                or not source.get("package")
                or source.get("version_policy", "semver") != "semver"
            ):
                component.update(
                    advisory_coverage="missing",
                    advisory_outcome=SecurityOutcome.UNSUPPORTED,
                    advisory_reason="advisory_source_unsupported",
                    advisory_gap="no supported structured advisory source configured",
                    advisory_error=None,
                    advisory_stale=False,
                    advisory_findings=[],
                    possible_finding_count=0,
                    advisory_checked_at=None,
                    advisory_identity=None,
                )
                continue
            current_text = component.get(
                "advisory_version", component.get("current_version")
            )
            identity = {
                "source": source,
                "current_version": current_text,
            }
            try:
                records = fetch_advisories(source)
                if not isinstance(records, list):
                    raise ValueError("advisory response must be an array")
                parsed = []
                prefix = source.get("current_prefix", "")
                current = _version(
                    current_text[len(prefix) :]
                    if isinstance(current_text, str)
                    and prefix
                    and current_text.startswith(prefix)
                    else current_text,
                    "semver",
                )
                for record in records:
                    if (
                        not isinstance(record, dict)
                        or not isinstance(record.get("id"), str)
                        or not _ID.fullmatch(record["id"])
                    ):
                        raise ValueError("invalid advisory ID")
                    if record.get("withdrawn"):
                        continue
                    aliases = record.get("aliases", [])
                    if not isinstance(aliases, list) or any(
                        not isinstance(v, str) or not _ID.fullmatch(v) for v in aliases
                    ):
                        raise ValueError("invalid advisory aliases")
                    outcome, ranges, fixes, exact_versions = _record_match(
                        record, source, current
                    )
                    if not any(
                        isinstance(a, dict)
                        and isinstance(a.get("package"), dict)
                        and a["package"].get("ecosystem") == source["ecosystem"]
                        and a["package"].get("name") == source["package"]
                        for a in record.get("affected", [])
                    ):
                        continue
                    if not ranges and not any(
                        a.get("versions")
                        for a in record.get("affected", [])
                        if isinstance(a, dict)
                    ):
                        outcome = None
                    parsed.append(
                        {
                            "id": record["id"],
                            "aliases": aliases,
                            "outcome": outcome,
                            "ranges": ranges,
                            "affected_versions": exact_versions,
                            "fixes": fixes,
                            "severity": _severity(record),
                            "url": f"https://osv.dev/vulnerability/{record['id']}",
                        }
                    )
                findings = []
                uncertain = current is None
                for group in _groups(parsed):
                    items = group["items"]
                    outcomes = {item["outcome"] for item in items}
                    if outcomes == {False}:
                        continue
                    possible = None in outcomes or len(outcomes) > 1
                    uncertain |= possible
                    rank = {
                        "critical": 4,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                        "unknown": 0,
                    }
                    representative = max(items, key=lambda item: rank[item["severity"]])
                    findings.append(
                        {
                            "id": sorted(group["ids"])[0],
                            "aliases": sorted(group["ids"]),
                            "match": "possible" if possible else "confirmed",
                            "severity": representative["severity"],
                            "source": "OSV upstream advisory",
                            "current_version": current_text,
                            "fixed_versions": sorted(
                                {v for item in items for v in item["fixes"]}
                            ),
                            "provenance": [
                                {
                                    "id": item["id"],
                                    "url": item["url"],
                                    "affected_ranges": item["ranges"],
                                    "affected_versions": item["affected_versions"],
                                }
                                for item in items
                            ],
                            "reason": "conflicting or ambiguous version evidence"
                            if possible
                            else None,
                        }
                    )
                component.update(
                    advisory_findings=findings,
                    possible_finding_count=sum(
                        f["match"] == "possible" for f in findings
                    ),
                    advisory_coverage="missing" if uncertain else "complete",
                    advisory_outcome=SecurityOutcome.UNAVAILABLE
                    if uncertain
                    else SecurityOutcome.SUCCESS,
                    advisory_reason="advisory_applicability_unknown"
                    if uncertain
                    else None,
                    advisory_gap="deployed version or advisory range is ambiguous"
                    if uncertain
                    else None,
                    advisory_checked_at=checked_at,
                    advisory_identity=identity,
                    advisory_error=None,
                    advisory_stale=False,
                )
            except (
                OSError,
                RuntimeError,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
            ) as error:
                failure = (
                    SecurityCheckError(
                        SecurityOutcome.MALFORMED,
                        "malformed_advisory_response",
                        "Invalid advisory provider response",
                    )
                    if isinstance(
                        error, (ValueError, TypeError, KeyError, AttributeError)
                    )
                    else provider_failure(error)
                )
                retained = bool(component.get("advisory_checked_at")) and (
                    component.get("advisory_identity") == identity
                )
                component.update(
                    advisory_coverage=failure.coverage,
                    advisory_outcome=failure.outcome,
                    advisory_reason=failure.reason,
                    advisory_error=str(failure),
                    advisory_stale=retained,
                    advisory_gap="advisory provider failed",
                    advisory_findings=component.get("advisory_findings", [])
                    if retained
                    else [],
                    possible_finding_count=component.get("possible_finding_count", 0)
                    if retained
                    else 0,
                    advisory_checked_at=component.get("advisory_checked_at")
                    if retained
                    else None,
                    advisory_identity=identity,
                )
        aggregate_security(service)
        successful = [
            item["advisory_checked_at"]
            for item in service.get("components", [])
            if item.get("advisory_checked_at")
        ]
        service["advisory_checked_at"] = min(successful, default=None)
        service["advisory_attempted_at"] = checked_at
    return result
