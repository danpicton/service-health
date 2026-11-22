"""Reconcile independent component checks into cached service signals."""


def _coverage(values):
    return (
        "complete"
        if values and all(value == "complete" for value in values)
        else "failed"
        if "failed" in values
        else "missing"
    )


def _groups(entries):
    """Merge transitive ID/alias overlap within one affected component."""
    groups = []
    for component_id, source, finding in entries:
        ids = set(finding.get("aliases", [])) | {finding["id"]}
        matches = [
            group
            for group in groups
            if group["component_id"] == component_id and ids & group["ids"]
        ]
        if matches:
            group = matches[0]
            for other in matches[1:]:
                group["ids"].update(other["ids"])
                group["sources"].extend(other["sources"])
                groups.remove(other)
            group["ids"].update(ids)
        else:
            group = {"component_id": component_id, "ids": ids, "sources": []}
            groups.append(group)
        group["sources"].append({"type": source, "finding": finding})
    return groups


def _findings(components):
    entries = []
    for component in components:
        component_id = component["id"]
        entries.extend(
            (component_id, "Trivy", finding)
            for finding in component.get("scan_findings", [])
        )
        entries.extend(
            (component_id, "upstream advisory", finding)
            for finding in component.get("advisory_findings", [])
            if finding.get("match") == "confirmed"
        )
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    result = []
    for group in _groups(entries):
        sources = group["sources"]
        result.append(
            {
                "id": sorted(group["ids"])[0],
                "aliases": sorted(group["ids"]),
                "component_id": group["component_id"],
                "severity": max(
                    (
                        source["finding"].get("severity", "unknown")
                        for source in sources
                    ),
                    key=lambda value: rank.get(value, 0),
                ),
                "fix_available": any(
                    source["finding"].get("fixed_version")
                    or source["finding"].get("fixed_versions")
                    for source in sources
                ),
                "sources": sources,
            }
        )
    return result


def aggregate_security(service):
    """Keep confirmed findings and check coverage independent at every level."""
    components = service.get("components", [])
    for component in components:
        component["confirmed_findings"] = _findings([component])
        component["possible_finding_count"] = sum(
            finding.get("match") == "possible"
            for finding in component.get("advisory_findings", [])
        )
        component["coverage_complete"] = (
            component.get("scan_coverage") == "complete"
            and component.get("advisory_coverage") == "complete"
        )
        component["security_status"] = _security_status(
            component["confirmed_findings"],
            component.get("scan_coverage"),
            component.get("advisory_coverage"),
            component["coverage_complete"],
        )
    service["scan_coverage"] = _coverage(
        [component.get("scan_coverage") for component in components]
    )
    service["advisory_coverage"] = _coverage(
        [component.get("advisory_coverage") for component in components]
    )
    service["coverage_complete"] = bool(components) and all(
        component["coverage_complete"] for component in components
    )
    service["confirmed_findings"] = _findings(components)
    service["advisory_findings"] = [
        finding
        for component in components
        for finding in component.get("advisory_findings", [])
    ]
    service["critical_count"] = sum(
        finding["severity"] == "critical" for finding in service["confirmed_findings"]
    )
    service["high_count"] = sum(
        finding["severity"] == "high" for finding in service["confirmed_findings"]
    )
    service["fix_available_count"] = sum(
        finding["fix_available"] for finding in service["confirmed_findings"]
    )
    service["confirmed_finding_count"] = len(service["confirmed_findings"])
    service["possible_finding_count"] = sum(
        component["possible_finding_count"] for component in components
    )
    service["advisory_stale"] = any(
        component.get("advisory_stale", False) for component in components
    )
    service["security_status"] = _security_status(
        service["confirmed_findings"],
        service["scan_coverage"],
        service["advisory_coverage"],
        service["coverage_complete"],
    )


def _security_status(findings, scan_coverage, advisory_coverage, complete):
    if findings:
        return "findings"
    if "failed" in (scan_coverage, advisory_coverage):
        return "check failed"
    return "no known findings" if complete else "incomplete coverage"
