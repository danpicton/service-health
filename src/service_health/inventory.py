"""Resolve an explicit service catalog against injected Kubernetes inventory."""

import re
from collections.abc import Mapping
from datetime import datetime, timezone

from service_health.images import deployed_image_config
from service_health.version_evidence import (
    configured_source,
    deployment_observations,
    endpoint_observation,
    fetch_endpoint,
    inventory_metadata_reader,
    normalize_observations,
)

_DIGEST = re.compile(r"(?:^|@)(sha256:[0-9a-fA-F]{64})$")
_SOURCE_LABELS = {
    "pod_annotation": "configured pod annotation",
    "image_metadata": "deployed image metadata",
    "exact_tag": "documented exact image tag",
}
_CONTAINER_FIELDS = (
    ("regular", "containers", "containerStatuses"),
    ("init", "initContainers", "initContainerStatuses"),
)


def _digest(image_id: str | None) -> str | None:
    if not image_id:
        return None
    match = _DIGEST.search(image_id.removeprefix("docker://"))
    return match.group(1).lower() if match else None


def _platform(node: Mapping | None) -> str | None:
    info = (node or {}).get("status", {}).get("nodeInfo", {})
    os_name, architecture = info.get("operatingSystem"), info.get("architecture")
    return f"{os_name}/{architecture}" if os_name and architecture else None


def _matches(pod: Mapping, selector: Mapping) -> bool:
    metadata = pod.get("metadata", {})
    return metadata.get("namespace") == selector["namespace"] and all(
        metadata.get("labels", {}).get(key) == value
        for key, value in selector["pod_labels"].items()
    )


def _observed_containers(
    pod: Mapping, component: Mapping, nodes: Mapping, checked_at: str, read_metadata
) -> list[dict]:
    result = []
    selector = component["selector"]
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})
    node_name = spec.get("nodeName")
    for kind, spec_field, status_field in _CONTAINER_FIELDS:
        if kind != selector["kind"]:
            continue
        configured = next(
            (
                item
                for item in spec.get(spec_field, [])
                if item.get("name") == selector["container"]
            ),
            None,
        )
        if configured is None:
            continue
        observed = next(
            (
                item
                for item in status.get(status_field, [])
                if item.get("name") == selector["container"]
            ),
            {},
        )
        image_id = observed.get("imageID")
        image = observed.get("image") or configured.get("image")
        metadata_image = image
        configured_image = configured.get("image") or ""
        if "@" in configured_image and "@" not in (image or ""):
            metadata_image = configured_image
        platform = _platform(nodes.get(node_name))
        evidence = deployment_observations(
            component["version_sources"],
            component.get("version_annotation"),
            metadata.get("annotations", {}),
            observed.get("image"),
            metadata_image,
            _digest(image_id),
            checked_at,
            platform,
            read_metadata,
        )
        normalize_observations(evidence, component.get("release_source"))
        versions = {item["normalized"] for item in evidence if item["normalized"]}
        version = next(iter(versions)) if len(versions) == 1 else None
        result.append(
            {
                "namespace": metadata["namespace"],
                "pod": metadata.get("name"),
                "node": node_name,
                "container": selector["container"],
                "kind": kind,
                "image": image,
                "configured_image": configured_image,
                "image_id": image_id,
                "digest": _digest(image_id),
                "platform": platform,
                "application_version": version,
                "version_state": "disputed"
                if len(versions) > 1
                else "observed"
                if version
                else "unknown",
                "version_observations": evidence,
                "state": "observed" if observed else "status unavailable",
            }
        )
    return result


def _reconcile(deployments, shared):
    replicas = {
        d["application_version"] for d in deployments if d["application_version"]
    }
    samples = {r["normalized"] for r in shared if r["normalized"]}
    records = [r for d in deployments for r in d["version_observations"]]
    disputes = [
        d["pod"] or "unknown pod"
        for d in deployments
        if d["version_state"] == "disputed"
    ]
    reasons = []
    if disputes:
        reasons.append("disputed deployment evidence for " + ", ".join(disputes))
    if len(samples) > 1 or (samples and replicas and samples - replicas):
        reasons.append(
            "disputed: endpoint-reported and deployed or shared versions differ"
        )
    disputed = bool(reasons)
    if len(replicas) > 1:
        reasons.append("mixed deployments: " + ", ".join(sorted(replicas)))
    if reasons:
        return "disputed" if disputed else "mixed", None, None, "; ".join(reasons)
    deployment_version = (
        next(iter(replicas))
        if replicas and all(d["application_version"] for d in deployments)
        else None
    )
    if samples:
        return (
            "observed",
            next(iter(samples)),
            deployment_version,
            "endpoint-reported version",
        )
    if deployment_version:
        labels = sorted(
            {_SOURCE_LABELS[r["source"]["type"]] for r in records if r["normalized"]}
        )
        return "observed", deployment_version, deployment_version, ", ".join(labels)
    gaps = [r["reason"] for r in [*records, *shared] if r["reason"]]
    return (
        "unknown",
        None,
        None,
        "; ".join(dict.fromkeys(gaps)) or "no reliable application version",
    )


def _component(
    component: Mapping,
    pods: list[dict],
    nodes: Mapping,
    checked_at: str,
    read_metadata,
    endpoint_fetch,
    track_prereleases=False,
) -> dict:
    configured = component.get("version_sources", [])
    if not isinstance(configured, list):
        configured = [{"type": "invalid"}]
    sources = []
    for raw in [component.get("version_source"), *configured]:
        source = configured_source(raw)
        if source and source not in sources:
            sources.append(source)
    component = {**component, "version_sources": sources}
    deployments = [
        deployment
        for pod in pods
        if _matches(pod, component["selector"])
        for deployment in _observed_containers(
            pod, component, nodes, checked_at, read_metadata
        )
    ]
    deployments.sort(key=lambda item: (item["namespace"], item["pod"] or ""))
    shared = [
        endpoint_observation(source, checked_at, endpoint_fetch, deployments)
        for source in sources
        if source["type"] == "endpoint"
    ]
    normalize_observations(shared, component.get("release_source"))
    state, version, deployment_version, label = _reconcile(deployments, shared)
    binding = {"version_annotation": component.get("version_annotation")}
    if sources:
        if len(sources) == 1:
            binding["version_source"] = sources[0]
        elif sources:
            binding["version_sources"] = sources
        binding.update(
            deployments=[
                [
                    d[key]
                    for key in (
                        "namespace",
                        "pod",
                        "container",
                        "image",
                        "digest",
                        "platform",
                    )
                ]
                for d in deployments
            ],
        )
    return {
        "id": component["id"],
        "name": component.get("name", component["id"]),
        "kind": component["selector"]["kind"],
        "current_version": version,
        "version_evidence": label,
        "version_state": state,
        **(
            {"version_observations": shared, "advisory_version": deployment_version}
            if shared
            else {}
        ),
        "version_source_identity": binding,
        "inventory_status": "observed" if deployments else "not observed",
        "deployments": deployments,
        "release_identity": (
            {
                "source": component["release_source"],
                "track_prereleases": component["release_source"].get(
                    "track_prereleases", track_prereleases
                ),
                "current_version": version,
                "selector": component["selector"],
                **({"version_evidence": label} if version is None else {}),
                **binding,
            }
            if isinstance(component.get("release_source"), dict)
            else None
        ),
        "advisory_source_identity": (
            {
                "source": component["advisory_source"],
                "current_version": deployment_version,
                "selector": component["selector"],
                **({"version_evidence": label} if version is None else {}),
                **binding,
            }
            if isinstance(component.get("advisory_source"), dict)
            else None
        ),
    }


def collect_inventory(
    registry: list[dict],
    catalog: list[dict],
    pods: list[dict],
    nodes: list[dict],
    clock=lambda: datetime.now(timezone.utc),
    *,
    image_config=deployed_image_config,
    endpoint_fetch=fetch_endpoint,
) -> list[dict]:
    """Return one cached service per active registry entry."""
    checked_at = clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    read_metadata = inventory_metadata_reader(checked_at, image_config)
    active = [item for item in registry if item.get("active") is True]
    registry_ids = [item["id"] for item in active]
    catalog_ids = [item["id"] for item in catalog]
    if len(registry_ids) != len(set(registry_ids)) or len(catalog_ids) != len(
        set(catalog_ids)
    ):
        raise ValueError("registry and catalog service IDs must be unique")
    by_id = {item["id"]: item for item in catalog}
    missing = sorted(set(registry_ids) - set(by_id))
    if missing:
        raise ValueError(
            f"active services have no component mapping: {', '.join(missing)}"
        )
    node_by_name = {node.get("metadata", {}).get("name"): node for node in nodes}
    usable_pods = [
        pod
        for pod in pods
        if pod.get("status", {}).get("phase") not in ("Succeeded", "Failed")
    ]
    services = []
    for entry in active:
        configured = by_id[entry["id"]]
        components = configured.get("components", [])
        if not components or len({item["id"] for item in components}) != len(
            components
        ):
            raise ValueError(f"service {entry['id']} needs unique, explicit components")
        for component in components:
            selector = component.get("selector", {})
            if (
                not selector.get("namespace")
                or not selector.get("pod_labels")
                or not selector.get("container")
                or selector.get("kind") not in ("regular", "init")
            ):
                raise ValueError(
                    f"component {component['id']} needs an explicit selector"
                )
        resolved = [
            _component(
                item,
                usable_pods,
                node_by_name,
                checked_at,
                read_metadata,
                endpoint_fetch,
                configured.get("track_prereleases", False),
            )
            for item in components
        ]
        services.append(
            {
                "id": entry["id"],
                "name": entry.get("name", configured.get("name", entry["id"])),
                "current_version": (
                    resolved[0]["current_version"] if len(resolved) == 1 else None
                ),
                "components": resolved,
                "inventory_status": (
                    "observed"
                    if all(item["inventory_status"] == "observed" for item in resolved)
                    else "incomplete"
                ),
            }
        )
    return services
