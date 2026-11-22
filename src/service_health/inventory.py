"""Resolve an explicit service catalog against injected Kubernetes inventory."""

import re
from collections.abc import Mapping

_DIGEST = re.compile(r"(?:^|@)(sha256:[0-9a-fA-F]{64})$")
_CONTAINER_FIELDS = (
    ("regular", "containers", "containerStatuses"),
    ("init", "initContainers", "initContainerStatuses"),
)


def _digest(image_id: str | None) -> str | None:
    if not image_id:
        return None
    match = _DIGEST.search(image_id)
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
    pod: Mapping, component: Mapping, nodes: Mapping
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
        version_key = component.get("version_annotation")
        version = (
            metadata.get("annotations", {}).get(version_key) if version_key else None
        )
        if not version:
            version = None
        result.append(
            {
                "namespace": metadata["namespace"],
                "pod": metadata.get("name"),
                "node": node_name,
                "container": selector["container"],
                "kind": kind,
                "image": image,
                "image_id": image_id,
                "digest": _digest(image_id),
                "platform": _platform(nodes.get(node_name)),
                "application_version": version,
                "state": "observed" if observed else "status unavailable",
            }
        )
    return result


def _component(
    component: Mapping, pods: list[dict], nodes: Mapping, track_prereleases=False
) -> dict:
    deployments = [
        deployment
        for pod in pods
        if _matches(pod, component["selector"])
        for deployment in _observed_containers(pod, component, nodes)
    ]
    deployments.sort(key=lambda item: (item["namespace"], item["pod"] or ""))
    versions = {item["application_version"] for item in deployments}
    version = next(iter(versions)) if len(versions) == 1 else None
    return {
        "id": component["id"],
        "name": component.get("name", component["id"]),
        "kind": component["selector"]["kind"],
        "current_version": version,
        "version_evidence": (
            "configured pod annotation"
            if version is not None
            else "unknown: no reliable application version or replicas disagree"
        ),
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
            }
            if isinstance(component.get("release_source"), dict)
            else None
        ),
        "advisory_source_identity": (
            {
                "source": component["advisory_source"],
                "current_version": version,
                "selector": component["selector"],
            }
            if isinstance(component.get("advisory_source"), dict)
            else None
        ),
    }


def collect_inventory(
    registry: list[dict], catalog: list[dict], pods: list[dict], nodes: list[dict]
) -> list[dict]:
    """Return one cached service per active registry entry."""
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
