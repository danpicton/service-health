"""Compare deployed and current OCI images for the deployed platform."""

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def _image_ref(image: str | None) -> tuple[str, str, str] | None:
    """Return registry, repository and explicit mutable tag."""
    if not isinstance(image, str) or "@" in image:
        return None
    name, separator, tag = image.rpartition(":")
    if not separator or "/" in tag or not tag or "/" in name.rsplit("/", 1)[-1]:
        return None
    parts = name.split("/")
    if not all(parts) or not all(
        re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts[1:]
    ):
        return None
    if len(parts) > 1 and (
        "." in parts[0] or ":" in parts[0] or parts[0] == "localhost"
    ):
        registry, repository = parts[0], "/".join(parts[1:])
        if registry == "docker.io":
            registry = "registry-1.docker.io"
            if "/" not in repository:
                repository = "library/" + repository
    else:
        registry, repository = "registry-1.docker.io", "/".join(parts)
        if "/" not in repository:
            repository = "library/" + repository
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", tag):
        return None
    return registry, repository, tag


def _request(
    registry: str, repository: str, resource: str, reference: str
) -> tuple[bytes, str | None]:
    url = (
        f"https://{registry}/v2/{quote(repository, safe='/')}"
        f"/{resource}/{quote(reference, safe=':')}"
    )
    headers = {"Accept": _ACCEPT, "User-Agent": "service-health"}

    def read(request_headers):
        with urlopen(Request(url, headers=request_headers), timeout=10) as response:
            return response.read(), response.headers.get("Docker-Content-Digest")

    try:
        return read(headers)
    except HTTPError as error:
        challenge = error.headers.get("WWW-Authenticate", "")
        match = re.fullmatch(
            r'Bearer realm="([^"]+)",service="([^"]+)",scope="([^"]+)"', challenge
        )
        if error.code != 401 or not match or not match[1].startswith("https://"):
            raise
        query = urlencode({"service": match[2], "scope": match[3]})
        with urlopen(
            Request(match[1] + "?" + query, headers={"User-Agent": "service-health"}),
            timeout=10,
        ) as response:
            token = json.load(response).get("token")
        if not isinstance(token, str):
            raise ValueError("registry token response has no token")
        return read({**headers, "Authorization": "Bearer " + token})


def registry_manifest(image: tuple[str, str, str], reference: str) -> tuple[str, dict]:
    registry, repository, _ = image
    body, header_digest = _request(registry, repository, "manifests", reference)
    actual = "sha256:" + hashlib.sha256(body).hexdigest()
    if header_digest and header_digest != actual:
        raise ValueError("registry manifest digest mismatch")
    if _DIGEST.fullmatch(reference) and reference != actual:
        raise ValueError("registry returned a different manifest digest")
    return actual, json.loads(body)


def registry_blob(image: tuple[str, str, str], digest: str) -> dict:
    registry, repository, _ = image
    body, _ = _request(registry, repository, "blobs", digest)
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise ValueError("registry config blob digest mismatch")
    return json.loads(body)


def _platform_digest(image, reference, platform, manifest, blob) -> str:
    digest, document = manifest(image, reference)
    media_type = document.get("mediaType")
    if media_type in _INDEX_TYPES:
        matches = [
            item
            for item in document.get("manifests", [])
            if item.get("platform", {}).get("os") == platform[0]
            and item.get("platform", {}).get("architecture") == platform[1]
            and (
                len(platform) == 2
                or item.get("platform", {}).get("variant") == platform[2]
            )
            and item.get("mediaType") in _MANIFEST_TYPES
        ]
        if len(matches) != 1 or not _DIGEST.fullmatch(matches[0].get("digest", "")):
            raise ValueError("platform manifest is missing or ambiguous")
        return matches[0]["digest"]
    if media_type not in _MANIFEST_TYPES:
        raise ValueError("unsupported OCI manifest media type")
    config_digest = document.get("config", {}).get("digest", "")
    if not _DIGEST.fullmatch(config_digest):
        raise ValueError("manifest has no valid config digest")
    config = blob(image, config_digest)
    if (config.get("os"), config.get("architecture")) != tuple(platform[:2]):
        raise ValueError("manifest platform differs from deployed platform")
    if len(platform) == 3 and config.get("variant") != platform[2]:
        raise ValueError("manifest variant differs from deployed platform")
    return digest


def _check_deployment(deployment, manifest, blob, checked_at):
    image_reference = deployment.get("image")
    image = _image_ref(image_reference)
    running = deployment.get("digest")
    platform = deployment.get("platform")
    if isinstance(image_reference, str) and re.match(
        r"^(?:localhost|127(?:\.\d+){3})(?::\d+)?/", image_reference
    ):
        deployment.update(
            image_status="unknown",
            image_reason="unsupported local image; supply an external scan report",
            image_error=None,
            image_stale=False,
        )
        return
    if (
        not image
        or not isinstance(platform, str)
        or len(platform.split("/")) not in (2, 3)
        or not _DIGEST.fullmatch(running or "")
    ):
        deployment.update(
            image_status="unknown",
            image_reason="mutable tag, running digest, or platform unavailable",
            candidate_image_digest=None,
            deployed_platform_digest=None,
            image_error=None,
            image_stale=False,
            image_checked_at=checked_at,
        )
        return
    try:
        platform_parts = platform.split("/")
        current = _platform_digest(image, image[2], platform_parts, manifest, blob)
        deployed = _platform_digest(image, running, platform_parts, manifest, blob)
    except HTTPError as error:
        deployment.update(
            image_status="unknown" if error.code in (401, 403) else "check failed",
            image_reason=(
                "private registry authentication required; "
                "application image comparison is anonymous only"
            )
            if error.code in (401, 403)
            else None,
            image_error=None
            if error.code in (401, 403)
            else f"registry HTTP {error.code}",
            image_stale=bool(deployment.get("candidate_image_digest")),
        )
        return
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        deployment.update(
            image_status="check failed",
            image_reason=None,
            image_error=str(error),
            image_stale=bool(deployment.get("candidate_image_digest")),
        )
        return
    deployment.update(
        image_status="image rebuild available" if current != deployed else "up to date",
        image_reason=None,
        image_error=None,
        image_stale=False,
        image_checked_at=checked_at,
        candidate_image_digest=current,
        deployed_platform_digest=deployed,
    )


def apply_image_checks(
    services,
    manifest=registry_manifest,
    blob=registry_blob,
    clock=None,
    only_failed=False,
):
    """Return a new cached snapshot with independent image rebuild evidence."""
    checked_at = (
        (clock or (lambda: datetime.now(timezone.utc)))()
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    result = copy.deepcopy(services)
    precedence = ("image rebuild available", "check failed", "unknown", "up to date")
    for service in result:
        for component in service.get("components", []):
            deployments = component.get("deployments", [])
            for deployment in deployments:
                if only_failed and deployment.get("image_status") != "check failed":
                    continue
                _check_deployment(deployment, manifest, blob, checked_at)
            statuses = {item.get("image_status", "unknown") for item in deployments}
            component["image_status"] = next(
                (s for s in precedence if s in statuses), "unknown"
            )
            component["image_coverage_complete"] = bool(deployments) and statuses <= {
                "image rebuild available",
                "up to date",
            }
            component["image_stale"] = any(
                item.get("image_stale", False) for item in deployments
            )
            successful = [
                item["image_checked_at"]
                for item in deployments
                if item.get("image_checked_at")
            ]
            component["image_checked_at"] = min(successful, default=None)
            component["candidate_image_digest"] = (
                deployments[0].get("candidate_image_digest")
                if len(deployments) == 1
                else None
            )
        components = service.get("components", [])
        statuses = {item.get("image_status", "unknown") for item in components}
        service["image_status"] = next(
            (s for s in precedence if s in statuses), "unknown"
        )
        service["image_coverage_complete"] = bool(components) and all(
            item.get("image_coverage_complete", False) for item in components
        )
        service["image_stale"] = any(
            item.get("image_stale", False) for item in components
        )
        successful = [
            item["image_checked_at"]
            for item in components
            if item.get("image_checked_at")
        ]
        service["image_checked_at"] = min(successful, default=None)
        service["candidate_image_digest"] = (
            components[0].get("candidate_image_digest")
            if len(components) == 1
            else None
        )
    return result
