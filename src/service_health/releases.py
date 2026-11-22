"""Configured release resolution; HTTP is injected for offline collection tests."""

import copy
import json
import re
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.request import Request, urlopen

_SEMVER = re.compile(
    r"^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_NUMERIC = re.compile(r"^(?:v)?(0|[1-9]\d*)(?:\.(0|[1-9]\d*)){1,3}$")


def _version(value: str | None, policy: str):
    if not isinstance(value, str):
        return None
    if policy == "semver":
        match = _SEMVER.fullmatch(value.strip())
        if not match:
            return None
        major, minor, patch = (int(part) for part in match.group(1, 2, 3))
        prerelease = match.group(4)
        if prerelease:
            parts = prerelease.split(".")
            if any(
                part.isdigit() and len(part) > 1 and part[0] == "0" for part in parts
            ):
                return None
            rank = tuple(
                (0, int(part)) if part.isdigit() else (1, part) for part in parts
            )
        else:
            rank = None
        return (major, minor, patch), rank
    if policy == "numeric":
        if not _NUMERIC.fullmatch(value.strip()):
            return None
        return tuple(
            int(part) for part in value.strip().removeprefix("v").split(".")
        ), None
    return None


def _newer(candidate, current) -> bool:
    if candidate[0] != current[0]:
        return candidate[0] > current[0]
    if candidate[1] is None:
        return current[1] is not None
    if current[1] is None:
        return False
    return candidate[1] > current[1]


def _normalized(value: str | None, prefix: str) -> str | None:
    if value is None:
        return None
    if prefix and value.startswith(prefix):
        return value[len(prefix) :]
    return value


def github_releases(source: dict) -> list[dict]:
    """Read up to 100 recent GitHub releases for a configured public repository."""
    if source.get("type") != "github_releases":
        raise ValueError("unsupported release source")
    repository = _repository(source)
    url = (
        "https://api.github.com/repos/"
        + quote(repository, safe="/")
        + "/releases?per_page=100"
    )
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "service-health",
        },
    )
    with urlopen(request, timeout=10) as response:
        releases = json.load(response)
    if not isinstance(releases, list):
        raise ValueError("release response must be an array")
    return releases


def _repository(source: dict) -> str:
    if source.get("type") != "github_releases":
        raise ValueError("unsupported release source")
    repository = source.get("repository", "")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        raise ValueError("invalid GitHub repository")
    return repository.lower()


def _check(
    component: dict, source: dict | None, fetch_releases, checked_at: str
) -> None:
    if not source:
        component.update(
            update_status="unknown",
            update_reason="no release source configured",
            candidate_version=None,
            update_kind=None,
        )
        return
    policy = source.get("version_policy", "semver")
    if policy not in ("semver", "numeric"):
        component.update(
            update_status="unknown",
            update_reason="unsupported version policy",
            candidate_version=None,
            update_kind=None,
        )
        return
    if source.get("type") != "github_releases":
        component.update(
            update_status="unknown",
            update_reason="unsupported release source",
            candidate_version=None,
            update_kind=None,
        )
        return
    current = _version(
        _normalized(component.get("current_version"), source.get("current_prefix", "")),
        policy,
    )
    # Ranges and image tags are deliberately not interpreted as deployed versions.
    try:
        releases = fetch_releases(source)
        if not isinstance(releases, list):
            raise ValueError("release response must be an array")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        component.update(
            update_status="check failed",
            release_error=str(error),
            release_stale=bool(component.get("release_checked_at")),
        )
        return
    candidates = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        tag = release.get("tag_name")
        parsed = _version(_normalized(tag, source.get("tag_prefix", "")), policy)
        if parsed is None:
            continue
        if (release.get("prerelease") or parsed[1] is not None) and not source.get(
            "track_prereleases", False
        ):
            continue
        link = release.get("html_url")
        if not isinstance(link, str) or not link.startswith("https://"):
            continue
        candidates.append((parsed, tag, link))
    component["release_checked_at"] = checked_at
    component["release_error"] = None
    component["release_stale"] = False
    if not candidates:
        component.update(
            candidate_version=None,
            release_source_url=None,
            update_kind=None,
            update_status="unknown",
            update_reason="no eligible releases",
        )
        return
    best = candidates[0]
    for candidate in candidates[1:]:
        if _newer(candidate[0], best[0]):
            best = candidate
    parsed, tag, link = best
    component["candidate_version"] = tag
    component["release_source_url"] = link
    if current is None:
        component.update(
            update_status="unknown",
            update_kind=None,
            update_reason="missing verified application version or ambiguous version",
        )
    elif len(parsed[0]) != len(current[0]):
        component.update(
            update_status="unknown",
            update_kind=None,
            update_reason="version segment counts differ",
        )
    elif _newer(parsed, current):
        kind = (
            "major migration"
            if parsed[0][0] > current[0][0]
            else "minor"
            if parsed[0][1] > current[0][1]
            else "patch"
            if len(parsed[0]) > 2 and parsed[0][2] > current[0][2]
            else "prerelease"
        )
        component.update(
            update_status="update available", update_kind=kind, update_reason=None
        )
    else:
        component.update(
            update_status="up to date", update_kind=None, update_reason=None
        )


def apply_release_checks(
    services: list[dict],
    catalog: list[dict],
    fetch_releases=github_releases,
    clock=None,
    only_failed=False,
) -> list[dict]:
    """Return updated service snapshots without changing caller data."""
    checked_at = (
        (clock or (lambda: datetime.now(timezone.utc)))()
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    result = copy.deepcopy(services)
    fetched = {}

    def shared_fetch(source):
        key = _repository(source)
        if key not in fetched:
            try:
                fetched[key] = fetch_releases(source)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
                fetched[key] = error
        value = fetched[key]
        if isinstance(value, Exception):
            raise value
        return value

    by_id = {item["id"]: item for item in catalog}
    for service in result:
        configured = by_id.get(service["id"], {})
        configured_components = {
            item["id"]: item for item in configured.get("components", [])
        }
        for component in service.get("components", []):
            if only_failed and component.get("update_status") != "check failed":
                continue
            source = configured_components.get(component["id"], {}).get(
                "release_source"
            )
            if source:
                source = {
                    "track_prereleases": configured.get("track_prereleases", False),
                    **source,
                }
            _check(component, source, shared_fetch, checked_at)
        components = service.get("components", [])
        statuses = {item.get("update_status", "unknown") for item in components}
        service["update_status"] = next(
            (
                status
                for status in (
                    "update available",
                    "check failed",
                    "unknown",
                    "up to date",
                )
                if status in statuses
            ),
            "unknown",
        )
        service["update_coverage_complete"] = bool(components) and statuses <= {
            "update available",
            "up to date",
        }
        service["release_stale"] = any(
            item.get("release_stale", False) for item in components
        )
        successful = [
            item["release_checked_at"]
            for item in components
            if item.get("release_checked_at")
        ]
        service["release_checked_at"] = min(successful, default=None)
        service["candidate_version"] = (
            components[0].get("candidate_version") if len(components) == 1 else None
        )
        service["update_kind"] = (
            components[0].get("update_kind") if len(components) == 1 else None
        )
    return result
