"""Collect application version observations from explicitly configured sources."""

import json
import re
import subprocess
import sys
from functools import lru_cache
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlsplit

from service_health.endpoint_transport import ENDPOINT_LIMIT
from service_health.images import RegistryDocumentError, _image_ref
from service_health.releases import _version

_EXACT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")


def configured_source(source):
    """Return only supported, public source fields for the cached evidence."""
    if source is None:
        return None
    invalid = {"type": "invalid"}
    if not isinstance(source, dict) or source.get("type") not in (
        "endpoint",
        "exact_tag",
        "image_metadata",
    ):
        return invalid
    documentation = source.get("documentation")
    if not isinstance(documentation, str):
        return invalid
    try:
        link = urlsplit(documentation)
        if (
            link.scheme != "https"
            or not link.hostname
            or link.username is not None
            or link.query
            or (link.fragment and not re.fullmatch(r"[\w.-]+", link.fragment))
        ):
            return invalid
    except ValueError:
        return invalid
    if source["type"] == "endpoint":
        url = source.get("url")
        path = source.get("json_path")
        if (
            not isinstance(path, list)
            or not 1 <= len(path) <= 12
            or any(
                not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k)
                for k in path
            )
            or not isinstance(url, str)
            or not url.isascii()
            or re.search(r"[\x00-\x20\x7f?#\\]", url)
        ):
            return invalid
        try:
            target = urlsplit(url)
            if (
                target.scheme not in ("http", "https")
                or not target.hostname
                or target.username is not None
            ):
                return invalid
            _ = target.port
        except ValueError:
            return invalid
        return {k: source[k] for k in ("type", "url", "json_path", "documentation")}
    repository = source.get("repository")
    if (
        not isinstance(repository, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", repository)
        or not _image_ref(repository + ":tag")
    ):
        return invalid
    if source["type"] == "image_metadata":
        keys = ("identity_label", "version_label")
        if any(
            not isinstance(source.get(key), str)
            or not re.fullmatch(r"[a-zA-Z0-9_.-]+", source[key])
            or source[key].startswith("org.opencontainers.image.base.")
            for key in keys
        ):
            return invalid
        if (
            source["identity_label"] == source["version_label"]
            or not isinstance(source.get("identity_value"), str)
            or not source["identity_value"].strip()
        ):
            return invalid
        return {
            key: source[key]
            for key in ("type", "repository", "documentation", *keys, "identity_value")
        }
    if any(not isinstance(source.get(k, ""), str) for k in ("prefix", "suffix")):
        return invalid
    return {
        k: source[k]
        for k in ("type", "repository", "documentation", "prefix", "suffix")
        if k in source
    }


def _record(source, reported, version, reason, checked_at):
    success = None
    if version is not None:
        success = {
            "reported": reported,
            "normalized": version,
            "checked_at": checked_at,
        }
    return {
        "source": source,
        "scope": "deployment",
        "reported": reported,
        "normalized": version,
        "checked_at": checked_at,
        "outcome": "success" if success else "unknown",
        "reason": reason,
        "last_success": success,
    }


def normalize_observations(records, release_source):
    """Apply the project's deployed-version spelling rules before reconciliation."""
    source = release_source if isinstance(release_source, dict) else {}
    policy = source.get("version_policy", "semver")
    prefix = source.get("current_prefix", "")
    for record in records:
        value = record["normalized"]
        if not value or len(value) > 128 or record["source"]["type"] == "exact_tag":
            continue
        candidate = value.strip()
        if isinstance(prefix, str):
            candidate = candidate.removeprefix(prefix)
        if _version(candidate, policy) is not None:
            normalized = candidate.removeprefix("v")
            record["normalized"] = normalized
            record["last_success"] = {
                **record["last_success"],
                "normalized": normalized,
            }


def fetch_endpoint(url):
    # Socket timeouts alone cannot bound DNS, headers or chunk framing.
    try:
        reply = subprocess.run(
            [sys.executable, "-m", "service_health.endpoint_transport"],
            input=url.encode("ascii"),
            capture_output=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError() from error
    if reply.returncode == 1 and re.fullmatch(rb"[0-9]{3}", reply.stdout):
        raise HTTPError(url, int(reply.stdout), "endpoint HTTP error", {}, None)
    if reply.returncode:
        raise OSError("endpoint request failed")
    return reply.stdout


def endpoint_observation(source, checked_at, fetch, deployed):
    def result(version=None, reason=None, outcome="unknown"):
        record = _record(source, version, version, reason, checked_at)
        record.update(
            scope="shared endpoint",
            outcome=outcome,
            limitation="Other replicas can report a different version.",
        )
        return record

    if not deployed:
        return result(reason="no matching deployment observed")
    try:
        body = fetch(source["url"])
        if len(body) > ENDPOINT_LIMIT:
            return result(
                reason="endpoint response exceeds 64 KiB", outcome="check failed"
            )
        value = json.loads(body)
        for key in source["json_path"]:
            if not isinstance(value, dict) or key not in value:
                return result(reason="configured JSON version field is absent")
            value = value[key]
        if (
            not isinstance(value, str)
            or len(value) > 128
            or not re.fullmatch(
                r"v?[0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?"
                r"(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?",
                value,
            )
        ):
            return result(reason="configured JSON field has no supported version value")
        return result(value, outcome="success")
    except HTTPError as error:
        error.close()
        if error.code in (401, 403):
            return result(reason="endpoint requires authentication")
        return result(
            reason=f"endpoint returned HTTP {error.code}", outcome="check failed"
        )
    except (HTTPException, OSError):
        return result(reason="version endpoint unavailable", outcome="check failed")
    except (ValueError, RecursionError):
        return result(reason="malformed endpoint response", outcome="check failed")


def image_metadata_observation(
    source, image, digest, platform, checked_at, read_config
):
    def gap(reason, outcome="unknown"):
        return {**_record(source, None, None, reason, checked_at), "outcome": outcome}

    name, at, pin = (image or "").partition("@")
    if at and not re.fullmatch(r"sha256:[0-9a-f]{64}", pin):
        return gap("observed image pin is malformed")
    ref = _image_ref(name) or _image_ref(name + ":unresolved")
    mapped = _image_ref(source["repository"] + ":mapped")
    if not ref or ref[:2] != mapped[:2]:
        return gap("observed repository differs from mapped application image")
    if not digest or not platform:
        return gap("running digest or deployed platform unavailable")
    target = (*mapped[:2], "")
    parts = tuple(platform.split("/"))
    try:
        manifest, config_digest, config = read_config(
            target, pin if at else digest, parts
        )
        if at and digest not in (pin, manifest, config_digest):
            running_manifest, _, _ = read_config(target, digest, parts)
            if running_manifest != manifest:
                return gap("observed image pin differs from deployed platform manifest")
        labels = config.get("config", {}).get("Labels")
        if labels is None:
            labels = {}
        if not isinstance(labels, dict):
            return gap("malformed image config labels", "check failed")
        if labels.get(source["identity_label"]) != source["identity_value"]:
            return gap("image metadata does not identify the mapped application")
        value = labels.get(source["version_label"])
        if value is None:
            return gap("mapped application version label is absent")
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value
        ):
            return gap("ambiguous or malformed application version label")
    except HTTPError as error:
        error.close()
        if error.code in (401, 403):
            return gap("registry authentication required for image metadata")
        return gap(
            f"image metadata unavailable: registry HTTP {error.code}", "check failed"
        )
    except (HTTPException, OSError):
        return gap("image metadata inaccessible", "check failed")
    except RegistryDocumentError as error:
        return gap(str(error), "check failed")
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return gap("malformed registry metadata", "check failed")
    return {
        **_record(source, value, value, None, checked_at),
        "manifest_digest": manifest,
        "config_digest": config_digest,
    }


def inventory_metadata_reader(checked_at, read_config):
    # Keep only small observations for this pass, including failed lookups.
    @lru_cache(maxsize=64)
    def read(source_items, image, digest, platform):
        return image_metadata_observation(
            dict(source_items), image, digest, platform, checked_at, read_config
        )

    return read


def deployment_observations(
    sources,
    annotation,
    annotations,
    observed_image,
    metadata_image,
    digest,
    checked_at,
    platform,
    read_metadata,
):
    records = []
    if annotation:
        value = annotations.get(annotation) or None
        records.append(
            _record(
                {"type": "pod_annotation", "key": annotation},
                value,
                value,
                None if value else "configured pod annotation is absent",
                checked_at,
            )
        )
    for source in sources:
        if source["type"] == "image_metadata":
            records.append(
                read_metadata(
                    tuple(source.items()), metadata_image, digest, platform
                ).copy()
            )
        elif source["type"] == "exact_tag":
            records.append(_tag_observation(source, observed_image, digest, checked_at))
        elif source["type"] == "invalid":
            records.append(
                _record(
                    source,
                    None,
                    None,
                    "invalid or unsupported version source",
                    checked_at,
                )
            )
    return records


def _tag_observation(source, observed_image, digest, checked_at):
    repository = source["repository"]
    prefix = source.get("prefix", "")
    suffix = source.get("suffix", "")
    ref = _image_ref(observed_image)
    mapped = _image_ref(repository + ":tag")
    version = None
    reported = ref[2] if ref else None
    if not digest or not ref:
        reason = "no observed tagged image with a running digest"
    elif not mapped or ref[:2] != mapped[:2]:
        reason = "observed image repository differs from the documented tag mapping"
    else:
        candidate = reported.removeprefix(prefix).removesuffix(suffix)
        if reported == prefix + candidate + suffix and _EXACT.fullmatch(candidate):
            version, reason = candidate, None
        else:
            reason = "tag does not match the documented exact three-segment version"
    return _record(source, reported, version, reason, checked_at)
