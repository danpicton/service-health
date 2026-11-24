"""Collect digest-bound image labels through inventory and the cached HTTP API."""

import hashlib
import io
import json
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.error import HTTPError

from test_cached_http import HttpHarness
from test_images import INDEX, MANIFEST
from test_inventory import component, pod

from service_health.images import (
    RegistryDocumentError,
    apply_image_checks,
    registry_manifest,
)
from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory


class ImageMetadataTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.docs = {}
        self.source = {
            "type": "image_metadata",
            "repository": "example/photos",
            "documentation": "https://example.org/photos/image-labels",
            "identity_label": "org.opencontainers.image.title",
            "identity_value": "Example Photos",
            "version_label": "org.opencontainers.image.version",
        }
        self.labels = {
            self.source["identity_label"]: "Example Photos",
            self.source["version_label"]: "1.2.3",
        }
        self.platform = {"os": "linux", "architecture": "amd64"}

    def put(self, document):
        body = json.dumps(document).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.docs[digest] = (body, digest)
        return digest

    def build(self, labels=None, config_platform=None, duplicate=False):
        config = self.put(
            {
                **(config_platform or self.platform),
                "config": {"Labels": self.labels if labels is None else labels},
            }
        )
        manifest = self.put({"mediaType": MANIFEST, "config": {"digest": config}})
        descriptor = {
            "mediaType": MANIFEST,
            "digest": manifest,
            "platform": self.platform,
        }
        index = self.put(
            {"mediaType": INDEX, "manifests": [descriptor] * (1 + duplicate)}
        )
        return index, manifest, config

    def collect(self, digest, image="example/photos:latest", configured_image=None):
        config = component("main", "photos", "server")
        config["version_source"] = self.source
        container = {"name": "server", "image": image}
        fixture = pod(
            "photos-1",
            {"app": "photos"},
            [{**container, "image": configured_image or image}],
            [{**container, "imageID": digest}],
        )
        node = {
            "metadata": {"name": "node-a"},
            "status": {
                "nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}
            },
        }

        def request(registry, repository, resource, ref):
            response = self.docs[ref]
            if isinstance(response, Exception):
                raise response
            return response

        with patch("service_health.images._request", side_effect=request):
            refresh_inventory(
                self.store,
                lambda: collect_inventory(
                    [{"id": "photos", "active": True}],
                    [{"id": "photos", "components": [config]}],
                    [fixture],
                    [node],
                    lambda: datetime.now(timezone.utc),
                ),
            )
        home = self.get_json("/api/v1/services/photos/homepage")[1]
        record = home["components"][0]["deployments"][0]["version_observations"][0]
        return home["current_version"], record

    def test_tag_movement_and_index_or_platform_pins_through_cache(self):
        index, manifest, config = self.build()
        _, newer, _ = self.build({**self.labels, self.source["version_label"]: "2.0.0"})
        self.docs["latest"] = self.docs[newer]
        for reference, running in (
            ("example/photos:latest", index),
            ("example/photos@" + index, manifest),
            ("example/photos@" + index, config),
            ("example/photos@" + manifest, config),
            ("example/photos:latest@" + manifest, manifest),
        ):
            with self.subTest(reference=reference):
                version, record = self.collect(running, reference)
                self.assertEqual(version, "1.2.3")
                self.assertEqual(record["source"], self.source)
                self.assertEqual(record["manifest_digest"], manifest)
                self.assertEqual(record["config_digest"], config)
                page = self.get("/services/photos")[1]
                for label in (config, manifest, "Example Photos", "image_metadata"):
                    self.assertIn(label, page)
        version, record = self.collect(manifest, "example/photos@" + newer)
        self.assertIsNone(version)
        self.assertIn("differs", record["reason"])

    def test_candidate_classification_from_immutable_mapped_config(self):
        running, _, _ = self.build()
        for value, kind, expected_reason in (
            ("1.2.3", "verified rebuild", "unchanged"),
            ("2.0.0", "image update", "changed"),
            (None, "image update", "absent"),
            ("unavailable", "image update", "inaccessible"),
        ):
            with self.subTest(value=value):
                self.collect(running)
                labels = {
                    self.source["identity_label"]: "Example Photos",
                    "build": "new",
                }
                if value is not None:
                    labels[self.source["version_label"]] = value
                candidate, manifest, config = self.build(labels)
                self.docs["latest"] = self.docs[candidate]

                def request(registry, repository, resource, ref):
                    if value == "unavailable" and ref == config:
                        raise OSError("synthetic failure")
                    return self.docs[ref]

                with patch("service_health.images._request", side_effect=request):
                    assessed = apply_image_checks(self.store.read()["services"])
                self.store.commit_evidence(
                    datetime.now(timezone.utc).isoformat(), assessed
                )
                home = self.get_json("/api/v1/services/photos/homepage")[1]
                result = home["components"][0]["deployments"][0]
                self.assertEqual(home["image_status"], "image update available")
                self.assertEqual(result["candidate_image_digest"], manifest)
                self.assertEqual(result["image_update_kind"], kind)
                self.assertEqual(
                    result["candidate_application_version"],
                    None if value == "unavailable" else value,
                )
                self.assertIn(expected_reason, result["image_reason"])
                page = self.get("/services/photos")[1]
                self.assertIn(expected_reason, page)
                self.assertEqual("verified rebuild" in page, kind == "verified rebuild")
                if kind == "verified rebuild":
                    with patch("service_health.images._request", side_effect=OSError):
                        failed = apply_image_checks(assessed)
                        retried = apply_image_checks(failed)
                    self.store.commit_evidence(
                        datetime.now(timezone.utc).isoformat(), retried
                    )
                    cached = self.get_json("/api/v1/services/photos/homepage")[1]
                    stale = cached["components"][0]["deployments"][0]
                    self.assertIsNone(stale["image_update_kind"])
                    self.assertTrue(stale["image_stale"])
                    history = stale["image_update_history"]
                    self.assertEqual(history["image_update_kind"], "verified rebuild")
                    self.assertEqual(history["candidate_application_version"], value)
                    self.assertEqual(history["candidate_image_digest"], manifest)
                    self.assertIn(
                        "previous classification: verified rebuild",
                        self.get("/services/photos")[1],
                    )

    def test_configured_pin_cannot_be_compared_using_runtime_tag(self):
        index, manifest, _ = self.build()
        self.collect(manifest, configured_image="example/photos@" + index)
        with patch("service_health.images._request") as request:
            checked = apply_image_checks(self.store.read()["services"])
        request.assert_not_called()
        deployment = checked[0]["components"][0]["deployments"][0]
        self.assertEqual(deployment["image_status"], "unknown")
        self.assertIsNone(deployment["image_update_kind"])

    def test_pod_pin_with_runtime_name_and_docker_config_id(self):
        index, manifest, config = self.build()
        version, record = self.collect(
            "docker://" + config, configured_image="example/photos@" + index
        )
        self.assertEqual(version, "1.2.3")
        self.assertEqual(record["manifest_digest"], manifest)
        self.assertEqual(record["config_digest"], config)
        _, newer, _ = self.build({**self.labels, self.source["version_label"]: "2.0.0"})
        version, record = self.collect(
            newer, configured_image="example/photos@" + index
        )
        self.assertIsNone(version)
        self.assertIn("differs", record["reason"])

    def test_application_identity_and_version_are_both_required(self):
        for labels, reason in (
            ({}, "identify"),
            ({**self.labels, self.source["identity_label"]: "base"}, "identify"),
            ({self.source["identity_label"]: "Example Photos"}, "absent"),
            (
                {**self.labels, self.source["version_label"]: "1.2.3 or 2.0"},
                "ambiguous",
            ),
        ):
            with self.subTest(labels=labels):
                version, record = self.collect(self.build(labels)[0])
                self.assertIsNone(version)
                self.assertIn(reason, record["reason"])

    def test_bad_registry_bytes_platform_and_anonymous_failures(self):
        digest, manifest, config = self.build()
        self.collect(digest)
        original = self.docs.copy()
        for reference, replacement, reason in (
            (digest, self.docs[manifest], "different manifest digest"),
            (manifest, (b"{}", manifest), "manifest digest mismatch"),
            (config, self.docs[manifest], "blob digest mismatch"),
            (digest, HTTPError("fixture", 401, "", {}, None), "authentication"),
            (digest, OSError("timeout"), "inaccessible"),
            (
                digest,
                ValueError("private transport detail"),
                "malformed registry metadata",
            ),
        ):
            with self.subTest(reason=reason):
                self.docs = {**original, reference: replacement}
                version, record = self.collect(digest)
                self.assertIsNone(version)
                self.assertIn(reason, record["reason"])
                self.assertEqual(record["last_success"]["normalized"], "1.2.3")
                self.assertNotIn("private transport detail", str(self.store.read()))
        for digest, reason in (
            (self.put("malformed"), "invalid registry document"),
            (self.build(duplicate=True)[0], "ambiguous"),
            (
                self.build(config_platform={"os": "linux", "architecture": "arm64"})[0],
                "platform differs",
            ),
        ):
            version, record = self.collect(digest)
            self.assertIsNone(version)
            self.assertIn(reason, record["reason"])

    def test_registry_limits_and_malformed_token(self):
        challenge = {
            "WWW-Authenticate": 'Bearer realm="https://auth.example/token",service="example",scope="read"'
        }
        for body, token_request, reason in (
            (b"X" * (4 * 1024 * 1024 + 1), False, "size limit"),
            (b"X" * (64 * 1024 + 1), True, "size limit"),
            (
                json.dumps({"token": "fixture\nvalue"}).encode(),
                True,
                "invalid registry token",
            ),
        ):
            with self.subTest(reason=reason, token_request=token_request):
                response = io.BytesIO(body)
                response.headers = {}
                replies = [response]
                if token_request:
                    replies.insert(0, HTTPError("fixture", 401, "", challenge, None))
                with patch("service_health.images.urlopen", side_effect=replies):
                    with self.assertRaisesRegex(RegistryDocumentError, reason):
                        registry_manifest(
                            ("registry.example", "example/photos", ""), "latest"
                        )
