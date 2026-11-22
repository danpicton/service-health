"""Offline OCI image checks through cached API and rendered HTML."""

from datetime import datetime, timezone

from test_cached_http import HttpHarness

from service_health.images import apply_image_checks

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def digest(char):
    return "sha256:" + char * 64


def service(image, running=digest("a"), platform="linux/amd64"):
    return [
        {
            "id": "app",
            "name": "App",
            "update_status": "up to date",
            "candidate_version": "1.0.0",
            "components": [
                {
                    "id": "server",
                    "name": "Server",
                    "update_status": "up to date",
                    "deployments": [
                        {
                            "image": image,
                            "digest": running,
                            "platform": platform,
                            "pod": "app-0",
                        }
                    ],
                }
            ],
        }
    ]


class Registry:
    def __init__(self, documents, configs=None):
        self.documents = documents
        self.configs = configs or {}
        self.calls = []

    def manifest(self, image, reference):
        self.calls.append((image, reference))
        return self.documents[reference]

    def blob(self, image, reference):
        return self.configs[reference]


def index(index_digest, platform_digest):
    return index_digest, {
        "mediaType": INDEX,
        "manifests": [
            {
                "mediaType": MANIFEST,
                "digest": platform_digest,
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        ],
    }


def manifest(manifest_digest, config_digest=digest("f")):
    return manifest_digest, {"mediaType": MANIFEST, "config": {"digest": config_digest}}


class ImageTest(HttpHarness):
    def check(self, image, registry, running=digest("a"), platform="linux/amd64"):
        result = apply_image_checks(
            service(image, running, platform),
            registry.manifest,
            registry.blob,
            lambda: datetime(2026, 11, 22, tzinfo=timezone.utc),
        )
        self.store.replace("2026-11-22T00:00:00Z", result)
        return (
            self.get_json("/api/v1/services/app/homepage")[1],
            self.get_json("/api/v1/services/app")[1],
            self.get("/services/app")[1],
        )

    def test_same_tag_rebuild_is_separate_from_application_release(self):
        registry = Registry(
            {
                "latest": index(digest("c"), digest("b")),
                digest("a"): index(digest("a"), digest("d")),
            }
        )
        homepage, detail, page = self.check("example.org/app:latest", registry)
        self.assertEqual(homepage["image_status"], "image rebuild available")
        self.assertEqual(homepage["candidate_image_digest"], digest("b"))
        self.assertEqual(homepage["update_status"], "up to date")
        self.assertEqual(homepage["candidate_version"], "1.0.0")
        self.assertTrue(homepage["image_coverage_complete"])
        self.assertEqual(
            detail["components"][0]["deployments"][0]["deployed_platform_digest"],
            digest("d"),
        )
        self.assertIn("image rebuild available", page)
        self.assertIn(digest("b"), page)
        self.assertEqual(
            self.get_json("/api/v1/summary")[1]["image_counts"][
                "image rebuild available"
            ],
            1,
        )
        self.assertEqual(len(registry.calls), 2)

    def test_index_and_manifest_representation_is_unchanged(self):
        registry = Registry(
            {
                "1.0": index(digest("b"), digest("a")),
                digest("a"): manifest(digest("a")),
            },
            {digest("f"): {"os": "linux", "architecture": "amd64"}},
        )
        homepage, _, page = self.check("registry.example/app:1.0", registry)
        self.assertEqual(homepage["image_status"], "up to date")
        self.assertIn("deployed platform digest " + digest("a"), page)

    def test_unchanged_indexes_and_digest_pin(self):
        registry = Registry(
            {
                "stable": index(digest("a"), digest("b")),
                digest("a"): index(digest("a"), digest("b")),
            }
        )
        home, _, _ = self.check("registry.example/app:stable", registry)
        self.assertEqual(home["image_status"], "up to date")
        pinned, detail, _ = self.check("registry.example/app@" + digest("a"), registry)
        self.assertEqual(pinned["image_status"], "unknown")
        self.assertFalse(pinned["image_coverage_complete"])
        self.assertIn(
            "mutable tag", detail["components"][0]["deployments"][0]["image_reason"]
        )

    def test_ambiguous_platform_and_registry_failure(self):
        ambiguous = Registry(
            {
                "latest": (
                    digest("c"),
                    {
                        "mediaType": INDEX,
                        "manifests": [
                            {
                                "mediaType": MANIFEST,
                                "digest": digest("b"),
                                "platform": {
                                    "os": "linux",
                                    "architecture": "amd64",
                                    "variant": "v1",
                                },
                            },
                            {
                                "mediaType": MANIFEST,
                                "digest": digest("d"),
                                "platform": {
                                    "os": "linux",
                                    "architecture": "amd64",
                                    "variant": "v2",
                                },
                            },
                        ],
                    },
                ),
            }
        )
        home, _, _ = self.check("registry.example/app:latest", ambiguous)
        self.assertEqual(home["image_status"], "check failed")
        self.assertFalse(home["image_coverage_complete"])
        missing = Registry({})
        home, detail, _ = self.check("registry.example/app:latest", missing)
        self.assertEqual(home["image_status"], "check failed")
        self.assertFalse(home["image_stale"])
        self.assertNotIn(
            "candidate_image_digest", detail["components"][0]["deployments"][0]
        )

    def test_unknown_platform_and_stale_retained_evidence(self):
        registry = Registry(
            {
                "latest": index(digest("c"), digest("b")),
                digest("a"): index(digest("a"), digest("d")),
            }
        )
        home, _, _ = self.check("registry.example/app:latest", registry, platform=None)
        self.assertEqual(home["image_status"], "unknown")
        first = apply_image_checks(
            service("registry.example/app:latest"), registry.manifest, registry.blob
        )
        failed = apply_image_checks(first, Registry({}).manifest, registry.blob)
        self.store.replace("2026-11-22T00:00:00Z", failed)
        home = self.get_json("/api/v1/services/app/homepage")[1]
        self.assertEqual(home["image_status"], "check failed")
        self.assertEqual(home["candidate_image_digest"], digest("b"))
        self.assertTrue(home["image_stale"])
        self.assertTrue(home["stale"])


if __name__ == "__main__":
    import unittest

    unittest.main()
