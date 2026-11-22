"""Offline regressions for the deployment's provider and interruption failures."""

import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

from service_health.github_cache import GitHubReleases
from service_health.images import apply_image_checks
from service_health.releases import apply_release_checks
from service_health.scanner import apply_scan_checks
from service_health.schedule import run_job
from service_health.store import Store

DIGEST = "sha256:" + "a" * 64
NOW = datetime(2026, 11, 22, tzinfo=timezone.utc)


class Response(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(json.dumps(body).encode())
        self.headers = headers or {}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.store = Store(self.path / "state.db")

    def test_shared_source_deduplicated_and_cache_survives_restart(self):
        calls = []

        def opener(request, timeout):
            calls.append(request)
            return Response(
                [{"tag_name": "1.1.0", "html_url": "https://example.org/release"}],
                {"ETag": '"abc"'},
            )

        catalog = [
            {
                "id": "app",
                "components": [
                    {
                        "id": "one",
                        "release_source": {
                            "type": "github_releases",
                            "repository": "Example/App",
                        },
                    },
                    {
                        "id": "two",
                        "release_source": {
                            "type": "github_releases",
                            "repository": "example/app",
                        },
                    },
                ],
            }
        ]
        services = [
            {
                "id": "app",
                "components": [
                    {"id": "one", "current_version": "1.0.0"},
                    {"id": "two", "current_version": "1.0.0"},
                ],
            }
        ]
        client = GitHubReleases(self.store, clock=lambda: NOW, opener=opener)
        result = apply_release_checks(services, catalog, client, lambda: NOW)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result[0]["update_status"], "update available")
        restarted = GitHubReleases(
            Store(self.store.path),
            clock=lambda: NOW + timedelta(hours=1),
            opener=opener,
        )
        restarted({"type": "github_releases", "repository": "EXAMPLE/APP"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            restarted.store.read_github_cache("example/app")["etag"], '"abc"'
        )

    def test_rate_limit_global_gate_recovery_and_redacted_authentication(self):
        token = self.path / "token"
        token.write_text("sensitive-test-token")
        calls = []
        tick = [NOW]

        def opener(request, timeout):
            calls.append(request)
            if len(calls) == 1:
                raise HTTPError(
                    request.full_url,
                    403,
                    "rate limit exceeded",
                    {"X-RateLimit-Remaining": "0", "Retry-After": "120"},
                    None,
                )
            return Response([])

        source = {"type": "github_releases", "repository": "example/one"}
        client = GitHubReleases(self.store, token, lambda: tick[0], opener=opener)
        with self.assertRaisesRegex(RuntimeError, "rate limited"):
            client(source)
        with self.assertRaisesRegex(RuntimeError, "rate limited"):
            GitHubReleases(self.store, token, lambda: tick[0], opener=opener)(
                {"type": "github_releases", "repository": "example/two"}
            )
        self.assertEqual(len(calls), 1)
        tick[0] += timedelta(seconds=121)
        GitHubReleases(self.store, token, lambda: tick[0], opener=opener)(source)
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0].get_header("Authorization"), "Bearer sensitive-test-token"
        )
        self.assertNotIn(
            "sensitive-test-token", self.store.path.read_bytes().decode("latin1")
        )

    def test_conditional_request_after_ttl_reuses_body(self):
        calls = []

        def opener(request, timeout):
            calls.append(request)
            if len(calls) == 2:
                raise HTTPError(request.full_url, 304, "not modified", {}, None)
            return Response([{"tag_name": "1.0.0"}], {"ETag": '"one"'})

        source = {"type": "github_releases", "repository": "example/app"}
        self.assertEqual(
            GitHubReleases(self.store, clock=lambda: NOW, opener=opener)(source)[0][
                "tag_name"
            ],
            "1.0.0",
        )
        next_day = NOW + timedelta(days=1)
        result = GitHubReleases(
            Store(self.store.path), clock=lambda: next_day, opener=opener
        )(source)
        self.assertEqual(result[0]["tag_name"], "1.0.0")
        self.assertEqual(calls[1].get_header("If-none-match"), '"one"')

    def test_retry_only_failed_release_component(self):
        services = [
            {
                "id": "app",
                "components": [
                    {
                        "id": "good",
                        "current_version": "1.0.0",
                        "update_status": "up to date",
                        "release_checked_at": "2026-11-22T00:00:00Z",
                    },
                    {
                        "id": "bad",
                        "current_version": "1.0.0",
                        "update_status": "check failed",
                    },
                ],
            }
        ]
        catalog = [
            {
                "id": "app",
                "components": [
                    {
                        "id": name,
                        "release_source": {
                            "type": "github_releases",
                            "repository": f"example/{name}",
                        },
                    }
                    for name in ("good", "bad")
                ],
            }
        ]
        calls = []

        def fetch(source):
            calls.append(source["repository"])
            return []

        result = apply_release_checks(
            services, catalog, fetch, lambda: NOW, only_failed=True
        )
        self.assertEqual(calls, ["example/bad"])
        self.assertEqual(result[0]["components"][0]["update_status"], "up to date")

    def test_local_and_private_image_are_unknown_without_remote_localhost(self):
        services = [
            {
                "id": "app",
                "components": [
                    {
                        "id": "main",
                        "deployments": [
                            {
                                "image": "localhost/pooky-upload-handler:latest",
                                "digest": DIGEST,
                                "platform": "linux/amd64",
                            },
                            {
                                "image": "private.example/app:latest",
                                "digest": DIGEST,
                                "platform": "linux/amd64",
                            },
                        ],
                    }
                ],
            }
        ]
        calls = []

        def manifest(image, reference):
            calls.append(image)
            raise HTTPError("https://private.example", 401, "unauthorized", {}, None)

        result = apply_image_checks(services, manifest=manifest, clock=lambda: NOW)
        local, private = result[0]["components"][0]["deployments"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(local["image_status"], "unknown")
        self.assertIn("unsupported local image", local["image_reason"])
        self.assertEqual(private["image_status"], "unknown")
        self.assertIn("authentication required", private["image_reason"])

    def test_scan_progress_retained_after_interruption_and_resumed(self):
        services = [
            {
                "id": "app",
                "components": [
                    {
                        "id": "main",
                        "deployments": [
                            {
                                "image": f"example.org/{name}:latest",
                                "digest": DIGEST,
                                "platform": "linux/amd64",
                            }
                            for name in ("one", "two")
                        ],
                    }
                ],
            }
        ]
        self.store.replace("2026-11-22T00:00:00Z", services)
        self.store.start_job("security", "2026-11-22T00:00:00Z")
        Path(str(self.store.path) + ".collection.lock").touch()

        class Scanner:
            def refresh_db(self):
                pass

            def scan(self, target, platform):
                return {
                    "SchemaVersion": 2,
                    "ArtifactName": target,
                    "Metadata": {
                        "ImageConfig": {"os": "linux", "architecture": "amd64"}
                    },
                    "Results": [],
                }

        def stop_after_one(partial):
            self.store.replace("2026-11-22T00:00:01Z", partial)
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            apply_scan_checks(
                services, Scanner(), lambda: NOW, max_workers=1, progress=stop_after_one
            )
        self.assertEqual(self.store.read_jobs()["security"]["state"], "interrupted")
        partial = self.store.read()["services"]
        complete = [
            d
            for d in partial[0]["components"][0]["deployments"]
            if d.get("scan_coverage") == "complete"
        ]
        self.assertEqual(len(complete), 1)
        resumed = apply_scan_checks(
            partial, Scanner(), lambda: NOW, max_workers=1, only_failed=True
        )
        self.assertTrue(
            all(
                d["scan_coverage"] == "complete"
                for d in resumed[0]["components"][0]["deployments"]
            )
        )

    def test_restarted_security_job_skips_completed_scan(self):
        checked = "2026-11-22T00:00:00Z"
        deployments = [
            {
                "image": f"example.org/{name}:latest",
                "digest": DIGEST,
                "platform": "linux/amd64",
            }
            for name in ("one", "two")
        ]
        deployments[0].update(
            scan_coverage="complete",
            scan_findings=[],
            scan_digest=DIGEST,
            scan_platform="linux/amd64",
            scan_checked_at=checked,
        )
        self.store.replace(
            checked,
            [{"id": "app", "components": [{"id": "main", "deployments": deployments}]}],
        )
        self.store.start_job("security", checked)
        catalog = self.path / "catalog.json"
        catalog.write_text("[]")

        class Scanner:
            def __init__(self):
                self.targets = []

            def refresh_db(self):
                pass

            def scan(self, target, platform):
                self.targets.append(target)
                return {
                    "SchemaVersion": 2,
                    "ArtifactName": target,
                    "Metadata": {
                        "ImageConfig": {"os": "linux", "architecture": "amd64"}
                    },
                    "Results": [],
                }

        scanner = Scanner()
        run_job(self.store, "security", catalog, scanner=scanner, clock=lambda: NOW)
        self.assertEqual(len(scanner.targets), 1)
        self.assertIn("/two@", scanner.targets[0])
        self.assertEqual(self.store.read_jobs()["security"]["state"], "completed")


if __name__ == "__main__":
    unittest.main()
