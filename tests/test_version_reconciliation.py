"""Reconcile automatic sources and component checks through the cached views."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from test_advisories import SOURCE, advisory
from test_cached_http import HttpHarness
from test_images import Registry, digest, manifest
from test_inventory import component, pod
from test_scanner import FakeScanner

from service_health.advisories import apply_advisory_checks
from service_health.images import apply_image_checks
from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory
from service_health.releases import apply_release_checks
from service_health.scanner import apply_scan_checks
from service_health.store import Store


class ReconciliationTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = datetime.now(timezone.utc)
        self.repo = "registry.example/alpha/web"
        self.tag = {
            "type": "exact_tag",
            "repository": self.repo,
            "documentation": "https://example.org/tags",
        }
        self.endpoint = {
            "type": "endpoint",
            "url": "http://app.invalid/version",
            "json_path": ["version"],
            "documentation": "https://example.org/version",
        }
        self.metadata = {
            "type": "image_metadata",
            "repository": self.repo,
            "identity_label": "app",
            "identity_value": "web",
            "version_label": "version",
            "documentation": "https://example.org/labels",
        }
        self.fetch = Mock(return_value=b'{"version":"1.0.0"}')
        self.sources = [self.tag, self.endpoint]
        release = {"type": "github_releases", "repository": "example/web"}
        self.app = {
            **component("web", "app", "server"),
            "version_sources": self.sources,
            "release_source": release,
            "advisory_source": SOURCE,
        }
        self.other = {
            **component("worker", "worker", "server", version_annotation="version"),
            "release_source": {**release, "repository": "example/worker"},
        }
        self.catalog = [{"id": "app", "components": [self.app, self.other]}]

    def refresh(self, *versions):
        pods = []
        for i, (label, version) in enumerate(
            [*(("app", v) for v in versions), ("worker", "1.0.0")]
        ):
            container = {"name": "server", "image": self.repo + ":" + version}
            pods.append(
                pod(
                    f"{label}-{i}",
                    {"app": label},
                    [container],
                    [{**container, "imageID": digest("a")}],
                    annotations={"version": version},
                )
            )
        node = {
            "metadata": {"name": "node-a"},
            "status": {
                "nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}
            },
        }
        refresh_inventory(
            self.store,
            lambda: collect_inventory(
                [{"id": "app", "active": True}],
                self.catalog,
                pods,
                [node],
                lambda: self.now,
                endpoint_fetch=self.fetch,
                image_config=lambda *_: (
                    digest("a"),
                    digest("f"),
                    {"config": {"Labels": {"app": "web", "version": "2.0.0"}}},
                ),
            ),
            lambda: self.now,
        )

    def assess(self, failed=False, tags=("1.2.0",)):
        def release(source):
            if failed and source["repository"] == "example/web":
                raise OSError("release provider offline")
            return [
                {"tag_name": tag, "html_url": "https://example.org/" + tag}
                for tag in tags
            ]

        services = apply_release_checks(
            self.store.read()["services"], self.catalog, release, lambda: self.now
        )
        services = apply_advisory_checks(
            services, self.catalog, lambda _: [advisory()], lambda: self.now
        )
        registry = Registry(
            {"1.0.0": manifest(digest("a")), digest("a"): manifest(digest("a"))},
            {digest("f"): {"os": "linux", "architecture": "amd64"}},
        )
        services = apply_image_checks(
            services, registry.manifest, registry.blob, lambda: self.now
        )
        services = apply_scan_checks(services, FakeScanner(), lambda: self.now)
        self.store.commit_evidence(self.now.isoformat(), services)

    def home(self):
        return self.get_json("/api/v1/services/app/homepage")[1]

    def test_same_replica_dispute_keeps_independent_checks_and_update(self):
        self.sources.append(self.metadata)
        self.refresh("1.0.0")
        self.assess()
        home = self.home()
        web, worker = home["components"]
        self.assertEqual(web["version_state"], "disputed")
        self.assertIsNone(home["current_version"])
        self.assertIsNone(web["current_version"])
        self.assertIsNone(web["advisory_version"])
        self.assertEqual(web["possible_finding_count"], 1)
        self.assertEqual(web["update_status"], "unknown")
        self.assertEqual(web["image_status"], "up to date")
        self.assertEqual(web["scan_coverage"], "complete")
        self.assertEqual(worker["update_status"], home["update_status"])
        self.assertEqual(home["update_status"], "update available")
        self.assertFalse(home["update_coverage_complete"])
        html = self.get("/services/app")[1]
        for phrase in (
            "disputed deployment evidence for app-0",
            "image_metadata",
            "exact_tag",
            "endpoint",
            "Incomplete component update checks",
            "CVE-2026-0001",
        ):
            self.assertIn(phrase, html)

    def test_endpoint_only_release_cannot_fix_every_replica(self):
        self.app["version_sources"] = [self.endpoint]
        self.app["release_source"]["version_policy"] = "semver"
        self.refresh("latest", "latest")
        self.assess()
        component = self.get_json("/api/v1/services/app")[1]["components"][0]
        self.assertEqual(component["release_candidates"]["routine"]["version"], "1.2.0")
        self.assertIsNone(component["advisory_version"])
        finding = component["advisory_findings"][0]
        assessment = component["advisory_candidate_assessments"][finding["id"]][
            "routine"
        ]
        self.assertEqual(assessment["status"], "unknown")
        self.assertIn("replicas", assessment["reason"])

    def test_mixed_replicas_and_one_shared_sample(self):
        self.refresh("1.0.0", "2.0.0")
        web = self.home()["components"][0]
        self.assertEqual(web["version_state"], "mixed")
        self.assertEqual(
            [d["application_version"] for d in web["deployments"]], ["1.0.0", "2.0.0"]
        )
        self.assertEqual(len(web["version_observations"]), 1)
        self.assertIsNone(web["current_version"])
        self.fetch.return_value = b'{"version":"3.0.0"}'
        self.refresh("1.0.0", "2.0.0")
        web = self.home()["components"][0]
        self.assertEqual(web["version_state"], "disputed")
        self.assertIn("mixed deployments", web["version_evidence"])
        self.assertIn("endpoint-reported", web["version_evidence"])
        self.assertEqual(self.fetch.call_count, 2)

    def test_equivalent_endpoint_and_tag_versions_support_comparison(self):
        self.fetch.return_value = b'{"version":"v1.0.0"}'
        self.refresh("1.0.0")
        self.assess()
        web = self.home()["components"][0]
        self.assertEqual(web["version_state"], "observed")
        self.assertEqual(web["current_version"], "1.0.0")
        self.assertEqual(web["update_status"], "update available")
        sample = web["version_observations"][0]
        self.assertEqual(sample["reported"], "v1.0.0")
        self.assertEqual(sample["normalized"], "1.0.0")

    def test_failed_component_beside_current_update_then_expired_inventory(self):
        self.now -= timedelta(hours=3)
        self.refresh("1.0.0")
        self.assess()
        self.assess(failed=True)
        expired = self.home()
        self.assertTrue(expired["inventory_stale"])
        self.assertFalse(expired["update_coverage_complete"])
        self.assertEqual(expired["update_status"], "unknown")
        self.now += timedelta(hours=3)
        self.refresh("1.0.0")
        self.assess(failed=True)
        home = self.home()
        self.assertEqual(home["update_status"], "update available")
        self.assertFalse(home["update_coverage_complete"])
        web = home["components"][0]
        self.assertEqual(web["update_status"], "check failed")
        self.assertTrue(web["release_stale"])
        self.assertIn("release provider offline", self.get("/services/app")[1])

    def test_complete_collection_survives_restart_and_repeated_dashboard_reads(self):
        self.app["release_source"]["version_policy"] = "semver"
        del self.other["release_source"]
        self.refresh("1.0.0")
        self.assess(tags=("1.2.0", "2.0.0"))
        routes = (
            "/api/v1/summary",
            "/api/v1/services",
            "/api/v1/services/app",
            "/api/v1/services/app/homepage",
            "/",
            "/services/app",
        )
        with (
            patch("socket.socket", side_effect=AssertionError("unexpected network")),
            patch("subprocess.Popen", side_effect=AssertionError("unexpected command")),
        ):
            responses = {route: self.get(route) for route in routes}
            self.store = Store(self.database)
            for _ in range(2):
                self.assertEqual(
                    responses, {route: self.get(route) for route in routes}
                )

        self.assertEqual(self.fetch.call_count, 1)
        self.assertTrue(all(status == 200 for status, _ in responses.values()))
        summary, services, detail, homepage = [
            json.loads(responses[route][1]) for route in routes[:4]
        ]
        self.assertEqual(summary["service_count"], 1)
        for view in (summary, services["services"][0], detail, homepage):
            self.assertEqual(view["update_status"], "update available")
            self.assertFalse(view["update_coverage_complete"])
            self.assertEqual(view["security_status"], "findings")
        for view in (services["services"][0], homepage):
            self.assertIsNone(view["current_version"])
            self.assertEqual([c["id"] for c in view["components"]], ["web", "worker"])
            self.assertNotIn('"scan_findings"', json.dumps(view))
            self.assertNotIn('"advisory_findings"', json.dumps(view))
            web, worker = view["components"]
            self.assertEqual(worker["update_status"], "unknown")
            self.assertEqual(web["current_version"], "1.0.0")
            self.assertEqual(web["version_observations"][0]["scope"], "shared endpoint")
            self.assertEqual(web["release_candidates"]["routine"]["version"], "1.2.0")
            self.assertEqual(web["release_candidates"]["major"]["version"], "2.0.0")
        self.assertEqual(
            detail["components"][0]["scan_findings"][0]["package"], "openssl"
        )
        self.assertIn('href="services/app"', responses["/"][1])
        for phrase in ("CVE-2026-0001", "GHSA-aaaa-bbbb-cccc", "1.2.0", "2.0.0"):
            self.assertIn(phrase, responses["/services/app"][1])
