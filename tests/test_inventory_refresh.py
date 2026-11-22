"""Inventory refresh keeps only evidence for the currently observed identities."""

import fcntl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from test_cached_http import HttpHarness
from test_inventory import component, pod

from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory


class InventoryRefreshTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
        self.registry = [{"id": "app", "active": True}]
        configured = component(
            "main", "app", "server", version_annotation="app/version"
        )
        configured["release_source"] = {
            "type": "github_releases",
            "repository": "example/app",
        }
        configured["advisory_source"] = {
            "type": "osv",
            "ecosystem": "PyPI",
            "package": "example-app",
        }
        self.catalog = [{"id": "app", "components": [configured]}]
        self.nodes = [
            {
                "metadata": {"name": "node-a"},
                "status": {
                    "nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}
                },
            }
        ]

    def inventory(self, version="1.0.0", digest="a"):
        image = "example/app:1"
        pods = [
            pod(
                "app-0",
                {"app": "app"},
                [{"name": "server", "image": image}],
                [
                    {
                        "name": "server",
                        "image": image,
                        "imageID": "example/app@sha256:" + digest * 64,
                    }
                ],
                annotations={"app/version": version},
            )
        ]
        return collect_inventory(self.registry, self.catalog, pods, self.nodes)

    def seed(self):
        services = self.inventory()
        component = services[0]["components"][0]
        deployment = component["deployments"][0]
        checked = self.now.isoformat().replace("+00:00", "Z")
        component.update(
            update_status="update available",
            candidate_version="v1.1.0",
            release_checked_at=checked,
            release_stale=False,
            advisory_coverage="complete",
            advisory_checked_at=checked,
            advisory_stale=False,
            advisory_identity={
                "source": self.catalog[0]["components"][0]["advisory_source"],
                "current_version": "1.0.0",
            },
            advisory_findings=[
                {
                    "id": "GHSA-example",
                    "aliases": [],
                    "match": "confirmed",
                    "severity": "high",
                }
            ],
        )
        deployment.update(
            image_status="up to date",
            image_checked_at=checked,
            candidate_image_digest=deployment["digest"],
            scan_coverage="complete",
            scan_checked_at=checked,
            scan_digest=deployment["digest"],
            scan_platform="linux/amd64",
            scan_findings=[
                {
                    "id": "CVE-TEST",
                    "severity": "high",
                    "package": "example",
                    "digest": deployment["digest"],
                    "platform": "linux/amd64",
                }
            ],
        )
        self.store.replace(checked, services)
        return checked

    def test_unchanged_refresh_keeps_evidence_and_last_success(self):
        checked = self.seed()
        self.now += timedelta(minutes=20)
        refresh_inventory(self.store, self.inventory, lambda: self.now)
        service = self.store.read()["services"][0]
        component = service["components"][0]
        self.assertEqual(component["release_checked_at"], checked)
        self.assertEqual(component["candidate_version"], "v1.1.0")
        self.assertEqual(component["advisory_checked_at"], checked)
        self.assertEqual(component["deployments"][0]["scan_checked_at"], checked)
        self.assertEqual(service["security_status"], "findings")
        self.assertEqual(service["confirmed_finding_count"], 2)
        self.assertEqual(
            self.store.read_jobs()["inventory"]["succeeded_at"],
            self.now.isoformat().replace("+00:00", "Z"),
        )

    def test_new_digest_invalidates_image_and_scan_only(self):
        self.seed()
        refresh_inventory(
            self.store,
            lambda: self.inventory(digest="b"),
            lambda: self.now + timedelta(minutes=1),
        )
        component = self.store.read()["services"][0]["components"][0]
        deployment = component["deployments"][0]
        self.assertEqual(component["candidate_version"], "v1.1.0")
        self.assertEqual(component["advisory_coverage"], "complete")
        self.assertEqual(deployment["image_status"], "unknown")
        self.assertEqual(deployment["scan_coverage"], "missing")
        self.assertNotIn("scan_findings", deployment)
        self.assertEqual(component["security_status"], "findings")
        self.assertFalse(component["coverage_complete"])

    def test_new_version_invalidates_release_and_advisory_only(self):
        self.seed()
        refresh_inventory(
            self.store,
            lambda: self.inventory(version="2.0.0"),
            lambda: self.now + timedelta(minutes=1),
        )
        component = self.store.read()["services"][0]["components"][0]
        self.assertEqual(component["update_status"], "unknown")
        self.assertNotIn("candidate_version", component)
        self.assertEqual(component["advisory_coverage"], "missing")
        self.assertEqual(component["advisory_findings"], [])
        self.assertEqual(component["deployments"][0]["scan_coverage"], "complete")

    def test_refresh_does_not_write_during_another_cycle(self):
        self.seed()
        before = self.store.read()
        lock_path = Path(str(self.database) + ".collection.lock")
        with lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                refresh_inventory(
                    self.store,
                    lambda: self.inventory(digest="b"),
                    lambda: self.now + timedelta(minutes=1),
                )
        self.assertEqual(self.store.read(), before)
        self.assertNotIn("inventory", self.store.read_jobs())

    def test_failed_refresh_retains_snapshot_and_marks_inventory_stale(self):
        self.seed()
        before = self.store.read()

        def fail():
            raise OSError("inventory API offline")

        with self.assertRaises(OSError):
            refresh_inventory(self.store, fail, lambda: self.now + timedelta(minutes=1))
        self.assertEqual(self.store.read(), before)
        self.assertIn(
            "inventory API offline", self.store.read_jobs()["inventory"]["error"]
        )
        _, home = self.get_json("/api/v1/services/app/homepage")
        _, summary = self.get_json("/api/v1/summary")
        _, page = self.get("/services/app")
        self.assertEqual(home["inventory_status"], "check failed")
        self.assertTrue(home["inventory_stale"])
        self.assertTrue(summary["stale"])
        self.assertIn("inventory API offline", page)
