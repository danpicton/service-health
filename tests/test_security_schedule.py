"""Exercise security scheduling against synthetic deployments and a fake clock."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import EAI_AGAIN, gaierror
from threading import Barrier
from urllib.error import HTTPError, URLError

from test_cached_http import HttpHarness, _MemorySocket

from service_health.http import make_handler
from service_health.inventory_refresh import refresh_inventory
from service_health.schedule import run_job, run_schedule
from service_health.store import Store

START = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
HEALTHY = "sha256:" + "a" * 64
FAILING = "sha256:" + "b" * 64
REPLACEMENT = "sha256:" + "c" * 64


class SchedulerTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = START
        self.catalog = self.database.with_name("catalog.json")
        self.catalog.write_text("[]")
        self.scans = []
        self.refreshes = []
        self.failing_digests = {FAILING}
        self.scan_errors = {}
        self.scan_reports = {}
        self.replacement_delay = 0
        self.store.replace(
            START.isoformat(),
            [
                {
                    "id": "app",
                    "components": [
                        {
                            "id": name,
                            "deployments": [
                                {
                                    "image": f"example.org/{name}:latest",
                                    "digest": digest,
                                    "platform": "linux/amd64",
                                }
                            ],
                        }
                        for name, digest in (("healthy", HEALTHY), ("failing", FAILING))
                    ],
                }
            ],
        )
        self.store.record_job("release", START.isoformat(), None)

    def clock(self):
        return self.now

    def get(self, path):
        connection = _MemorySocket(f"GET {path} HTTP/1.1\r\n\r\n".encode())
        make_handler(self.store, self.clock)(connection, ("offline", 0), None)
        head, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
        return int(head.split(b" ")[1]), body.decode()

    def sleep(self, seconds):
        self.now += timedelta(seconds=seconds)

    def refresh_db(self):
        self.refreshes.append(int((self.now - START).total_seconds()))

    def scan(self, target, platform):
        digest = target.rsplit("@", 1)[1]
        self.scans.append((int((self.now - START).total_seconds()), digest))
        if digest == FAILING and self.now == getattr(self, "replace_during_scan", None):
            self.sleep(self.replacement_delay)
            services = self.store.read()["services"]
            deployment = services[0]["components"][1]["deployments"][0]
            deployment["digest"] = REPLACEMENT
            refresh_inventory(self.store, lambda: services, self.clock)
        if digest in self.failing_digests:
            raise TimeoutError("synthetic scan timeout")
        if digest in self.scan_errors:
            raise self.scan_errors[digest]
        if digest in self.scan_reports:
            return self.scan_reports[digest]
        return {
            "SchemaVersion": 2,
            "ArtifactName": target,
            "Metadata": {"ImageConfig": {"os": "linux", "architecture": "amd64"}},
            "Results": [{"Target": "alpine", "Class": "os-pkgs"}],
        }

    def run_until(self, end, *, interval=100):
        deadline = START + timedelta(seconds=end)
        run_schedule(
            self.store,
            self.catalog,
            scanner=self,
            release_interval=1000,
            security_interval=interval,
            retry_initial=10,
            retry_max=40,
            scan_workers=1,
            clock=self.clock,
            sleep=lambda seconds: self.sleep(
                min(seconds, (deadline - self.now).total_seconds())
            ),
            stop=lambda: self.now >= deadline,
        )

    def test_failed_image_does_not_starve_full_scan_across_restart(self):
        self.run_until(75)
        self.store = Store(self.database)
        self.run_until(105)
        self.assertEqual(
            [at for at, digest in self.scans if digest == HEALTHY], [0, 100]
        )
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING], [0, 10, 30, 70, 100]
        )
        self.assertEqual(self.refreshes, [0, 10, 30, 70, 100])

    def test_concurrent_store_startup_migrates_existing_jobs(self):
        database = self.database.with_name("legacy.db")
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(
                "CREATE TABLE jobs (name TEXT PRIMARY KEY, attempted_at TEXT NOT NULL, "
                "succeeded_at TEXT, error TEXT, failures INTEGER NOT NULL, "
                "state TEXT NOT NULL DEFAULT 'completed')"
            )
            connection.execute(
                "INSERT INTO jobs VALUES ('security', ?, ?, NULL, 0, 'completed')",
                (START.isoformat(), START.isoformat()),
            )

        startup = Barrier(8)

        def read_security_job():
            startup.wait(timeout=5)
            return Store(database).read_jobs()["security"]

        with ThreadPoolExecutor(max_workers=8) as workers:
            reads = [workers.submit(read_security_job) for _ in range(8)]
            for read in reads:
                self.assertEqual(read.result()["succeeded_at"], START.isoformat())

    def test_partial_cycle_keeps_good_scan_and_reports_retry_and_full_times(self):
        self.run_until(1)
        _, summary = self.get_json("/api/v1/summary")
        job = summary["jobs"]["security"]
        self.assertEqual(job["state"], "partial")
        self.assertIsNone(job["error"])
        self.assertEqual(job["next_retry_at"], "2026-11-22T12:00:10Z")
        self.assertEqual(job["next_full_at"], "2026-11-22T12:01:40Z")
        self.assertFalse(summary["coverage_complete"])
        _, detail = self.get_json("/api/v1/services/app")
        healthy, failing = detail["components"]
        self.assertEqual(healthy["deployments"][0]["scan_outcome"], "success")
        self.assertEqual(failing["deployments"][0]["scan_outcome"], "transient_failure")
        self.assertEqual(healthy["advisory_reason"], "advisory_source_unsupported")
        self.assertIn("security job completed with coverage gaps", self.get("/")[1])

    def test_access_gap_rechecks_on_full_scan_without_automatic_retry(self):
        self.failing_digests.clear()
        denied = HTTPError("https://example.org/v2/", 403, "denied", None, None)
        self.addCleanup(denied.close)
        self.scan_errors[FAILING] = denied
        services = self.store.read()["services"]
        deployments = services[0]["components"][1]["deployments"]
        deployments.append({"image": "localhost/local:latest"})
        self.store.replace(START.isoformat(), services)
        self.run_until(30)
        _, detail = self.get_json("/api/v1/services/app")
        blocked, local = detail["components"][1]["deployments"]
        self.assertEqual(blocked["scan_coverage"], "missing")
        self.assertEqual(blocked["scan_outcome"], "access_required")
        self.assertEqual(blocked["scan_reason"], "provider_access_required")
        self.assertEqual(local["scan_outcome"], "unavailable")
        self.assertEqual(local["scan_reason"], "image_not_pullable")
        _, summary = self.get_json("/api/v1/summary")
        self.assertIsNone(summary["jobs"]["security"]["next_retry_at"])
        self.assertIn("provider_access_required", self.get("/services/app")[1])
        self.store = Store(self.database)
        self.run_until(101)
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING], [0, 100]
        )

    def test_busybox_reports_without_targets_wait_for_next_full_scan(self):
        services = self.store.read()["services"]
        deployments = services[0]["components"][1]["deployments"]
        deployments.clear()
        for tag in ("1.38.0", "latest"):
            fixture = Path(__file__).parent / "fixtures" / f"trivy-busybox-{tag}.json"
            report = json.loads(fixture.read_text())
            digest = report["ArtifactName"].rsplit("@", 1)[1]
            self.scan_reports[digest] = report
            deployments.append(
                {
                    "image": f"docker.io/library/busybox:{tag}",
                    "digest": digest,
                    "platform": "linux/amd64",
                }
            )
        self.store.replace(START.isoformat(), services)

        self.run_until(95)
        _, detail = self.get_json("/api/v1/services/app")
        for item in detail["components"][1]["deployments"]:
            self.assertEqual(item["scan_coverage"], "missing")
            self.assertEqual(item["scan_outcome"], "unsupported")
            self.assertEqual(item["scan_reason"], "no_supported_package_targets")
        _, summary = self.get_json("/api/v1/summary")
        self.assertEqual(summary["jobs"]["security"]["state"], "partial")
        self.assertIsNone(summary["jobs"]["security"]["next_retry_at"])
        self.assertIn("No supported package targets", self.get("/services/app")[1])
        self.run_until(101)
        for digest in self.scan_reports:
            self.assertEqual(
                [at for at, image in self.scans if image == digest], [0, 100]
            )

    def test_unreadable_catalog_marks_job_failed(self):
        self.run_until(1)
        self.catalog.write_text("invalid JSON")
        with self.assertRaises(ValueError):
            run_job(
                self.store,
                "security",
                self.catalog,
                self,
                clock=self.clock,
                security_interval=100,
                retry_initial=10,
                retry_max=40,
            )
        self.store = Store(self.database)
        _, summary = self.get_json("/api/v1/summary")
        job = summary["jobs"]["security"]
        self.assertEqual(job["state"], "failed")
        self.assertIn("JSONDecodeError", job["error"])
        self.assertEqual(job["next_retry_at"], "2026-11-22T12:00:11Z")
        self.assertIn("security job failed", self.get("/")[1])

    def test_unclassified_and_malformed_reports_do_not_schedule_retries(self):
        self.failing_digests.clear()
        self.scan_errors[HEALTHY] = RuntimeError("Trivy exited with status 1")
        self.scan_reports[FAILING] = {"SchemaVersion": 99}
        self.run_until(95)
        _, detail = self.get_json("/api/v1/services/app")
        healthy, failing = detail["components"]
        self.assertEqual(healthy["deployments"][0]["scan_outcome"], "unknown_failure")
        self.assertEqual(failing["deployments"][0]["scan_reason"], "malformed_report")
        self.assertEqual(self.refreshes, [0])

    def test_unknown_provider_error_does_not_publish_opaque_details(self):
        self.failing_digests.clear()
        self.scan_errors[FAILING] = RuntimeError("synthetic-sensitive-marker")
        self.run_until(1)
        _, detail = self.get_json("/api/v1/services/app")
        scan = detail["components"][1]["deployments"][0]
        self.assertEqual(scan["scan_reason"], "provider_failed")
        self.assertNotIn("synthetic-sensitive-marker", scan["scan_error"])
        self.assertNotIn("synthetic-sensitive-marker", self.get("/services/app")[1])

    def test_temporary_dns_failure_uses_bounded_retry(self):
        self.failing_digests.clear()
        self.scan_errors[FAILING] = URLError(gaierror(EAI_AGAIN, "temporary DNS"))
        self.run_until(12)
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING], [0, 10]
        )
        _, detail = self.get_json("/api/v1/services/app")
        scan = detail["components"][1]["deployments"][0]
        self.assertEqual(scan["scan_outcome"], "transient_failure")

    def test_infrastructure_failure_keeps_cached_blocked_coverage(self):
        services = self.store.read()["services"]
        services[0]["components"][1]["deployments"][0] = {
            "image": "localhost/local:latest"
        }
        self.store.replace(START.isoformat(), services)
        self.run_until(1)
        self.catalog.write_text("invalid JSON")
        with self.assertRaises(ValueError):
            run_job(self.store, "security", self.catalog, self, clock=self.clock)
        _, detail = self.get_json("/api/v1/services/app")
        healthy, local = detail["components"]
        self.assertEqual(healthy["deployments"][0]["scan_coverage"], "failed")
        self.assertEqual(local["deployments"][0]["scan_coverage"], "missing")
        self.assertEqual(local["deployments"][0]["scan_reason"], "image_not_pullable")
        self.assertEqual(local["advisory_coverage"], "missing")

    def test_expiry_preserves_the_latest_provider_failure(self):
        self.failing_digests.clear()
        self.run_until(1)
        self.scan_errors[FAILING] = TimeoutError("timeout")
        self.run_until(101)
        self.now += timedelta(days=3)
        _, detail = self.get_json("/api/v1/services/app")
        scan = detail["components"][1]["deployments"][0]
        self.assertEqual(scan["scan_coverage"], "failed")
        self.assertEqual(scan["scan_error"], "Provider timed out")
        self.assertTrue(scan["scan_stale"])

    def test_replicas_of_same_digest_share_remote_retry_budget(self):
        services = self.store.read()["services"]
        deployments = services[0]["components"][1]["deployments"]
        deployments.append({**deployments[0], "image": "example.org/failing:stable"})
        self.store.replace(START.isoformat(), services)
        self.run_until(75)
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING], [0, 10, 30, 70]
        )

    def test_full_scan_is_due_before_next_retry(self):
        self.run_until(27, interval=25)
        self.assertEqual(
            [at for at, digest in self.scans if digest == HEALTHY], [0, 25]
        )
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING], [0, 10, 25]
        )

    def test_failed_retry_cannot_delay_the_full_deadline(self):
        self.replace_during_scan = START + timedelta(seconds=10)
        self.run_until(16, interval=15)
        self.assertEqual(
            [at for at, digest in self.scans if digest == HEALTHY], [0, 15]
        )

    def test_failed_retry_cannot_delay_the_full_deadline_after_restart(self):
        self.replace_during_scan = START + timedelta(seconds=10)
        self.run_until(11, interval=15)
        self.store = Store(self.database)
        self.run_until(16, interval=15)
        self.assertEqual(
            [at for at, digest in self.scans if digest == HEALTHY], [0, 15]
        )

    def test_failed_retry_respects_published_backoff_after_restart(self):
        self.replace_during_scan = START + timedelta(seconds=10)
        self.replacement_delay = 6
        self.run_until(17)
        _, summary = self.get_json("/api/v1/summary")
        self.assertEqual(
            summary["jobs"]["security"]["next_retry_at"], "2026-11-22T12:00:26Z"
        )
        self.store = Store(self.database)
        self.run_until(27)
        self.assertEqual(
            [at for at, digest in self.scans if digest == REPLACEMENT], [26]
        )

    def test_replacement_digest_has_its_own_retry_budget(self):
        self.run_until(75)
        services = self.store.read()["services"]
        services[0]["components"][1]["deployments"] = [
            {
                "image": "example.org/failing:latest",
                "digest": REPLACEMENT,
                "platform": "linux/amd64",
            }
        ]
        refresh_inventory(self.store, lambda: services, self.clock)
        self.failing_digests.add(REPLACEMENT)
        self.run_until(90)
        self.assertEqual(
            [at for at, digest in self.scans if digest == REPLACEMENT], [75, 85]
        )
        self.assertEqual([at for at, digest in self.scans if digest == HEALTHY], [0])

    def test_scanner_settings_change_resets_retry_budget(self):
        self.run_until(75)
        self.timeout = 30
        self.store = Store(self.database)
        self.run_until(90)
        self.assertEqual(
            [at for at, digest in self.scans if digest == FAILING],
            [0, 10, 30, 70, 75, 85],
        )
