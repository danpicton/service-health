"""Offline freshness lifecycle through the public cached views."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from test_cached_http import HttpHarness, _MemorySocket

from service_health.http import make_handler
from service_health.schedule import run_job, run_schedule
from service_health.store import Store


class FreshnessTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
        self.catalog = self.database.with_name("catalog.json")
        self.catalog.write_text("[]")

    def get(self, path):
        request = f"GET {path} HTTP/1.1\r\nHost: offline\r\n\r\n".encode()
        connection = _MemorySocket(request)
        make_handler(self.store, lambda: self.now, 3600, 3600)(
            connection, ("offline", 0), None
        )
        head, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
        return int(head.split(b" ")[1]), body.decode()

    def seed(self):
        checked = self.now.isoformat().replace("+00:00", "Z")
        deployment = {
            "pod": "app-0",
            "image": "example/app:1",
            "digest": "sha256:" + "a" * 64,
            "platform": "linux/amd64",
            "image_status": "up to date",
            "image_checked_at": checked,
            "scan_coverage": "complete",
            "scan_checked_at": checked,
            "scan_findings": [],
        }
        component = {
            "id": "main",
            "update_status": "up to date",
            "release_checked_at": checked,
            "scan_coverage": "complete",
            "advisory_coverage": "complete",
            "advisory_checked_at": checked,
            "deployments": [deployment],
            "scan_findings": [],
            "advisory_findings": [],
        }
        self.store.replace(
            checked,
            [
                {
                    "id": "app",
                    "name": "App",
                    "components": [component],
                    "update_status": "up to date",
                    "scan_coverage": "complete",
                    "advisory_coverage": "complete",
                    "coverage_complete": True,
                    "security_status": "no known findings",
                }
            ],
        )
        self.store.record_job("release", checked, None)
        self.store.record_job("security", checked, None)

    def test_failure_restart_expiry_and_cached_views(self):
        self.seed()
        _, clean = self.get_json("/api/v1/services/app/homepage")
        self.assertEqual(clean["security_status"], "no known findings")
        self.now += timedelta(minutes=10)
        attempted = self.now.isoformat().replace("+00:00", "Z")
        self.store.record_job("security", attempted, "provider offline")
        self.store = Store(self.database)  # a new process reads the same SQLite data
        _, home = self.get_json("/api/v1/services/app/homepage")
        _, detail = self.get_json("/api/v1/services/app")
        _, summary = self.get_json("/api/v1/summary")
        _, page = self.get("/services/app")
        self.assertEqual(home["security_status"], "check failed")
        self.assertTrue(home["stale"])
        self.assertEqual(
            detail["components"][0]["deployments"][0]["scan_coverage"], "failed"
        )
        self.assertEqual(
            summary["jobs"]["security"]["succeeded_at"], clean["checked_at"]
        )
        self.assertIn("provider offline", page)
        self.assertIn("Previous result is stale", page)
        self.assertEqual(
            self.store.read()["services"][0]["security_status"], "no known findings"
        )
        self.store.record_job("security", attempted, None)
        self.now += timedelta(hours=2)
        _, expired = self.get_json("/api/v1/services/app/homepage")
        self.assertEqual(expired["security_status"], "incomplete coverage")
        self.assertEqual(expired["update_status"], "unknown")
        self.assertTrue(expired["scan_stale"])
        self.assertTrue(expired["release_stale"])
        self.assertFalse(expired["coverage_complete"])

    def test_first_failure_stays_unassessed_and_reads_do_not_collect(self):
        self.seed()
        services = self.store.read()["services"]
        component = services[0]["components"][0]
        component.pop("release_checked_at")
        component.pop("advisory_checked_at")
        component["deployments"][0].pop("scan_checked_at")
        self.store.replace(self.now.isoformat(), services)
        self.store.record_job("security", self.now.isoformat(), "first failure")
        with patch(
            "service_health.schedule.run_job",
            side_effect=AssertionError("collector called"),
        ):
            _, home = self.get_json("/api/v1/services/app/homepage")
            self.get("/")
        self.assertEqual(home["security_status"], "check failed")
        self.assertFalse(home["scan_stale"])
        self.assertFalse(home["coverage_complete"])

    def test_failure_before_inventory_is_visible_with_empty_cache(self):
        self.store.record_job("release", self.now.isoformat(), "inventory unavailable")
        _, summary = self.get_json("/api/v1/summary")
        _, page = self.get("/")
        self.assertEqual(summary["cache_state"], "empty")
        self.assertEqual(summary["update_status"], "unknown")
        self.assertEqual(summary["jobs"]["release"]["succeeded_at"], None)
        self.assertIn("inventory unavailable", page)

    def test_job_failure_retains_snapshot_and_records_retry_state(self):
        self.seed()
        before = self.store.read()
        with patch(
            "service_health.schedule.apply_release_checks",
            side_effect=TimeoutError("timed out"),
        ):
            with self.assertRaises(TimeoutError):
                run_job(self.store, "release", self.catalog, clock=lambda: self.now)
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.store.read_jobs()["release"]["failures"], 1)
        self.assertIn("timed out", self.store.read_jobs()["release"]["error"])

    def test_schedule_backoff_is_independent(self):
        self.seed()
        calls = []
        ticks = [self.now]

        def clock():
            return ticks[0]

        def sleep(seconds):
            ticks[0] += timedelta(seconds=seconds)

        def fake_job(store, name, *args):
            calls.append((name, ticks[0]))
            store.record_job(
                name, ticks[0].isoformat(), "offline" if name == "security" else None
            )
            if name == "security":
                raise OSError("offline")

        with patch("service_health.schedule.run_job", side_effect=fake_job):
            run_schedule(
                self.store,
                self.catalog,
                object(),
                release_interval=100,
                security_interval=100,
                retry_initial=10,
                retry_max=40,
                clock=clock,
                sleep=sleep,
                stop=lambda: ticks[0] >= self.now + timedelta(seconds=135),
            )
        security_times = [time for name, time in calls if name == "security"]
        self.assertEqual((security_times[1] - security_times[0]).total_seconds(), 10)
        self.assertEqual((security_times[2] - security_times[1]).total_seconds(), 20)
        self.assertTrue(any(name == "release" for name, _ in calls))
