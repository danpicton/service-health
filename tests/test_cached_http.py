"""Offline fixture exercising collection, persistence, JSON and HTML over HTTP."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from service_health.collection import collect_once
from service_health.http import make_handler
from service_health.store import Store


class _OpenBuffer(BytesIO):
    def close(self) -> None:
        self.flush()


class _MemorySocket:
    def __init__(self, request: bytes):
        self.input = BytesIO(request)
        self.output = _OpenBuffer()

    def makefile(self, mode: str, buffering: int = -1):
        return self.input if "r" in mode else self.output

    def sendall(self, data: bytes) -> None:
        self.output.write(data)


class HttpHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / "state.db"
        self.store = Store(self.database)

    def get(self, path: str) -> tuple[int, str]:
        request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
        connection = _MemorySocket(request)
        make_handler(self.store)(connection, ("offline", 0), None)
        head, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
        return int(head.split(b" ")[1]), body.decode()

    def get_json(self, path: str) -> tuple[int, dict]:
        status, body = self.get(path)
        return status, json.loads(body)


class CachedHttpTest(HttpHarness):
    def test_unusable_cache_is_not_ready(self) -> None:
        self.database.write_bytes(b"unreadable SQLite database")
        self.assertEqual(self.get_json("/healthz"), (200, {"status": "alive"}))
        self.assertEqual(self.get_json("/readyz"), (503, {"status": "unready"}))

    def test_empty_startup_is_ready_but_unassessed(self) -> None:
        self.assertEqual(self.get_json("/healthz"), (200, {"status": "alive"}))
        self.assertEqual(
            self.get_json("/readyz"),
            (200, {"status": "ready", "cache_state": "empty"}),
        )
        _, summary = self.get_json("/api/v1/summary")
        self.assertEqual(summary["checked_at"], None)
        self.assertEqual(summary["update_status"], "unknown")
        self.assertEqual(summary["security_status"], "incomplete coverage")
        self.assertFalse(summary["coverage_complete"])
        self.assertEqual(summary["service_count"], 0)
        _, services = self.get_json("/api/v1/services")
        self.assertEqual(services["services"], [])
        self.assertEqual(services["cache_state"], "empty")
        _, page = self.get("/")
        self.assertIn("No cached collection has completed", page)
        self.assertIn("not been assessed", page)
        self.assertEqual(self.get_json("/api/v1/services/missing")[0], 404)

    def test_injected_cycle_is_cached_and_read_through_http(self) -> None:
        calls = []

        def fixture_provider() -> list[dict]:
            calls.append("called")
            return [{"id": "example", "name": "Example & Friends"}]

        collect_once(
            self.store,
            fixture_provider,
            lambda: datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(calls, ["called"])
        _, homepage = self.get_json("/api/v1/services/example/homepage")
        self.assertEqual(homepage["current_version"], None)
        self.assertEqual(homepage["candidate_version"], None)
        self.assertEqual(homepage["update_status"], "unknown")
        self.assertEqual(homepage["security_status"], "incomplete coverage")
        self.assertEqual(homepage["checked_at"], "2026-11-22T12:00:00Z")
        _, detail = self.get_json("/api/v1/services/example")
        self.assertEqual(detail["id"], "example")
        _, page = self.get("/")
        self.assertIn("Example &amp; Friends", page)
        self.assertIn('href="services/example"', page)
        _, detail_page = self.get("/services/example")
        self.assertIn("Detailed findings have not been assessed", detail_page)
        self.assertEqual(calls, ["called"])
        self.assertEqual(Store(self.database).read()["services"][0]["id"], "example")

    def test_failed_provider_does_not_replace_cached_snapshot(self) -> None:
        collect_once(
            self.store,
            lambda: [{"id": "example"}],
            lambda: datetime(2026, 11, 22, tzinfo=timezone.utc),
        )

        def failed_provider() -> list[dict]:
            raise RuntimeError("offline fixture failure")

        with self.assertRaises(RuntimeError):
            collect_once(self.store, failed_provider)
        _, services = self.get_json("/api/v1/services")
        self.assertEqual(services["services"][0]["id"], "example")
        self.assertEqual(services["checked_at"], "2026-11-22T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
