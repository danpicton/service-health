"""Offline API and rendered finding contract from one synthetic cached assessment."""

import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from service_health.aggregation import aggregate_security
from service_health.http import make_handler
from service_health.store import Store

CHECKED = "2026-11-22T12:00:00Z"


def representative_service() -> dict:
    scanner_finding = {
        "id": "CVE-2026-0001",
        "severity": "high",
        "package": "libexample",
        "installed_version": "1.0",
        "fixed_version": "1.1",
        "source": "Trivy",
        "source_url": "https://example.org/CVE-2026-0001",
        "target": "fixture",
        "digest": "sha256:abc",
        "platform": "linux/amd64",
    }
    advisory_finding = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2026-0001"],
        "match": "confirmed",
        "severity": "high",
        "source": "OSV upstream advisory",
        "current_version": "1.0.0",
        "fixed_versions": ["1.1.0"],
        "provenance": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
                "affected_versions": [],
                "affected_ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.1.0"}],
                    }
                ],
            }
        ],
    }
    service = {
        "id": "example",
        "name": "Example & Friends",
        "current_version": None,
        "candidate_version": None,
        "update_status": "update available",
        "update_kind": None,
        "update_coverage_complete": False,
        "image_status": "unknown",
        "image_coverage_complete": False,
        "inventory_status": "observed",
        "inventory_stale": False,
        "scan_checked_at": CHECKED,
        "scan_stale": False,
        "advisory_checked_at": CHECKED,
        "advisory_stale": False,
        "components": [
            {
                "id": "app",
                "name": "Application",
                "kind": "regular",
                "current_version": "1.0.0",
                "candidate_version": "2.0.0",
                "release_candidates": {
                    group: {
                        "version": version,
                        "normalized_version": version,
                        "source_url": "https://example.org/releases/" + version,
                    }
                    for group, version in (("routine", "1.1.0"), ("major", "2.0.0"))
                },
                "update_status": "update available",
                "update_kind": "major migration",
                "release_checked_at": CHECKED,
                "release_stale": False,
                "release_source_url": "https://example.org/releases/2.0.0",
                "scan_coverage": "complete",
                "advisory_coverage": "complete",
                "advisory_findings": [advisory_finding],
                "deployments": [
                    {
                        "namespace": "fictional",
                        "pod": "example-1",
                        "node": "node-1",
                        "container": "app",
                        "kind": "regular",
                        "image": "example/app:1.0.0",
                        "version_observations": [
                            {
                                "source": {
                                    "type": "exact_tag",
                                    "repository": "example/app",
                                    "documentation": "https://example.org/app/image-tags",
                                },
                                "scope": "deployment",
                                "reported": "1.0.0",
                                "normalized": "1.0.0",
                                "checked_at": CHECKED,
                                "reason": None,
                                "outcome": "success",
                                "last_success": {
                                    "reported": "1.0.0",
                                    "normalized": "1.0.0",
                                    "checked_at": CHECKED,
                                },
                            }
                        ],
                        "image_id": "example/app@sha256:abc",
                        "digest": "sha256:abc",
                        "platform": "linux/amd64",
                        "state": "observed",
                        "image_status": "up to date",
                        "scan_coverage": "complete",
                        "scan_findings": [scanner_finding],
                        "scan_checked_at": CHECKED,
                    }
                ],
                "scan_findings": [scanner_finding],
            },
            {
                "id": "database",
                "name": "Database",
                "kind": "regular",
                "current_version": None,
                "candidate_version": None,
                "update_status": "unknown",
                "scan_coverage": "missing",
                "advisory_coverage": "missing",
                "advisory_gap": "no supported source",
                "advisory_findings": [],
                "scan_findings": [],
                "deployments": [],
            },
        ],
    }
    aggregate_security(service)
    return service


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


def request(store: Store, path: str) -> tuple[int, str]:
    socket = _MemorySocket(f"GET {path} HTTP/1.1\r\nHost: hub.example\r\n\r\n".encode())
    make_handler(store)(socket, ("offline", 0), None)
    head, body = socket.output.getvalue().split(b"\r\n\r\n", 1)
    return int(head.split(b" ")[1]), body.decode()


class ApiContractTest(unittest.TestCase):
    def test_homepage_service_id_keeps_findings_in_detail_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            store.replace(CHECKED, [{**representative_service(), "id": "homepage"}])
            for route in ("/api/v1/services/homepage", "/services/homepage"):
                with self.subTest(route=route):
                    status, detail = request(store, route)
                    self.assertEqual(status, 200)
                    self.assertIn("CVE-2026-0001", detail)
            status, homepage = request(store, "/api/v1/services/homepage/homepage")
            self.assertEqual(status, 200)
            self.assertNotIn("CVE-2026-0001", homepage)

    def test_dashboard_reads_omit_findings_but_detail_keeps_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            store.replace(CHECKED, [representative_service()])
            with patch.object(store, "read", side_effect=AssertionError("full read")):
                for route in (
                    "/healthz",
                    "/readyz",
                    "/api/v1/summary",
                    "/api/v1/services",
                    "/api/v1/services/example/homepage",
                ):
                    self.assertEqual(request(store, route)[0], 200)
            _, listing = request(store, "/api/v1/services")
            _, homepage = request(store, "/api/v1/services/example/homepage")
            _, detail = request(store, "/api/v1/services/example")
            self.assertNotIn("CVE-2026-0001", listing)
            self.assertNotIn("CVE-2026-0001", homepage)
            self.assertIn("CVE-2026-0001", detail)

    def test_existing_snapshot_is_indexed_without_a_full_python_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            store = Store(path)
            with store._connect() as connection:
                connection.execute(
                    "INSERT INTO snapshot VALUES (1, ?, ?)",
                    (CHECKED, json.dumps([representative_service()])),
                )
            upgraded = Store(path)
            self.assertEqual(upgraded.read_compact()["services"][0]["id"], "example")
            self.assertIn(
                "CVE-2026-0001",
                json.dumps(upgraded.read_service("example")),
            )

    def test_compact_failed_check_keeps_known_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            store.replace(CHECKED, [representative_service()])
            store.record_job("security", CHECKED, "scanner unavailable")
            summary = json.loads(request(store, "/api/v1/summary")[1])
            homepage = json.loads(
                request(store, "/api/v1/services/example/homepage")[1]
            )
            self.assertEqual(summary["security_status"], "findings")
            self.assertEqual(homepage["security_status"], "findings")
            self.assertEqual(homepage["confirmed_finding_count"], 1)
            self.assertFalse(homepage["coverage_complete"])

    def test_internal_links_use_origin_relative_navigation_and_encoded_ids(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            service = representative_service()
            service["id"] = "example test"
            store.replace(CHECKED, [service])
            root = request(store, "/")[1]
            detail = request(store, "/services/example%20test")[1]
            homepage = json.loads(
                request(store, "/api/v1/services/example%20test/homepage")[1]
            )
            self.assertIn('href="services/example%20test"', root)
            self.assertIn('href="../"', detail)
            self.assertEqual(homepage["detail_path"], "/services/example%20test")

    def test_cached_json_and_rendered_findings_agree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            store.replace(CHECKED, [representative_service()])
            summary = json.loads(request(store, "/api/v1/summary")[1])
            service_list = json.loads(request(store, "/api/v1/services")[1])
            detail = json.loads(request(store, "/api/v1/services/example")[1])
            homepage = json.loads(
                request(store, "/api/v1/services/example/homepage")[1]
            )
            root_status, root = request(store, "/")
            detail_status, page = request(store, "/services/example")

            self.assertEqual((root_status, detail_status), (200, 200))
            self.assertEqual(summary["confirmed_finding_count"], 1)
            self.assertEqual(summary["coverage_gap_service_count"], 1)
            self.assertEqual(summary["security_status"], "findings")
            self.assertEqual(service_list["services"][0]["id"], detail["id"])
            self.assertEqual(homepage["critical_count"], detail["critical_count"])
            self.assertEqual(homepage["high_count"], detail["high_count"])
            self.assertEqual(homepage["fix_available_count"], 1)
            self.assertFalse(homepage["coverage_complete"])
            self.assertEqual(homepage["detail_path"], "/services/example")
            self.assertIn('href="services/example"', root)
            self.assertIn('href="../"', page)
            self.assertIn("Example &amp; Friends", root)
            self.assertIn("Trivy finding: CVE-2026-0001", page)
            self.assertIn("Upstream advisory: GHSA-aaaa-bbbb-cccc", page)
            self.assertIn("https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc", page)
            self.assertIn("https://example.org/CVE-2026-0001", page)
            self.assertIn("no supported source", page)
            self.assertIn("coverage complete: false", page)
            self.assertEqual(request(store, "/api/v1/services/missing")[0], 404)

    def test_checked_in_examples_contain_real_response_fields(self) -> None:
        schema = json.loads(Path("docs/api-v1.schema.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            empty = json.loads(Path("examples/api-v1-empty-summary.json").read_text())
            error = json.loads(Path("examples/api-v1-error.json").read_text())
            self.assertEqual(empty, json.loads(request(store, "/api/v1/summary")[1]))
            self.assertEqual(
                error, json.loads(request(store, "/api/v1/services/missing")[1])
            )
            store.replace(CHECKED, [representative_service()])
            for name, definition, route in (
                ("summary", "summary", "/api/v1/summary"),
                ("services", "serviceList", "/api/v1/services"),
                ("detail", "serviceDetail", "/api/v1/services/example"),
                ("homepage", "homepage", "/api/v1/services/example/homepage"),
            ):
                sample = json.loads(Path(f"examples/api-v1-{name}.json").read_text())
                self.assertGreaterEqual(
                    sample.keys(), set(schema["$defs"][definition].get("required", []))
                )
                self.assertEqual(sample, json.loads(request(store, route)[1]))
            store.record_job(
                "release", "2026-11-22T13:00:00Z", "fixture upstream timeout"
            )
            retained = json.loads(
                Path("examples/api-v1-homepage-stale.json").read_text()
            )
            actual = json.loads(request(store, "/api/v1/services/example/homepage")[1])
            self.assertEqual(retained, actual)


if __name__ == "__main__":
    unittest.main()
