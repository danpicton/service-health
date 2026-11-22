"""Offline scanner fixture checks through the SQLite and HTTP presentation seams."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from test_cached_http import HttpHarness

from service_health.http import _homepage, _page, _summary
from service_health.scanner import (
    ExternalReports,
    TrivyScanner,
    apply_scan_checks,
    scan_store_once,
)
from service_health.store import Store

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def NOW():
    return datetime(2026, 11, 22, tzinfo=timezone.utc)


def service(digest=DIGEST):
    return {
        "id": "alpha",
        "name": "Alpha",
        "components": [
            {
                "id": "web",
                "name": "Web",
                "kind": "regular",
                "deployments": [
                    {
                        "image": "registry.example/alpha/web:1",
                        "digest": digest,
                        "platform": "linux/amd64",
                        "pod": "web-1",
                    }
                ],
            }
        ],
    }


def report(digest=DIGEST, findings=True):
    return {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example/alpha/web@" + digest,
        "Metadata": {"ImageConfig": {"os": "linux", "architecture": "amd64"}},
        "Results": [
            {
                "Target": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "1",
                        "FixedVersion": "2",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://example.org/advisory",
                    }
                ]
                if findings
                else [],
            }
        ],
    }


class FakeScanner:
    def __init__(self, output=None, error=None):
        self.output = output or report()
        self.error = error
        self.calls = []
        self.refreshes = 0

    def refresh_db(self):
        self.refreshes += 1

    def scan(self, target, platform):
        self.calls.append((target, platform))
        if self.error:
            raise RuntimeError(self.error)
        return copy.deepcopy(self.output)


class ScannerTests(unittest.TestCase):
    def test_findings_cache_and_page(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.db")
            store.replace("2026-11-22T00:00:00Z", [service()])
            scanner = FakeScanner()
            scan_store_once(store, scanner, NOW)
            cached = store.read()
            item = cached["services"][0]
            self.assertEqual(
                scanner.calls, [("registry.example/alpha/web@" + DIGEST, "linux/amd64")]
            )
            self.assertEqual(scanner.refreshes, 1)
            self.assertEqual(item["security_status"], "findings")
            self.assertEqual(item["scan_coverage"], "complete")
            self.assertFalse(item["coverage_complete"])
            self.assertEqual(item["high_count"], 1)
            self.assertEqual(item["fix_available_count"], 1)
            self.assertEqual(item["scan_findings"][0]["digest"], DIGEST)
            self.assertEqual(item["scan_findings"][0]["fixed_version"], "2")
            self.assertEqual(
                _homepage(item, cached["checked_at"])["scan_coverage"], "complete"
            )
            self.assertEqual(_summary(cached)["security_status"], "findings")
            page = _page(cached, item)
            self.assertIn("CVE-2026-0001", page)
            self.assertIn("openssl", page)
            self.assertIn("Trivy finding", page)
            self.assertIn(DIGEST, page)

    def test_no_findings_is_not_clean_without_advisories(self):
        item = apply_scan_checks([service()], FakeScanner(report(findings=False)), NOW)[
            0
        ]
        self.assertEqual(item["scan_coverage"], "complete")
        self.assertEqual(item["security_status"], "incomplete coverage")
        self.assertEqual(item["critical_count"], 0)

    def test_failure_retains_prior_evidence_as_stale(self):
        prior = apply_scan_checks([service()], FakeScanner(), NOW)
        item = apply_scan_checks(prior, FakeScanner(error="registry offline"), NOW)[0]
        self.assertEqual(item["scan_coverage"], "failed")
        self.assertTrue(item["scan_stale"])
        self.assertEqual(len(item["scan_findings"]), 1)
        self.assertEqual(item["security_status"], "findings")
        self.assertIn(
            "registry offline", item["components"][0]["deployments"][0]["scan_error"]
        )

    def test_mismatched_digest_and_missing_identity_reject_reports(self):
        for output in (
            report(OTHER),
            {
                **report(),
                "ArtifactName": "alpha:latest",
                "Metadata": {"ImageConfig": {"os": "linux", "architecture": "amd64"}},
            },
        ):
            item = apply_scan_checks([service()], FakeScanner(output), NOW)[0]
            self.assertEqual(item["scan_coverage"], "failed")
            self.assertEqual(item["security_status"], "check failed")
            self.assertEqual(item["scan_findings"], [])

    def test_missing_digest_has_coverage_gap(self):
        item = apply_scan_checks([service(None)], FakeScanner(), NOW)[0]
        self.assertEqual(item["scan_coverage"], "missing")
        self.assertEqual(item["security_status"], "incomplete coverage")

    def test_same_digest_rescanned_after_db_refresh(self):
        scanner = FakeScanner()
        first = apply_scan_checks([service()], scanner, NOW)
        scanner.output = report(findings=False)
        second = apply_scan_checks(first, scanner, NOW)
        self.assertEqual(scanner.refreshes, 2)
        self.assertEqual(len(scanner.calls), 2)
        self.assertEqual(second[0]["scan_findings"], [])

    def test_trivy_command_is_remote_vuln_only_with_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = TrivyScanner(directory, timeout=42)
            calls = []

            def record(args):
                calls.append(args)
                if "--output" in args:
                    Path(args[args.index("--output") + 1]).write_text(
                        json.dumps(report())
                    )

            scanner._run = record
            scanner.refresh_db()
            scanner.scan("registry.example/alpha/web@" + DIGEST, "linux/amd64")
            self.assertIn("--download-db-only", calls[0])
            self.assertEqual(calls[1][calls[1].index("--scanners") + 1], "vuln")
            self.assertEqual(calls[1][calls[1].index("--image-src") + 1], "remote")
            self.assertIn("--skip-db-update", calls[1])
            self.assertIn("--max-image-size", calls[1])


class ScannerHttpTests(HttpHarness):
    def test_injected_scan_is_exposed_over_cached_http(self):
        self.store.replace("2026-11-22T00:00:00Z", [service()])
        scanner = FakeScanner()
        scan_store_once(self.store, scanner, NOW)
        _, homepage = self.get_json("/api/v1/services/alpha/homepage")
        _, detail = self.get_json("/api/v1/services/alpha")
        _, page = self.get("/services/alpha")
        self.assertEqual(homepage["security_status"], "findings")
        self.assertEqual(homepage["scan_coverage"], "complete")
        self.assertEqual(detail["scan_findings"][0]["package"], "openssl")
        self.assertIn("CVE-2026-0001", page)
        self.assertEqual(len(scanner.calls), 1)

    def test_local_external_report_identity_freshness_and_presentation(self):
        local = service()
        deployment = local["components"][0]["deployments"][0]
        deployment["image"] = "localhost/example-app:latest"
        self.store.replace("2026-11-22T00:00:00Z", [local])
        reports = Path(self.directory.name) / "reports"
        reports.mkdir()
        scanner = FakeScanner()

        def write_report(digest=DIGEST, scanned_at="2026-11-22T00:00:00Z"):
            value = report(digest)
            value["ArtifactName"] = "localhost/example-app@" + digest
            (reports / "local.json").write_text(
                json.dumps(
                    {
                        "image": "localhost/example-app:latest",
                        "digest": digest,
                        "platform": "linux/amd64",
                        "scanned_at": scanned_at,
                        "report": value,
                    }
                )
            )

        external = ExternalReports(reports)
        scan_store_once(self.store, scanner, NOW, external_reports=external)
        _, missing = self.get_json("/api/v1/services/alpha/homepage")
        self.assertEqual(missing["scan_coverage"], "missing")
        self.assertEqual(scanner.calls, [])
        write_report(OTHER)
        scan_store_once(self.store, scanner, NOW, external_reports=external)
        _, mismatch = self.get_json("/api/v1/services/alpha")
        self.assertEqual(mismatch["scan_coverage"], "missing")
        self.assertIn(
            "differs", mismatch["components"][0]["deployments"][0]["scan_error"]
        )
        write_report(scanned_at="2026-11-01T00:00:00Z")
        scan_store_once(self.store, scanner, NOW, external_reports=external)
        _, old = self.get_json("/api/v1/services/alpha")
        self.assertEqual(old["scan_coverage"], "missing")
        write_report()
        scan_store_once(self.store, scanner, NOW, external_reports=external)
        _, homepage = self.get_json("/api/v1/services/alpha/homepage")
        _, detail = self.get_json("/api/v1/services/alpha")
        _, page = self.get("/services/alpha")
        self.assertEqual(homepage["scan_coverage"], "complete")
        self.assertEqual(homepage["scan_sources"], ["external"])
        self.assertEqual(homepage["high_count"], 1)
        self.assertEqual(detail["scan_findings"][0]["scan_source"], "external")
        self.assertIn("scan source: external", page)
        self.assertIn("CVE-2026-0001", page)
        self.assertEqual(scanner.calls, [])
        (reports / "duplicate.json").write_text((reports / "local.json").read_text())
        scan_store_once(self.store, scanner, NOW, external_reports=external)
        _, ambiguous = self.get_json("/api/v1/services/alpha")
        self.assertEqual(ambiguous["scan_coverage"], "missing")
        self.assertTrue(ambiguous["scan_stale"])


if __name__ == "__main__":
    unittest.main()
