"""Offline command diagnostics through the real subprocess and cached API."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from test_cached_http import HttpHarness
from test_scanner import DIGEST, NOW, FakeScanner, service

from service_health.scanner import TrivyScanner, scan_store_once
from service_health.trivy_command import TrivyFailure, run_trivy


class TrivyCommandTests(unittest.TestCase):
    def test_registry_scanner_and_network_failures(self):
        cases = [
            (
                "remote error: UNAUTHORIZED: authentication required",
                "access_required",
                "authentication_denied",
                "image_pull",
            ),
            (
                "GET /v2/app: TOOMANYREQUESTS: Too Many Requests",
                "transient_failure",
                "rate_limited",
                "image_pull",
            ),
            (
                "remote error: MANIFEST_UNKNOWN: manifest unknown",
                "unavailable",
                "manifest_unavailable",
                "image_pull",
            ),
            (
                "no matching manifest for linux/arm64",
                "unsupported",
                "unsupported_image",
                "image_pull",
            ),
            ("unsupported media type", "unsupported", "unsupported_image", "scan"),
            (
                "unable to pull: i/o timeout",
                "transient_failure",
                "provider_timeout",
                "image_pull",
            ),
            (
                "failed to pull: connection refused",
                "transient_failure",
                "network_failure",
                "image_pull",
            ),
            ("write: no space left on device", "unavailable", "resource_limit", "scan"),
            (
                "database disk image is malformed",
                "unavailable",
                "database_invalid",
                "scan",
            ),
            ("unknown failure", "unknown_failure", "trivy_failed", "scan"),
            (
                "unauthorized and connection refused",
                "unknown_failure",
                "trivy_failed",
                "scan",
            ),
        ]
        for stderr, outcome, reason, phase in cases:
            with self.subTest(reason=reason, stderr=stderr):
                command = [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write(sys.argv[1]); sys.exit(23)",
                    stderr,
                ]
                with self.assertRaises(TrivyFailure) as caught:
                    run_trivy(command, "scan", 5)
                failure = caught.exception
                self.assertEqual((failure.outcome, failure.reason), (outcome, reason))
                self.assertEqual((failure.phase, failure.exit_status), (phase, 23))

    def test_wall_timeout_and_launch_failure_hide_command_arguments(self):
        for command, reason in [
            (
                [sys.executable, "-c", "import time; time.sleep(30)", "SECRET"],
                "provider_timeout",
            ),
            (["/missing/executable/SECRET"], "scanner_unavailable"),
        ]:
            with self.subTest(reason=reason), self.assertRaises(TrivyFailure) as caught:
                run_trivy(command, "db_refresh", 0.2)
            self.assertNotIn("SECRET", str(caught.exception))
            self.assertEqual(caught.exception.reason, reason)
            self.assertEqual(caught.exception.phase, "db_refresh")
            if reason == "provider_timeout":
                self.assertLess(caught.exception.exit_status, 0)
            else:
                self.assertIsNone(caught.exception.exit_status)


class TrivyDiagnosticHttpTests(HttpHarness):
    def test_oversized_sensitive_db_failure_is_safe_in_cache_and_api(self):
        self.store.replace("2026-11-22T00:00:00Z", [service()])
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "print('SECRET_stdout' * 100000)\n"
                "sys.stderr.write('SECRET_dump' * 100000 + '\\n')\n"
                "sys.stderr.write('Authorization: Bearer SECRET_token\\n"
                "https://user:SECRET_pass@fake.invalid/path?sig=SECRET_key\\n"
                "--password SECRET_arg ENV=SECRET --token=SECRET_arg\\n"
                "remote error: too many requests')\n"
                "sys.exit(17)\n"
            )
            binary.chmod(0o700)
            scan_store_once(self.store, TrivyScanner(directory, binary), NOW)
        _, detail = self.get_json("/api/v1/services/alpha")
        _, page = self.get("/services/alpha")
        deployment = detail["components"][0]["deployments"][0]
        self.assertEqual(deployment["scan_failed_at"], "2026-11-22T00:00:00Z")
        self.assertIsNone(deployment["scan_checked_at"])
        self.assertEqual(deployment["scan_failure_phase"], "db_refresh")
        self.assertEqual(deployment["scan_exit_status"], 17)
        self.assertEqual(deployment["scan_digest"], DIGEST)
        self.assertEqual(deployment["scan_platform"], "linux/amd64")
        self.assertEqual(deployment["scan_reason"], "rate_limited")
        self.assertEqual(deployment["scan_outcome"], "transient_failure")
        self.assertLess(len(deployment["scan_error"]), 128)
        self.assertIn(deployment["scan_error"], page)
        for serialized in (json.dumps(self.store.read()), json.dumps(detail), page):
            self.assertNotIn("SECRET", serialized)
            self.assertNotIn("fake.invalid", serialized)
        scan_store_once(self.store, FakeScanner(), NOW)
        _, detail = self.get_json("/api/v1/services/alpha")
        recovered = detail["components"][0]["deployments"][0]
        for field in ("scan_failed_at", "scan_exit_status", "scan_failure_phase"):
            self.assertIsNone(recovered[field])

    def test_invalid_json_after_successful_command_is_report_parsing_failure(self):
        self.store.replace("2026-11-22T00:00:00Z", [service()])
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text(
                f"#!{sys.executable}\n"
                "import sys\nfrom pathlib import Path\n"
                "if '--output' in sys.argv:\n"
                "    Path(sys.argv[sys.argv.index('--output') + 1])"
                ".write_text('SECRET malformed JSON')\n"
            )
            binary.chmod(0o700)
            scan_store_once(self.store, TrivyScanner(directory, binary), NOW)
        _, detail = self.get_json("/api/v1/services/alpha")
        deployment = detail["components"][0]["deployments"][0]
        self.assertEqual(deployment["scan_failure_phase"], "report_parsing")
        self.assertEqual(deployment["scan_reason"], "malformed_report")
        self.assertEqual(deployment["scan_exit_status"], 0)
        self.assertNotIn("SECRET", json.dumps(detail))
