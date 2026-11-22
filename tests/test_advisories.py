"""Offline OSV advisory checks through the cached API and rendered page."""

from datetime import datetime, timezone

from test_cached_http import HttpHarness

from service_health.advisories import apply_advisory_checks


def NOW():
    return datetime(2026, 11, 22, tzinfo=timezone.utc)


SOURCE = {"type": "osv", "ecosystem": "PyPI", "package": "example-app"}
CATALOG = [{"id": "app", "components": [{"id": "server", "advisory_source": SOURCE}]}]


def service(version="1.5.0"):
    return [
        {
            "id": "app",
            "name": "Example",
            "scan_coverage": "complete",
            "components": [
                {
                    "id": "server",
                    "name": "Server",
                    "current_version": version,
                    "scan_findings": [],
                    "scan_coverage": "complete",
                    "deployments": [],
                }
            ],
        }
    ]


def advisory(issue="GHSA-aaaa-bbbb-cccc", aliases=None, events=None, severity="HIGH"):
    return {
        "id": issue,
        "aliases": aliases or [],
        "database_specific": {"severity": severity},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example-app"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": events
                        or [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
                    }
                ],
            }
        ],
    }


class AdvisoryTest(HttpHarness):
    def check(self, version, records, source=SOURCE):
        catalog = [
            {"id": "app", "components": [{"id": "server", "advisory_source": source}]}
        ]
        checked = apply_advisory_checks(
            service(version), catalog, lambda _: records, NOW
        )
        self.store.replace("2026-11-22T00:00:00Z", checked)
        _, detail = self.get_json("/api/v1/services/app")
        _, home = self.get_json("/api/v1/services/app/homepage")
        _, page = self.get("/services/app")
        return detail, home, page

    def test_boundaries_and_prerelease(self):
        for version, expected in [
            ("0.9.9", 0),
            ("1.0.0", 1),
            ("1.9.9", 1),
            ("2.0.0", 0),
            ("2.0.0-rc.1", 1),
        ]:
            with self.subTest(version=version):
                detail, home, _ = self.check(version, [advisory()])
                self.assertEqual(home["high_count"], expected)
                self.assertEqual(
                    detail["security_status"],
                    "findings" if expected else "no known findings",
                )

    def test_aliases_no_cve_and_provenance(self):
        one = advisory(aliases=["ALIAS-1234"])
        two = advisory("ALIAS-1234", aliases=["GHSA-aaaa-bbbb-cccc"])
        detail, home, page = self.check("1.5.0", [one, two])
        self.assertEqual(home["high_count"], 1)
        self.assertEqual(len(detail["advisory_findings"]), 1)
        self.assertEqual(len(detail["advisory_findings"][0]["provenance"]), 2)
        self.assertIn("Upstream advisory", page)
        self.assertIn("https://osv.dev/vulnerability/ALIAS-1234", page)
        self.assertIn("2.0.0", page)

    def test_conflicts_unknown_version_and_unsupported(self):
        yes = advisory()
        no = advisory(
            "OTHER-1234",
            aliases=["GHSA-aaaa-bbbb-cccc"],
            events=[{"introduced": "2.0.0"}],
        )
        detail, home, page = self.check("1.5.0", [yes, no])
        self.assertEqual(home["high_count"], 0)
        self.assertEqual(home["possible_finding_count"], 1)
        self.assertEqual(home["advisory_coverage"], "missing")
        self.assertIn("Possible upstream advisory", page)
        detail, home, _ = self.check(None, [yes])
        self.assertEqual(home["possible_finding_count"], 1)
        self.assertEqual(home["security_status"], "incomplete coverage")
        detail, home, _ = self.check("1.5.0", [], {"type": "unsupported"})
        self.assertEqual(home["advisory_coverage"], "missing")
        self.assertIn("source", detail["components"][0]["advisory_gap"])

    def test_last_affected_and_uninterpretable_range(self):
        inclusive = advisory(
            events=[{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}]
        )
        _, home, _ = self.check("1.5.0", [inclusive])
        self.assertEqual(home["high_count"], 1)
        _, home, _ = self.check("1.5.1", [inclusive])
        self.assertEqual(home["high_count"], 0)
        unsupported = advisory()
        unsupported["affected"][0]["ranges"][0]["type"] = "ECOSYSTEM"
        _, home, _ = self.check("1.5.0", [unsupported])
        self.assertEqual(home["possible_finding_count"], 1)
        self.assertFalse(home["coverage_complete"])

    def test_failure_retains_previous_evidence(self):
        checked = apply_advisory_checks(service(), CATALOG, lambda _: [advisory()], NOW)

        def fail(_):
            raise OSError("offline")

        failed = apply_advisory_checks(checked, CATALOG, fail, NOW)
        self.store.replace("2026-11-22T00:00:00Z", failed)
        _, home = self.get_json("/api/v1/services/app/homepage")
        _, detail = self.get_json("/api/v1/services/app")
        self.assertEqual(home["security_status"], "findings")
        self.assertEqual(home["advisory_coverage"], "failed")
        self.assertTrue(home["stale"])
        self.assertEqual(detail["components"][0]["advisory_error"], "offline")

        changed = checked
        changed[0]["components"][0]["current_version"] = "2.5.0"
        failed_changed = apply_advisory_checks(changed, CATALOG, fail, NOW)
        self.assertEqual(failed_changed[0]["advisory_findings"], [])
        self.assertIsNone(failed_changed[0]["advisory_checked_at"])

    def test_scanner_alias_is_counted_once(self):
        with_scan = service()
        with_scan[0]["components"][0]["scan_findings"] = [
            {
                "id": "CVE-2026-1234",
                "severity": "high",
                "fixed_version": "2.0.0",
            }
        ]
        record = advisory(aliases=["CVE-2026-1234"])
        checked = apply_advisory_checks(with_scan, CATALOG, lambda _: [record], NOW)
        self.assertEqual(checked[0]["high_count"], 1)
        self.assertEqual(checked[0]["fix_available_count"], 1)
