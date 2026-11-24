"""Offline OSV advisory checks through the cached API and rendered page."""

from datetime import datetime, timezone

from test_cached_http import HttpHarness

from service_health.advisories import apply_advisory_checks
from service_health.releases import apply_release_checks


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
        self.assertEqual(detail["components"][0]["advisory_reason"], "provider_failed")

        changed = checked
        changed[0]["components"][0]["current_version"] = "2.5.0"
        failed_changed = apply_advisory_checks(changed, CATALOG, fail, NOW)
        self.assertEqual(failed_changed[0]["advisory_findings"], [])
        self.assertIsNone(failed_changed[0]["advisory_checked_at"])

    def assess_candidates(self, records, **component_fields):
        services = service()
        services[0]["components"][0].update(component_fields)
        catalog = [
            {
                "id": "app",
                "components": [
                    {
                        **CATALOG[0]["components"][0],
                        "release_source": {
                            "type": "github_releases",
                            "repository": "example/app",
                            "tag_prefix": "release-",
                            "version_policy": "semver",
                        },
                    }
                ],
            }
        ]
        services = apply_advisory_checks(services, catalog, lambda _: records, NOW)
        services = apply_release_checks(
            services,
            catalog,
            lambda _: [
                {
                    "tag_name": "release-" + version,
                    "html_url": "https://example.org/" + version,
                }
                for version in ("1.9.0", "2.0.0")
            ],
            NOW,
        )
        self.store.replace(NOW().isoformat(), services)
        component = self.get_json("/api/v1/services/app")[1]["components"][0]
        finding = component["advisory_findings"][0]
        return component["advisory_candidate_assessments"][finding["id"]], finding

    def test_fixed_major_and_still_affected_routine(self):
        record = advisory(aliases=["CVE-2026-1234"])
        assessments, finding = self.assess_candidates(
            [record],
            scan_findings=[
                {
                    "id": "CVE-2026-1234",
                    "severity": "high",
                    "package": "libexample",
                    "fixed_version": "1.9.0",
                }
            ],
        )
        self.assertEqual(assessments["major"]["status"], "fixed")
        self.assertEqual(
            assessments["major"]["source_url"], "https://example.org/2.0.0"
        )
        self.assertEqual(assessments["routine"]["status"], "still affected")
        self.assertEqual(finding["fixed_versions"], ["2.0.0"])
        self.assertIn(
            "major release release-2.0.0 (fixed)", self.get("/services/app")[1]
        )
        self.store.record_job("release", NOW().isoformat(), "fixture failure")
        component = self.get_json("/api/v1/services/app")[1]["components"][0]
        self.assertEqual(
            component["advisory_candidate_assessments"][finding["id"]]["major"][
                "status"
            ],
            "unknown",
        )

    def test_limited_range_reintroduction_and_explicit_affected_version(self):
        limit = advisory(events=[{"introduced": "0"}, {"limit": "1.9.0"}])
        assessments, _ = self.assess_candidates([limit])
        self.assertEqual(assessments["major"]["status"], "unknown")
        reintroduced = advisory(
            events=[
                {"introduced": "0"},
                {"fixed": "1.9.0"},
                {"introduced": "2.0.0"},
            ]
        )
        assessments, _ = self.assess_candidates([reintroduced])
        self.assertEqual(assessments["routine"]["status"], "fixed")
        self.assertEqual(assessments["major"]["status"], "still affected")
        explicit = advisory()
        explicit["affected"][0]["versions"] = ["2.0.0"]
        assessments, finding = self.assess_candidates([explicit])
        self.assertEqual(assessments["major"]["status"], "still affected")
        self.assertEqual(finding["provenance"][0]["affected_versions"], ["2.0.0"])

    def test_alias_disagreement_and_shared_endpoint_scope(self):
        other = advisory(
            "ALIAS-1234",
            aliases=["GHSA-aaaa-bbbb-cccc"],
            events=[{"introduced": "0"}, {"fixed": "2.5.0"}],
        )
        assessments, _ = self.assess_candidates([advisory(), other])
        self.assertEqual(assessments["major"]["status"], "unknown")
        assessments, finding = self.assess_candidates(
            [advisory()], advisory_version=None
        )
        self.assertEqual(finding["match"], "possible")
        self.assertEqual(assessments["major"]["status"], "unknown")
        self.assertIn("replicas", assessments["major"]["reason"])

    def test_explicit_affected_version_after_fix_requires_new_fix_evidence(self):
        record = advisory(events=[{"introduced": "0"}, {"fixed": "1.8.0"}])
        record["affected"][0]["versions"] = ["1.9.0"]
        assessments, _ = self.assess_candidates([record])
        self.assertEqual(assessments["routine"]["status"], "still affected")
        self.assertEqual(assessments["major"]["status"], "unknown")
        record["affected"][0]["ranges"][0]["events"].extend(
            [{"introduced": "1.9.0"}, {"fixed": "2.0.0"}]
        )
        assessments, _ = self.assess_candidates([record])
        self.assertEqual(assessments["major"]["status"], "fixed")

    def test_unrecognized_affected_version_preserves_unknown_applicability(self):
        record = advisory()
        record["affected"][0].pop("ranges")
        record["affected"][0]["versions"] = ["release-one"]
        detail, home, _ = self.check("1.5.0", [record])
        self.assertEqual(detail["advisory_findings"][0]["match"], "possible")
        self.assertEqual(home["advisory_coverage"], "missing")

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
