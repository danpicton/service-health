"""Offline collection and presentation contract for mixed service signals."""

import copy
from datetime import datetime, timezone

from test_cached_http import HttpHarness

from service_health.advisories import apply_advisory_checks
from service_health.images import apply_image_checks
from service_health.releases import apply_release_checks
from service_health.scanner import apply_scan_checks

DIGEST = "sha256:" + "a" * 64
REBUILT = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64


def now():
    return datetime(2026, 11, 22, tzinfo=timezone.utc)


def component(component_id, version="1.0.0", observed=True):
    return {
        "id": component_id,
        "name": component_id.title(),
        "current_version": version,
        "deployments": [
            {
                "pod": component_id + "-pod",
                "image": "registry.example/" + component_id + ":1",
                "digest": DIGEST,
                "platform": "linux/amd64",
            }
        ]
        if observed
        else [],
    }


def fixture():
    services = [
        {
            "id": "mixed",
            "name": "Mixed",
            "components": [
                component("app"),
                component("database"),
                component("helper", None, False),
            ],
        },
        {
            "id": "unsupported",
            "name": "Unsupported",
            "components": [component("worker")],
        },
        {"id": "clean", "name": "Clean", "components": [component("clean")]},
    ]

    def osv(package):
        return {"type": "osv", "ecosystem": "PyPI", "package": package}

    catalog = [
        {
            "id": "mixed",
            "components": [
                {
                    "id": "app",
                    "release_source": {
                        "type": "github_releases",
                        "repository": "example/app",
                    },
                    "advisory_source": osv("app"),
                },
                {"id": "database", "advisory_source": osv("database")},
                {"id": "helper", "advisory_source": osv("helper")},
            ],
        },
        {"id": "unsupported", "components": [{"id": "worker"}]},
        {
            "id": "clean",
            "components": [{"id": "clean", "advisory_source": osv("clean")}],
        },
    ]
    return services, catalog


def advisory(source):
    return {
        "id": "GHSA-abcd-1234-5678",
        "aliases": ["CVE-2026-1234"],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": source["package"]},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
                    }
                ],
            }
        ],
    }


class Scanner:
    def refresh_db(self):
        pass

    def scan(self, target, platform):
        issue = (
            [
                {
                    "VulnerabilityID": "CVE-2026-1234",
                    "PkgName": "database",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "2.0.0",
                    "Severity": "HIGH",
                    "PrimaryURL": "https://example.org/cve",
                }
            ]
            if "/database@" in target
            else []
        )
        return {
            "SchemaVersion": 2,
            "ArtifactName": target,
            "Metadata": {"ImageConfig": {"os": "linux", "architecture": "amd64"}},
            "Results": [
                {"Target": "packages", "Class": "os-pkgs", "Vulnerabilities": issue}
            ],
        }


def collect(advisories_first=False):
    services, catalog = fixture()

    def releases(_):
        return [
            {
                "tag_name": "2.0.0",
                "html_url": "https://example.org/release/2.0.0",
            }
        ]

    def advisories(source):
        return [advisory(source)] if source["package"] in ("database", "helper") else []

    def manifest(image, reference):
        digest = REBUILT if image[1] == "app" and reference == "1" else DIGEST
        return digest, {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": CONFIG},
        }

    def blob(_image, _digest):
        return {"os": "linux", "architecture": "amd64"}

    services = apply_release_checks(services, catalog, releases, now)
    services = apply_image_checks(services, manifest, blob, now)
    if advisories_first:
        services = apply_advisory_checks(services, catalog, advisories, now)
        services = apply_scan_checks(services, Scanner(), now)
    else:
        services = apply_scan_checks(services, Scanner(), now)
        services = apply_advisory_checks(services, catalog, advisories, now)
    return copy.deepcopy(services)


class AggregationTest(HttpHarness):
    def test_collectors_agree_in_both_orders_and_all_views(self):
        for advisories_first in (False, True):
            with self.subTest(advisories_first=advisories_first):
                self.store.replace("2026-11-22T00:00:00Z", collect(advisories_first))
                _, summary = self.get_json("/api/v1/summary")
                _, services = self.get_json("/api/v1/services")
                _, mixed = self.get_json("/api/v1/services/mixed")
                _, home = self.get_json("/api/v1/services/mixed/homepage")
                _, page = self.get("/services/mixed")
                _, root = self.get("/")

                self.assertEqual(summary["service_count"], 3)
                self.assertEqual(summary["update_status"], "update available")
                self.assertEqual(summary["image_status"], "image update available")
                self.assertEqual(summary["security_status"], "findings")
                self.assertEqual(summary["confirmed_finding_count"], 1)
                self.assertEqual(summary["high_count"], 1)
                self.assertEqual(summary["possible_finding_count"], 1)
                self.assertEqual(summary["coverage_gap_service_count"], 2)
                self.assertEqual(summary["security_counts"]["no known findings"], 1)
                self.assertFalse(summary["coverage_complete"])

                self.assertEqual(mixed["update_status"], "update available")
                self.assertEqual(mixed["image_status"], "image update available")
                self.assertEqual(
                    mixed["components"][0]["update_status"], "update available"
                )
                self.assertEqual(
                    mixed["components"][0]["security_status"], "no known findings"
                )
                self.assertEqual(mixed["security_status"], "findings")
                self.assertEqual(mixed["confirmed_finding_count"], 1)
                self.assertEqual(mixed["high_count"], 1)
                self.assertEqual(mixed["possible_finding_count"], 1)
                self.assertFalse(mixed["coverage_complete"])
                self.assertEqual(mixed["scan_coverage"], "missing")
                self.assertEqual(mixed["advisory_coverage"], "missing")
                self.assertEqual(mixed["components"][1]["security_status"], "findings")
                self.assertEqual(len(mixed["confirmed_findings"][0]["sources"]), 2)
                self.assertEqual(
                    {
                        item["type"]
                        for item in mixed["confirmed_findings"][0]["sources"]
                    },
                    {"Trivy", "upstream advisory"},
                )
                self.assertEqual(home["confirmed_finding_count"], 1)
                self.assertEqual(home["update_status"], "update available")
                self.assertEqual(home["image_status"], "image update available")
                self.assertEqual(home["high_count"], 1)
                self.assertEqual(home["possible_finding_count"], 1)
                self.assertFalse(home["coverage_complete"])
                self.assertIn("Confirmed findings: 1", page)
                self.assertIn("possible findings: 1", page)
                self.assertIn("Trivy finding", page)
                self.assertIn("Upstream advisory", page)
                self.assertIn("services with coverage gaps: 2", root)
                self.assertEqual(len(services["services"]), 3)

                unsupported = self.get_json("/api/v1/services/unsupported")[1]
                clean = self.get_json("/api/v1/services/clean")[1]
                self.assertEqual(unsupported["security_status"], "incomplete coverage")
                self.assertEqual(unsupported["confirmed_finding_count"], 0)
                self.assertEqual(clean["security_status"], "no known findings")
                self.assertTrue(clean["coverage_complete"])
