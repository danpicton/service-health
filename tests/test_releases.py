"""Offline release fixtures through cached JSON and rendered pages."""

import unittest
from datetime import datetime, timezone

from test_cached_http import HttpHarness

from service_health.releases import apply_release_checks


def catalog(version_policy="semver", track_prereleases=False, **release_rules):
    return [
        {
            "id": "app",
            "components": [
                {
                    "id": "server",
                    "release_source": {
                        "type": "github_releases",
                        "repository": "example/app",
                        "version_policy": version_policy,
                        "track_prereleases": track_prereleases,
                        **release_rules,
                    },
                }
            ],
        }
    ]


def service(version):
    return [
        {
            "id": "app",
            "name": "App",
            "components": [
                {
                    "id": "server",
                    "name": "Server",
                    "current_version": version,
                    "deployments": [],
                    "version_evidence": "configured pod annotation"
                    if version
                    else "unknown",
                }
            ],
        }
    ]


def release(tag, prerelease=False):
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": False,
        "html_url": "https://example.com/releases/" + tag,
    }


class ReleaseTest(HttpHarness):
    def check(self, current, releases, **policy):
        result = apply_release_checks(
            service(current),
            catalog(**policy),
            lambda _: releases,
            lambda: datetime(2026, 11, 22, tzinfo=timezone.utc),
        )
        self.store.replace("2026-11-22T00:00:00Z", result)
        _, homepage = self.get_json("/api/v1/services/app/homepage")
        _, detail = self.get_json("/api/v1/services/app")
        _, page = self.get("/services/app")
        return homepage, detail["components"][0], page

    def test_stable_major_release_is_available_and_rendered(self):
        homepage, component, page = self.check(
            "1.9.2", [release("v2.0.0"), release("v3.0.0-rc.1", True)]
        )
        self.assertEqual(homepage["update_status"], "update available")
        self.assertEqual(homepage["candidate_version"], "v2.0.0")
        self.assertEqual(homepage["update_kind"], "major migration")
        self.assertTrue(homepage["update_coverage_complete"])
        self.assertEqual(component["release_checked_at"], "2026-11-22T00:00:00Z")
        self.assertIn("v2.0.0", page)
        self.assertIn("major migration", page)
        self.assertIn("https://example.com/releases/v2.0.0", page)
        _, summary = self.get_json("/api/v1/summary")
        self.assertEqual(summary["update_counts"]["update available"], 1)

    def test_patch_minor_and_prerelease_opt_in(self):
        for current, candidate, kind in [
            ("1.2.3", "1.2.4", "patch"),
            ("1.2.3", "1.3.0", "minor"),
        ]:
            with self.subTest(kind=kind):
                home, _, _ = self.check(current, [release(candidate)])
                self.assertEqual(home["update_kind"], kind)
        home, _, _ = self.check(
            "1.2.3", [release("1.3.0-beta.1", True), release("1.2.3")]
        )
        self.assertEqual(home["update_status"], "up to date")
        home, _, _ = self.check(
            "1.2.3", [release("1.3.0-beta.1", True)], track_prereleases=True
        )
        self.assertEqual(home["update_status"], "update available")
        self.assertEqual(home["update_kind"], "minor")

    def test_no_candidate_ambiguous_current_and_numeric_policy(self):
        home, component, _ = self.check("1.0.0", [])
        self.assertEqual(home["update_status"], "unknown")
        self.assertEqual(component["update_reason"], "no eligible releases")
        home, component, _ = self.check(None, [release("1.1.0")])
        self.assertEqual(home["update_status"], "unknown")
        self.assertEqual(component["candidate_version"], "1.1.0")
        home, _, _ = self.check(">=1.0 <2", [release("1.1.0")])
        self.assertEqual(home["update_status"], "unknown")
        home, _, _ = self.check(
            "2026.11", [release("2026.12")], version_policy="numeric"
        )
        self.assertEqual(home["update_status"], "update available")
        home, _, _ = self.check("1.2", [release("1.3")])
        self.assertEqual(home["update_status"], "unknown")
        home, _, _ = self.check("latest", [release("1.3.0")])
        self.assertEqual(home["update_status"], "unknown")

    def test_numeric_project_lines_and_unclassified_releases(self):
        releases = [release(tag) for tag in ("2026.11.10", "2026.12.1", "2026.11.2")]
        home, component, page = self.check(
            "2026.11.1", releases, version_policy="numeric", release_line_segments=2
        )
        self.assertEqual(home["update_status"], "update available")
        groups = component["release_candidates"]
        self.assertEqual(groups["routine"]["version"], "2026.11.10")
        self.assertEqual(groups["major"]["version"], "2026.12.1")
        self.assertIn("routine release", page)
        home, component, page = self.check(
            "2026.11.1", releases, version_policy="numeric"
        )
        self.assertEqual(home["update_kind"], "unclassified")
        self.assertEqual(list(component["release_candidates"]), ["unclassified"])
        self.assertIn("unclassified release", page)
        home, component, _ = self.check("2027.1.0", releases, version_policy="numeric")
        self.assertEqual(home["update_status"], "up to date")
        self.assertEqual(component["release_candidates"], {})

    def test_unknown_version_and_default_policy_do_not_classify_a_release(self):
        _, component, _ = self.check(None, [release("1.1.0")])
        self.assertEqual(list(component["release_candidates"]), ["unclassified"])
        configured = catalog()
        configured[0]["components"][0]["release_source"].pop("version_policy")
        result = apply_release_checks(
            service("1.0.0"), configured, lambda _: [release("1.2.0")]
        )
        self.assertEqual(result[0]["update_kind"], "unclassified")

    def test_service_prerelease_opt_in_and_missing_source(self):
        configured = catalog()
        configured[0]["track_prereleases"] = True
        configured[0]["components"][0]["release_source"].pop("track_prereleases")
        result = apply_release_checks(
            service("1.2.3"), configured, lambda _: [release("1.3.0-rc.1", True)]
        )
        self.assertEqual(result[0]["update_status"], "update available")
        result = apply_release_checks(
            service("1.2.3"),
            [{"id": "app", "components": [{"id": "server"}]}],
            lambda _: [],
        )
        self.assertEqual(result[0]["update_status"], "unknown")
        self.assertEqual(
            result[0]["components"][0]["update_reason"], "no release source configured"
        )

    def test_configured_prefix_normalization_keeps_original_candidate(self):
        configured = catalog()
        source = configured[0]["components"][0]["release_source"]
        source["tag_prefix"] = "app-"
        source["current_prefix"] = "release-"
        result = apply_release_checks(
            service("release-1.0.0"), configured, lambda _: [release("app-1.1.0")]
        )
        self.assertEqual(result[0]["update_status"], "update available")
        self.assertEqual(result[0]["candidate_version"], "app-1.1.0")

    def test_provider_failure_preserves_prior_candidate_as_stale(self):
        first = apply_release_checks(
            service("1.0.0"), catalog(), lambda _: [release("1.1.0")]
        )

        def fail(_):
            raise OSError("upstream offline")

        second = apply_release_checks(first, catalog(), fail)
        self.store.replace("2026-11-22T00:00:00Z", second)
        home, component = (
            self.get_json("/api/v1/services/app/homepage")[1],
            self.get_json("/api/v1/services/app")[1]["components"][0],
        )
        self.assertEqual(home["update_status"], "check failed")
        self.assertTrue(home["release_stale"])
        self.assertTrue(home["stale"])
        self.assertEqual(component["candidate_version"], "1.1.0")
        self.assertEqual(component["release_error"], "upstream offline")
        self.assertEqual(component["release_candidates"]["routine"]["version"], "1.1.0")
        self.assertIn("previous routine release", self.get("/services/app")[1])

    def test_multicomponent_unknown_does_not_hide_available_update(self):
        snapshot = service("1.0.0")
        snapshot[0]["components"].append(
            {"id": "database", "current_version": None, "deployments": []}
        )
        result = apply_release_checks(snapshot, catalog(), lambda _: [release("1.1.0")])
        self.assertEqual(result[0]["update_status"], "update available")
        self.assertFalse(result[0]["update_coverage_complete"])
        self.assertIsNone(result[0]["candidate_version"])
        self.assertEqual(result[0]["components"][1]["update_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
