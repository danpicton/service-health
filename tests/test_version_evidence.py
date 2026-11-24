"""Mapped tag inventory, release comparison and cached presentation."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from test_cached_http import HttpHarness, _MemorySocket
from test_inventory import component, pod

from service_health.http import make_handler
from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory
from service_health.releases import apply_release_checks
from service_health.store import Store


class ExactTagTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
        self.config = component("main", "app", "server")
        self.config["version_source"] = {
            "type": "exact_tag",
            "repository": "example/app",
            "documentation": "https://example.org/app/image-tags",
            "prefix": "v",
            "suffix": "-slim",
        }
        self.config["release_source"] = {
            "type": "github_releases",
            "repository": "example/app",
        }
        self.catalog = [{"id": "app", "components": [self.config]}]

    def get(self, path):
        connection = _MemorySocket(
            f"GET {path} HTTP/1.1\r\nHost: offline\r\n\r\n".encode()
        )
        make_handler(self.store, clock=lambda: self.now)(
            connection, ("offline", 0), None
        )
        head, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
        return int(head.split(b" ")[1]), body.decode()

    def refresh(self, image="example/app:v1.2.3-slim", digest="a", annotations=None):
        container = {"name": "server", "image": image}
        observed = {**container, "imageID": "sha256:" + digest * 64}
        pods = [
            pod(
                "app-0",
                {"app": "app"},
                [container],
                [observed],
                annotations=annotations,
            )
        ]
        refresh_inventory(
            self.store,
            lambda: collect_inventory(
                [{"id": "app", "active": True}],
                self.catalog,
                pods,
                [],
                lambda: self.now,
            ),
            lambda: self.now,
        )

    def release(self, tag):
        return apply_release_checks(
            self.store.read()["services"],
            self.catalog,
            lambda _: [{"tag_name": tag, "html_url": "https://example.org/release"}],
            lambda: self.now,
        )

    def homepage(self):
        return self.get_json("/api/v1/services/app/homepage")[1]

    def test_restart_and_expiry_of_cached_release_evidence(self):
        self.refresh()
        self.store.commit_evidence(self.now.isoformat(), self.release("1.2.3"))
        self.store = Store(self.database)
        with patch(
            "urllib.request.urlopen", side_effect=AssertionError("network read")
        ):
            page = self.homepage()
            self.assertEqual(
                (page["current_version"], page["update_status"]),
                ("1.2.3", "up to date"),
            )
            html = self.get("/services/app")[1]
            for label in (
                "exact_tag",
                "scope deployment",
                "v1.2.3-slim",
                "2026-11-22T12:00:00Z",
            ):
                self.assertIn(label, html)
            self.now += timedelta(hours=3)
            page = self.homepage()
            self.assertIsNone(page["current_version"])
            self.assertEqual(page["update_status"], "unknown")
            record = page["components"][0]["deployments"][0]["version_observations"][0]
            self.assertEqual(record["outcome"], "expired")
            self.assertEqual(record["last_success"]["normalized"], "1.2.3")
            self.assertIn("Last successful version 1.2.3", self.get("/services/app")[1])
            self.store.record_job(
                "inventory", self.now.isoformat(), "inventory timeout"
            )
            record = self.homepage()["components"][0]["deployments"][0][
                "version_observations"
            ][0]
            self.assertEqual(record["outcome"], "check failed")
            self.assertEqual(record["checked_at"], self.now.isoformat())
            self.assertEqual(
                record["last_success"]["checked_at"], "2026-11-22T12:00:00Z"
            )

    def test_cached_routine_and_major_choices_require_current_inventory(self):
        self.config["release_source"].update(version_policy="semver", tag_prefix="app-")
        self.refresh()
        tags = ("app-v1.2.4", "app-v2.0.0", "app-v3.0.0-rc.1", "app-v1.2.1")
        result = apply_release_checks(
            self.store.read()["services"],
            self.catalog,
            lambda _: [
                {"tag_name": tag, "html_url": "https://example.org/" + tag}
                for tag in tags
            ],
            lambda: self.now,
        )
        self.store.commit_evidence(self.now.isoformat(), result)
        self.refresh()
        self.store = Store(self.database)
        groups = self.homepage()["components"][0]["release_candidates"]
        self.assertEqual(set(groups), {"routine", "major"})
        self.assertEqual(groups["routine"]["normalized_version"], "1.2.4")
        self.assertEqual(groups["major"]["normalized_version"], "2.0.0")
        html = self.get("/services/app")[1]
        for group in ("routine", "major"):
            self.assertIn(group + " release", html)
            self.assertIn(groups[group]["source_url"], html)
        self.now += timedelta(hours=3)
        home = self.homepage()
        self.assertEqual(home["update_status"], "unknown")
        self.assertTrue(home["components"][0]["release_stale"])
        self.assertEqual(home["components"][0]["release_candidates"], groups)
        self.assertIn("previous major release", self.get("/services/app")[1])

    def test_floating_family_and_unmapped_tags_preserve_observed_image(self):
        for image in (
            "example/app:v1.2-slim",
            "example/app:latest",
            "other/app:v1.2.3-slim",
        ):
            with self.subTest(image=image):
                self.refresh(image)
                self.store.commit_evidence(self.now.isoformat(), self.release("1.2.3"))
                page = self.homepage()
                deployment = page["components"][0]["deployments"][0]
                self.assertEqual(deployment["image"], image)
                self.assertIsNone(page["current_version"])
                self.assertEqual(page["update_status"], "unknown")
                record = deployment["version_observations"][0]
                self.assertTrue(record["reason"])
                self.assertIsNone(record["last_success"])

    def test_source_and_digest_change_reject_late_comparisons(self):
        self.refresh()
        old = self.release("1.3.0")
        self.store.commit_evidence(self.now.isoformat(), old)
        self.assertEqual(self.homepage()["update_status"], "update available")
        self.refresh(digest="b")
        self.assertTrue(self.store.commit_evidence(self.now.isoformat(), old))
        self.assertEqual(self.homepage()["update_status"], "unknown")
        old = self.release("1.3.0")
        self.config["version_source"]["documentation"] += "/revised"
        self.refresh(digest="b")
        self.assertTrue(self.store.commit_evidence(self.now.isoformat(), old))
        self.assertIsNone(self.homepage()["candidate_version"])

    def test_malformed_source_is_a_local_gap_and_private_fields_stay_out_of_cache(self):
        self.config["version_source"]["extra"] = "unpublished-field"
        invalid = component("broken", "app", "server")
        invalid["version_source"] = {
            "type": "unsupported",
            "extra": "unpublished-field",
        }
        self.catalog[0]["components"].append(invalid)
        self.refresh()
        self.assertNotIn("unpublished-field", str(self.store.read()))
        healthy, broken = self.homepage()["components"]
        self.assertEqual(healthy["current_version"], "1.2.3")
        observation = broken["deployments"][0]["version_observations"][0]
        self.assertEqual(observation["outcome"], "unknown")
        self.assertIn("invalid or unsupported", observation["reason"])

    def test_credential_bearing_documentation_urls_stay_out_of_cache(self):
        for ending in ("?token=private-fixture", "#access_token=private-fixture"):
            with self.subTest(ending=ending):
                self.config["version_source"]["documentation"] = (
                    "https://example.org/tags" + ending
                )
                self.refresh()
                self.assertNotIn("private-fixture", str(self.store.read()))
                component = self.homepage()["components"][0]
                self.assertIsNone(component["current_version"])
                record = component["deployments"][0]["version_observations"][0]
                self.assertEqual(record["source"], {"type": "invalid"})

    def test_same_deployment_keeps_annotation_history_without_node_metadata(self):
        self.config["version_annotation"] = "app/version"
        self.refresh(annotations={"app/version": "1.2.3"})
        self.now += timedelta(minutes=2)
        self.config["version_source"]["documentation"] += "/updated"
        self.refresh()
        annotation = self.homepage()["components"][0]["deployments"][0][
            "version_observations"
        ][0]
        self.assertEqual(annotation["outcome"], "unknown")
        self.assertEqual(annotation["last_success"]["normalized"], "1.2.3")
        self.assertEqual(
            annotation["last_success"]["checked_at"], "2026-11-22T12:00:00Z"
        )

    def test_failed_refresh_clears_legacy_annotation_version(self):
        self.refresh()
        snapshot = self.store.read()
        comp = snapshot["services"][0]["components"][0]
        del comp["version_source_identity"]
        del comp["deployments"][0]["version_observations"]
        self.store.replace(snapshot["checked_at"], snapshot["services"])
        self.store.record_job("inventory", self.now.isoformat(), "unavailable")
        page = self.homepage()
        self.assertIsNone(page["current_version"])
        self.assertIsNone(page["components"][0]["current_version"])
        self.assertIsNone(
            page["components"][0]["deployments"][0]["application_version"]
        )
