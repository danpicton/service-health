"""Offline shared endpoint checks through inventory, persistence and HTTP."""

import subprocess
from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from test_advisories import SOURCE, advisory
from test_cached_http import HttpHarness
from test_inventory import component, pod

from service_health.advisories import apply_advisory_checks
from service_health.endpoint_transport import read_endpoint
from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory
from service_health.releases import apply_release_checks
from service_health.store import Store
from service_health.version_evidence import fetch_endpoint


class EndpointTest(HttpHarness):
    def setUp(self):
        super().setUp()
        self.now = datetime.now(timezone.utc)
        self.source = {
            "type": "endpoint",
            "url": "http://app.invalid/api/version",
            "json_path": ["application", "version"],
            "documentation": "https://example.org/docs/version",
        }
        self.config = {
            **component("server", "app", "server"),
            "version_source": self.source,
            "release_source": {"type": "github_releases", "repository": "example/app"},
            "advisory_source": SOURCE,
        }
        self.catalog = [{"id": "app", "components": [self.config]}]
        self.fetch = Mock(return_value=b'{"application":{"version":"1.5.0"}}')

    def refresh(self, replicas="ab"):
        container = {"name": "server", "image": "example/app:stable"}
        pods = [
            pod(
                f"app-{i}",
                {"app": "app"},
                [container],
                [{**container, "imageID": "sha256:" + digest * 64}],
            )
            for i, digest in enumerate(replicas)
        ]
        refresh_inventory(
            self.store,
            lambda: collect_inventory(
                [{"id": "app", "active": True}],
                self.catalog,
                pods,
                [],
                lambda: self.now,
                endpoint_fetch=self.fetch,
            ),
            lambda: self.now,
        )

    def cached(self):
        return self.get_json("/api/v1/services/app/homepage")[1]["components"][0]

    def test_shared_sample_compares_release_and_leaves_advisory_possible(self):
        self.refresh()
        services = apply_release_checks(
            self.store.read()["services"],
            self.catalog,
            lambda _: [
                {"tag_name": "1.6.0", "html_url": "https://example.org/release"}
            ],
            lambda: self.now,
        )
        services = apply_advisory_checks(
            services, self.catalog, lambda _: [advisory()], lambda: self.now
        )
        self.store.commit_evidence(self.now.isoformat(), services)
        self.store = Store(self.database)
        for _ in range(2):
            cached = self.cached()
            self.assertEqual(cached["current_version"], "1.5.0")
            self.assertEqual(cached["update_status"], "update available")
            self.assertEqual(cached["possible_finding_count"], 1)
            (sample,) = cached["version_observations"]
            self.assertEqual(sample["scope"], "shared endpoint")
            self.assertEqual(sample["source"], self.source)
            for replica in cached["deployments"]:
                self.assertIsNone(replica["application_version"])
                self.assertEqual(replica["version_observations"], [])
            html = self.get("/services/app")[1]
            for phrase in (
                "endpoint-reported",
                self.source["url"],
                sample["limitation"],
            ):
                self.assertIn(phrase, html)
        self.fetch.assert_called_once_with(self.source["url"])

    def test_gaps_and_failures_never_supply_current_versions(self):
        self.refresh()
        for reply, outcome, reason in (
            (b"{", "check failed", "malformed"),
            (b"{" + b" " * 65536, "check failed", "64 KiB"),
            (b'{"application":{}}', "unknown", "absent"),
            (b'{"application":{"version":42}}', "unknown", "version value"),
            (OSError(), "check failed", "unavailable"),
            (
                HTTPError(self.source["url"], 401, "", {}, None),
                "unknown",
                "authentication",
            ),
            (HTTPError(self.source["url"], 503, "", {}, None), "check failed", "503"),
        ):
            with self.subTest(reason=reason):
                self.fetch.side_effect = reply if isinstance(reply, Exception) else None
                self.fetch.return_value = reply
                self.refresh()
                cached = self.cached()
                self.assertIsNone(cached["current_version"])
                (sample,) = cached["version_observations"]
                self.assertEqual(sample["outcome"], outcome)
                self.assertIn(reason, sample["reason"])
                self.assertEqual(sample["last_success"]["normalized"], "1.5.0")

    def test_source_and_deployment_change_keep_only_labeled_history(self):
        self.refresh()
        old = apply_release_checks(
            self.store.read()["services"],
            self.catalog,
            lambda _: [
                {"tag_name": "1.5.0", "html_url": "https://example.org/release"}
            ],
            lambda: self.now,
        )
        self.fetch.side_effect = TimeoutError()
        self.source["url"] = "http://replacement.invalid/version"
        self.refresh("cc")
        self.store.commit_evidence(self.now.isoformat(), old)
        cached = self.cached()
        self.assertIsNone(cached["current_version"])
        self.assertEqual(cached["update_status"], "unknown")
        (sample,) = cached["version_observations"]
        prior = sample["last_success"]["assessed_identity"]
        self.assertEqual(
            prior["version_source"]["url"], "http://app.invalid/api/version"
        )
        self.assertEqual(prior["deployments"][0][4], "sha256:" + "a" * 64)

    def test_expiry_preserves_success(self):
        self.now -= timedelta(hours=3)
        self.refresh()
        cached = self.cached()
        (sample,) = cached["version_observations"]
        self.assertIsNone(cached["current_version"])
        self.assertEqual(sample["outcome"], "expired")
        self.assertEqual(sample["last_success"]["normalized"], "1.5.0")
        self.assertIn("Last successful version 1.5.0", self.get("/services/app")[1])

    def test_credentials_and_unsupported_urls_are_never_fetched_or_cached(self):
        for url in (
            "https://secret@example.org/api",
            "https://example.org/?secret",
            "https://example.org/#secret",
            "file:///secret",
        ):
            self.source["url"] = url
            self.refresh()
            self.assertNotIn("secret", str(self.cached()))
        self.fetch.assert_not_called()

    def test_transport_makes_one_direct_get_and_rejects_redirect(self):
        for status, body, outcome in (
            (b"200 OK", b'{"application":{"version":"1.5.0"}}', "success"),
            (b"302 Found", b"", "check failed"),
        ):
            with self.subTest(status=status):
                client = Mock()
                client.makefile.return_value = BytesIO(
                    b"HTTP/1.1 "
                    + status
                    + b"\r\nLocation: http://redirect.invalid/\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
                self.fetch = read_endpoint
                with patch("socket.create_connection", return_value=client) as connect:
                    self.refresh()
                    self.assertEqual(connect.call_count, 1)
                request = client.sendall.call_args.args[0]
                self.assertTrue(request.startswith(b"GET /api/version HTTP/1.1\r\n"))
                self.assertNotIn(b"Authorization", request)
                (sample,) = self.cached()["version_observations"]
                self.assertEqual(sample["outcome"], outcome)

    def test_partial_response_never_supplies_a_version(self):
        client = Mock()
        client.makefile.return_value = BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
            b'{"application":{"version":"1.5.0"}}'
        )
        self.fetch = read_endpoint
        with patch("socket.create_connection", return_value=client):
            self.refresh()
        sample = self.cached()["version_observations"][0]
        self.assertEqual(sample["outcome"], "check failed")
        self.assertIsNone(sample["last_success"])

    def test_transport_timeout_covers_the_entire_worker(self):
        self.fetch = fetch_endpoint
        with patch(
            "service_health.version_evidence.subprocess.run",
            side_effect=subprocess.TimeoutExpired("endpoint worker", 5),
        ) as run:
            self.refresh()
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertEqual(
            self.cached()["version_observations"][0]["outcome"], "check failed"
        )

    def test_invalid_replacement_preserves_sanitized_endpoint_history(self):
        self.refresh()
        original = self.source["url"]
        self.source["url"] = "http://example.invalid/?secret"
        for _ in range(2):
            self.refresh()
            component = self.cached()
            self.assertIsNone(component["current_version"])
            self.assertNotIn("secret", str(component))
            (sample,) = component["version_observations"]
            self.assertEqual(sample["outcome"], "unknown")
            prior = sample["last_success"]
            self.assertEqual(prior["normalized"], "1.5.0")
            self.assertEqual(
                prior["assessed_identity"]["version_source"]["url"], original
            )
            self.assertIn("Last successful version 1.5.0", self.get("/services/app")[1])

    def test_absent_deployment_is_an_unsampled_gap(self):
        self.refresh("")
        (sample,) = self.cached()["version_observations"]
        self.assertIsNone(sample["last_success"])
        self.assertIn("no matching deployment", sample["reason"])
        self.fetch.assert_not_called()
