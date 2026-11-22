"""Offline inventory fixture covering active services and deployed components."""

import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from test_cached_http import HttpHarness

from service_health.__main__ import main
from service_health.collection import collect_once
from service_health.inventory import collect_inventory
from service_health.kubernetes import read_inventory
from service_health.store import Store


def pod(
    name, labels, containers, statuses, init=(), init_statuses=(), annotations=None
):
    return {
        "metadata": {
            "name": name,
            "namespace": "apps",
            "labels": labels,
            "annotations": annotations or {},
        },
        "spec": {
            "nodeName": "node-a",
            "containers": list(containers),
            "initContainers": list(init),
        },
        "status": {
            "phase": "Running",
            "containerStatuses": list(statuses),
            "initContainerStatuses": list(init_statuses),
        },
    }


def component(identifier, app, container, kind="regular", version_annotation=None):
    return {
        "id": identifier,
        "name": identifier,
        "selector": {
            "namespace": "apps",
            "pod_labels": {"app": app},
            "container": container,
            "kind": kind,
        },
        **({"version_annotation": version_annotation} if version_annotation else {}),
    }


class InventoryTest(HttpHarness):
    def test_active_multicomponent_inventory_is_cached_in_all_views(self) -> None:
        digest_server = "sha256:" + "a" * 64
        digest_init = "sha256:" + "b" * 64
        registry = [
            {"id": "photo", "name": "Photos & More", "active": True},
            {"id": "custom", "name": "Custom", "active": True},
            {"id": "retired", "active": False},
        ]
        catalog = [
            {
                "id": "photo",
                "components": [
                    component(
                        "server",
                        "photo",
                        "server",
                        version_annotation="app.example/version",
                    ),
                    component("database", "photo", "database"),
                    component("migration", "photo", "migrate", kind="init"),
                ],
            },
            {"id": "custom", "components": [component("worker", "custom", "worker")]},
        ]
        pods = [
            pod(
                "photo-1",
                {"app": "photo"},
                [
                    {"name": "server", "image": "example/photo:2.0"},
                    {"name": "database", "image": "postgres:16"},
                ],
                [
                    {
                        "name": "server",
                        "image": "example/photo:2.0",
                        "imageID": "docker-pullable://example/photo@" + digest_server,
                    },
                    {
                        "name": "database",
                        "image": "postgres:16",
                        "imageID": "docker://not-a-digest",
                    },
                ],
                [{"name": "migrate", "image": "example/migrate:2.0"}],
                [{"name": "migrate", "imageID": "example/migrate@" + digest_init}],
                {"app.example/version": "2.0.1"},
            ),
            pod(
                "custom-1",
                {"app": "custom"},
                [{"name": "worker", "image": "localhost/custom:latest"}],
                [{"name": "worker", "image": "localhost/custom:latest", "imageID": ""}],
            ),
        ]
        nodes = [
            {
                "metadata": {"name": "node-a"},
                "status": {
                    "nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}
                },
            }
        ]
        collect_once(
            self.store,
            lambda: collect_inventory(registry, catalog, pods, nodes),
            lambda: datetime(2026, 11, 22, tzinfo=timezone.utc),
        )
        _, listing = self.get_json("/api/v1/services")
        self.assertEqual(
            [item["id"] for item in listing["services"]], ["photo", "custom"]
        )
        photo = listing["services"][0]
        self.assertEqual(
            [item["id"] for item in photo["components"]],
            ["server", "database", "migration"],
        )
        self.assertEqual(photo["components"][0]["current_version"], "2.0.1")
        self.assertEqual(
            photo["components"][0]["deployments"][0]["digest"], digest_server
        )
        self.assertEqual(
            photo["components"][0]["deployments"][0]["platform"], "linux/amd64"
        )
        self.assertIsNone(photo["components"][1]["deployments"][0]["digest"])
        self.assertEqual(
            photo["components"][2]["deployments"][0]["digest"], digest_init
        )
        self.assertEqual(photo["components"][2]["kind"], "init")
        self.assertIsNone(listing["services"][1]["components"][0]["current_version"])
        self.assertEqual(
            listing["services"][1]["components"][0]["deployments"][0]["image"],
            "localhost/custom:latest",
        )
        _, detail = self.get_json("/api/v1/services/photo")
        _, homepage = self.get_json("/api/v1/services/photo/homepage")
        self.assertEqual(detail["components"], photo["components"])
        self.assertEqual(homepage["components"], photo["components"])
        self.assertEqual(homepage["component_count"], 3)
        self.assertIsNone(homepage["current_version"])
        _, page = self.get("/")
        _, detail_page = self.get("/services/photo")
        for text in ("server", "database", "migration", digest_server, "linux/amd64"):
            self.assertIn(text, page)
            self.assertIn(text, detail_page)
        self.assertIn("Photos &amp; More", page)
        self.assertEqual(Store(self.database).read()["services"], listing["services"])

    def test_missing_mapping_rejects_cycle_without_erasing_cache(self) -> None:
        collect_once(self.store, lambda: [{"id": "existing"}])
        with self.assertRaisesRegex(ValueError, "no component mapping"):
            collect_once(
                self.store,
                lambda: collect_inventory([{"id": "new", "active": True}], [], [], []),
            )
        self.assertEqual(Store(self.database).read()["services"], [{"id": "existing"}])

    def test_unobserved_component_keeps_unknown_facts(self) -> None:
        services = collect_inventory(
            [{"id": "example", "active": True}],
            [
                {
                    "id": "example",
                    "components": [component("missing", "example", "server")],
                }
            ],
            [],
            [],
        )
        self.assertEqual(services[0]["inventory_status"], "incomplete")
        self.assertEqual(services[0]["components"][0]["deployments"], [])
        self.assertIsNone(services[0]["components"][0]["current_version"])

    def test_kubernetes_reader_follows_list_pagination_offline(self) -> None:
        requested = []

        def fake_api(path):
            requested.append(path)
            return {
                "/api/v1/pods?limit=500": {
                    "items": [{"metadata": {"name": "one"}}],
                    "metadata": {"continue": "next/token"},
                },
                "/api/v1/pods?limit=500&continue=next%2Ftoken": {
                    "items": [{"metadata": {"name": "two"}}]
                },
                "/api/v1/nodes?limit=500": {
                    "items": [{"metadata": {"name": "node-a"}}]
                },
            }[path]

        pods, nodes = read_inventory(fake_api)
        self.assertEqual([pod["metadata"]["name"] for pod in pods], ["one", "two"])
        self.assertEqual(nodes[0]["metadata"]["name"], "node-a")
        self.assertEqual(len(requested), 3)

    def test_inventory_command_uses_injected_kubernetes_api(self) -> None:
        root = Path(self.directory.name)
        registry = root / "registry.json"
        catalog = root / "catalog.json"
        token = root / "token"
        registry.write_text('[{"id":"example","active":true}]')
        catalog.write_text(
            '[{"id":"example","components":[{"id":"server",'
            '"selector":{"namespace":"apps","pod_labels":{"app":"example"},'
            '"container":"server","kind":"regular"}}]}]'
        )
        token.write_text("fixture-token")

        def fake_api(path):
            if path.startswith("/api/v1/pods"):
                return {"items": []}
            return {"items": []}

        argv = [
            "service_health",
            "--inventory-once",
            "--db",
            str(self.database),
            "--registry",
            str(registry),
            "--catalog",
            str(catalog),
            "--token-file",
            str(token),
            "--kube-api",
            "https://kubernetes.example",
        ]
        with (
            patch("sys.argv", argv),
            patch(
                "service_health.__main__.api_reader", return_value=fake_api
            ) as reader,
        ):
            main()
        self.assertEqual(
            reader.call_args.args[:2],
            ("https://kubernetes.example", "fixture-token"),
        )
        self.assertEqual(Store(self.database).read()["services"][0]["id"], "example")


if __name__ == "__main__":
    unittest.main()
