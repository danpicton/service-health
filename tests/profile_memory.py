"""Offline, synthetic 30 MiB snapshot memory and dashboard load probe.

Run prepare, then each probe in a separate process so peak RSS is comparable.
No network, cluster credentials, or real inventory are used.
"""

import argparse
import copy
import json
import resource
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType

from test_api_contract import _MemorySocket, representative_service, request

from service_health.freshness import project
from service_health.scanner import apply_scan_checks
from service_health.store import Store


def rss_kib():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise RuntimeError("Linux RSS unavailable")


def prepare(store):
    services = []
    for index in range(21):
        service = representative_service()
        service["id"] = f"service-{index}"
        service["name"] = f"Synthetic service {index}"
        service["components"] = []
        for part in range(3 if index < 12 else 2):
            component = copy.deepcopy(representative_service()["components"][0])
            component["id"] = f"component-{part}"
            findings = []
            for number in range(70):
                finding = {
                    "id": f"CVE-SYNTH-{index}-{part}-{number}",
                    "severity": "high",
                    "package": "synthetic-package",
                    "digest": "sha256:abc",
                    "platform": "linux/amd64",
                    "description": "synthetic detail " + "x" * 1800,
                }
                findings.append(finding)
            component["deployments"][0]["scan_findings"] = findings
            component["scan_findings"] = findings
            component["confirmed_findings"] = [
                {
                    "id": finding["id"],
                    "severity": "high",
                    "sources": [{"finding": finding}],
                }
                for finding in findings
            ]
            service["components"].append(component)
        service["confirmed_findings"] = [
            finding
            for component in service["components"]
            for finding in component["confirmed_findings"]
        ]
        service["confirmed_finding_count"] = len(service["confirmed_findings"])
        services.append(service)
    store.replace("2026-11-22T12:00:00Z", services)
    with store._connect() as connection:
        sizes = connection.execute(
            "SELECT length(services_json) FROM snapshot WHERE id=1"
        ).fetchone()[0]
        detail, compact = connection.execute(
            "SELECT sum(length(detail_json)), "
            "sum(length(compact_json)) FROM service_rows"
        ).fetchone()
    print(
        json.dumps(
            {
                "snapshot_bytes": sizes,
                "detail_rows_bytes": detail,
                "compact_rows_bytes": compact,
                "services": 21,
                "components": 54,
            }
        )
    )


def probe(store, mode):
    before = rss_kib()
    sizes = {}
    if mode == "scanner":

        class InjectedScanner:
            def refresh_db(self):
                pass

            def scan(self, target, platform):
                return {
                    "SchemaVersion": 2,
                    "ArtifactName": target,
                    "Metadata": {
                        "ImageConfig": {"os": "linux", "architecture": "amd64"}
                    },
                    "Results": [{"Target": "alpine", "Class": "os-pkgs"}],
                }

        snapshot = store.read()
        result = apply_scan_checks(
            snapshot["services"], InjectedScanner(), max_workers=2
        )
        print(
            json.dumps(
                {
                    "mode": mode,
                    "idle_rss_kib": before,
                    "after_rss_kib": rss_kib(),
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "services": len(result),
                }
            )
        )
        return
    if mode == "worker":
        print("READY", flush=True)
        cycle_rss = []
        for cycle in range(3):
            snapshot = store.read()
            store.commit_evidence(f"2026-11-22T12:0{cycle}:00Z", snapshot["services"])
            del snapshot
            cycle_rss.append(rss_kib())
        print(
            json.dumps(
                {
                    "mode": mode,
                    "idle_rss_kib": before,
                    "cycle_rss_kib": cycle_rss,
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                }
            )
        )
        return

    paths = ["/api/v1/summary", "/api/v1/services", "/healthz", "/readyz"]
    paths += [f"/api/v1/services/service-{i % 21}/homepage" for i in range(42)]
    paths += [f"/api/v1/services/service-{i}" for i in range(4)]
    paths += [f"/services/service-{i}" for i in range(4)]

    worker = subprocess.Popen(
        [sys.executable, __file__, "worker", str(store.path)],
        stdout=subprocess.PIPE,
        text=True,
    )
    if worker.stdout.readline().strip() != "READY":
        raise RuntimeError("worker did not start")
    if mode == "http":
        limit = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    if mode == "legacy":
        old = ModuleType("legacy_http")
        source = subprocess.check_output(
            ["git", "show", "v0.1.1:src/service_health/http.py"]
        ).decode()
        exec(compile(source, "legacy_http.py", "exec"), old.__dict__)
        old.project = (
            lambda snapshot, jobs, clock, release_max_age, security_max_age: project(
                copy.deepcopy(snapshot), jobs, clock, release_max_age, security_max_age
            )
        )
        handler = old.make_handler(store)

        def one(path):
            connection = _MemorySocket(
                f"GET {path} HTTP/1.1\r\nHost: hub.example\r\n\r\n".encode()
            )
            handler(connection, ("offline", 0), None)
            head, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
            return int(head.split(b" ", 2)[1]), len(body)
    else:

        def one(path):
            status, body = request(store, path)
            return status, len(body.encode())

    with ThreadPoolExecutor(max_workers=4) as pool:
        for path, (status, size) in zip(paths, pool.map(one, paths), strict=True):
            if status != 200:
                raise RuntimeError(f"{mode} {path} returned HTTP {status}")
            key = (
                "homepage"
                if path.endswith("/homepage")
                else "detail"
                if "/service-" in path
                else path
            )
            sizes[key] = max(sizes.get(key, 0), size)
    worker_result = worker.stdout.read().strip()
    if worker.wait() != 0:
        raise RuntimeError("worker failed")
    print(
        json.dumps(
            {
                "mode": mode,
                "idle_rss_kib": before,
                "after_rss_kib": rss_kib(),
                "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "response_bytes": sizes,
                "worker": json.loads(worker_result),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("prepare", "legacy", "http", "worker", "scanner")
    )
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    store = Store(args.database)
    if args.mode == "prepare":
        prepare(store)
    else:
        probe(store, args.mode)
