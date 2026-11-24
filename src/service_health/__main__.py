"""Run the cached service health server."""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from service_health.advisories import apply_advisory_checks
from service_health.freshness import DEFAULT_INVENTORY_MAX_AGE
from service_health.github_cache import GitHubReleases
from service_health.http import create_server
from service_health.images import apply_image_checks
from service_health.inventory import collect_inventory
from service_health.inventory_refresh import refresh_inventory
from service_health.kubernetes import api_reader, read_inventory
from service_health.releases import apply_release_checks
from service_health.scanner import ExternalReports, TrivyScanner, scan_store_once
from service_health.schedule import run_schedule
from service_health.store import Store


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="./service-health.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--inventory-once", action="store_true")
    parser.add_argument("--releases-once", action="store_true")
    parser.add_argument("--advisories-once", action="store_true")
    parser.add_argument("--images-once", action="store_true")
    parser.add_argument("--scans-once", action="store_true")
    parser.add_argument("--scans-scheduled", action="store_true")
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--release-interval", type=int, default=21600)
    parser.add_argument("--security-interval", type=int, default=86400)
    parser.add_argument("--retry-initial", type=int, default=60)
    parser.add_argument("--retry-max", type=int, default=3600)
    parser.add_argument("--release-max-age", type=int, default=43200)
    parser.add_argument("--security-max-age", type=int, default=172800)
    parser.add_argument(
        "--inventory-max-age", type=int, default=DEFAULT_INVENTORY_MAX_AGE
    )
    parser.add_argument("--scan-interval", type=int, default=86400)
    parser.add_argument("--scan-timeout", type=int, default=300)
    parser.add_argument("--scan-workers", type=int, default=2)
    parser.add_argument("--trivy-cache", default="/var/cache/service-health/trivy")
    parser.add_argument("--external-reports", type=Path)
    parser.add_argument("--external-report-max-age", type=int, default=172800)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--github-token-file", type=Path)
    parser.add_argument("--kube-api")
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("/var/run/secrets/kubernetes.io/serviceaccount/token"),
    )
    parser.add_argument(
        "--ca-file",
        type=Path,
        default=Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
    )
    args = parser.parse_args()
    store = Store(args.db)
    if min(args.release_max_age, args.security_max_age, args.inventory_max_age) < 1:
        parser.error("freshness limits must be positive")
    if args.scheduled:
        if not args.catalog:
            parser.error("--scheduled requires --catalog")
        scanner = TrivyScanner(args.trivy_cache, timeout=args.scan_timeout)
        external = (
            ExternalReports(args.external_reports, args.external_report_max_age)
            if args.external_reports
            else None
        )
        run_schedule(
            store,
            args.catalog,
            scanner,
            external,
            args.release_interval,
            args.security_interval,
            args.retry_initial,
            args.retry_max,
            args.scan_workers,
            github_token_file=args.github_token_file,
        )
        return
    if args.scans_once or args.scans_scheduled:
        if args.scan_interval < 60:
            parser.error("--scan-interval must be at least 60 seconds")
        scanner = TrivyScanner(args.trivy_cache, timeout=args.scan_timeout)
        external = (
            ExternalReports(args.external_reports, args.external_report_max_age)
            if args.external_reports
            else None
        )
        while True:
            try:
                scan_store_once(
                    store,
                    scanner,
                    max_workers=args.scan_workers,
                    external_reports=external,
                )
            except BlockingIOError:
                pass  # another worker owns this database's scan cycle
            if not args.scans_scheduled:
                break
            time.sleep(args.scan_interval)
        return
    if args.images_once:
        snapshot = store.read()
        if snapshot is None:
            parser.error("--images-once requires a cached inventory")
        services = apply_image_checks(snapshot["services"])
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if store.commit_evidence(checked_at, services):
            raise RuntimeError("inventory changed during collection; retry required")
        return
    if args.advisories_once:
        if not args.catalog:
            parser.error("--advisories-once requires --catalog")
        snapshot = store.read()
        if snapshot is None:
            parser.error("--advisories-once requires a cached inventory")
        services = apply_advisory_checks(
            snapshot["services"], json.loads(args.catalog.read_text())
        )
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if store.commit_evidence(checked_at, services):
            raise RuntimeError("inventory changed during collection; retry required")
        return
    if args.releases_once:
        if not args.catalog:
            parser.error("--releases-once requires --catalog")
        snapshot = store.read()
        if snapshot is None:
            parser.error("--releases-once requires a cached inventory")
        services = apply_release_checks(
            snapshot["services"],
            json.loads(args.catalog.read_text()),
            fetch_releases=GitHubReleases(store, args.github_token_file),
        )
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if store.commit_evidence(checked_at, services):
            raise RuntimeError("inventory changed during collection; retry required")
        return
    if args.inventory_once:
        if not args.registry or not args.catalog:
            parser.error("--inventory-once requires --registry and --catalog")

        def collect():
            api_url = args.kube_api or _in_cluster_api()
            token = args.token_file.read_text(encoding="utf-8").strip()
            pods, nodes = read_inventory(api_reader(api_url, token, str(args.ca_file)))
            return collect_inventory(
                json.loads(args.registry.read_text()),
                json.loads(args.catalog.read_text()),
                pods,
                nodes,
            )

        refresh_inventory(store, collect)
        return
    server = create_server(
        store,
        args.host,
        args.port,
        args.release_max_age,
        args.security_max_age,
        args.inventory_max_age,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _in_cluster_api() -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    if not host:
        raise ValueError("--kube-api or KUBERNETES_SERVICE_HOST is required")
    return f"https://{host}:{port}"


if __name__ == "__main__":
    main()
