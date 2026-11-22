"""Build-independent, synthetic smoke test for an already built local image.

Run explicitly with ``python tests/container_smoke.py service-health:local``.
Only Docker/Podman volumes created by this script are touched.
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from uuid import uuid4


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=30, check=True
    )
    return result.stdout.strip()


def get(base: str, path: str) -> str:
    with urllib.request.urlopen(base + path, timeout=2) as response:
        if response.status != 200:
            raise AssertionError(f"{path}: HTTP {response.status}")
        return response.read().decode("utf-8")


def main(image: str) -> None:
    marker = uuid4().hex[:12]
    volume = f"service-health-smoke-{marker}"
    container = f"service-health-smoke-{marker}"
    docker("volume", "create", volume)
    try:
        trivy_version = docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "trivy",
            image,
            "--version",
        )
        assert "Version:" in trivy_version, trivy_version
        seed = (
            "from datetime import datetime, timezone; "
            "from service_health.collection import collect_once; "
            "from service_health.store import Store; "
            "collect_once(Store('/var/lib/service-health/state.db'), "
            "lambda: [{'id':'fixture','name':'Synthetic fixture'}], "
            "lambda: datetime.now(timezone.utc))"
        )
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            f"type=volume,src={volume},dst=/var/lib/service-health",
            "--entrypoint",
            "python",
            image,
            "-c",
            seed,
        )
        docker(
            "run",
            "-d",
            "--name",
            container,
            "--publish",
            "127.0.0.1::8080",
            "--mount",
            f"type=volume,src={volume},dst=/var/lib/service-health",
            image,
        )
        published = docker("port", container, "8080/tcp")
        port = published.rsplit(":", 1)[-1]
        base = f"http://127.0.0.1:{port}"
        for attempt in range(30):
            try:
                assert json.loads(get(base, "/healthz")) == {"status": "alive"}
                break
            except (OSError, urllib.error.URLError):
                if attempt == 29:
                    raise
                time.sleep(0.2)
        summary = json.loads(get(base, "/api/v1/summary"))
        assert summary["service_count"] == 1, summary
        homepage = json.loads(get(base, "/api/v1/services/fixture/homepage"))
        assert homepage["update_status"] == "unknown", homepage
        assert homepage["security_status"] == "incomplete coverage", homepage
        assert "Synthetic fixture" in get(base, "/")
        assert "fixture" in get(base, "/services/fixture")
        print(f"Smoke passed: {base}; Trivy {trivy_version}")
        try:
            memory = docker(
                "stats", "--no-stream", "--format", "{{.MemUsage}}", container
            )
            size = docker("image", "inspect", "--format", "{{.Size}}", image)
            print("Container stats:", memory)
            print("Image bytes:", size)
        except subprocess.CalledProcessError:
            print("Resource metrics unavailable from local container runtime")
    finally:
        subprocess.run(["docker", "rm", "--force", container], capture_output=True)
        subprocess.run(
            ["docker", "volume", "rm", "--force", volume], capture_output=True
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/container_smoke.py IMAGE")
    main(sys.argv[1])
