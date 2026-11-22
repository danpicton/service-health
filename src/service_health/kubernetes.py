"""Read-only Kubernetes API source for pod and node inventory."""

import json
import ssl
from collections.abc import Callable
from urllib.parse import quote
from urllib.request import Request, urlopen


def api_reader(
    base_url: str, token: str, ca_file: str, timeout: float = 10
) -> Callable[[str], dict]:
    """Build a reader using the mounted service account and cluster CA."""
    if not base_url.startswith("https://"):
        raise ValueError("Kubernetes API URL must use HTTPS")
    context = ssl.create_default_context(cafile=ca_file)

    def read(path: str) -> dict:
        request = Request(
            base_url.rstrip("/") + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        with urlopen(request, timeout=timeout, context=context) as response:
            return json.load(response)

    return read


def read_inventory(
    request_json: Callable[[str], dict],
) -> tuple[list[dict], list[dict]]:
    """List all pods and nodes, following Kubernetes pagination tokens."""

    def list_items(resource: str) -> list[dict]:
        items = []
        continuation = None
        while True:
            path = f"/api/v1/{resource}?limit=500"
            if continuation:
                path += "&continue=" + quote(continuation, safe="")
            page = request_json(path)
            items.extend(page["items"])
            continuation = page.get("metadata", {}).get("continue")
            if not continuation:
                return items

    return list_items("pods"), list_items("nodes")
