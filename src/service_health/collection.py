"""Injected collection boundary used by offline fixtures and later collectors."""

from collections.abc import Callable
from datetime import datetime, timezone

from service_health.store import Store


def collect_once(
    store: Store,
    provider: Callable[[], list[dict]],
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    """Replace one cached snapshot after an injected provider succeeds."""
    services = provider()
    checked_at = clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    store.replace(checked_at, services)
