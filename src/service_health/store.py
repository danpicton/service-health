"""Persistent snapshots consumed by the read-only HTTP application."""

import fcntl
import json
import sqlite3
from contextlib import closing
from pathlib import Path

_DETAIL_KEYS = frozenset(("scan_findings", "advisory_findings", "confirmed_findings"))


def _decode_service(service):
    # Older caches used rebuild wording for every platform digest change.
    for component in service.get("components", []):
        for item in [component, *component.get("deployments", [])]:
            if item.get("image_status") == "image rebuild available":
                item["image_status"] = "image update available"
    if service.get("image_status") == "image rebuild available":
        service["image_status"] = "image update available"
    return service


def _compact(value):
    if isinstance(value, dict):
        compact = {
            key: _compact(item)
            for key, item in value.items()
            if key not in _DETAIL_KEYS
        }
        if "confirmed_findings" in value:
            compact["confirmed_finding_count"] = len(value["confirmed_findings"])
        return compact
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def _identities(services):
    """The observed pod facts that a collector must never put back in time."""
    deployment_fields = (
        "namespace",
        "pod",
        "node",
        "container",
        "kind",
        "image",
        "configured_image",
        "image_id",
        "digest",
        "platform",
        "application_version",
        "state",
    )
    return {
        service["id"]: (
            service.get("name"),
            service.get("current_version"),
            service.get("inventory_status"),
            {
                component["id"]: (
                    component.get("name"),
                    component.get("kind"),
                    component.get("current_version"),
                    component.get("version_evidence"),
                    component.get("version_source_identity"),
                    component.get("inventory_status"),
                    component.get("release_identity"),
                    component.get("advisory_source_identity"),
                    [
                        tuple(deployment.get(field) for field in deployment_fields)
                        for deployment in component.get("deployments", [])
                    ],
                )
                for component in service.get("components", [])
            },
        )
        for service in services
    }


def _observation_times(services):
    return [
        record["checked_at"]
        for service in services
        for component in service.get("components", [])
        for owner in [component, *component.get("deployments", [])]
        for record in owner.get("version_observations", [])
    ]


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            with connection:
                # Serialize schema inspection and changes across process startup.
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS snapshot ("
                    "id INTEGER PRIMARY KEY CHECK (id = 1), "
                    "checked_at TEXT NOT NULL, services_json TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS jobs ("
                    "name TEXT PRIMARY KEY, attempted_at TEXT NOT NULL, "
                    "succeeded_at TEXT, error TEXT, failures INTEGER NOT NULL)"
                )
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(jobs)")
                }
                if "state" not in columns:
                    connection.execute(
                        "ALTER TABLE jobs ADD COLUMN state TEXT NOT NULL "
                        "DEFAULT 'completed'"
                    )
                for column in ("next_full_at", "next_retry_at"):
                    if column not in columns:
                        connection.execute(f"ALTER TABLE jobs ADD COLUMN {column} TEXT")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS security_schedule ("
                    "name TEXT PRIMARY KEY CHECK (name = 'security'), "
                    "full_attempted_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS github_cache ("
                    "repository TEXT PRIMARY KEY, fetched_at TEXT, etag TEXT, "
                    "body_json TEXT, retry_at TEXT, "
                    "failures INTEGER NOT NULL DEFAULT 0)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS service_rows ("
                    "id TEXT PRIMARY KEY, position INTEGER NOT NULL, "
                    "detail_json TEXT NOT NULL, compact_json TEXT NOT NULL)"
                )
                # Upgrade old databases one service at a time. SQLite's json_each
                # avoids constructing the entire scan snapshot in the HTTP process.
                has_snapshot = connection.execute(
                    "SELECT 1 FROM snapshot WHERE id=1"
                ).fetchone()
                has_rows = connection.execute(
                    "SELECT 1 FROM service_rows LIMIT 1"
                ).fetchone()
                if has_snapshot and not has_rows:
                    rows = connection.execute(
                        "SELECT CAST(key AS INTEGER), value FROM snapshot, "
                        "json_each(snapshot.services_json) WHERE snapshot.id=1"
                    )
                    for position, detail_json in rows:
                        service = json.loads(detail_json)
                        connection.execute(
                            "INSERT INTO service_rows VALUES (?, ?, ?, ?)",
                            (
                                service["id"],
                                position,
                                detail_json,
                                json.dumps(_compact(service), allow_nan=False),
                            ),
                        )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def read(self) -> dict | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT checked_at, services_json FROM snapshot WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        return {
            "checked_at": row[0],
            "services": [_decode_service(s) for s in json.loads(row[1])],
        }

    def cache_state(self) -> str:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT 1 FROM snapshot WHERE id=1").fetchone()
        return "populated" if row else "empty"

    def read_compact(self) -> dict | None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT checked_at FROM snapshot WHERE id=1"
            ).fetchone()
            if row is None:
                return None
            services = [
                _decode_service(json.loads(item[0]))
                for item in connection.execute(
                    "SELECT compact_json FROM service_rows ORDER BY position"
                )
            ]
        return {"checked_at": row[0], "services": services}

    def read_service(self, service_id: str, compact: bool = False) -> dict | None:
        column = "compact_json" if compact else "detail_json"
        with closing(self._connect()) as connection:
            row = connection.execute(
                f"SELECT checked_at, {column} FROM snapshot JOIN service_rows "
                "ON snapshot.id=1 WHERE service_rows.id=?",
                (service_id,),
            ).fetchone()
        return (
            {"checked_at": row[0], "services": [_decode_service(json.loads(row[1]))]}
            if row
            else None
        )

    def replace(
        self, checked_at: str, services: list[dict], *, completed_job: str | None = None
    ) -> None:
        """Publish the snapshot and optional job success in one transaction."""
        ids = [service["id"] for service in services]
        if len(ids) != len(set(ids)):
            raise ValueError("service IDs must be unique")
        payload = json.dumps(services, allow_nan=False)
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO snapshot (id, checked_at, services_json) "
                    "VALUES (1, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET checked_at=excluded.checked_at, "
                    "services_json=excluded.services_json",
                    (checked_at, payload),
                )
                connection.execute("DELETE FROM service_rows")
                connection.executemany(
                    "INSERT INTO service_rows VALUES (?, ?, ?, ?)",
                    (
                        (
                            service["id"],
                            position,
                            json.dumps(service, allow_nan=False),
                            json.dumps(_compact(service), allow_nan=False),
                        )
                        for position, service in enumerate(services)
                    ),
                )
                if completed_job is not None:
                    self._record_job(
                        connection, completed_job, checked_at, None, "completed"
                    )

    def commit_evidence(self, checked_at: str, services: list[dict]) -> bool:
        """Publish checks onto the latest inventory, never onto older pod facts."""
        from service_health.inventory_refresh import merge_inventory

        lock_path = Path(str(self.path) + ".inventory.lock")
        with lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = self.read()
            if current is None:
                raise ValueError("collection requires a cached inventory")
            inventory_changed = _identities(current["services"]) != _identities(
                services
            )
            # A same-identity inventory refresh can advance observation times
            # while providers run. Keep the newer inventory in that case too.
            if inventory_changed or _observation_times(
                current["services"]
            ) != _observation_times(services):
                services = merge_inventory(
                    current["services"], services, restore_history=False
                )
            self.replace(checked_at, services)
            return inventory_changed

    def record_job(
        self,
        name: str,
        attempted_at: str,
        error: str | None,
        state="completed",
        *,
        security_deadlines: tuple[str | None, str | None] | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            with connection:
                self._record_job(connection, name, attempted_at, error, state)
                if security_deadlines is not None:
                    connection.execute(
                        "UPDATE jobs SET next_full_at=?, next_retry_at=? WHERE name=?",
                        (*security_deadlines, name),
                    )

    @staticmethod
    def _record_job(connection, name, attempted_at, error, state):
        connection.execute(
            "INSERT INTO jobs "
            "(name, attempted_at, succeeded_at, error, failures, state) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
            "attempted_at=excluded.attempted_at, "
            "succeeded_at=COALESCE(excluded.succeeded_at, jobs.succeeded_at), "
            "error=excluded.error, "
            "state=excluded.state, "
            "failures=CASE WHEN excluded.error IS NULL THEN 0 "
            "ELSE jobs.failures+1 END",
            (
                name,
                attempted_at,
                attempted_at if error is None and state == "completed" else None,
                error,
                0 if error is None else 1,
                state,
            ),
        )

    def start_job(
        self, name: str, attempted_at: str, *, full_attempted_at: str | None = None
    ) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO jobs (name, attempted_at, succeeded_at, "
                    "error, failures, state) VALUES (?, ?, NULL, NULL, 0, "
                    "'running') ON CONFLICT(name) DO UPDATE SET "
                    "attempted_at=excluded.attempted_at, error=NULL, state='running'",
                    (name, attempted_at),
                )
                if full_attempted_at is not None:
                    connection.execute(
                        "INSERT INTO security_schedule (name, full_attempted_at) "
                        "VALUES (?, ?) "
                        "ON CONFLICT(name) DO UPDATE SET "
                        "full_attempted_at=excluded.full_attempted_at",
                        (name, full_attempted_at),
                    )

    def read_github_cache(self, repository: str) -> dict | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT fetched_at, etag, body_json, retry_at, failures "
                "FROM github_cache WHERE repository=?",
                (repository,),
            ).fetchone()
        return (
            dict(zip(("fetched_at", "etag", "body_json", "retry_at", "failures"), row))
            if row
            else None
        )

    def write_github_cache(
        self,
        repository: str,
        fetched_at=None,
        etag=None,
        body_json=None,
        retry_at=None,
        failures=0,
    ) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO github_cache VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(repository) DO UPDATE SET "
                    "fetched_at=excluded.fetched_at, "
                    "etag=excluded.etag, body_json=excluded.body_json, "
                    "retry_at=excluded.retry_at, failures=excluded.failures",
                    (repository, fetched_at, etag, body_json, retry_at, failures),
                )

    def read_jobs(self) -> dict:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT name, attempted_at, succeeded_at, error, "
                "failures, state, full_attempted_at, next_full_at, next_retry_at "
                "FROM jobs "
                "LEFT JOIN security_schedule USING (name)"
            ).fetchall()
        jobs = {}
        for row in rows:
            (
                name,
                attempted,
                succeeded,
                error,
                failures,
                state,
                full,
                next_full,
                retry,
            ) = row
            jobs[name] = {
                "attempted_at": attempted,
                "succeeded_at": succeeded,
                "error": error,
                "failures": failures,
                "state": state,
                **({"full_attempted_at": full} if full is not None else {}),
                **(
                    {"next_full_at": next_full, "next_retry_at": retry}
                    if next_full is not None or retry is not None
                    else {}
                ),
            }
        if any(job["state"] == "running" for job in jobs.values()):
            lock_path = Path(str(self.path) + ".collection.lock")
            if lock_path.exists():
                with lock_path.open("r") as lock:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        for job in jobs.values():
                            if job["state"] == "running":
                                job["state"] = "interrupted"
                                job["error"] = (
                                    "collection interrupted; completed checks retained"
                                )
                        fcntl.flock(lock, fcntl.LOCK_UN)
        return jobs
