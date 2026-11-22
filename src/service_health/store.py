"""Persistent snapshots consumed by the read-only HTTP application."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            with connection:
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

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def read(self) -> dict | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT checked_at, services_json FROM snapshot WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        return {"checked_at": row[0], "services": json.loads(row[1])}

    def replace(self, checked_at: str, services: list[dict]) -> None:
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

    def record_job(self, name: str, attempted_at: str, error: str | None) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO jobs "
                    "(name, attempted_at, succeeded_at, error, failures) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                    "attempted_at=excluded.attempted_at, "
                    "succeeded_at=CASE WHEN excluded.error IS NULL "
                    "THEN excluded.succeeded_at ELSE jobs.succeeded_at END, "
                    "error=excluded.error, "
                    "failures=CASE WHEN excluded.error IS NULL THEN 0 "
                    "ELSE jobs.failures+1 END",
                    (
                        name,
                        attempted_at,
                        attempted_at if error is None else None,
                        error,
                        0 if error is None else 1,
                    ),
                )

    def read_jobs(self) -> dict:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT name, attempted_at, succeeded_at, error, failures FROM jobs"
            ).fetchall()
        return {
            name: {
                "attempted_at": attempted,
                "succeeded_at": succeeded,
                "error": error,
                "failures": failures,
            }
            for name, attempted, succeeded, error, failures in rows
        }
