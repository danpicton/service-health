"""Persistent, credential-free GitHub release response cache and rate-limit gate."""

import json
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _date(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class GitHubReleases:
    def __init__(
        self,
        store,
        token_file=None,
        clock=lambda: datetime.now(timezone.utc),
        ttl=21600,
        opener=urlopen,
    ):
        self.store = store
        self.token_file = Path(token_file) if token_file else None
        self.clock = clock
        self.ttl = ttl
        self.opener = opener
        self.memo = {}

    def __call__(self, source):
        from service_health.releases import _repository

        repository = _repository(source)
        if repository in self.memo:
            result = self.memo[repository]
            if isinstance(result, Exception):
                raise result
            return result
        try:
            result = self._fetch(repository)
        except (OSError, ValueError, RuntimeError) as error:
            self.memo[repository] = error
            raise
        self.memo[repository] = result
        return result

    def _fetch(self, repository):
        now = self.clock().astimezone(timezone.utc)
        cache = self.store.read_github_cache(repository) or {}
        global_limit = self.store.read_github_cache("__global__") or {}
        if global_limit.get("retry_at") and now < _date(global_limit["retry_at"]):
            raise RuntimeError(
                "GitHub rate limited; retry after " + global_limit["retry_at"]
            )
        if cache.get("retry_at") and now < _date(cache["retry_at"]):
            raise RuntimeError("GitHub rate limited; retry after " + cache["retry_at"])
        if (
            cache.get("body_json")
            and cache.get("fetched_at")
            and (now - _date(cache["fetched_at"])).total_seconds() < self.ttl
        ):
            return json.loads(cache["body_json"])
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "service-health",
        }
        if cache.get("etag"):
            headers["If-None-Match"] = cache["etag"]
        if self.token_file:
            token = self.token_file.read_text(encoding="utf-8").strip()
            if not token or "\n" in token or "\r" in token:
                raise ValueError("GitHub token file is empty or invalid")
            headers["Authorization"] = "Bearer " + token
        request = Request(
            "https://api.github.com/repos/"
            + quote(repository, safe="/")
            + "/releases?per_page=100",
            headers=headers,
        )
        try:
            with self.opener(request, timeout=10) as response:
                body = json.load(response)
                etag = response.headers.get("ETag")
        except HTTPError as error:
            if error.code == 304 and cache.get("body_json"):
                self.store.write_github_cache(
                    repository, _stamp(now), cache.get("etag"), cache["body_json"]
                )
                return json.loads(cache["body_json"])
            if error.code in (403, 429) and (
                error.code == 429
                or error.headers.get("X-RateLimit-Remaining") == "0"
                or bool(error.headers.get("Retry-After"))
            ):
                retry = self._retry_at(now, error.headers, cache.get("failures", 0))
                self.store.write_github_cache(
                    repository,
                    cache.get("fetched_at"),
                    cache.get("etag"),
                    cache.get("body_json"),
                    _stamp(retry),
                    cache.get("failures", 0) + 1,
                )
                self.store.write_github_cache(
                    "__global__",
                    retry_at=_stamp(retry),
                    failures=global_limit.get("failures", 0) + 1,
                )
                raise RuntimeError(
                    "GitHub rate limited; retry after " + _stamp(retry)
                ) from None
            if error.code in (401, 403):
                raise RuntimeError(
                    "GitHub authentication required or access denied"
                ) from None
            raise RuntimeError(f"GitHub HTTP {error.code}") from None
        except OSError:
            raise RuntimeError("GitHub request failed") from None
        if not isinstance(body, list):
            raise ValueError("release response must be an array")
        self.store.write_github_cache(
            repository, _stamp(now), etag, json.dumps(body, allow_nan=False)
        )
        return body

    @staticmethod
    def _retry_at(now, headers, failures):
        delay = min(3600, 60 * 2 ** min(failures, 6))
        value = headers.get("Retry-After")
        if value:
            try:
                delay = float(value)
            except ValueError:
                try:
                    delay = (parsedate_to_datetime(value) - now).total_seconds()
                except (TypeError, ValueError, OverflowError):
                    pass
        elif headers.get("X-RateLimit-Reset"):
            try:
                delay = float(headers["X-RateLimit-Reset"]) - now.timestamp()
            except ValueError:
                pass
        return now + timedelta(seconds=max(60, min(3600, delay)))
