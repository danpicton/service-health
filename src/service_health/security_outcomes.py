"""Classify provider checks separately from coverage and cached evidence."""

from enum import StrEnum
from socket import EAI_AGAIN, gaierror
from subprocess import TimeoutExpired
from urllib.error import HTTPError, URLError


class SecurityOutcome(StrEnum):
    SUCCESS = "success"
    TRANSIENT_FAILURE = "transient_failure"
    ACCESS_REQUIRED = "access_required"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    UNKNOWN_FAILURE = "unknown_failure"


class SecurityCheckError(RuntimeError):
    """An adapter's classified coverage gap or provider failure."""

    def __init__(self, outcome: SecurityOutcome, reason: str, message: str):
        super().__init__(message)
        self.outcome = outcome
        self.reason = reason

    @property
    def coverage(self):
        if self.outcome in (
            SecurityOutcome.ACCESS_REQUIRED,
            SecurityOutcome.UNSUPPORTED,
            SecurityOutcome.UNAVAILABLE,
        ):
            return "missing"
        return "failed"


def provider_failure(error: Exception) -> SecurityCheckError:
    if isinstance(error, SecurityCheckError):
        return error
    if isinstance(error, HTTPError):
        code = error.code
        if code in (401, 403):
            return SecurityCheckError(
                SecurityOutcome.ACCESS_REQUIRED,
                "provider_access_required",
                f"Provider access denied (HTTP {code})",
            )
        if code in (404, 410):
            return SecurityCheckError(
                SecurityOutcome.UNAVAILABLE,
                "provider_resource_unavailable",
                f"Provider resource unavailable (HTTP {code})",
            )
        if code in (408, 429) or 500 <= code < 600:
            return SecurityCheckError(
                SecurityOutcome.TRANSIENT_FAILURE,
                "provider_http_failure",
                f"Provider returned HTTP {code}",
            )
    cause = error.reason if isinstance(error, URLError) else error
    if isinstance(cause, (TimeoutError, TimeoutExpired)):
        return SecurityCheckError(
            SecurityOutcome.TRANSIENT_FAILURE, "provider_timeout", "Provider timed out"
        )
    if isinstance(cause, ConnectionError):
        return SecurityCheckError(
            SecurityOutcome.TRANSIENT_FAILURE,
            "provider_connection_failed",
            "Could not connect to provider",
        )
    if isinstance(cause, gaierror) and cause.errno == EAI_AGAIN:
        return SecurityCheckError(
            SecurityOutcome.TRANSIENT_FAILURE,
            "provider_dns_unavailable",
            "Provider DNS is temporarily unavailable",
        )
    return SecurityCheckError(
        SecurityOutcome.UNKNOWN_FAILURE,
        "provider_failed",
        "Provider check failed for an unknown reason",
    )
