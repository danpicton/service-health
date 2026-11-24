"""Run Trivy with bounded stderr capture and an allowlist of public diagnostics."""

import os
import re
import selectors
import subprocess
import time

from service_health.security_outcomes import SecurityCheckError, SecurityOutcome

_STDERR_TAIL_BYTES = 16 * 1024


class TrivyFailure(SecurityCheckError):
    def __init__(self, outcome, reason, detail, phase, exit_status):
        status = "" if exit_status is None else f" (exit {exit_status})"
        super().__init__(outcome, reason, f"Trivy {phase}{status}: {detail}")
        self.phase = phase
        self.exit_status = exit_status


# Only fixed text may leave the adapter. Raw stderr can contain signed URLs,
# arbitrary command arguments, environment dumps, or unlabelled credential values.
_CAUSES = (
    (
        r"\b(unauthorized|authentication required|denied: requested access"
        r"|401 unauthorized|403 forbidden|(?:http|status code)[: ]+(?:401|403))\b",
        SecurityOutcome.ACCESS_REQUIRED,
        "authentication_denied",
        "Access denied",
    ),
    (
        r"\b(toomanyrequests|too many requests|rate limit exceeded"
        r"|(?:http|status code)[: ]+429)\b",
        SecurityOutcome.TRANSIENT_FAILURE,
        "rate_limited",
        "Rate limit reached",
    ),
    (
        r"\b(manifest_unknown|manifest unknown|name_unknown)\b",
        SecurityOutcome.UNAVAILABLE,
        "manifest_unavailable",
        "Manifest unavailable",
    ),
    (
        r"\b(unsupported (image|media type|platform)|no matching manifest"
        r"|no child with platform|no match for platform)\b",
        SecurityOutcome.UNSUPPORTED,
        "unsupported_image",
        "Unsupported image or platform",
    ),
    (
        r"\b(context deadline exceeded|i/o timeout|timed out)\b",
        SecurityOutcome.TRANSIENT_FAILURE,
        "provider_timeout",
        "Operation timed out",
    ),
    (
        r"\b(connection (reset by peer|refused)|network is unreachable"
        r"|temporary failure in name resolution|tls handshake timeout)\b",
        SecurityOutcome.TRANSIENT_FAILURE,
        "network_failure",
        "Network request failed",
    ),
    (
        r"\b(database disk image is malformed|database is corrupted"
        r"|invalid database schema)\b",
        SecurityOutcome.UNAVAILABLE,
        "database_invalid",
        "Scanner database is invalid",
    ),
    (
        r"\b(no space left on device|out of memory|image size exceeds)\b",
        SecurityOutcome.UNAVAILABLE,
        "resource_limit",
        "Resource limit reached",
    ),
)


def _command_failure(stderr, phase, status):
    message = stderr.decode("utf-8", errors="replace").lower()
    if phase == "scan" and re.search(
        r"manifest_unknown|manifest unknown|no matching manifest|no child with platform"
        r"|unable to pull|failed to (pull|fetch the image)|remote error:|/v2/",
        message,
    ):
        phase = "image_pull"
    matches = [
        (outcome, reason, detail)
        for pattern, outcome, reason, detail in _CAUSES
        if re.search(pattern, message)
    ]
    if len(matches) == 1:
        return TrivyFailure(*matches[0], phase, status)
    return TrivyFailure(
        SecurityOutcome.UNKNOWN_FAILURE,
        "trivy_failed",
        "Command failed with no unambiguous cause",
        phase,
        status,
    )


def run_trivy(command, phase, timeout):
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except OSError:
        raise TrivyFailure(
            SecurityOutcome.UNAVAILABLE,
            "scanner_unavailable",
            "Could not start scanner",
            phase,
            None,
        ) from None
    tail = bytearray()
    with process, selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError
                chunk = os.read(process.stderr.fileno(), _STDERR_TAIL_BYTES)
                if not chunk:
                    break
                tail.extend(chunk)
                del tail[:-_STDERR_TAIL_BYTES]
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired):
            process.kill()
            status = process.wait()
            raise TrivyFailure(
                SecurityOutcome.TRANSIENT_FAILURE,
                "provider_timeout",
                "Scanner exceeded its deadline",
                phase,
                status,
            ) from None
    if status:
        raise _command_failure(tail, phase, status)
