"""URL security helpers for provider metadata validation."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit


def is_https_url(url: str, *, allowed_hosts: Iterable[str] | None = None) -> bool:
    """Return whether a URL is HTTPS and optionally host-allowlisted."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False

    if parts.scheme.lower() != "https" or not parts.netloc:
        return False

    if allowed_hosts is None:
        return True

    host = (parts.hostname or "").lower()
    allowed = {
        entry.lower().strip() for entry in allowed_hosts if entry and entry.strip()
    }
    return host in allowed
