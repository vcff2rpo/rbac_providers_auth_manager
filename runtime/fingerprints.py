"""Fingerprint helpers for logging sensitive values safely."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable


def fingerprint_text(value: str, *, prefix_len: int = 12) -> str:
    """Return a short stable fingerprint for a sensitive value."""
    digest = hashlib.sha256((value or "").encode("utf-8")).hexdigest()
    return digest[:prefix_len]


def fingerprint_values(
    values: Iterable[str],
    *,
    prefix_len: int = 12,
    max_items: int = 20,
) -> list[str]:
    """Return short stable fingerprints for a collection of sensitive values."""
    fingerprints: list[str] = []
    for index, item in enumerate(values):
        if index >= max_items:
            fingerprints.append(f"...(+{index - max_items + 1} more)")
            break
        fingerprints.append(fingerprint_text(str(item), prefix_len=prefix_len))
    return fingerprints
