"""Small, dependency-free helper utilities used across the plugin.

The helpers in this module are intentionally generic and side-effect free. They
are used by configuration loading, request handling, RBAC mapping, and proxy
awareness code paths.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

_BOOLEAN_TRUE_VALUES = {"1", "true", "yes", "on"}
_DN_WHITESPACE_RE = re.compile(r"\s+")
_LINE_CONTINUATION_RE = re.compile(r"(?m)\\\s*$")


def parse_bool(value: str, default: bool = False) -> bool:
    """Parse a boolean-like string into a Python ``bool``.

    The parser is intentionally conservative: only a short allow-list of truthy
    values is accepted and everything else is treated as ``False`` unless the
    input is blank, in which case ``default`` is returned.

    Args:
        value: Raw text value.
        default: Value returned for empty or whitespace-only input.

    Returns:
        Parsed boolean value.
    """
    raw = (value or "").strip().lower()
    if not raw:
        return default
    return raw in _BOOLEAN_TRUE_VALUES


def parse_csv(value: str) -> list[str]:
    """Parse a comma-separated list while tolerating INI line continuations.

    This helper is intended for non-DN values such as lists of RBAC resources.
    LDAP DNs are *not* handled here because commas are part of the DN syntax.

    Args:
        value: Raw comma-separated text from ``permissions.ini``.

    Returns:
        A list of non-empty, stripped tokens in source order.
    """
    if not value:
        return []

    normalized = value.replace("\\\r\n", "\n").replace("\\\n", "\n")
    normalized = _LINE_CONTINUATION_RE.sub("", normalized)
    return [token.strip() for token in normalized.split(",") if token.strip()]


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    """Remove duplicates while preserving input order.

    Args:
        values: Iterable of string values.

    Returns:
        A list containing the first occurrence of each unique value.
    """
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique_values.append(value)
    return unique_values


def canonicalize_dn(dn: str) -> str:
    """Return a stable, comparison-friendly representation of an LDAP DN.

    The normalization is intentionally conservative and avoids full RFC4514
    parsing. It focuses on the forms of variation that matter most for config
    lookups in this plugin:

    - leading/trailing whitespace
    - whitespace around ``,`` and ``=`` separators
    - repeated internal whitespace
    - case-insensitive comparisons

    Args:
        dn: Raw distinguished name.

    Returns:
        Canonicalized DN suitable for dictionary keys and comparisons.
    """
    raw = (dn or "").strip()
    if not raw:
        return ""

    raw = re.sub(r"\s*,\s*", ",", raw)
    raw = re.sub(r"\s*=\s*", "=", raw)
    raw = _DN_WHITESPACE_RE.sub(" ", raw)
    return raw.casefold()


def ip_in_trusted_proxies(client_ip: str, trusted: Iterable[str]) -> bool:
    """Return whether ``client_ip`` matches any trusted proxy entry.

    ``trusted`` may contain single IP addresses or CIDR ranges. Invalid values
    are ignored deliberately so that configuration mistakes fail closed.

    Args:
        client_ip: Remote client IP to evaluate.
        trusted: Iterable of single-IP or CIDR entries.

    Returns:
        ``True`` when the IP matches at least one trusted entry, otherwise
        ``False``.
    """
    if not client_ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for entry in trusted:
        raw = (entry or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                if ip_obj in ipaddress.ip_network(raw, strict=False):
                    return True
            elif ip_obj == ipaddress.ip_address(raw):
                return True
        except ValueError:
            continue
    return False
