"""Shared low-level helpers for parsing ``permissions.ini``."""

from __future__ import annotations

import configparser
import os
import re
from pathlib import Path

from rbac_providers_auth_manager.core.util import parse_bool

_DN_HINT_RE = re.compile(r"\b(dc|ou|cn)\s*=", re.IGNORECASE)


def default_permissions_path() -> Path:
    """Return the default packaged or local ``permissions.ini`` path."""
    module_dir = Path(__file__).resolve().parent
    packaged = module_dir / "permissions.ini"
    if packaged.exists():
        return packaged

    airflow_home = os.environ.get("AIRFLOW_HOME")
    if airflow_home:
        fallback = Path(airflow_home) / "permissions.ini"
        if fallback.exists():
            return fallback
        return fallback

    return packaged


def section_aliases(section: str) -> list[str]:
    """Return accepted section aliases for a logical configuration section."""
    normalized = (section or "").strip().lower()
    if normalized == "jwt_cookie":
        return ["jwt_cookie", "jwt"]
    if normalized == "ldap":
        return ["ldap"]
    if normalized == "entra_id":
        return ["entra_id", "azure", "azure_entra_id"]
    if normalized == "general":
        return ["general"]
    return [normalized]


def has_any_section(parser: configparser.ConfigParser, sections: list[str]) -> bool:
    """Return whether any alias section exists in the parser."""
    return any(parser.has_section(section) for section in sections)


def get_any(
    parser: configparser.ConfigParser,
    sections: list[str],
    keys: list[str],
    default: str | None = None,
) -> str | None:
    """Return the first non-empty value across section/key combinations."""
    for section in sections:
        if not parser.has_section(section):
            continue
        for key in keys:
            if parser.has_option(section, key):
                value = parser.get(section, key, fallback=default)
                if value is None:
                    continue
                stripped = value.strip()
                return stripped if stripped else default
    return default


def get_int(
    parser: configparser.ConfigParser,
    sections: list[str],
    keys: list[str],
    default: int,
) -> int:
    """Parse an integer setting with fallback to ``default``."""
    raw = get_any(parser, sections, keys, default=None)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def get_bool(
    parser: configparser.ConfigParser,
    sections: list[str],
    keys: list[str],
    default: bool,
) -> bool:
    """Parse a boolean setting with fallback to ``default``."""
    raw = get_any(parser, sections, keys, default=None)
    if raw is None:
        return default
    return parse_bool(raw, default=default)


def normalize_claim_value(value: str) -> str:
    """Normalize Azure group/role claim values for dictionary lookup."""
    return " ".join((value or "").strip().split()).casefold()


def looks_like_dn(value: str) -> bool:
    """Heuristic for distinguishing LDAP DNs from ordinary values."""
    if not value:
        return False
    return bool(_DN_HINT_RE.search(value)) and ("," in value)
