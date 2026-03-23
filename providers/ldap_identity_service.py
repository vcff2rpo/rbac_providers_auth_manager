"""LDAP identity normalization helpers.

This module owns username validation, LDAP attribute decoding, and normalized
identity construction so the LDAP client facade can stay focused on request
orchestration instead of raw attribute parsing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from rbac_providers_auth_manager.config import LdapConfig
from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.core.util import dedupe_preserve_order
from rbac_providers_auth_manager.runtime.security import fingerprint_values

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LdapUserInfo:
    """Normalized identity information returned from LDAP."""

    user_id: str
    username: str
    login: str
    user_dn: str
    uid: str
    first_name: str | None
    last_name: str | None
    display_name: str
    email: str | None
    group_dns: list[str]


def decode(value: object) -> str:
    """Decode an LDAP result value into a stripped string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def decode_first(attrs: dict[str, list[bytes]], key: str) -> str:
    """Return the first decoded value for an LDAP attribute."""
    values = attrs.get(key) or []
    if not values:
        return ""
    return decode(values[0])


def decode_many(attrs: dict[str, list[bytes]], key: str) -> list[str]:
    """Return all decoded non-empty values for an LDAP attribute."""
    decoded: list[str] = []
    for value in attrs.get(key) or []:
        item = decode(value)
        if item:
            decoded.append(item)
    return decoded


def contains_control_characters(value: str) -> bool:
    """Return whether a username contains control characters."""
    return any(ord(char) < 32 for char in value)


def validate_username(*, username: str, pattern: str | None, max_length: int) -> str:
    """Validate and normalize the supplied LDAP username."""
    normalized = (username or "").strip()
    if not normalized:
        raise LdapAuthError("Missing username")
    if len(normalized) > max(1, int(max_length)):
        raise LdapAuthError("Invalid username format")
    if contains_control_characters(normalized):
        raise LdapAuthError("Invalid username format")
    if pattern:
        try:
            if re.fullmatch(pattern, normalized) is None:
                raise LdapAuthError("Invalid username format")
        except re.error as exc:
            raise LdapAuthError("Invalid LDAP username_pattern") from exc
    return normalized


def build_user_info(
    *,
    cfg: LdapConfig,
    username: str,
    user_dn: str,
    attrs: dict[str, list[bytes]],
) -> LdapUserInfo:
    """Convert LDAP attributes into the plugin's normalized identity model."""
    login = username
    uid = decode_first(attrs, cfg.attr_uid)
    resolved_username = decode_first(attrs, cfg.attr_username)

    canonical_username = resolved_username or login
    stable_user_id = uid or canonical_username or login

    first_name = decode_first(attrs, cfg.attr_first_name) or None
    last_name = decode_first(attrs, cfg.attr_last_name) or None
    email = decode_first(attrs, cfg.attr_email) or None

    if first_name and last_name:
        display_name = f"{first_name} {last_name}".strip()
    else:
        display_name = (first_name or last_name or "").strip() or canonical_username

    groups = dedupe_preserve_order(decode_many(attrs, cfg.group_attribute))

    log.debug(
        "LDAP user resolved login=%s user_dn=%s user_id=%s username=%s groups=%d",
        login,
        user_dn,
        stable_user_id,
        canonical_username,
        len(groups),
    )
    log.debug(
        "LDAP group_dns fingerprints login=%s: %s",
        login,
        fingerprint_values(groups),
    )

    return LdapUserInfo(
        user_id=stable_user_id,
        username=canonical_username,
        login=login,
        user_dn=user_dn,
        uid=uid or stable_user_id,
        first_name=first_name,
        last_name=last_name,
        display_name=display_name,
        email=email,
        group_dns=groups,
    )
