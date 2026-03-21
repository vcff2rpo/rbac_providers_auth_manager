"""LDAP connection, bind, search, and nested-group helpers.

This module owns python-ldap loading and wire operations so the LDAP client
facade can stay small and easier to reason about.
"""

from __future__ import annotations

import importlib
import logging
import threading
from functools import lru_cache
from typing import Any

from rbac_providers_auth_manager.config import LdapConfig
from rbac_providers_auth_manager.core.exceptions import (
    LdapAuthError,
    OptionalProviderDependencyError,
)
from rbac_providers_auth_manager.core.util import dedupe_preserve_order
from rbac_providers_auth_manager.providers.ldap_identity_service import decode

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_python_ldap() -> tuple[Any, Any]:
    """Return the lazily imported python-ldap modules required at runtime."""
    try:
        ldap_module = importlib.import_module("ldap")
        ldap_filter_module = importlib.import_module("ldap.filter")
    except (
        ModuleNotFoundError
    ) as exc:  # pragma: no cover - depends on deployment extras
        raise OptionalProviderDependencyError(
            "LDAP authentication requires the optional python-ldap dependency to be installed."
        ) from exc
    return ldap_module, ldap_filter_module.escape_filter_chars


def ldap_module() -> Any:
    """Return the lazily imported top-level ``ldap`` module."""
    return load_python_ldap()[0]


def escape_filter_chars(value: str) -> str:
    """Escape LDAP filter characters using the lazily imported helper."""
    return load_python_ldap()[1](value)


class LdapConnectionService:
    """Own LDAP connection and search behavior for a configured client."""

    _tls_lock = threading.Lock()

    def __init__(self, cfg: LdapConfig) -> None:
        self.cfg = cfg

    def reconfigure(self, cfg: LdapConfig) -> None:
        """Replace the active LDAP configuration."""
        self.cfg = cfg

    def format_user_dn(self, username: str) -> str:
        """Render the direct-bind DN for a username."""
        format_string = (self.cfg.username_dn_format or "").strip()
        if not format_string:
            raise LdapAuthError("username_dn_format not configured")
        try:
            return format_string % username
        except Exception as exc:  # noqa: BLE001
            raise LdapAuthError("Invalid username_dn_format") from exc

    def configure_tls_options(self) -> None:
        """Apply global python-ldap TLS settings for the current config."""
        ldap = ldap_module()
        policy = (self.cfg.tls_require_cert or "").strip().lower()
        if not policy:
            policy = "never" if self.cfg.allow_self_signed else "demand"

        mapping = {
            "never": ldap.OPT_X_TLS_NEVER,
            "allow": ldap.OPT_X_TLS_ALLOW,
            "try": ldap.OPT_X_TLS_TRY,
            "demand": ldap.OPT_X_TLS_DEMAND,
            "hard": ldap.OPT_X_TLS_HARD,
        }
        ldap.set_option(
            ldap.OPT_X_TLS_REQUIRE_CERT, mapping.get(policy, ldap.OPT_X_TLS_DEMAND)
        )

        if self.cfg.tls_ca_cert_file:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self.cfg.tls_ca_cert_file)

    def connect(self) -> Any:
        """Create and configure a new LDAP connection object."""
        if self.cfg.uri.lower().startswith("ldaps://") or self.cfg.start_tls:
            with self._tls_lock:
                self.configure_tls_options()

        ldap = ldap_module()
        conn = ldap.initialize(self.cfg.uri)
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_REFERRALS, 1 if self.cfg.chase_referrals else 0)

        try:
            conn.set_option(
                ldap.OPT_NETWORK_TIMEOUT, float(self.cfg.network_timeout_seconds)
            )
        except Exception:  # noqa: BLE001
            log.debug(
                "LDAP library does not accept network timeout option", exc_info=True
            )
        try:
            conn.set_option(ldap.OPT_TIMEOUT, float(self.cfg.operation_timeout_seconds))
        except Exception:  # noqa: BLE001
            log.debug(
                "LDAP library does not accept operation timeout option", exc_info=True
            )
        try:
            conn.set_option(
                ldap.OPT_CONNECT_TIMEOUT, int(self.cfg.connect_timeout_seconds)
            )
        except Exception:  # noqa: BLE001
            log.debug(
                "LDAP library does not accept connect timeout option", exc_info=True
            )

        if self.cfg.start_tls:
            try:
                conn.start_tls_s()
            except ldap.LDAPError:
                log.exception("LDAP startTLS failed")
                raise

        return conn

    def bind_service(self, conn: Any) -> None:
        """Bind with the optional LDAP service account."""
        if not self.cfg.bind_dn:
            return

        ldap = ldap_module()
        try:
            conn.simple_bind_s(self.cfg.bind_dn, self.cfg.bind_password or "")
        except ldap.LDAPError as exc:
            raise LdapAuthError("Service bind failed") from exc

    def attrlist(self) -> list[str]:
        """Return the minimal attribute list needed by this plugin."""
        return [
            self.cfg.attr_uid,
            self.cfg.attr_username,
            self.cfg.attr_first_name,
            self.cfg.attr_last_name,
            self.cfg.attr_email,
            self.cfg.group_attribute,
        ]

    def augment_group_attrs(
        self,
        conn: Any,
        *,
        user_dn: str,
        attrs: dict[str, list[bytes]],
    ) -> dict[str, list[bytes]]:
        """Optionally add nested LDAP/AD groups to the returned attributes."""
        if not self.cfg.resolve_nested_groups:
            return attrs

        nested_dns = self.resolve_nested_group_dns(conn, user_dn=user_dn)
        if not nested_dns:
            return attrs

        merged_attrs = dict(attrs)
        direct_groups = [
            decode(value)
            for value in (merged_attrs.get(self.cfg.group_attribute) or [])
            if decode(value)
        ]
        all_groups = dedupe_preserve_order([*direct_groups, *nested_dns])
        merged_attrs[self.cfg.group_attribute] = [
            group.encode("utf-8") for group in all_groups
        ]
        return merged_attrs

    def resolve_nested_group_dns(self, conn: Any, *, user_dn: str) -> list[str]:
        """Resolve nested group memberships using the configured LDAP match rule."""
        ldap = ldap_module()
        if not self.cfg.resolve_nested_groups:
            return []

        base_dn = (
            self.cfg.nested_groups_base_dn
            or self.cfg.search_base
            or self.cfg.user_base_dn
        )
        match_rule = (self.cfg.nested_group_match_rule or "").strip()
        if not base_dn or not match_rule:
            return []

        safe_user_dn = escape_filter_chars(user_dn)
        group_filter = f"(&(objectClass=group)(member:{match_rule}:={safe_user_dn}))"

        try:
            results = conn.search_ext_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                group_filter,
                ["distinguishedName"],
                0,
                None,
                None,
                int(self.cfg.search_time_limit_seconds),
                int(self.cfg.size_limit) if self.cfg.size_limit else 0,
            )
        except ldap.LDAPError:
            log.debug(
                "Nested group resolution failed or is unsupported by the LDAP server",
                exc_info=True,
            )
            return []

        nested_dns: list[str] = []
        for dn, _ in results:
            if dn:
                nested_dns.append(str(dn))
        return dedupe_preserve_order(nested_dns)

    def fetch_user_attrs(
        self,
        conn: Any,
        *,
        username: str,
        user_dn: str,
    ) -> dict[str, list[bytes]]:
        """Fetch attributes for an authenticated user."""
        ldap = ldap_module()

        attrs = self.attrlist()

        try:
            result = conn.search_ext_s(
                user_dn,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                attrs,
                0,
                None,
                None,
                int(self.cfg.search_time_limit_seconds),
                1,
            )
            if (
                result
                and isinstance(result[0], tuple)
                and isinstance(result[0][1], dict)
            ):
                data = result[0][1]
                if data:
                    return data
        except ldap.LDAPError:
            pass

        search_base = self.cfg.search_base or self.cfg.user_base_dn
        if not search_base:
            return {}

        try:
            _, data = self.search_user(conn, username=username, base_dn=search_base)
            return data
        except Exception:  # noqa: BLE001
            return {}

    def search_user(
        self,
        conn: Any,
        *,
        username: str,
        base_dn: str | None = None,
    ) -> tuple[str, dict[str, list[bytes]]]:
        """Search for a user entry and return its DN and attributes."""
        ldap = ldap_module()
        search_base = base_dn or self.cfg.user_base_dn or self.cfg.search_base
        if not search_base:
            raise LdapAuthError("Search base is not configured")

        safe_username = escape_filter_chars(username)
        user_filter = (self.cfg.user_filter or "").format(username=safe_username)

        try:
            results = conn.search_ext_s(
                search_base,
                ldap.SCOPE_SUBTREE,
                user_filter,
                self.attrlist(),
                0,
                None,
                None,
                int(self.cfg.search_time_limit_seconds),
                int(self.cfg.size_limit) if self.cfg.size_limit else 0,
            )
        except ldap.LDAPError as exc:
            raise LdapAuthError("LDAP search failed") from exc

        for dn, data in results:
            if dn and isinstance(data, dict):
                return str(dn), data

        raise LdapAuthError("User not found")
