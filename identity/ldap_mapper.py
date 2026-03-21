"""LDAP-specific identity-to-role mapping helpers.

This module isolates LDAP group distinguished-name mapping from the generic
identity-mapper facade so future LDAP-specific rules can evolve without
mixing with Entra claim translation logic.
"""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.identity.models import (
    ExternalIdentity,
    RoleMappingResult,
)
from rbac_providers_auth_manager.core.util import canonicalize_dn


class LdapIdentityMapper:
    """Translate LDAP group distinguished names into Airflow role sets."""

    def __init__(self, manager: Any) -> None:
        self._manager = manager

    def map_identity(
        self,
        *,
        identity: ExternalIdentity,
        ip_address: str,
    ) -> RoleMappingResult:
        """Return mapped Airflow roles for a normalized LDAP identity."""
        cfg = self._manager._cfg_loader.get_config()
        policy = self._manager._policy
        if policy is None:
            raise RuntimeError(
                "LDAP identity mapping requires an initialized authorization policy"
            )

        mapping_hits: list[tuple[str, tuple[str, ...]]] = []
        roles_raw: set[str] = set()

        for dn in identity.group_dns:
            canonical_dn = canonicalize_dn(dn)
            if not canonical_dn:
                continue

            mapped = cfg.role_mapping.dn_to_roles.get(canonical_dn)
            if not mapped:
                continue

            resolved = tuple(sorted(mapped))
            mapping_hits.append((canonical_dn, resolved))
            roles_raw.update(resolved)

        roles = policy.map_dns_to_roles(identity.group_dns)
        defined_roles = set(cfg.roles.role_to_permissions.keys())
        dropped = (
            sorted(role for role in roles_raw if role not in defined_roles)
            if cfg.general.strict_permissions
            else []
        )

        if not roles:
            self._manager._audit_service.log_role_mapping_empty(
                provider="ldap",
                principal=identity.username,
                subject=identity.user_id,
                ip_address=ip_address,
                external_values_count=len(identity.group_dns),
                mapped_values_count=len(mapping_hits),
                strict_permissions=bool(cfg.general.strict_permissions),
                deny_if_no_roles=bool(cfg.general.deny_if_no_roles),
            )
            self._manager._log_sensitive_values(
                label="LDAP groups",
                principal=identity.username,
                values=list(identity.group_dns),
            )
            self._manager._audit_service.log_mapping_hits(
                provider="ldap",
                principal=identity.username,
                mapping_hits=[(key, list(values)) for key, values in mapping_hits],
            )
            if dropped:
                self._manager._audit_service.log_dropped_roles(
                    provider="ldap",
                    principal=identity.username,
                    dropped_roles=dropped,
                    strict_mode=True,
                )
            roles = self._manager._apply_default_role_if_allowed(
                principal=identity.username,
                subject=identity.user_id,
                ip_address=ip_address,
            )

        self._manager._audit_service.log_provider_success(
            provider="ldap",
            principal=identity.username,
            subject=identity.user_id,
            ip_address=ip_address,
            roles=sorted(roles),
            external_values_count=len(identity.group_dns),
            mapped_values_count=len(mapping_hits),
            strict_permissions=bool(cfg.general.strict_permissions),
        )
        if dropped:
            self._manager._audit_service.log_dropped_roles(
                provider="ldap",
                principal=identity.username,
                dropped_roles=dropped,
                strict_mode=True,
            )

        self._manager._log_sensitive_values(
            label="LDAP groups",
            principal=identity.username,
            values=list(identity.group_dns),
        )
        self._manager._audit_service.log_mapping_hits(
            provider="ldap",
            principal=identity.username,
            mapping_hits=[(key, list(values)) for key, values in mapping_hits],
        )
        self._manager._debug_log_role_permissions(
            username=identity.username, roles=sorted(roles)
        )
        return RoleMappingResult(
            roles=tuple(sorted(roles)),
            dropped_roles=tuple(dropped),
            mapping_hits=tuple(mapping_hits),
            external_values_count=len(identity.group_dns),
            mapped_values_count=len(mapping_hits),
        )
