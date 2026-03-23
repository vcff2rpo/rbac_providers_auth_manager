"""Entra-specific identity-to-role mapping helpers.

This module isolates Entra claim-value mapping from the generic identity-
mapper facade so future Entra-specific claim selection or transformation rules
can evolve independently from LDAP mapping behavior.
"""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.identity.models import (
    ExternalIdentity,
    RoleMappingResult,
)


class EntraIdentityMapper:
    """Translate Entra role or group claim values into Airflow role sets."""

    def __init__(self, manager: Any) -> None:
        self._manager = manager

    def map_identity(
        self,
        *,
        identity: ExternalIdentity,
        ip_address: str,
    ) -> RoleMappingResult:
        """Return mapped Airflow roles for a normalized Entra identity."""
        cfg = self._manager._cfg_loader.get_config()

        mapping_hits: list[tuple[str, tuple[str, ...]]] = []
        roles_raw: set[str] = set()

        for value in identity.claim_values:
            normalized_value = self._manager._normalize_entra_claim_value(value)
            if not normalized_value:
                continue

            mapped = cfg.entra_role_mapping.claim_value_to_roles.get(normalized_value)
            if not mapped:
                continue

            resolved = tuple(sorted(mapped))
            mapping_hits.append((normalized_value, resolved))
            roles_raw.update(resolved)

        defined_roles = set(cfg.roles.role_to_permissions.keys())
        if cfg.general.strict_permissions:
            roles = {role for role in roles_raw if role in defined_roles}
            dropped = sorted(role for role in roles_raw if role not in defined_roles)
        else:
            roles = set(roles_raw)
            dropped = []

        if not roles:
            self._manager._audit_service.log_role_mapping_empty(
                provider="entra",
                principal=identity.username,
                subject=identity.user_id,
                ip_address=ip_address,
                external_values_count=len(identity.claim_values),
                mapped_values_count=len(mapping_hits),
                strict_permissions=bool(cfg.general.strict_permissions),
                deny_if_no_roles=bool(cfg.general.deny_if_no_roles),
            )
            self._manager._log_sensitive_values(
                label="Entra external values",
                principal=identity.username,
                values=list(identity.claim_values),
            )
            self._manager._audit_service.log_mapping_hits(
                provider="entra",
                principal=identity.username,
                mapping_hits=[(key, list(values)) for key, values in mapping_hits],
            )
            if dropped:
                self._manager._audit_service.log_dropped_roles(
                    provider="entra",
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
            provider="entra",
            principal=identity.username,
            subject=identity.user_id,
            ip_address=ip_address,
            roles=sorted(roles),
            external_values_count=len(identity.claim_values),
            mapped_values_count=len(mapping_hits),
            strict_permissions=bool(cfg.general.strict_permissions),
        )
        if dropped:
            self._manager._audit_service.log_dropped_roles(
                provider="entra",
                principal=identity.username,
                dropped_roles=dropped,
                strict_mode=True,
            )

        self._manager._log_sensitive_values(
            label="Entra external values",
            principal=identity.username,
            values=list(identity.claim_values),
        )
        self._manager._audit_service.log_mapping_hits(
            provider="entra",
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
            external_values_count=len(identity.claim_values),
            mapped_values_count=len(mapping_hits),
        )
