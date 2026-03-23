"""Identity mapping and provider-authentication helpers for the auth manager."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.core.logging_utils import get_logger
from rbac_providers_auth_manager.identity.models import ExternalIdentity
from rbac_providers_auth_manager.runtime.security import fingerprint_values

log = get_logger("auth_manager")


class IdentityAuthService:
    """Own role mapping, sensitive debug logging, and provider auth helpers."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    @staticmethod
    def summarize_list(values: list[str] | tuple[str, ...], limit: int = 6) -> str:
        """Return a readable preview of a list for debug/audit logging."""
        materialized = [item for item in values if item]
        if len(materialized) <= limit:
            return ", ".join(materialized)
        remaining = len(materialized) - limit
        return ", ".join(materialized[:limit]) + f", ... (+{remaining} more)"

    def log_sensitive_values(
        self, *, label: str, principal: str, values: list[str] | tuple[str, ...]
    ) -> None:
        """Log raw and fingerprinted external values when sensitive debug is enabled."""
        cfg = self.manager._cfg_loader.get_config()
        if not cfg.security.sensitive_debug_logging:
            return

        materialized = [item for item in values if item]
        log.debug(
            "%s for principal=%s count=%d values=[%s]",
            label,
            principal,
            len(materialized),
            self.summarize_list(materialized),
        )
        if materialized:
            log.debug(
                "%s fingerprints for principal=%s count=%d sha256_12=[%s]",
                label,
                principal,
                len(materialized),
                self.summarize_list(list(fingerprint_values(materialized))),
            )

    def debug_log_role_permissions(self, *, username: str, roles: list[str]) -> None:
        """Log final mapped roles and permission expansion for debugging/audit."""
        cfg = self.manager._cfg_loader.get_config()
        role_permissions = cfg.roles.role_to_permissions

        sorted_roles = sorted(set(roles))
        log.info(
            "Final mapped roles for user=%s roles=%s",
            username,
            sorted_roles,
        )

        if not cfg.security.sensitive_debug_logging:
            return

        if not sorted_roles:
            log.debug("No Airflow roles mapped for user=%s", username)
            return

        for role in sorted_roles:
            permissions = sorted(role_permissions.get(role, set()))
            log.debug(
                "Role permission expansion user=%s role=%s permissions=%s",
                username,
                role,
                permissions,
            )

    def apply_default_role_if_allowed(
        self, *, principal: str, subject: str, ip_address: str
    ) -> set[str]:
        """Apply the default self-registration role when allowed by config."""
        cfg = self.manager._cfg_loader.get_config()
        if not cfg.general.auth_user_registration:
            raise LdapAuthError("No Airflow roles mapped for principal")

        default_role = (cfg.general.auth_user_registration_role or "").strip()
        if not default_role:
            raise LdapAuthError("No Airflow roles mapped for principal")

        role_permissions = cfg.roles.role_to_permissions.get(default_role)
        if role_permissions is None:
            raise LdapAuthError(
                f"Default registration role {default_role!r} is not defined in permissions.ini"
            )

        self.manager._audit_service.log_flow_event(
            event="auth.role_mapping.fallback",
            provider="registration",
            principal=principal,
            subject=subject,
            ip_address=ip_address,
            fallback_role=default_role,
        )
        return {default_role}

    def map_ldap_roles(
        self, *, identity: ExternalIdentity, ip_address: str
    ) -> list[str]:
        """Map normalized LDAP groups to Airflow roles with audit logging."""
        result = self.manager._identity_mapper.map_ldap_identity(
            identity=identity,
            ip_address=ip_address,
        )
        return list(result.roles)

    def map_entra_roles(
        self, *, identity: ExternalIdentity, ip_address: str
    ) -> list[str]:
        """Map normalized Entra role/group claims to Airflow roles with audit logging."""
        result = self.manager._identity_mapper.map_entra_identity(
            identity=identity,
            ip_address=ip_address,
        )
        return list(result.roles)

    def _build_authenticated_user(
        self,
        *,
        identity: ExternalIdentity,
        roles: list[str] | tuple[str, ...],
    ) -> Any:
        """Materialize the Airflow auth-manager user from a normalized identity."""
        return self.manager._user_model()(  # type: ignore[misc]
            user_id=identity.user_id,
            username=identity.username,
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            roles=tuple(sorted({str(role) for role in roles if str(role).strip()})),
        )

    def authenticate_ldap(
        self, *, username: str, password: str, request: Any | None
    ) -> Any:
        """Authenticate via LDAP provider and return the resolved user object."""
        self.manager._refresh_if_needed()
        if (
            self.manager._ldap_provider is None
            or not self.manager._ldap_provider.is_enabled()
        ):
            raise LdapAuthError("LDAP authentication is disabled")

        identity = self.manager._ldap_provider.authenticate_credentials(
            username=username,
            password=password,
            request=request,
        )
        roles = self.map_ldap_roles(
            identity=identity,
            ip_address=self.manager._client_ip(request),
        )
        return self._build_authenticated_user(identity=identity, roles=roles)

    def authenticate_entra_identity(
        self, *, identity: ExternalIdentity, request: Any | None
    ) -> Any:
        """Resolve an Entra external identity into an authenticated user."""
        self.manager._refresh_if_needed()
        if (
            self.manager._entra_provider is None
            or not self.manager._entra_provider.is_enabled()
        ):
            raise LdapAuthError("Azure Entra ID authentication is disabled")

        roles = self.map_entra_roles(
            identity=identity,
            ip_address=self.manager._client_ip(request),
        )
        return self._build_authenticated_user(identity=identity, roles=roles)
