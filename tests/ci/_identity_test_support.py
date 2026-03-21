from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.authorization.vocabulary import (
    ACTION_CAN_READ,
    RESOURCE_DAG,
)
from rbac_providers_auth_manager.config import (
    AuthConfig,
    AuthConfigValidation,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.core.exceptions import LdapAuthError


@dataclass(frozen=True)
class _CfgLoader:
    cfg: AuthConfig

    def get_config(self) -> AuthConfig:
        return self.cfg


class _AuditService:
    def __init__(self) -> None:
        self.role_mapping_empty: list[dict[str, Any]] = []
        self.mapping_hits: list[dict[str, Any]] = []
        self.dropped_roles: list[dict[str, Any]] = []
        self.provider_success: list[dict[str, Any]] = []

    def log_role_mapping_empty(self, **payload: Any) -> None:
        self.role_mapping_empty.append(payload)

    def log_mapping_hits(self, **payload: Any) -> None:
        self.mapping_hits.append(payload)

    def log_dropped_roles(self, **payload: Any) -> None:
        self.dropped_roles.append(payload)

    def log_provider_success(self, **payload: Any) -> None:
        self.provider_success.append(payload)


class _FakeManager:
    def __init__(self, cfg: AuthConfig) -> None:
        self._cfg_loader = _CfgLoader(cfg)
        self._policy = RbacPolicy(cfg)
        self._audit_service = _AuditService()
        self.debug_role_logs: list[tuple[str, list[str]]] = []
        self.sensitive_value_logs: list[tuple[str, str, list[str]]] = []

    def _apply_default_role_if_allowed(
        self, *, principal: str, subject: str, ip_address: str
    ) -> set[str]:
        del principal, subject, ip_address
        cfg = self._cfg_loader.get_config()
        if not cfg.general.auth_user_registration:
            raise LdapAuthError("No Airflow roles mapped for principal")
        role = (cfg.general.auth_user_registration_role or "").strip()
        if not role or role not in cfg.roles.role_to_permissions:
            raise LdapAuthError("Default registration role is not defined")
        return {role}

    def _log_sensitive_values(
        self, *, label: str, principal: str, values: list[str]
    ) -> None:
        self.sensitive_value_logs.append((label, principal, list(values)))

    def _debug_log_role_permissions(self, *, username: str, roles: list[str]) -> None:
        self.debug_role_logs.append((username, list(roles)))

    @staticmethod
    def _normalize_entra_claim_value(value: str) -> str:
        return " ".join((value or "").strip().split()).casefold()


def build_identity_test_config(
    *,
    strict_permissions: bool = True,
    auth_user_registration: bool = False,
    auth_user_registration_role: str = "Public",
    dn_to_roles: dict[str, set[str]] | None = None,
    claim_value_to_roles: dict[str, set[str]] | None = None,
    role_to_permissions: dict[str, set[tuple[str, str]]] | None = None,
) -> AuthConfig:
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(
            strict_permissions=strict_permissions,
            auth_user_registration=auth_user_registration,
            auth_user_registration_role=auth_user_registration_role,
            enable_ldap=True,
            enable_entra_id=True,
        ),
        security=SecurityConfig(sensitive_debug_logging=True),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ldap=None,
        entra_id=None,
        role_mapping=RoleMappingConfig(
            dn_to_roles=dn_to_roles
            or {
                "cn=viewer,ou=groups,dc=example,dc=com": {"Viewer", "Ghost"},
                "cn=operator,ou=groups,dc=example,dc=com": {"Operator"},
            }
        ),
        entra_role_mapping=EntraRoleMappingConfig(
            claim_value_to_roles=claim_value_to_roles
            or {
                "viewer-group": {"Viewer", "Ghost"},
                "operator-group": {"Operator"},
            }
        ),
        roles=RolesConfig(
            role_to_permissions=role_to_permissions
            or {
                "Viewer": {(ACTION_CAN_READ, RESOURCE_DAG)},
                "Operator": {(ACTION_CAN_READ, RESOURCE_DAG)},
                "Public": {(ACTION_CAN_READ, RESOURCE_DAG)},
            }
        ),
        role_filters=RoleFiltersConfig(role_to_filters={}),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )
