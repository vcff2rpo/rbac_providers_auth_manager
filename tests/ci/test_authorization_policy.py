from __future__ import annotations

from rbac_providers_auth_manager.authorization.helpers import resource_name
from rbac_providers_auth_manager.authorization.policy_models import (
    AuthorizationContext,
    ResourceAttributes,
    RoleFilterRule,
)
from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.authorization.vocabulary import (
    ACTION_CAN_READ,
    RESOURCE_DAG,
    RESOURCE_DAG_PREFIX,
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


def _build_config(*, strict_permissions: bool = True) -> AuthConfig:
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(strict_permissions=strict_permissions),
        security=SecurityConfig(),
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
            dn_to_roles={
                "cn=viewer,ou=groups,dc=example,dc=com": {"Viewer", "Ghost"},
                "cn=op,ou=groups,dc=example,dc=com": {"Op"},
            }
        ),
        entra_role_mapping=EntraRoleMappingConfig(claim_value_to_roles={}),
        roles=RolesConfig(
            role_to_permissions={
                "Viewer": {(ACTION_CAN_READ, RESOURCE_DAG)},
                "Scoped": {(ACTION_CAN_READ, RESOURCE_DAG)},
                "Op": {(ACTION_CAN_READ, f"{RESOURCE_DAG_PREFIX}finance_daily")},
            }
        ),
        role_filters=RoleFiltersConfig(
            role_to_filters={
                "Scoped": RoleFilterRule(
                    dag_tags=("finance",),
                    environments=("prod",),
                    resource_prefixes=("finance_",),
                )
            }
        ),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )


def test_resource_name_preserves_prefixed_resources_and_scopes_dag_ids() -> None:
    assert resource_name("example", RESOURCE_DAG) == "DAG:example"
    assert resource_name("DAG:already-scoped", RESOURCE_DAG) == "DAG:already-scoped"
    assert resource_name("run-1", "Custom") == "Custom:run-1"


def test_rbac_policy_honors_global_and_scoped_dag_permissions() -> None:
    policy = RbacPolicy(_build_config())

    assert policy.is_allowed(roles=("Viewer",), action=ACTION_CAN_READ, resource=RESOURCE_DAG) is True
    assert policy.is_allowed(roles=("Op",), action=ACTION_CAN_READ, resource="DAG:finance_daily") is True
    assert policy.is_allowed(roles=("Op",), action=ACTION_CAN_READ, resource="DAG:other_dag") is False


def test_rbac_policy_applies_role_filters_when_context_is_available() -> None:
    policy = RbacPolicy(_build_config())
    matching_context = AuthorizationContext(
        resource=ResourceAttributes(
            resource_id="finance_daily",
            resource_type="dag",
            dag_tags=("finance", "critical"),
            environments=("prod",),
        )
    )
    non_matching_context = AuthorizationContext(
        resource=ResourceAttributes(
            resource_id="hr_daily",
            resource_type="dag",
            dag_tags=("hr",),
            environments=("dev",),
        )
    )

    assert policy.is_allowed(
        roles=("Scoped",),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=matching_context,
    ) is True
    assert policy.is_allowed(
        roles=("Scoped",),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=non_matching_context,
    ) is False


def test_map_dns_to_roles_respects_strict_permissions_mode() -> None:
    strict_policy = RbacPolicy(_build_config(strict_permissions=True))
    permissive_policy = RbacPolicy(_build_config(strict_permissions=False))
    group_dns = ("CN=Viewer,OU=Groups,DC=example,DC=com",)

    assert strict_policy.map_dns_to_roles(group_dns) == {"Viewer"}
    assert permissive_policy.map_dns_to_roles(group_dns) == {"Ghost", "Viewer"}
