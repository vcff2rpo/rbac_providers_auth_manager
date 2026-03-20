"""Rule functions for operator-facing configuration advisories."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rbac_providers_auth_manager.config_runtime.models import AuthConfig, ConfigAdvisory
from rbac_providers_auth_manager.authorization.compat_matrix import (
    advisories_from_role_consistency,
)
from rbac_providers_auth_manager.authorization.rbac import (
    ACTION_CAN_CREATE,
    ACTION_CAN_DELETE,
    ACTION_CAN_EDIT,
    ACTION_CAN_READ,
    ACTION_MENU_ACCESS,
    RESOURCE_ADMIN_MENU,
    RESOURCE_ASSET,
    RESOURCE_ASSET_ALIAS,
    RESOURCE_AUDIT_LOG,
    RESOURCE_BACKFILL,
    RESOURCE_BROWSE_MENU,
    RESOURCE_CLUSTER_ACTIVITY,
    RESOURCE_CONFIG,
    RESOURCE_CONNECTION,
    RESOURCE_DAG,
    RESOURCE_DAG_CODE,
    RESOURCE_DAG_DEPENDENCIES,
    RESOURCE_DAG_PREFIX,
    RESOURCE_DAG_RUN,
    RESOURCE_DAG_RUN_PREFIX,
    RESOURCE_DAG_VERSION,
    RESOURCE_DAG_WARNING,
    RESOURCE_DOCS,
    RESOURCE_DOCS_MENU,
    RESOURCE_HITL_DETAIL,
    RESOURCE_IMPORT_ERROR,
    RESOURCE_JOB,
    RESOURCE_PLUGIN,
    RESOURCE_POOL,
    RESOURCE_PROVIDER,
    RESOURCE_SLA_MISSES,
    RESOURCE_TASK_INSTANCE,
    RESOURCE_TASK_LOG,
    RESOURCE_TRIGGER,
    RESOURCE_VARIABLE,
    RESOURCE_WEBSITE,
    RESOURCE_XCOM,
    normalize_action,
    normalize_resource,
)
from rbac_providers_auth_manager.authorization.vocabulary import (
    RESOURCE_TASK_RESCHEDULE,
)

_KNOWN_ACTIONS = frozenset(
    {
        ACTION_MENU_ACCESS,
        ACTION_CAN_READ,
        ACTION_CAN_EDIT,
        ACTION_CAN_CREATE,
        ACTION_CAN_DELETE,
        "*",
    }
)

_KNOWN_RESOURCES = frozenset(
    {
        RESOURCE_ADMIN_MENU,
        RESOURCE_ASSET,
        RESOURCE_ASSET_ALIAS,
        RESOURCE_AUDIT_LOG,
        RESOURCE_BACKFILL,
        RESOURCE_BROWSE_MENU,
        RESOURCE_CLUSTER_ACTIVITY,
        RESOURCE_CONFIG,
        RESOURCE_CONNECTION,
        RESOURCE_DAG,
        RESOURCE_DAG_CODE,
        RESOURCE_DAG_DEPENDENCIES,
        RESOURCE_DAG_RUN,
        RESOURCE_DAG_VERSION,
        RESOURCE_DAG_WARNING,
        RESOURCE_DOCS,
        RESOURCE_DOCS_MENU,
    RESOURCE_DOCS_MENU,
        RESOURCE_HITL_DETAIL,
        RESOURCE_IMPORT_ERROR,
        RESOURCE_JOB,
        RESOURCE_PLUGIN,
        RESOURCE_POOL,
        RESOURCE_PROVIDER,
        RESOURCE_SLA_MISSES,
        RESOURCE_TASK_INSTANCE,
        RESOURCE_TASK_LOG,
        RESOURCE_TASK_RESCHEDULE,
        RESOURCE_TRIGGER,
        RESOURCE_VARIABLE,
        RESOURCE_WEBSITE,
        RESOURCE_XCOM,
        "My Profile",
        "My Password",
        "*",
    }
)

_SAFE_PUBLIC_ROLE_RESOURCES = frozenset({"My Profile", "My Password"})


def effective_rate_limit_backend(value: str) -> str:
    """Return the canonical rate-limit backend name."""
    normalized = (value or "memory").strip().lower()
    if normalized in {"memory", "in_memory", "local"}:
        return "memory"
    return normalized


def effective_auth_state_backend(value: str) -> str:
    """Return the canonical auth-state backend name."""
    normalized = (value or "cookie").strip().lower()
    if normalized in {"cookie", "browser_cookie"}:
        return "cookie"
    if normalized in {"memory", "in_memory", "local"}:
        return "memory"
    return normalized


def _is_known_resource(resource: str) -> bool:
    """Return whether a normalized resource belongs to the supported vocabulary."""
    if resource in _KNOWN_RESOURCES:
        return True
    return resource.startswith((RESOURCE_DAG_PREFIX, RESOURCE_DAG_RUN_PREFIX))


def _role_mapping_targets(
    mapping_values: dict[str, set[str]], *, defined_roles: set[str]
) -> list[str]:
    """Return undefined role names referenced by a mapping dictionary."""
    undefined: set[str] = set()
    for mapped_roles in mapping_values.values():
        undefined.update(role for role in mapped_roles if role not in defined_roles)
    return sorted(undefined)


def _rule_missing_meta_section(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    if cfg.meta.section_present:
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="missing_meta_section",
            message=(
                "permissions.ini does not declare a [meta] section; add schema_version "
                "and plugin_family explicitly to make future upgrades safer."
            ),
        ),
    )


def _rule_ldap_mapping_undefined_roles(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    ldap_undefined_roles = _role_mapping_targets(
        cfg.role_mapping.dn_to_roles, defined_roles=defined_roles
    )
    if not ldap_undefined_roles:
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="ldap_mapping_undefined_roles",
            message=(
                "LDAP role mappings reference undefined Airflow roles: "
                + ", ".join(ldap_undefined_roles)
            ),
        ),
    )


def _rule_entra_mapping_undefined_roles(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    entra_undefined_roles = _role_mapping_targets(
        cfg.entra_role_mapping.claim_value_to_roles,
        defined_roles=defined_roles,
    )
    if not entra_undefined_roles:
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="entra_mapping_undefined_roles",
            message=(
                "Entra role mappings reference undefined Airflow roles: "
                + ", ".join(entra_undefined_roles)
            ),
        ),
    )


def _rule_role_filters_undefined_roles(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    undefined_role_filters = sorted(
        set(cfg.role_filters.role_to_filters.keys()) - defined_roles
    )
    if not undefined_role_filters:
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="role_filters_undefined_roles",
            message=(
                "Role-filter sections target undefined roles: "
                + ", ".join(undefined_role_filters)
            ),
        ),
    )


def _rule_unknown_actions_or_resources(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    advisories: list[ConfigAdvisory] = []
    unknown_actions: set[str] = set()
    unknown_resources: set[str] = set()
    for permissions in cfg.roles.role_to_permissions.values():
        for action, resource in permissions:
            normalized_action = normalize_action(action)
            normalized_resource = normalize_resource(resource)
            if normalized_action not in _KNOWN_ACTIONS:
                unknown_actions.add(normalized_action)
            if normalized_resource and not _is_known_resource(normalized_resource):
                unknown_resources.add(normalized_resource)

    if unknown_actions:
        advisories.append(
            ConfigAdvisory(
                severity="warning",
                code="unknown_actions",
                message=(
                    "Role definitions contain unknown actions: "
                    + ", ".join(sorted(unknown_actions))
                ),
            )
        )
    if unknown_resources:
        advisories.append(
            ConfigAdvisory(
                severity="warning",
                code="unknown_resources",
                message=(
                    "Role definitions contain resources outside the supported vocabulary: "
                    + ", ".join(sorted(unknown_resources))
                ),
            )
        )
    return tuple(advisories)


def _rule_broad_public_role(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    public_permissions = cfg.roles.role_to_permissions.get("Public") or set()
    if not (cfg.general.auth_user_registration and public_permissions):
        return ()
    risky_public = sorted(
        f"{action}:{resource}"
        for action, resource in public_permissions
        if action == "*"
        or resource == "*"
        or normalize_action(action) in {ACTION_CAN_CREATE, ACTION_CAN_DELETE}
        or normalize_resource(resource) not in _SAFE_PUBLIC_ROLE_RESOURCES
    )
    if not risky_public:
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="broad_public_role",
            message=(
                "auth_user_registration is enabled and the Public role grants broad "
                "permissions: " + ", ".join(risky_public)
            ),
        ),
    )


def _rule_memory_rate_limit_multi_worker(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    backend = effective_rate_limit_backend(cfg.security.rate_limit_backend)
    if not (backend == "memory" and airflow_worker_count > 1):
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="memory_rate_limit_multi_worker",
            message=(
                "security.rate_limit_backend=memory is configured while Airflow API "
                f"workers={airflow_worker_count}; lockout state will not be shared "
                "across workers. Consider the Redis backend for enterprise deployments."
            ),
        ),
    )


def _rule_non_shared_auth_state_backend_multi_worker(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    auth_state_backend = effective_auth_state_backend(cfg.security.auth_state_backend)
    if not (
        cfg.entra_id is not None
        and airflow_worker_count > 1
        and auth_state_backend in {"cookie", "memory"}
    ):
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="non_shared_auth_state_backend_multi_worker",
            message=(
                "Entra ID is enabled while security.auth_state_backend="
                f"{auth_state_backend} and Airflow API workers={airflow_worker_count}. "
                "SSO callback state may not be resilient across multi-worker deployments. "
                "Prefer the Redis auth-state backend for enterprise deployments."
            ),
        ),
    )


def _rule_redis_auth_state_missing_url(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    auth_state_backend = effective_auth_state_backend(cfg.security.auth_state_backend)
    if not (
        auth_state_backend == "redis"
        and not (cfg.security.auth_state_redis_url or "").strip()
    ):
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="redis_auth_state_missing_url",
            message=(
                "security.auth_state_backend=redis is configured but security.auth_state_redis_url is empty. "
                "The plugin will fall back to cookie-backed auth state until Redis is configured."
            ),
        ),
    )


def _rule_entra_without_trusted_proxies(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    if not (cfg.entra_id is not None and not cfg.general.trusted_proxies):
        return ()
    return (
        ConfigAdvisory(
            severity="warning",
            code="entra_without_trusted_proxies",
            message=(
                "Entra ID is enabled but general.trusted_proxies is empty. Reverse-proxy "
                "header handling and callback URL reconstruction may be unsafe or incorrect."
            ),
        ),
    )


def _rule_non_admin_role_consistency(
    cfg: AuthConfig, *, defined_roles: set[str], airflow_worker_count: int
) -> tuple[ConfigAdvisory, ...]:
    return advisories_from_role_consistency(cfg)


ConfigAdvisoryRule = Callable[..., tuple[ConfigAdvisory, ...]]

ADVISORY_RULES: tuple[ConfigAdvisoryRule, ...] = (
    _rule_missing_meta_section,
    _rule_ldap_mapping_undefined_roles,
    _rule_entra_mapping_undefined_roles,
    _rule_role_filters_undefined_roles,
    _rule_unknown_actions_or_resources,
    _rule_broad_public_role,
    _rule_memory_rate_limit_multi_worker,
    _rule_non_shared_auth_state_backend_multi_worker,
    _rule_redis_auth_state_missing_url,
    _rule_entra_without_trusted_proxies,
    _rule_non_admin_role_consistency,
)


def collect_advisories_from_rules(
    cfg: AuthConfig,
    *,
    defined_roles: set[str],
    airflow_worker_count: int,
    rules: Sequence[ConfigAdvisoryRule] = ADVISORY_RULES,
) -> tuple[ConfigAdvisory, ...]:
    """Evaluate advisory rules in deterministic order and flatten their output."""
    advisories: list[ConfigAdvisory] = []
    for rule in rules:
        advisories.extend(
            rule(
                cfg,
                defined_roles=defined_roles,
                airflow_worker_count=airflow_worker_count,
            )
        )
    return tuple(advisories)
