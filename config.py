"""Compatibility configuration facade.

The canonical configuration implementation lives in
:mod:`rbac_providers_auth_manager.config_runtime.facade`.
"""

from __future__ import annotations

from rbac_providers_auth_manager.config_runtime.facade import (
    EXPECTED_PLUGIN_FAMILY,
    SUPPORTED_SCHEMA_VERSION,
    AuthConfig,
    AuthConfigValidation,
    ConfigAdvisory,
    ConfigLoader,
    EntraIdConfig,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    LdapConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
    airflow_worker_count,
    build_runtime_capability_report,
    collect_config_advisories,
    effective_auth_state_backend,
    effective_rate_limit_backend,
    effective_session_revocation_backend,
    load_config,
)

__all__ = (
    "EXPECTED_PLUGIN_FAMILY",
    "SUPPORTED_SCHEMA_VERSION",
    "AuthConfig",
    "AuthConfigValidation",
    "ConfigAdvisory",
    "ConfigLoader",
    "EntraIdConfig",
    "EntraRoleMappingConfig",
    "GeneralConfig",
    "JwtCookieConfig",
    "LdapConfig",
    "MetaConfig",
    "RoleFiltersConfig",
    "RoleMappingConfig",
    "RolesConfig",
    "SecurityConfig",
    "UiConfig",
    "airflow_worker_count",
    "build_runtime_capability_report",
    "collect_config_advisories",
    "effective_auth_state_backend",
    "effective_rate_limit_backend",
    "effective_session_revocation_backend",
    "load_config",
)
