"""Operator-facing configuration advisories and capability reporting."""

from __future__ import annotations

import logging
import sys

try:
    from airflow.configuration import conf as airflow_conf  # type: ignore
except Exception:  # pragma: no cover  # noqa: BLE001
    airflow_conf = None  # type: ignore[assignment]

from rbac_providers_auth_manager.config_runtime.advisory_rules import (
    collect_advisories_from_rules,
    effective_auth_state_backend,
    effective_rate_limit_backend,
    effective_session_revocation_backend,
)
from rbac_providers_auth_manager.config_runtime.models import AuthConfig, ConfigAdvisory
from rbac_providers_auth_manager.runtime.version_policy import (
    build_runtime_version_policy_report,
)

log = logging.getLogger(__name__)


def airflow_worker_count() -> int:
    """Return the configured Airflow API worker count when available."""
    if airflow_conf is None:
        return 1
    try:
        return max(1, airflow_conf.getint("api", "workers", fallback=1))
    except Exception:  # pragma: no cover  # noqa: BLE001
        return 1


def collect_config_advisories(cfg: AuthConfig) -> tuple[ConfigAdvisory, ...]:
    """Return non-fatal operator-facing diagnostics for the loaded configuration."""
    return collect_advisories_from_rules(
        cfg,
        defined_roles=set(cfg.roles.role_to_permissions.keys()),
        airflow_worker_count=airflow_worker_count(),
    )


def build_runtime_capability_report(cfg: AuthConfig) -> dict[str, str]:
    """Return a concise capability snapshot for operator diagnostics."""
    try:  # pragma: no cover - depends on Airflow runtime presence
        from rbac_providers_auth_manager.compatibility.airflow_public_api import (
            BaseAuthManager,
        )
        from rbac_providers_auth_manager.compatibility.internal_shims import (
            AccessView,
            DagAccessEntity,
        )

        airflow_public_api = "available"
        hitl_hook = (
            "available"
            if hasattr(BaseAuthManager, "is_authorized_hitl_task")
            else "missing"
        )
        access_view_model = "available" if AccessView is not object else "fallback"
        dag_access_entity_model = (
            "available" if DagAccessEntity is not object else "fallback"
        )
    except Exception:  # pragma: no cover  # noqa: BLE001
        airflow_public_api = "unavailable"
        hitl_hook = "unknown"
        access_view_model = "unknown"
        dag_access_entity_model = "unknown"

    version_policy = build_runtime_version_policy_report()

    return {
        "plugin_family": cfg.meta.plugin_family,
        "schema_version": str(cfg.meta.schema_version),
        "airflow_version": version_policy.airflow_version or "unavailable",
        "fab_provider_version": version_policy.fab_provider_version or "unavailable",
        "python_version": version_policy.python_version,
        "airflow_version_status": version_policy.airflow_status,
        "fab_provider_version_status": version_policy.fab_provider_status,
        "python_version_status": version_policy.python_status,
        "airflow_public_api": airflow_public_api,
        "hitl_task_hook": hitl_hook,
        "access_view_model": access_view_model,
        "dag_access_entity_model": dag_access_entity_model,
        "ldap_provider": "enabled" if cfg.ldap is not None else "disabled",
        "entra_provider": "enabled" if cfg.entra_id is not None else "disabled",
        "rate_limit_backend": effective_rate_limit_backend(
            cfg.security.rate_limit_backend
        ),
        "auth_state_backend": effective_auth_state_backend(
            cfg.security.auth_state_backend
        ),
        "session_revocation_backend": effective_session_revocation_backend(
            cfg.security.session_revocation_backend
        ),
        "session_revocation_on_sensitive_reload": (
            "enabled"
            if cfg.security.enable_session_revocation_on_sensitive_reload
            else "disabled"
        ),
        "api_worker_count": str(airflow_worker_count()),
        "trusted_proxies_configured": "yes" if cfg.general.trusted_proxies else "no",
        "role_filters_configured": str(len(cfg.role_filters.role_to_filters)),
        "config_advisories": str(len(cfg.advisories)),
        "version_policy_advisories": str(len(version_policy.advisories)),
        "python_runtime": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
