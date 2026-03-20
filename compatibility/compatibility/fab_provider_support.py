from __future__ import annotations

import importlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

from rbac_providers_auth_manager.authorization.compat_matrix import (
    build_non_admin_compatibility_matrix,
    evaluate_non_admin_role_consistency,
)
from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.authorization import vocabulary as vocab
from rbac_providers_auth_manager.config_runtime.models import (
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

ROLE_ORDER: Final[tuple[str, ...]] = ("Viewer", "User", "Op", "Admin")
EXCLUDED_DB_BACKED_RESOURCES: Final[frozenset[str]] = frozenset(
    {
        "Action",
        "Actions",
        "Password",
        "Passwords",
        "Permission",
        "Permissions",
        "Permission View",
        "Permission Views",
        "Resource Permission",
        "Resource Permissions",
        "Role",
        "Roles",
        "Security",
        "User",
        "Users",
        "User Stats Chart",
        "View Menu",
        "View Menus",
    }
)
SUPPORTED_ACTIONS: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(vocab).items()
    if name.startswith("ACTION_") and isinstance(value, str)
)
SUPPORTED_RESOURCES: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(vocab).items()
    if name.startswith("RESOURCE_")
    and isinstance(value, str)
    and not name.endswith("_PREFIX")
)


@dataclass(frozen=True, slots=True)
class SupportGap:
    role: str
    action: str
    resource: str
    normalized_action: str
    normalized_resource: str
    reason: str


@dataclass(frozen=True, slots=True)
class SupportReport:
    official_permission_counts: dict[str, int]
    supported_permission_counts: dict[str, int]
    unsupported_permissions: tuple[SupportGap, ...]
    contract_advisories: tuple[dict[str, str], ...]
    compatibility_matrix: tuple[dict[str, object], ...]

    @property
    def has_blocking_gaps(self) -> bool:
        return bool(self.unsupported_permissions)

    def as_dict(self) -> dict[str, object]:
        return {
            "official_permission_counts": self.official_permission_counts,
            "supported_permission_counts": self.supported_permission_counts,
            "unsupported_permissions": [
                asdict(item) for item in self.unsupported_permissions
            ],
            "contract_advisories": list(self.contract_advisories),
            "compatibility_matrix": list(self.compatibility_matrix),
        }


def provider_role_permissions() -> dict[str, frozenset[tuple[str, str]]]:
    importlib.import_module("airflow")
    provider_mod = importlib.import_module(
        "airflow.providers.fab.auth_manager.security_manager.override"
    )
    manager_cls = provider_mod.FabAirflowSecurityManagerOverride
    return {
        "Viewer": frozenset(manager_cls.VIEWER_PERMISSIONS),
        "User": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS) | set(manager_cls.USER_PERMISSIONS)
        ),
        "Op": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
        ),
        "Admin": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
            | set(manager_cls.ADMIN_PERMISSIONS)
        ),
    }


def _is_db_backed_resource(resource: str) -> bool:
    normalized = vocab.normalize_resource(resource)
    return (
        resource in EXCLUDED_DB_BACKED_RESOURCES
        or normalized in EXCLUDED_DB_BACKED_RESOURCES
    )


def _filtered_official_permissions(
    permissions_by_role: dict[str, frozenset[tuple[str, str]]],
) -> dict[str, frozenset[tuple[str, str]]]:
    filtered: dict[str, frozenset[tuple[str, str]]] = {}
    for role_name, permissions in permissions_by_role.items():
        filtered[role_name] = frozenset(
            (str(action), str(resource))
            for action, resource in permissions
            if not _is_db_backed_resource(str(resource))
        )
    return filtered


def _build_synthetic_config(
    permissions_by_role: dict[str, frozenset[tuple[str, str]]],
) -> AuthConfig:
    role_to_permissions = {
        role_name: set(permissions_by_role.get(role_name, frozenset()))
        for role_name in ROLE_ORDER
    }
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(),
        security=SecurityConfig(),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="Lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ldap=None,
        entra_id=None,
        role_mapping=RoleMappingConfig(dn_to_roles={}),
        entra_role_mapping=EntraRoleMappingConfig(claim_value_to_roles={}),
        roles=RolesConfig(role_to_permissions=role_to_permissions),
        role_filters=RoleFiltersConfig(role_to_filters={}),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )


def build_support_report() -> SupportReport:
    official = _filtered_official_permissions(provider_role_permissions())
    synthetic_cfg = _build_synthetic_config(official)
    policy = RbacPolicy(synthetic_cfg)

    unsupported: list[SupportGap] = []
    official_counts: dict[str, int] = {}
    supported_counts: dict[str, int] = {}

    for role_name in ROLE_ORDER:
        official_permissions = official.get(role_name, frozenset())
        official_counts[role_name] = len(official_permissions)
        supported_count = 0
        for action, resource in sorted(official_permissions):
            normalized_action = vocab.normalize_action(action)
            normalized_resource = vocab.normalize_resource(resource)
            if normalized_action not in SUPPORTED_ACTIONS:
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="unknown_action",
                    )
                )
                continue
            if normalized_resource not in SUPPORTED_RESOURCES:
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="unknown_resource",
                    )
                )
                continue
            if not policy.is_allowed(
                roles=(role_name,),
                action=normalized_action,
                resource=normalized_resource,
            ):
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="policy_engine_rejected_official_permission",
                    )
                )
                continue
            supported_count += 1
        supported_counts[role_name] = supported_count

    advisories = tuple(
        asdict(issue) for issue in evaluate_non_admin_role_consistency(synthetic_cfg)
    )
    matrix = tuple(
        asdict(row) for row in build_non_admin_compatibility_matrix(synthetic_cfg)
    )
    return SupportReport(
        official_permission_counts=official_counts,
        supported_permission_counts=supported_counts,
        unsupported_permissions=tuple(unsupported),
        contract_advisories=advisories,
        compatibility_matrix=matrix,
    )


def write_support_artifacts(*, artifact_dir: Path) -> SupportReport:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report = build_support_report()
    payload = report.as_dict()
    (artifact_dir / "official-fab-permissions-support.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_lines = ["# FAB provider support validation", ""]
    for role_name in ROLE_ORDER:
        summary_lines.append(f"## {role_name}")
        summary_lines.append(
            f"- official permissions: {report.official_permission_counts.get(role_name, 0)}"
        )
        summary_lines.append(
            f"- supported by plugin design: {report.supported_permission_counts.get(role_name, 0)}"
        )
        summary_lines.append("")
    summary_lines.append(
        f"- unsupported official permissions: {len(report.unsupported_permissions)}"
    )
    summary_lines.append(f"- contract advisories: {len(report.contract_advisories)}")
    (artifact_dir / "official-fab-permissions-support-summary.md").write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )
    return report
