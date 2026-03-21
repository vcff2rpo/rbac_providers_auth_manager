"""Compatibility matrix and consistency helpers for mirrored non-admin RBAC."""

from __future__ import annotations

from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.resource_contracts import (
    FAB_OFFICIAL_ROLE_ORDER,
    MIRRORED_ROLE_ORDER,
    NON_ADMIN_PERMISSION_CONTRACTS,
    contract_permissions_by_role,
    roles_at_or_above,
)
from rbac_providers_auth_manager.config_runtime.models import AuthConfig, ConfigAdvisory


@dataclass(frozen=True, slots=True)
class CompatibilityMatrixRow:
    """One permission-level row in the mirrored non-admin compatibility matrix."""

    resource: str
    action: str
    minimum_role: str
    viewer_has_access: bool
    user_has_access: bool
    op_has_access: bool
    admin_has_access: bool
    shipped_role_consistency: tuple[str, ...]
    notes: str = ""


@dataclass(frozen=True, slots=True)
class RoleConsistencyIssue:
    """A consistency issue detected in the configured official role ladder."""

    severity: str
    code: str
    message: str


def _normalized_permissions_for_role(
    cfg: AuthConfig, role_name: str
) -> frozenset[tuple[str, str]]:
    permissions = cfg.roles.role_to_permissions.get(role_name) or set()
    return frozenset((action, resource) for action, resource in permissions)


def evaluate_non_admin_role_consistency(
    cfg: AuthConfig,
) -> tuple[RoleConsistencyIssue, ...]:
    """Return consistency issues for the official non-admin role ladder."""
    issues: list[RoleConsistencyIssue] = []
    defined_roles = set(cfg.roles.role_to_permissions.keys())
    expected_by_role = contract_permissions_by_role()

    missing_roles = [
        role_name
        for role_name in FAB_OFFICIAL_ROLE_ORDER
        if role_name not in defined_roles
    ]
    if missing_roles:
        issues.append(
            RoleConsistencyIssue(
                severity="warning",
                code="official_roles_missing",
                message=(
                    "Official FAB-compatible roles are missing from the bundled role ladder: "
                    + ", ".join(missing_roles)
                ),
            )
        )

    for role_name in MIRRORED_ROLE_ORDER:
        actual = _normalized_permissions_for_role(cfg, role_name)
        expected = expected_by_role.get(role_name, frozenset())
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)

        if missing:
            preview = ", ".join(
                f"{action}:{resource}" for action, resource in missing[:8]
            )
            if len(missing) > 8:
                preview += f", ... (+{len(missing) - 8})"
            issues.append(
                RoleConsistencyIssue(
                    severity="warning",
                    code="official_role_contract_gap",
                    message=(
                        f"Role {role_name} is missing mirrored non-DB FAB permissions: {preview}."
                    ),
                )
            )

        if extra:
            preview = ", ".join(
                f"{action}:{resource}" for action, resource in extra[:8]
            )
            if len(extra) > 8:
                preview += f", ... (+{len(extra) - 8})"
            issues.append(
                RoleConsistencyIssue(
                    severity="info",
                    code="official_role_contract_extra",
                    message=(
                        f"Role {role_name} grants additional non-DB permissions beyond the mirrored FAB contract: {preview}."
                    ),
                )
            )

    return tuple(issues)


def build_non_admin_compatibility_matrix(
    cfg: AuthConfig,
) -> tuple[CompatibilityMatrixRow, ...]:
    """Build a deterministic permission-level compatibility matrix."""
    actual_by_role = {
        role_name: _normalized_permissions_for_role(cfg, role_name)
        for role_name in MIRRORED_ROLE_ORDER
    }

    rows: list[CompatibilityMatrixRow] = []
    for contract in sorted(
        NON_ADMIN_PERMISSION_CONTRACTS,
        key=lambda item: (item.resource, item.action, item.minimum_role),
    ):
        permission = (contract.action, contract.resource)
        expected_roles = set(roles_at_or_above(contract.minimum_role))
        actual_roles = {
            role_name
            for role_name, permissions in actual_by_role.items()
            if permission in permissions
        }
        consistency: list[str] = []
        missing_roles = sorted(expected_roles - actual_roles)
        extra_roles = sorted(actual_roles - expected_roles)
        if missing_roles:
            consistency.append("missing:" + ",".join(missing_roles))
        if extra_roles:
            consistency.append("extra:" + ",".join(extra_roles))
        rows.append(
            CompatibilityMatrixRow(
                resource=contract.resource,
                action=contract.action,
                minimum_role=contract.minimum_role,
                viewer_has_access="Viewer" in actual_roles,
                user_has_access="User" in actual_roles,
                op_has_access="Op" in actual_roles,
                admin_has_access="Admin" in actual_roles,
                shipped_role_consistency=tuple(consistency),
                notes=contract.notes,
            )
        )
    return tuple(rows)


def advisories_from_role_consistency(cfg: AuthConfig) -> tuple[ConfigAdvisory, ...]:
    """Convert consistency issues into config advisories."""
    return tuple(
        ConfigAdvisory(severity=issue.severity, code=issue.code, message=issue.message)
        for issue in evaluate_non_admin_role_consistency(cfg)
    )
