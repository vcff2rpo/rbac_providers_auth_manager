"""Compatibility matrix and consistency helpers for mirrored non-admin RBAC."""

from __future__ import annotations

from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.resource_contracts import (
    FAB_OFFICIAL_ROLE_ORDER,
    NON_ADMIN_RESOURCE_CONTRACTS,
    role_meets_minimum,
)
from rbac_providers_auth_manager.authorization.vocabulary import ACTION_MENU_ACCESS
from rbac_providers_auth_manager.config_runtime.models import AuthConfig, ConfigAdvisory


@dataclass(frozen=True, slots=True)
class CompatibilityMatrixRow:
    """One row in the mirrored non-admin compatibility matrix."""

    resource: str
    menu_resource: str
    minimum_role: str
    functional_actions: tuple[str, ...]
    implemented: bool
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


def _has_permission(
    permissions: frozenset[tuple[str, str]], action: str, resource: str
) -> bool:
    return (
        ("*", "*") in permissions
        or (action, resource) in permissions
        or ("*", resource) in permissions
        or (action, "*") in permissions
    )


def evaluate_non_admin_role_consistency(
    cfg: AuthConfig,
) -> tuple[RoleConsistencyIssue, ...]:
    """Return consistency issues for the official non-admin role ladder."""
    issues: list[RoleConsistencyIssue] = []
    defined_roles = set(cfg.roles.role_to_permissions.keys())

    missing_roles = [
        role for role in FAB_OFFICIAL_ROLE_ORDER if role not in defined_roles
    ]
    if missing_roles:
        issues.append(
            RoleConsistencyIssue(
                severity="warning",
                code="official_roles_missing",
                message="Official FAB-compatible roles are missing from the bundled role ladder: "
                + ", ".join(missing_roles),
            )
        )

    for role_name in FAB_OFFICIAL_ROLE_ORDER:
        permissions = _normalized_permissions_for_role(cfg, role_name)
        if not permissions:
            continue

        for contract in NON_ADMIN_RESOURCE_CONTRACTS:
            functional_visible = any(
                _has_permission(permissions, action, contract.resource)
                for action in contract.functional_actions
            )
            menu_visible = _has_permission(
                permissions,
                contract.menu_action,
                contract.menu_resource,
            )

            if functional_visible and not menu_visible:
                issues.append(
                    RoleConsistencyIssue(
                        severity="warning",
                        code="menu_access_missing_for_functional_resource",
                        message=(
                            f"Role {role_name} grants functional access to {contract.resource} "
                            f"but is missing {ACTION_MENU_ACCESS} on {contract.menu_resource}."
                        ),
                    )
                )

            if (
                contract.resource == contract.menu_resource
                and menu_visible
                and not functional_visible
            ):
                issues.append(
                    RoleConsistencyIssue(
                        severity="info",
                        code="menu_without_functional_access",
                        message=(
                            f"Role {role_name} grants {ACTION_MENU_ACCESS} on {contract.menu_resource} "
                            f"without any mirrored functional actions on the same resource."
                        ),
                    )
                )

            if role_meets_minimum(role_name, contract.minimum_role):
                minimum_actions_missing = [
                    action
                    for action in contract.functional_actions
                    if not _has_permission(permissions, action, contract.resource)
                ]
                if minimum_actions_missing:
                    issues.append(
                        RoleConsistencyIssue(
                            severity="info",
                            code="official_role_contract_gap",
                            message=(
                                f"Role {role_name} is at or above the FAB-compatible minimum role for {contract.resource} "
                                f"but is missing mirrored actions: {', '.join(minimum_actions_missing)}."
                            ),
                        )
                    )

    return tuple(issues)


def build_non_admin_compatibility_matrix(
    cfg: AuthConfig,
) -> tuple[CompatibilityMatrixRow, ...]:
    """Build a deterministic compatibility matrix for supported non-admin resources."""
    rows: list[CompatibilityMatrixRow] = []
    issues_by_resource: dict[str, list[str]] = {}
    for issue in evaluate_non_admin_role_consistency(cfg):
        for contract in NON_ADMIN_RESOURCE_CONTRACTS:
            if (
                contract.resource in issue.message
                or contract.menu_resource in issue.message
            ):
                issues_by_resource.setdefault(contract.resource, []).append(issue.code)

    for contract in NON_ADMIN_RESOURCE_CONTRACTS:
        rows.append(
            CompatibilityMatrixRow(
                resource=contract.resource,
                menu_resource=contract.menu_resource,
                minimum_role=contract.minimum_role,
                functional_actions=contract.functional_actions,
                implemented=True,
                shipped_role_consistency=tuple(
                    sorted(set(issues_by_resource.get(contract.resource, [])))
                ),
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
