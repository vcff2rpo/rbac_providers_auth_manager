"""Permission-level contracts for the mirrored non-DB FAB permission surface.

These contracts deliberately model the official Airflow FAB provider permission
surface at the *permission* level rather than the older resource-level minimum
role approximation. This keeps the shipped contract aligned with official FAB
for non-DB-backed workflow/UI resources where different actions on the same
resource may have different role ladders.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.vocabulary import (
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
    RESOURCE_DAG_RUN,
    RESOURCE_DAG_VERSION,
    RESOURCE_DAG_WARNING,
    RESOURCE_DOCS,
    RESOURCE_DOCS_MENU,
    RESOURCE_HITL_DETAIL,
    RESOURCE_IMPORT_ERROR,
    RESOURCE_JOB,
    RESOURCE_MY_PASSWORD,
    RESOURCE_MY_PROFILE,
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
)

FAB_OFFICIAL_ROLE_ORDER: tuple[str, ...] = ("Public", "Viewer", "User", "Op", "Admin")
MIRRORED_ROLE_ORDER: tuple[str, ...] = ("Viewer", "User", "Op", "Admin")


@dataclass(frozen=True, slots=True)
class PermissionContract:
    """Describe one mirrored non-DB FAB permission contract row."""

    resource: str
    action: str
    minimum_role: str
    notes: str = ""

    @property
    def expected_roles(self) -> tuple[str, ...]:
        """Return the official roles expected to own this permission."""
        return roles_at_or_above(self.minimum_role)


NON_ADMIN_PERMISSION_CONTRACTS: tuple[PermissionContract, ...] = (
    PermissionContract(RESOURCE_ADMIN_MENU, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_ASSET_ALIAS, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_ASSET, ACTION_CAN_CREATE, "User"),
    PermissionContract(RESOURCE_ASSET, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_ASSET, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_ASSET, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_AUDIT_LOG, ACTION_CAN_READ, "Admin"),
    PermissionContract(RESOURCE_AUDIT_LOG, ACTION_MENU_ACCESS, "Admin"),
    PermissionContract(RESOURCE_BACKFILL, ACTION_CAN_CREATE, "Op"),
    PermissionContract(RESOURCE_BACKFILL, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_BACKFILL, ACTION_CAN_EDIT, "Op"),
    PermissionContract(RESOURCE_BACKFILL, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_BROWSE_MENU, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_CLUSTER_ACTIVITY, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_CLUSTER_ACTIVITY, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_CONFIG, ACTION_CAN_READ, "Op"),
    PermissionContract(RESOURCE_CONFIG, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_CONNECTION, ACTION_CAN_CREATE, "Op"),
    PermissionContract(RESOURCE_CONNECTION, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_CONNECTION, ACTION_CAN_EDIT, "Op"),
    PermissionContract(RESOURCE_CONNECTION, ACTION_CAN_READ, "Op"),
    PermissionContract(RESOURCE_CONNECTION, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_DAG_CODE, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG_DEPENDENCIES, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG_DEPENDENCIES, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_DAG_RUN, ACTION_CAN_CREATE, "User"),
    PermissionContract(RESOURCE_DAG_RUN, ACTION_CAN_DELETE, "User"),
    PermissionContract(RESOURCE_DAG_RUN, ACTION_CAN_EDIT, "User"),
    PermissionContract(RESOURCE_DAG_RUN, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG_RUN, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_DAG_VERSION, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG_WARNING, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG, ACTION_CAN_DELETE, "User"),
    PermissionContract(RESOURCE_DAG, ACTION_CAN_EDIT, "User"),
    PermissionContract(RESOURCE_DAG, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_DAG, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_DOCS_MENU, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(
        RESOURCE_DOCS,
        ACTION_MENU_ACCESS,
        "Viewer",
        notes="Official FAB exposes Documentation as a view-level menu target.",
    ),
    PermissionContract(RESOURCE_HITL_DETAIL, ACTION_CAN_EDIT, "User"),
    PermissionContract(RESOURCE_HITL_DETAIL, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_HITL_DETAIL, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_IMPORT_ERROR, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_JOB, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_JOB, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_MY_PASSWORD, ACTION_CAN_EDIT, "Viewer"),
    PermissionContract(RESOURCE_MY_PASSWORD, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_MY_PROFILE, ACTION_CAN_EDIT, "Viewer"),
    PermissionContract(RESOURCE_MY_PROFILE, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_PLUGIN, ACTION_CAN_READ, "Op"),
    PermissionContract(RESOURCE_PLUGIN, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_POOL, ACTION_CAN_CREATE, "Op"),
    PermissionContract(RESOURCE_POOL, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_POOL, ACTION_CAN_EDIT, "Op"),
    PermissionContract(RESOURCE_POOL, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_POOL, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_PROVIDER, ACTION_CAN_READ, "Op"),
    PermissionContract(RESOURCE_PROVIDER, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_SLA_MISSES, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_SLA_MISSES, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_TASK_INSTANCE, ACTION_CAN_CREATE, "User"),
    PermissionContract(RESOURCE_TASK_INSTANCE, ACTION_CAN_DELETE, "User"),
    PermissionContract(RESOURCE_TASK_INSTANCE, ACTION_CAN_EDIT, "User"),
    PermissionContract(RESOURCE_TASK_INSTANCE, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_TASK_INSTANCE, ACTION_MENU_ACCESS, "Viewer"),
    PermissionContract(RESOURCE_TASK_LOG, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_TASK_RESCHEDULE, ACTION_CAN_READ, "Admin"),
    PermissionContract(RESOURCE_TASK_RESCHEDULE, ACTION_MENU_ACCESS, "Admin"),
    PermissionContract(RESOURCE_TRIGGER, ACTION_CAN_READ, "Admin"),
    PermissionContract(RESOURCE_TRIGGER, ACTION_MENU_ACCESS, "Admin"),
    PermissionContract(RESOURCE_VARIABLE, ACTION_CAN_CREATE, "Op"),
    PermissionContract(RESOURCE_VARIABLE, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_VARIABLE, ACTION_CAN_EDIT, "Op"),
    PermissionContract(RESOURCE_VARIABLE, ACTION_CAN_READ, "Op"),
    PermissionContract(RESOURCE_VARIABLE, ACTION_MENU_ACCESS, "Op"),
    PermissionContract(RESOURCE_WEBSITE, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_XCOM, ACTION_CAN_CREATE, "Op"),
    PermissionContract(RESOURCE_XCOM, ACTION_CAN_DELETE, "Op"),
    PermissionContract(RESOURCE_XCOM, ACTION_CAN_EDIT, "Op"),
    PermissionContract(RESOURCE_XCOM, ACTION_CAN_READ, "Viewer"),
    PermissionContract(RESOURCE_XCOM, ACTION_MENU_ACCESS, "Op"),
)


def official_role_rank(role_name: str) -> int:
    """Return the ordering rank of an official FAB role."""
    try:
        return FAB_OFFICIAL_ROLE_ORDER.index(role_name)
    except ValueError:
        return -1


def role_meets_minimum(role_name: str, minimum_role: str) -> bool:
    """Return whether a role sits at or above a permission contract minimum."""
    role_rank = official_role_rank(role_name)
    minimum_rank = official_role_rank(minimum_role)
    return role_rank >= 0 and minimum_rank >= 0 and role_rank >= minimum_rank


def roles_at_or_above(minimum_role: str) -> tuple[str, ...]:
    """Return mirrored official roles at or above ``minimum_role``."""
    return tuple(
        role_name
        for role_name in MIRRORED_ROLE_ORDER
        if role_meets_minimum(role_name, minimum_role)
    )


def contract_permissions_by_role(
    contracts: Iterable[PermissionContract] = NON_ADMIN_PERMISSION_CONTRACTS,
) -> dict[str, frozenset[tuple[str, str]]]:
    """Return the permission contract expanded into cumulative official roles."""
    permissions: dict[str, set[tuple[str, str]]] = {
        role_name: set() for role_name in MIRRORED_ROLE_ORDER
    }
    for contract in contracts:
        permission = (contract.action, contract.resource)
        for role_name in roles_at_or_above(contract.minimum_role):
            permissions[role_name].add(permission)
    return {
        role_name: frozenset(sorted(role_permissions))
        for role_name, role_permissions in permissions.items()
    }


__all__ = (
    "FAB_OFFICIAL_ROLE_ORDER",
    "MIRRORED_ROLE_ORDER",
    "NON_ADMIN_PERMISSION_CONTRACTS",
    "PermissionContract",
    "contract_permissions_by_role",
    "official_role_rank",
    "role_meets_minimum",
    "roles_at_or_above",
)
