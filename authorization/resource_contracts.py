"""Mirrored non-admin workflow/UI resource contracts.

These contracts describe the supported FAB-aligned, non-DB resource surface for
workflow and UI parity. They intentionally exclude FAB DB-backed security/admin
pages such as Users, Roles, Passwords, Permission Views, and View Menus.
"""

from __future__ import annotations

from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.vocabulary import (
    ACTION_CAN_CREATE,
    ACTION_CAN_EDIT,
    ACTION_CAN_READ,
    ACTION_MENU_ACCESS,
    RESOURCE_ASSET,
    RESOURCE_ASSET_ALIAS,
    RESOURCE_AUDIT_LOG,
    RESOURCE_BACKFILL,
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


@dataclass(frozen=True, slots=True)
class ResourceContract:
    """Describe one mirrored non-admin FAB workflow/UI resource contract."""

    resource: str
    menu_resource: str
    minimum_role: str
    functional_actions: tuple[str, ...]
    menu_action: str = ACTION_MENU_ACCESS
    notes: str = ""


NON_ADMIN_RESOURCE_CONTRACTS: tuple[ResourceContract, ...] = (
    ResourceContract(
        RESOURCE_WEBSITE,
        RESOURCE_WEBSITE,
        "Public",
        (ACTION_CAN_READ,),
        notes="Landing/site navigation surface.",
    ),
    ResourceContract(
        RESOURCE_DOCS,
        RESOURCE_DOCS,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="Documentation UI surface.",
    ),
    ResourceContract(
        RESOURCE_MY_PROFILE,
        RESOURCE_MY_PROFILE,
        "Viewer",
        (ACTION_CAN_READ, ACTION_CAN_EDIT),
        notes="Self-service profile access.",
    ),
    ResourceContract(
        RESOURCE_MY_PASSWORD,
        RESOURCE_MY_PASSWORD,
        "Viewer",
        (ACTION_CAN_READ, ACTION_CAN_EDIT),
        notes="Self-service password access.",
    ),
    ResourceContract(RESOURCE_DAG, RESOURCE_DAG, "Viewer", (ACTION_CAN_READ,)),
    ResourceContract(
        RESOURCE_DAG_RUN,
        RESOURCE_DAG,
        "User",
        (ACTION_CAN_READ, ACTION_CAN_CREATE),
        notes="DAG run creation/read is anchored under the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_DAG_CODE,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="DAG code is reachable from the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_DAG_DEPENDENCIES,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="DAG dependencies are reachable from the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_DAG_VERSION,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="DAG versions are reachable from the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_DAG_WARNING,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="DAG warnings are reachable from the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_TASK_INSTANCE,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="Task instance views are anchored under the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_TASK_LOG,
        RESOURCE_DAG,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="Task log views are anchored under the DAGs UI.",
    ),
    ResourceContract(
        RESOURCE_TASK_RESCHEDULE,
        RESOURCE_TASK_RESCHEDULE,
        "Admin",
        (ACTION_CAN_READ,),
        notes="Mirrored FAB workflow/admin-adjacent resource without DB-backed admin pages.",
    ),
    ResourceContract(
        RESOURCE_XCOM,
        RESOURCE_DAG,
        "Op",
        (ACTION_CAN_READ,),
        notes="XCom views are anchored under the DAGs UI.",
    ),
    ResourceContract(RESOURCE_ASSET, RESOURCE_ASSET, "Viewer", (ACTION_CAN_READ,)),
    ResourceContract(
        RESOURCE_ASSET_ALIAS,
        RESOURCE_ASSET,
        "Viewer",
        (ACTION_CAN_READ,),
        notes="Asset aliases are anchored under the Assets UI.",
    ),
    ResourceContract(
        RESOURCE_POOL,
        RESOURCE_POOL,
        "Op",
        (ACTION_CAN_READ, ACTION_CAN_EDIT, ACTION_CAN_CREATE),
    ),
    ResourceContract(
        RESOURCE_CONNECTION,
        RESOURCE_CONNECTION,
        "Op",
        (ACTION_CAN_READ, ACTION_CAN_EDIT, ACTION_CAN_CREATE),
    ),
    ResourceContract(
        RESOURCE_VARIABLE,
        RESOURCE_VARIABLE,
        "Op",
        (ACTION_CAN_READ, ACTION_CAN_EDIT, ACTION_CAN_CREATE),
    ),
    ResourceContract(RESOURCE_CONFIG, RESOURCE_CONFIG, "Op", (ACTION_CAN_READ,)),
    ResourceContract(RESOURCE_PROVIDER, RESOURCE_PROVIDER, "Op", (ACTION_CAN_READ,)),
    ResourceContract(RESOURCE_PLUGIN, RESOURCE_PLUGIN, "Op", (ACTION_CAN_READ,)),
    ResourceContract(
        RESOURCE_TRIGGER,
        RESOURCE_TRIGGER,
        "Admin",
        (ACTION_CAN_READ,),
        notes="Trigger inspection is admin-scoped in FAB docs.",
    ),
    ResourceContract(
        RESOURCE_IMPORT_ERROR, RESOURCE_IMPORT_ERROR, "Admin", (ACTION_CAN_READ,)
    ),
    ResourceContract(RESOURCE_JOB, RESOURCE_JOB, "Admin", (ACTION_CAN_READ,)),
    ResourceContract(
        RESOURCE_SLA_MISSES, RESOURCE_SLA_MISSES, "Admin", (ACTION_CAN_READ,)
    ),
    ResourceContract(
        RESOURCE_AUDIT_LOG, RESOURCE_AUDIT_LOG, "Admin", (ACTION_CAN_READ,)
    ),
    ResourceContract(
        RESOURCE_BACKFILL,
        RESOURCE_BACKFILL,
        "Admin",
        (ACTION_CAN_READ, ACTION_CAN_CREATE),
        notes="Compatibility-only hook mapped to DAG Run semantics at runtime.",
    ),
    ResourceContract(
        RESOURCE_CLUSTER_ACTIVITY,
        RESOURCE_CLUSTER_ACTIVITY,
        "Admin",
        (ACTION_CAN_READ,),
    ),
)


def official_role_rank(role_name: str) -> int:
    """Return the ordering rank of an official FAB role."""
    try:
        return FAB_OFFICIAL_ROLE_ORDER.index(role_name)
    except ValueError:
        return -1


def role_meets_minimum(role_name: str, minimum_role: str) -> bool:
    """Return whether a role sits at or above a contract's minimum role."""
    role_rank = official_role_rank(role_name)
    minimum_rank = official_role_rank(minimum_role)
    return role_rank >= 0 and minimum_rank >= 0 and role_rank >= minimum_rank
