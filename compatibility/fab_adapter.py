"""FAB-oriented resource mapping helpers for Airflow auth-manager objects.

Airflow's auth-manager API still exposes several FAB-shaped enums and menu
objects. This module centralizes the translation between those public Airflow
objects and the plugin's internal resource vocabulary so the auth manager does
not carry a large block of version-sensitive mapping tables.
"""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.compatibility.airflow_public_api import MenuItem
from rbac_providers_auth_manager.compatibility.internal_shims import (
    AccessView,
    DagAccessEntity,
)
from rbac_providers_auth_manager.authorization.rbac import (
    RESOURCE_ADMIN_MENU,
    RESOURCE_ASSET,
    RESOURCE_AUDIT_LOG,
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
    RESOURCE_HITL_DETAIL,
    RESOURCE_IMPORT_ERROR,
    RESOURCE_JOB,
    RESOURCE_PLUGIN,
    RESOURCE_POOL,
    RESOURCE_PROVIDER,
    RESOURCE_TASK_INSTANCE,
    RESOURCE_TASK_LOG,
    RESOURCE_TRIGGER,
    RESOURCE_VARIABLE,
    RESOURCE_WEBSITE,
    RESOURCE_XCOM,
)

_MAP_DAG_ACCESS_ENTITY_TO_RESOURCE_TYPE: dict[Any, tuple[str, ...]] = {
    getattr(DagAccessEntity, "AUDIT_LOG", "AUDIT_LOG"): (RESOURCE_AUDIT_LOG,),
    getattr(DagAccessEntity, "CODE", "CODE"): (RESOURCE_DAG_CODE,),
    getattr(DagAccessEntity, "DEPENDENCIES", "DEPENDENCIES"): (
        RESOURCE_DAG_DEPENDENCIES,
    ),
    getattr(DagAccessEntity, "RUN", "RUN"): (RESOURCE_DAG_RUN,),
    getattr(DagAccessEntity, "TASK", "TASK"): (RESOURCE_TASK_INSTANCE,),
    getattr(DagAccessEntity, "TASK_INSTANCE", "TASK_INSTANCE"): (
        RESOURCE_DAG_RUN,
        RESOURCE_TASK_INSTANCE,
    ),
    getattr(DagAccessEntity, "TASK_LOGS", "TASK_LOGS"): (RESOURCE_TASK_LOG,),
    getattr(DagAccessEntity, "VERSION", "VERSION"): (RESOURCE_DAG_VERSION,),
    getattr(DagAccessEntity, "WARNING", "WARNING"): (RESOURCE_DAG_WARNING,),
    getattr(DagAccessEntity, "XCOM", "XCOM"): (RESOURCE_XCOM,),
}

if hasattr(DagAccessEntity, "HITL_DETAIL"):
    _MAP_DAG_ACCESS_ENTITY_TO_RESOURCE_TYPE[getattr(DagAccessEntity, "HITL_DETAIL")] = (
        RESOURCE_HITL_DETAIL,
    )

_MAP_ACCESS_VIEW_TO_RESOURCE_TYPE: dict[Any, str] = {
    getattr(
        AccessView, "CLUSTER_ACTIVITY", "CLUSTER_ACTIVITY"
    ): RESOURCE_CLUSTER_ACTIVITY,
    getattr(AccessView, "DOCS", "DOCS"): RESOURCE_DOCS,
    getattr(AccessView, "IMPORT_ERRORS", "IMPORT_ERRORS"): RESOURCE_IMPORT_ERROR,
    getattr(AccessView, "JOBS", "JOBS"): RESOURCE_JOB,
    getattr(AccessView, "PLUGINS", "PLUGINS"): RESOURCE_PLUGIN,
    getattr(AccessView, "PROVIDERS", "PROVIDERS"): RESOURCE_PROVIDER,
    getattr(AccessView, "TRIGGERS", "TRIGGERS"): RESOURCE_TRIGGER,
    getattr(AccessView, "WEBSITE", "WEBSITE"): RESOURCE_WEBSITE,
}

_MAP_MENU_ITEM_TO_RESOURCE_TYPE: dict[Any, str] = {
    MenuItem.ASSETS: RESOURCE_ASSET,
    MenuItem.AUDIT_LOG: RESOURCE_AUDIT_LOG,
    MenuItem.CONFIG: RESOURCE_CONFIG,
    MenuItem.CONNECTIONS: RESOURCE_CONNECTION,
    MenuItem.DAGS: RESOURCE_DAG,
    MenuItem.DOCS: RESOURCE_DOCS,
    MenuItem.PLUGINS: RESOURCE_PLUGIN,
    MenuItem.POOLS: RESOURCE_POOL,
    MenuItem.PROVIDERS: RESOURCE_PROVIDER,
    MenuItem.VARIABLES: RESOURCE_VARIABLE,
    MenuItem.XCOMS: RESOURCE_XCOM,
}

for menu_name, menu_resource in (
    ("ADMIN", RESOURCE_ADMIN_MENU),
    ("BROWSE", RESOURCE_BROWSE_MENU),
):
    if hasattr(MenuItem, menu_name):
        _MAP_MENU_ITEM_TO_RESOURCE_TYPE[getattr(MenuItem, menu_name)] = menu_resource

if hasattr(MenuItem, "REQUIRED_ACTIONS"):
    _MAP_MENU_ITEM_TO_RESOURCE_TYPE[getattr(MenuItem, "REQUIRED_ACTIONS")] = (
        RESOURCE_HITL_DETAIL
    )


def access_view_to_resource_type(access_view: Any) -> str:
    """Translate an Airflow access-view value into an internal resource name."""
    return _MAP_ACCESS_VIEW_TO_RESOURCE_TYPE.get(
        access_view,
        getattr(access_view, "value", None) or str(access_view),
    )


def is_docs_access_view(access_view: Any) -> bool:
    """Return whether the supplied view represents the Airflow documentation page."""
    return access_view == getattr(AccessView, "DOCS", object())


def dag_access_entity_to_resource_types(access_entity: Any | None) -> tuple[str, ...]:
    """Translate a DAG access entity into one or more internal resource names."""
    if access_entity is None:
        return (RESOURCE_DAG,)
    return _MAP_DAG_ACCESS_ENTITY_TO_RESOURCE_TYPE.get(access_entity, (RESOURCE_DAG,))


def menu_item_to_resource_type(menu_item: Any) -> str:
    """Translate a menu item object into the underlying permission resource."""
    if menu_item in _MAP_MENU_ITEM_TO_RESOURCE_TYPE:
        return _MAP_MENU_ITEM_TO_RESOURCE_TYPE[menu_item]

    value = getattr(menu_item, "value", None)
    if isinstance(value, str) and value.strip():
        return value.strip()

    if isinstance(menu_item, dict):
        for key in ("name", "value", "title"):
            item_value = menu_item.get(key)
            if isinstance(item_value, str) and item_value.strip():
                return item_value.strip()

    return str(menu_item)


__all__ = (
    "access_view_to_resource_type",
    "dag_access_entity_to_resource_types",
    "is_docs_access_view",
    "menu_item_to_resource_type",
)
