"""Canonical authorization vocabulary and normalization helpers.

This module contains the stable action/resource names used across the auth
manager, config parsing, UI authorization checks, and compatibility adapters.
Keeping the vocabulary separate from policy evaluation makes it easier to track
upstream Airflow/FAB permission drift without touching the policy engine.
"""

from __future__ import annotations

ACTION_MENU_ACCESS = "menu_access"
ACTION_CAN_READ = "can_read"
ACTION_CAN_EDIT = "can_edit"
ACTION_CAN_CREATE = "can_create"
ACTION_CAN_DELETE = "can_delete"

RESOURCE_DAG = "DAGs"
RESOURCE_DAG_RUN = "DAG Runs"
RESOURCE_DAG_CODE = "DAG Code"
RESOURCE_DAG_DEPENDENCIES = "DAG Dependencies"
RESOURCE_DAG_VERSION = "DAG Versions"
RESOURCE_DAG_WARNING = "DAG Warnings"

RESOURCE_TASK_INSTANCE = "Task Instances"
RESOURCE_TASK_LOG = "Task Logs"
RESOURCE_TASK_RESCHEDULE = "Task Reschedules"
RESOURCE_XCOM = "XComs"

RESOURCE_MY_PROFILE = "My Profile"
RESOURCE_MY_PASSWORD = "My Password"

RESOURCE_POOL = "Pools"
RESOURCE_CONNECTION = "Connections"
RESOURCE_VARIABLE = "Variables"

RESOURCE_JOB = "Jobs"
RESOURCE_SLA_MISSES = "SLA Misses"
RESOURCE_IMPORT_ERROR = "ImportError"

RESOURCE_CLUSTER_ACTIVITY = "Cluster Activity"
RESOURCE_BACKFILL = "Backfills"

RESOURCE_ASSET = "Assets"
RESOURCE_ASSET_ALIAS = "Asset Aliases"

RESOURCE_ADMIN_MENU = "Admin"
RESOURCE_BROWSE_MENU = "Browse"

RESOURCE_DOCS = "Documentation"
RESOURCE_DOCS_MENU = "Docs"

RESOURCE_WEBSITE = "Website"
RESOURCE_PLUGIN = "Plugins"
RESOURCE_PROVIDER = "Providers"
RESOURCE_TRIGGER = "Triggers"
RESOURCE_CONFIG = "Configurations"

RESOURCE_AUDIT_LOG = "Audit Logs"
RESOURCE_HITL_DETAIL = "HITL Detail"

RESOURCE_DAG_PREFIX = "DAG:"
RESOURCE_DAG_RUN_PREFIX = "DAG Run:"

_RESOURCE_ALIASES: dict[str, str] = {
    "import errors": RESOURCE_IMPORT_ERROR,
    "importerrors": RESOURCE_IMPORT_ERROR,
    "importerror": RESOURCE_IMPORT_ERROR,
    "dag": RESOURCE_DAG,
    "dags": RESOURCE_DAG,
    "dag run": RESOURCE_DAG_RUN,
    "dag runs": RESOURCE_DAG_RUN,
    "task instance": RESOURCE_TASK_INSTANCE,
    "task instances": RESOURCE_TASK_INSTANCE,
    "task log": RESOURCE_TASK_LOG,
    "task logs": RESOURCE_TASK_LOG,
    "task reschedule": RESOURCE_TASK_RESCHEDULE,
    "task reschedules": RESOURCE_TASK_RESCHEDULE,
    "xcom": RESOURCE_XCOM,
    "xcoms": RESOURCE_XCOM,
    "asset alias": RESOURCE_ASSET_ALIAS,
    "asset aliases": RESOURCE_ASSET_ALIAS,
    "my profile": RESOURCE_MY_PROFILE,
    "my password": RESOURCE_MY_PASSWORD,
    "admin": RESOURCE_ADMIN_MENU,
    "browse": RESOURCE_BROWSE_MENU,
    "docs": RESOURCE_DOCS_MENU,
    "documentation": RESOURCE_DOCS,
    "audit log": RESOURCE_AUDIT_LOG,
    "audit logs": RESOURCE_AUDIT_LOG,
    "required action": RESOURCE_HITL_DETAIL,
    "required actions": RESOURCE_HITL_DETAIL,
    "configs": RESOURCE_CONFIG,
    "configurations": RESOURCE_CONFIG,
}

_ACTION_ALIASES: dict[str, str] = {
    "menu": ACTION_MENU_ACCESS,
    "menu_access": ACTION_MENU_ACCESS,
    "can_access_menu": ACTION_MENU_ACCESS,
}


def normalize_action(action: str) -> str:
    """Normalize an action name into the canonical FAB-style vocabulary."""
    normalized = (action or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(normalized, normalized)


def normalize_resource(resource: str) -> str:
    """Normalize a resource name into the canonical vocabulary."""
    normalized = " ".join((resource or "").strip().split())
    if not normalized:
        return ""
    return _RESOURCE_ALIASES.get(normalized.casefold(), normalized)
