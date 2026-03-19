from __future__ import annotations

from pathlib import Path

from rbac_providers_auth_manager.config_runtime.parser import load_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"


def _role_permissions(role_name: str) -> set[tuple[str, str]]:
    cfg = load_config(CONFIG_PATH)
    permissions = cfg.roles.role_to_permissions.get(role_name)
    if permissions is None:
        raise AssertionError(f"missing role in bundled permissions.ini: {role_name}")
    return set(permissions)


def test_viewer_role_contains_latest_fab_350_non_db_baseline() -> None:
    viewer = _role_permissions("Viewer")
    expected = {
        ("can_read", "DAGs"),
        ("can_read", "DAG Dependencies"),
        ("can_read", "DAG Code"),
        ("can_read", "DAG Runs"),
        ("can_read", "DAG Versions"),
        ("can_read", "DAG Warnings"),
        ("can_read", "Assets"),
        ("can_read", "Asset Aliases"),
        ("can_read", "Backfills"),
        ("can_read", "Cluster Activity"),
        ("can_read", "Configurations"),
        ("can_read", "ImportError"),
        ("can_read", "Jobs"),
        ("can_read", "Pools"),
        ("can_read", "My Password"),
        ("can_edit", "My Password"),
        ("can_read", "My Profile"),
        ("can_edit", "My Profile"),
        ("can_read", "SLA Misses"),
        ("can_read", "Task Instances"),
        ("can_read", "Task Logs"),
        ("can_read", "XComs"),
        ("can_read", "HITL Detail"),
        ("can_read", "Website"),
        ("menu_access", "Browse"),
        ("menu_access", "DAGs"),
        ("menu_access", "DAG Dependencies"),
        ("menu_access", "DAG Runs"),
        ("menu_access", "Assets"),
        ("menu_access", "Cluster Activity"),
        ("menu_access", "Documentation"),
        ("menu_access", "Docs"),
        ("menu_access", "Jobs"),
        ("menu_access", "SLA Misses"),
        ("menu_access", "Task Instances"),
    }
    missing = expected - viewer
    assert not missing, f"Viewer is missing latest FAB 3.5.0 mirrored permissions: {sorted(missing)}"


def test_user_role_contains_latest_fab_350_additions() -> None:
    user = _role_permissions("User")
    expected = {
        ("can_edit", "DAGs"),
        ("can_delete", "DAGs"),
        ("can_create", "Task Instances"),
        ("can_edit", "Task Instances"),
        ("can_delete", "Task Instances"),
        ("can_create", "DAG Runs"),
        ("can_edit", "DAG Runs"),
        ("can_delete", "DAG Runs"),
        ("can_edit", "HITL Detail"),
        ("can_create", "Assets"),
    }
    missing = expected - user
    assert not missing, f"User is missing latest FAB 3.5.0 mirrored permissions: {sorted(missing)}"


def test_op_role_contains_latest_fab_350_additions() -> None:
    op = _role_permissions("Op")
    expected = {
        ("menu_access", "Admin"),
        ("menu_access", "Configurations"),
        ("menu_access", "Connections"),
        ("menu_access", "Pools"),
        ("menu_access", "Plugins"),
        ("menu_access", "Variables"),
        ("menu_access", "Providers"),
        ("menu_access", "XComs"),
        ("menu_access", "HITL Detail"),
        ("can_read", "Configurations"),
        ("can_create", "Connections"),
        ("can_read", "Connections"),
        ("can_edit", "Connections"),
        ("can_delete", "Connections"),
        ("can_create", "Pools"),
        ("can_edit", "Pools"),
        ("can_delete", "Pools"),
        ("can_read", "Plugins"),
        ("can_read", "Providers"),
        ("can_create", "Variables"),
        ("can_read", "Variables"),
        ("can_edit", "Variables"),
        ("can_delete", "Variables"),
        ("can_create", "XComs"),
        ("can_edit", "XComs"),
        ("can_delete", "XComs"),
        ("can_create", "Assets"),
        ("can_delete", "Assets"),
        ("can_create", "Backfills"),
        ("can_edit", "Backfills"),
        ("can_delete", "Backfills"),
    }
    missing = expected - op
    assert not missing, f"Op is missing latest FAB 3.5.0 mirrored permissions: {sorted(missing)}"


def test_admin_role_contains_latest_fab_350_non_db_admin_additions() -> None:
    admin = _role_permissions("Admin")
    expected = {
        ("can_read", "Audit Logs"),
        ("menu_access", "Audit Logs"),
        ("can_read", "Task Reschedules"),
        ("menu_access", "Task Reschedules"),
        ("can_read", "Triggers"),
        ("menu_access", "Triggers"),
    }
    missing = expected - admin
    assert not missing, f"Admin is missing latest FAB 3.5.0 mirrored permissions: {sorted(missing)}"
