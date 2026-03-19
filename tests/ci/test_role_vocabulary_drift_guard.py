from __future__ import annotations

from pathlib import Path

from rbac_providers_auth_manager.config_runtime.parser import load_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"


def _all_permissions() -> set[tuple[str, str]]:
    cfg = load_config(CONFIG_PATH)
    all_permissions: set[tuple[str, str]] = set()
    for permissions in cfg.roles.role_to_permissions.values():
        all_permissions.update(permissions)
    return all_permissions


def _resources() -> set[str]:
    return {resource for _action, resource in _all_permissions()}


def _actions() -> set[str]:
    return {action for action, _resource in _all_permissions()}


def test_docs_and_documentation_remain_distinct_menu_targets() -> None:
    permissions = _all_permissions()
    assert ("menu_access", "Docs") in permissions
    assert ("menu_access", "Documentation") in permissions
    assert "Docs" != "Documentation"


def test_curated_resource_names_match_expected_upstream_spelling() -> None:
    resources = _resources()
    expected = {
        "Audit Logs",
        "Backfills",
        "Cluster Activity",
        "Configurations",
        "DAG Code",
        "DAG Dependencies",
        "DAG Runs",
        "DAG Versions",
        "DAG Warnings",
        "Docs",
        "Documentation",
        "HITL Detail",
        "ImportError",
        "Task Logs",
        "Task Reschedules",
        "Triggers",
        "XComs",
    }
    missing = expected - resources
    assert not missing, f"Missing curated vocabulary resources: {sorted(missing)}"


def test_forbidden_alias_spellings_do_not_appear_in_permissions_bundle() -> None:
    resources = _resources()
    forbidden = {
        "Audit Log",
        "Backfill",
        "ClusterActivity",
        "Config",
        "Dag Code",
        "Dag Dependencies",
        "Dag Runs",
        "Dag Versions",
        "Dag Warnings",
        "Doc",
        "Import Error",
        "Task Log",
        "TaskReschedules",
        "Trigger",
        "XCom",
    }
    assert resources.isdisjoint(forbidden), (
        "Detected vocabulary drift aliases in permissions bundle: "
        f"{sorted(resources & forbidden)}"
    )


def test_resource_vocabulary_has_no_whitespace_drift() -> None:
    resources = _resources()
    bad = sorted(
        resource
        for resource in resources
        if resource != resource.strip() or "  " in resource or "_" in resource
    )
    assert not bad, f"Resources contain whitespace or separator drift: {bad}"


def test_action_vocabulary_is_known_and_stable() -> None:
    actions = _actions()
    allowed = {
        "can_create",
        "can_delete",
        "can_edit",
        "can_read",
        "menu_access",
    }
    assert actions <= allowed, f"Unknown action vocabulary detected: {sorted(actions - allowed)}"
    assert {"can_read", "menu_access"}.issubset(actions)
