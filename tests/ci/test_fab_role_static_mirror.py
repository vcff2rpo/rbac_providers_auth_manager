from __future__ import annotations

from pathlib import Path

from rbac_providers_auth_manager.authorization.resource_contracts import (
    contract_permissions_by_role,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"
ROLE_ORDER = ("Viewer", "User", "Op", "Admin")


def _bundled_permissions() -> dict[str, set[tuple[str, str]]]:
    cfg = load_config(CONFIG_PATH)
    return {
        role_name: set(cfg.roles.role_to_permissions.get(role_name) or set())
        for role_name in ROLE_ORDER
    }


def test_bundled_permissions_ini_matches_shipped_non_db_contract_exactly() -> None:
    bundled = _bundled_permissions()
    contract = {
        role_name: set(permissions)
        for role_name, permissions in contract_permissions_by_role().items()
    }

    for role_name in ROLE_ORDER:
        assert bundled[role_name] == contract[role_name], (
            f"{role_name} drifted from the shipped non-DB FAB contract. "
            f"Missing={sorted(contract[role_name] - bundled[role_name])}; "
            f"Extra={sorted(bundled[role_name] - contract[role_name])}"
        )


def test_xcom_and_backfill_permissions_match_official_role_ladder() -> None:
    bundled = _bundled_permissions()

    viewer = bundled["Viewer"]
    user = bundled["User"]
    op = bundled["Op"]
    admin = bundled["Admin"]

    assert ("can_read", "XComs") in viewer
    assert ("menu_access", "XComs") not in viewer
    assert ("can_create", "XComs") not in user
    assert {
        ("can_create", "XComs"),
        ("can_edit", "XComs"),
        ("can_delete", "XComs"),
        ("menu_access", "XComs"),
    } <= op
    assert {
        ("can_create", "Backfills"),
        ("can_edit", "Backfills"),
        ("can_delete", "Backfills"),
    } <= op
    assert ("menu_access", "Backfills") not in admin


def test_docs_profile_and_website_permissions_match_official_non_db_surface() -> None:
    bundled = _bundled_permissions()
    viewer = bundled["Viewer"]

    assert ("menu_access", "Docs") in viewer
    assert ("menu_access", "Documentation") in viewer
    assert ("can_read", "Documentation") not in viewer
    assert ("menu_access", "Website") not in viewer
    assert ("menu_access", "My Profile") not in viewer
    assert ("menu_access", "My Password") not in viewer
