from __future__ import annotations

from pathlib import Path

import pytest

from rbac_providers_auth_manager.config_runtime.parser import load_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"

EXCLUDED_DB_BACKED_RESOURCES = {
    "Password",
    "Roles",
}


@pytest.fixture(scope="module")
def provider_role_permissions() -> dict[str, set[tuple[str, str]]]:
    airflow = pytest.importorskip("airflow")
    provider_mod = pytest.importorskip(
        "airflow.providers.fab.auth_manager.security_manager.override"
    )
    manager_cls = provider_mod.FabAirflowSecurityManagerOverride
    return {
        "Viewer": set(manager_cls.VIEWER_PERMISSIONS),
        "User": set(manager_cls.VIEWER_PERMISSIONS) | set(manager_cls.USER_PERMISSIONS),
        "Op": set(manager_cls.VIEWER_PERMISSIONS)
        | set(manager_cls.USER_PERMISSIONS)
        | set(manager_cls.OP_PERMISSIONS),
        "Admin": set(manager_cls.VIEWER_PERMISSIONS)
        | set(manager_cls.USER_PERMISSIONS)
        | set(manager_cls.OP_PERMISSIONS)
        | set(manager_cls.ADMIN_PERMISSIONS),
    }


def _local_role_permissions() -> dict[str, set[tuple[str, str]]]:
    cfg = load_config(CONFIG_PATH)
    roles = cfg.roles.role_to_permissions
    return {
        role_name: set(roles.get(role_name, set()))
        for role_name in ("Viewer", "User", "Op", "Admin")
    }


def _filtered(perms: set[tuple[str, str]]) -> set[tuple[str, str]]:
    filtered: set[tuple[str, str]] = set()
    for action, resource in perms:
        if resource in EXCLUDED_DB_BACKED_RESOURCES:
            continue
        filtered.add((str(action), str(resource)))
    return filtered


def test_bundled_permissions_cover_official_fab_provider_350_non_db_subset(
    provider_role_permissions: dict[str, set[tuple[str, str]]],
) -> None:
    local = _local_role_permissions()
    for role_name, official_perms in provider_role_permissions.items():
        official_filtered = _filtered(official_perms)
        local_filtered = _filtered(local[role_name])
        missing = sorted(official_filtered - local_filtered)
        assert not missing, (
            f"Bundled permissions.ini role {role_name} is missing official "
            f"apache-airflow-providers-fab 3.5.0 non-DB permissions: {missing}"
        )
