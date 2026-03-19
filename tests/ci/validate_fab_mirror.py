from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Iterable

from rbac_providers_auth_manager.config_runtime.parser import load_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"
EXCLUDED_DB_BACKED_RESOURCES = {"Password", "Roles"}
ROLE_ORDER = ("Viewer", "User", "Op", "Admin")


def _normalize_permissions(perms: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    normalized = {
        (str(action), str(resource))
        for action, resource in perms
        if str(resource) not in EXCLUDED_DB_BACKED_RESOURCES
    }
    return [
        {"action": action, "resource": resource}
        for action, resource in sorted(normalized)
    ]


def _local_role_permissions() -> dict[str, list[dict[str, str]]]:
    cfg = load_config(CONFIG_PATH)
    roles = cfg.roles.role_to_permissions
    return {
        role_name: _normalize_permissions(roles.get(role_name, set()))
        for role_name in ROLE_ORDER
    }


def _provider_role_permissions() -> dict[str, list[dict[str, str]]]:
    importlib.import_module("airflow")
    provider_mod = importlib.import_module(
        "airflow.providers.fab.auth_manager.security_manager.override"
    )
    manager_cls = provider_mod.FabAirflowSecurityManagerOverride
    return {
        "Viewer": _normalize_permissions(manager_cls.VIEWER_PERMISSIONS),
        "User": _normalize_permissions(
            set(manager_cls.VIEWER_PERMISSIONS) | set(manager_cls.USER_PERMISSIONS)
        ),
        "Op": _normalize_permissions(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
        ),
        "Admin": _normalize_permissions(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
            | set(manager_cls.ADMIN_PERMISSIONS)
        ),
    }


def _diff(
    local: dict[str, list[dict[str, str]]],
    official: dict[str, list[dict[str, str]]],
) -> dict[str, dict[str, list[dict[str, str]]]]:
    diff: dict[str, dict[str, list[dict[str, str]]]] = {}
    for role_name in ROLE_ORDER:
        local_set = {(item["action"], item["resource"]) for item in local[role_name]}
        official_set = {
            (item["action"], item["resource"]) for item in official[role_name]
        }
        missing = _normalize_permissions(official_set - local_set)
        extra = _normalize_permissions(local_set - official_set)
        diff[role_name] = {"missing": missing, "extra": extra}
    return diff


def main() -> None:
    artifact_dir = Path(".ci-artifacts/fab-provider")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    local = _local_role_permissions()
    official = _provider_role_permissions()
    diff = _diff(local, official)

    (artifact_dir / "local-rbac-snapshot.json").write_text(
        json.dumps(local, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "official-fab-rbac-snapshot.json").write_text(
        json.dumps(official, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "rbac-snapshot-diff.json").write_text(
        json.dumps(diff, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary_lines = ["# FAB RBAC snapshot diff", ""]
    has_missing = False
    for role_name in ROLE_ORDER:
        missing = diff[role_name]["missing"]
        extra = diff[role_name]["extra"]
        summary_lines.append(f"## {role_name}")
        summary_lines.append(f"- missing: {len(missing)}")
        summary_lines.append(f"- extra: {len(extra)}")
        summary_lines.append("")
        if missing:
            has_missing = True
    (artifact_dir / "rbac-snapshot-summary.md").write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(diff, indent=2, sort_keys=True))
    if has_missing:
        raise SystemExit(
            "Official FAB provider permissions are missing from local mirrored RBAC snapshot"
        )


if __name__ == "__main__":
    main()
