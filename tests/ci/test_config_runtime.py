from __future__ import annotations

from pathlib import Path

from rbac_providers_auth_manager.config_runtime.models import (
    EXPECTED_PLUGIN_FAMILY,
    SUPPORTED_SCHEMA_VERSION,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config


def test_bundled_permissions_ini_parses() -> None:
    ini_path = (
        Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"
    )
    cfg = load_config(ini_path)

    assert cfg.meta.plugin_family == EXPECTED_PLUGIN_FAMILY
    assert cfg.meta.schema_version == SUPPORTED_SCHEMA_VERSION
    assert cfg.general.enable_ldap is True
    assert cfg.ldap is not None
    assert cfg.ui.enable_rich_login_status is True
    assert "Viewer" in cfg.roles.role_to_permissions
    assert len(cfg.advisories) >= 0
