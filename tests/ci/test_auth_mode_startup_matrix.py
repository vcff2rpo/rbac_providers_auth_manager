from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.requests import Request

from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.config import AuthConfig
from rbac_providers_auth_manager.config_runtime.advisories import (
    build_runtime_capability_report,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.services.flow_payloads import AuthFlowPayloadBuilder
from rbac_providers_auth_manager.ui.status_presenter import LoginStatusPresenter

from .permissions_fixture_loader import apply_env, case_metadata

FIXTURE_ROOT = (
    Path(__file__).resolve().parents[1] / "fixtures" / "permissions" / "load_config"
)


@dataclass(frozen=True)
class _CfgLoader:
    cfg: AuthConfig

    def get_config(self) -> AuthConfig:
        return self.cfg


class _Provider:
    def __init__(self, enabled: bool) -> None:
        self._enabled = enabled

    def is_enabled(self) -> bool:
        return self._enabled


class _UiRenderer:
    def __init__(self, manager: Any) -> None:
        self.status_presenter = LoginStatusPresenter(manager)


class _Manager:
    def __init__(self, cfg: AuthConfig) -> None:
        self._cfg_loader = _CfgLoader(cfg)
        self._ui_renderer = _UiRenderer(self)
        self._ldap_provider = _Provider(bool(cfg.ldap and cfg.ldap.enabled))
        self._entra_provider = _Provider(bool(cfg.entra_id and cfg.entra_id.enabled))

    def _refresh_if_needed(self) -> None:
        return None

    def _auth_config_broken(self) -> bool:
        return self._cfg_loader.cfg.validation.has_errors

    def _ui_environment_label(self) -> str:
        return "CI"

    def _support_contact_label(self) -> str:
        return "platform@example.com"


def _request(params: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/flow/login-status",
            "query_string": "&".join(
                f"{key}={value}" for key, value in params.items()
            ).encode(),
            "headers": [],
        }
    )


@pytest.mark.parametrize(
    ("fixture_name", "expected"),
    [
        (
            "valid_ldap_only_strict.ini",
            {
                "ldap_enabled": True,
                "entra_enabled": False,
                "strict_permissions": True,
                "primary_method": "ldap",
                "primary_title": "Sign in",
            },
        ),
        (
            "valid_entra_only_strict.ini",
            {
                "ldap_enabled": False,
                "entra_enabled": True,
                "strict_permissions": True,
                "primary_method": "entra",
                "primary_title": "Sign in",
            },
        ),
        (
            "valid_dual_provider_strict.ini",
            {
                "ldap_enabled": True,
                "entra_enabled": True,
                "strict_permissions": True,
                "primary_method": "ldap",
                "primary_title": "Sign in",
            },
        ),
        (
            "valid_dual_provider_permissive.ini",
            {
                "ldap_enabled": True,
                "entra_enabled": True,
                "strict_permissions": False,
                "primary_method": "entra",
                "primary_title": "Sign in",
            },
        ),
    ],
    ids=(
        "ldap_only_strict",
        "entra_only_strict",
        "dual_provider_strict",
        "dual_provider_permissive",
    ),
)
def test_auth_mode_permissions_variants_drive_startup_capability_and_provider_readiness(
    fixture_name: str,
    expected: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = FIXTURE_ROOT / fixture_name
    metadata = case_metadata(config_path)
    apply_env(metadata, monkeypatch)
    cfg = load_config(config_path)
    manager = _Manager(cfg)
    builder = AuthFlowPayloadBuilder(manager)

    provider_payload = builder.get_provider_readiness_payload().to_dict()
    methods_list = cast(list[dict[str, object]], provider_payload["methods"])
    methods = {str(item["identifier"]): item for item in methods_list}
    capability_report = build_runtime_capability_report(cfg)
    status_payload = builder.build_login_status_payload(
        _request({"status": "ready", "method": str(expected["primary_method"])}),
        next_url="/dags",
        error=None,
        status_value="ready",
        reference=None,
    ).to_dict()

    print("provider_payload=", provider_payload)
    print("capability_report=", capability_report)
    print("status_payload=", status_payload)

    assert cfg.validation.has_errors is False
    assert cfg.general.strict_permissions is expected["strict_permissions"]
    assert methods["ldap"]["enabled"] is expected["ldap_enabled"]
    assert methods["entra"]["enabled"] is expected["entra_enabled"]
    assert methods["ldap"]["label"] == cfg.ui.ldap_method_label
    assert methods["entra"]["label"] == cfg.ui.entra_method_label
    assert provider_payload["auth_config_broken"] is False
    assert capability_report["ldap_provider"] == (
        "enabled" if expected["ldap_enabled"] else "disabled"
    )
    assert capability_report["entra_provider"] == (
        "enabled" if expected["entra_enabled"] else "disabled"
    )
    assert status_payload["title"] == expected["primary_title"]
    assert status_payload["method"] == expected["primary_method"]
    assert status_payload["next_url"] == "/dags"


def test_admin_wildcard_permissions_variant_grants_global_access() -> None:
    cfg = load_config(FIXTURE_ROOT / "valid_admin_wildcard.ini")
    policy = RbacPolicy(cfg)

    assert ("*", "*") in cfg.roles.role_to_permissions["Admin"]
    assert policy.is_allowed(
        roles=("Admin",),
        action="can_delete",
        resource="XComs",
    )
    assert policy.is_allowed(
        roles=("Admin",),
        action="menu_access",
        resource="Admin",
    )
    assert policy.allowed_resources_for_action(
        roles=("Admin",),
        action="can_read",
    ) == {"*"}
