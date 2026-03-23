from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.requests import Request

from rbac_providers_auth_manager.config import AuthConfig
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.services.flow_payloads import AuthFlowPayloadBuilder
from rbac_providers_auth_manager.ui.status_presenter import LoginStatusPresenter

CONFIG_ROOT = Path(__file__).resolve().parents[2] / "config_runtime"
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
        self._entra_provider = _Provider(cfg.general.enable_entra_id)

    def _refresh_if_needed(self) -> None:
        return None

    def _auth_config_broken(self) -> bool:
        return False

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
    ("config_path", "query", "expected"),
    [
        (
            CONFIG_ROOT / "permissions.ini",
            {"status": "success", "method": "ldap", "next": "/dags"},
            {
                "title": "Access granted",
                "message": "Your credentials were accepted and Airflow access was assigned.",
                "ldap_label": "LDAP Sign-In",
                "entra_label": "Microsoft Sign-In",
                "entra_enabled": False,
            },
        ),
        (
            FIXTURE_ROOT / "valid_ui_status_customization.ini",
            {"status": "success", "method": "ldap", "next": "/datasets"},
            {
                "title": "Welcome to Airflow",
                "message": "LDAP granted access.",
                "ldap_label": "Enterprise LDAP",
                "entra_label": "Microsoft SSO",
                "entra_enabled": False,
            },
        ),
    ],
    ids=("default_permissions_ini", "customized_ui_permissions_ini"),
)
def test_permissions_ini_drives_provider_labels_and_login_status_payload(
    config_path: Path,
    query: dict[str, str],
    expected: dict[str, object],
) -> None:
    cfg = load_config(config_path)
    manager = _Manager(cfg)
    builder = AuthFlowPayloadBuilder(manager)

    provider_payload = builder.get_provider_readiness_payload().to_dict()
    print("provider_payload=", provider_payload)

    payload = builder.build_login_status_payload(
        _request(query),
        next_url=query["next"],
        error=None,
        status_value=query["status"],
        reference=None,
    ).to_dict()
    print("login_status_payload=", payload)

    methods_list = cast(list[dict[str, object]], provider_payload["methods"])
    methods = {item["identifier"]: item for item in methods_list}

    assert payload["title"] == expected["title"]
    assert payload["message"] == expected["message"]
    assert payload["next_url"] == query["next"]
    assert payload["method"] == query["method"]
    assert payload["level"] == "success"
    assert methods["ldap"]["label"] == expected["ldap_label"]
    assert methods["ldap"]["enabled"] is True
    assert methods["entra"]["label"] == expected["entra_label"]
    assert methods["entra"]["enabled"] is expected["entra_enabled"]
    assert cfg.ui.ldap_method_label == expected["ldap_label"]
    assert cfg.ui.entra_method_label == expected["entra_label"]


def test_permissions_ini_customization_changes_failure_title_but_keeps_api_surface_shape() -> (
    None
):
    cfg = load_config(FIXTURE_ROOT / "valid_ui_status_customization.ini")
    manager = _Manager(cfg)
    builder = AuthFlowPayloadBuilder(manager)

    payload = builder.build_login_status_payload(
        _request({"error": "invalid", "method": "ldap", "next": "/grid"}),
        next_url="/grid",
        error="invalid",
        status_value=None,
        reference=None,
    ).to_dict()
    print("custom_failure_payload=", payload)

    assert payload["level"] == "error"
    assert payload["title"] == "Access denied"
    assert payload["message"] == (
        "Sign-in failed. Check your credentials or try Microsoft sign-in."
    )
    assert payload["next_url"] == "/grid"
    assert payload["environment_label"] == "CI"
    assert payload["retry_after"] == 0
