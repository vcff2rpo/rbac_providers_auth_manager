from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from . import test_browser_token_flow_matrix as browser_matrix
from rbac_providers_auth_manager.config import AuthConfig


class _BrokenConfigManager(browser_matrix._FakeManager):
    def __init__(self, cfg: AuthConfig) -> None:
        super().__init__(cfg)
        self._config_error_message = "permissions.ini invalid"

    def _auth_config_broken(self) -> bool:
        return True


class _MissingLdapManager(browser_matrix._FakeManager):
    def _authenticate_ldap(
        self, *, username: str, password: str, request: Any | None
    ) -> browser_matrix._FakeUser:
        del username, password, request
        raise browser_matrix.LdapAuthError("Auth manager not configured")


@pytest.fixture()
def auth_cfg() -> AuthConfig:
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


@pytest.fixture()
def broken_client(
    monkeypatch: pytest.MonkeyPatch, auth_cfg: AuthConfig
) -> tuple[TestClient, _BrokenConfigManager]:
    import rbac_providers_auth_manager.services.flow_payloads as flow_payloads_module
    import rbac_providers_auth_manager.services.ldap_browser_flow_service as ldap_browser_module
    import rbac_providers_auth_manager.services.oauth_browser_flow_service as oauth_browser_module

    class _FakeAirflowConf:
        @staticmethod
        def getint(section: str, option: str) -> int:
            assert section == "api_auth"
            return 7200 if option == "jwt_cli_expiration_time" else 1800

    monkeypatch.setattr(flow_payloads_module, "airflow_conf", _FakeAirflowConf())
    monkeypatch.setattr(ldap_browser_module, "airflow_conf", _FakeAirflowConf())
    monkeypatch.setattr(oauth_browser_module, "airflow_conf", _FakeAirflowConf())

    manager = _BrokenConfigManager(auth_cfg)
    app = manager._entrypoint_app_service.get_fastapi_app()
    return TestClient(app), manager


@pytest.fixture()
def missing_ldap_client(
    monkeypatch: pytest.MonkeyPatch, auth_cfg: AuthConfig
) -> tuple[TestClient, _MissingLdapManager]:
    import rbac_providers_auth_manager.services.flow_payloads as flow_payloads_module
    import rbac_providers_auth_manager.services.ldap_browser_flow_service as ldap_browser_module
    import rbac_providers_auth_manager.services.oauth_browser_flow_service as oauth_browser_module

    class _FakeAirflowConf:
        @staticmethod
        def getint(section: str, option: str) -> int:
            assert section == "api_auth"
            return 7200 if option == "jwt_cli_expiration_time" else 1800

    monkeypatch.setattr(flow_payloads_module, "airflow_conf", _FakeAirflowConf())
    monkeypatch.setattr(ldap_browser_module, "airflow_conf", _FakeAirflowConf())
    monkeypatch.setattr(oauth_browser_module, "airflow_conf", _FakeAirflowConf())

    manager = _MissingLdapManager(auth_cfg)
    app = manager._entrypoint_app_service.get_fastapi_app()
    return TestClient(app), manager


def test_providers_endpoint_reports_broken_auth_configuration(
    broken_client: tuple[TestClient, _BrokenConfigManager],
) -> None:
    http, _manager = broken_client

    response = http.get("/flow/providers")
    print("broken_providers_payload=", response.json())

    assert response.status_code == 200
    payload = response.json()
    assert payload["auth_config_broken"] is True
    assert payload.get("config_error") in {None, "permissions.ini invalid"}


def test_login_route_redirects_on_missing_runtime_authentication(
    missing_ldap_client: tuple[TestClient, _MissingLdapManager],
) -> None:
    http, manager = missing_ldap_client

    http.cookies.set(manager._session_service.LDAP_CSRF_COOKIE_NAME, "csrf-ok")
    response = http.post(
        "/login",
        data={
            "username": "alice",
            "password": "correct-password",
            "csrf": "csrf-ok",
            "next": "/grid",
        },
        follow_redirects=False,
    )
    print("missing_runtime_login_location=", response.headers.get("location"))

    assert response.status_code == 303
    assert "error=" in response.headers["location"]


def test_token_endpoint_rejects_missing_required_credentials(
    missing_ldap_client: tuple[TestClient, _MissingLdapManager],
) -> None:
    http, _manager = missing_ldap_client

    response = http.post("/token", json={"username": "alice"})
    print("missing_credentials_status=", response.status_code)
    print("missing_credentials_body=", response.text)

    assert response.status_code >= 400
