from __future__ import annotations

from http.cookies import SimpleCookie

import pytest
from fastapi.testclient import TestClient

from . import test_browser_token_flow_matrix as browser_matrix
from rbac_providers_auth_manager.config import AuthConfig


@pytest.fixture()
def auth_cfg() -> AuthConfig:
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


@pytest.fixture()
def client(
    monkeypatch: pytest.MonkeyPatch, auth_cfg: AuthConfig
) -> tuple[TestClient, browser_matrix._FakeManager]:
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

    manager = browser_matrix._FakeManager(auth_cfg)
    app = manager._entrypoint_app_service.get_fastapi_app()
    return TestClient(app), manager


def _cookie_names(set_cookie_headers: list[str]) -> set[str]:
    names: set[str] = set()
    for header in set_cookie_headers:
        cookie = SimpleCookie()
        cookie.load(header)
        names.update(cookie.keys())
    return names


def test_login_page_sets_csrf_cookie_and_html_content_type(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, manager = client

    response = http.get("/login", params={"next": "/home"})
    print("login_content_type=", response.headers.get("content-type"))
    print("login_set_cookie=", response.headers.get("set-cookie"))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "LOGIN next=/home" in response.text
    assert manager._session_service.LDAP_CSRF_COOKIE_NAME in response.cookies


def test_json_endpoints_return_json_and_cli_token_has_longer_ttl(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, _manager = client

    token_response = http.post(
        "/token",
        json={"username": "alice", "password": "correct-password"},
    )
    token_cli_response = http.post(
        "/token/cli",
        json={"username": "alice", "password": "correct-password"},
    )
    providers_response = http.get("/flow/providers")
    status_response = http.get("/flow/login-status")

    print("token_headers=", dict(token_response.headers))
    print("token_cli_headers=", dict(token_cli_response.headers))
    print("providers_headers=", dict(providers_response.headers))
    print("status_headers=", dict(status_response.headers))

    assert token_response.status_code == 201
    assert token_cli_response.status_code == 201
    assert providers_response.status_code == 200
    assert status_response.status_code == 200

    assert token_response.headers["content-type"].startswith("application/json")
    assert token_cli_response.headers["content-type"].startswith("application/json")
    assert providers_response.headers["content-type"].startswith("application/json")
    assert status_response.headers["content-type"].startswith("application/json")

    token_value = token_response.json()["access_token"]
    token_cli_value = token_cli_response.json()["access_token"]
    assert token_value.endswith("::1800")
    assert token_cli_value.endswith("::7200")


def test_logout_redirect_clears_auth_related_cookies(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, manager = client

    response = http.get("/logout", follow_redirects=False)
    set_cookie_headers = response.headers.get_list("set-cookie")
    cleared = _cookie_names(set_cookie_headers)
    print("logout_headers=", dict(response.headers))
    print("logout_set_cookie_headers=", set_cookie_headers)

    assert response.status_code == 307
    assert response.headers["location"].endswith("/auth/login/?status=logged_out")
    assert manager._session_service.clear_logout_calls == 1
    assert {"_token", manager._session_service.LDAP_CSRF_COOKIE_NAME}.issubset(cleared)
