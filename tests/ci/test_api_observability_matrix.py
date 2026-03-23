from __future__ import annotations

from typing import Any

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
    monkeypatch: pytest.MonkeyPatch,
    auth_cfg: AuthConfig,
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


def test_flow_login_status_payload_surfaces_reference_roles_and_retry_after(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, _manager = client

    response = http.get(
        "/flow/login-status",
        params={
            "next": "/datasets",
            "error": "throttled",
            "status": "ready",
            "method": "ldap",
            "stage": "rate_limit",
            "roles": "Viewer,Op",
            "ref": "REF-2026",
            "retry_after": "17",
        },
    )
    payload = response.json()
    print("login_status_payload=", payload)

    assert response.status_code == 200
    assert payload["error"] == "throttled"
    assert payload["level"] == "error"
    assert payload["reference"] == "REF-2026"
    assert payload["method"] == "ldap"
    assert payload["stage"] == "rate_limit"
    assert payload["roles"] == ["Viewer", "Op"]
    assert payload["retry_after"] == 17
    assert payload["next_url"] == "/datasets"
    assert payload["environment_label"] == "CI"


def test_token_endpoints_emit_failure_audit_events_for_api_and_cli(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, manager = client

    invalid_api = http.post(
        "/token",
        json={"username": "alice", "password": "wrong-password"},
    )
    invalid_cli = http.post(
        "/token/cli",
        json={"username": "", "password": ""},
    )

    print("api_failure_json=", invalid_api.json())
    print("cli_failure_json=", invalid_cli.json())
    print("token_audit_events=", manager._audit_service.token_events)

    assert invalid_api.status_code == 401
    assert invalid_cli.status_code == 400
    assert manager._audit_service.token_events == [
        {
            "mode": "api",
            "principal": "alice",
            "ip_address": "127.0.0.1",
            "outcome": "failure",
            "detail": "invalid credentials",
        },
        {
            "mode": "cli",
            "principal": None,
            "ip_address": "127.0.0.1",
            "outcome": "failure",
            "detail": "username and password required",
        },
    ]


def test_ldap_browser_failures_emit_mapped_audit_details(
    client: tuple[TestClient, browser_matrix._FakeManager],
) -> None:
    http, manager = client
    http.cookies.set(manager._session_service.LDAP_CSRF_COOKIE_NAME, "csrf-ok")

    invalid = http.post(
        "/login",
        data={
            "username": "alice",
            "password": "wrong-password",
            "csrf": "csrf-ok",
            "next": "/grid",
        },
        follow_redirects=False,
    )
    throttled = http.post(
        "/login",
        data={
            "username": "throttle",
            "password": "correct-password",
            "csrf": "csrf-ok",
            "next": "/grid",
        },
        follow_redirects=False,
    )

    print("invalid_location=", invalid.headers.get("location"))
    print("throttled_location=", throttled.headers.get("location"))
    print("flow_events=", manager._audit_service.flow_events)

    assert invalid.status_code == 303
    assert throttled.status_code == 303
    assert (
        manager._audit_service.flow_events[-2]["event"] == "auth.browser_login.failure"
    )
    assert manager._audit_service.flow_events[-2]["mapped_error"] == "invalid"
    assert manager._audit_service.flow_events[-2]["reason"] == "Invalid credentials"
    assert (
        manager._audit_service.flow_events[-1]["event"] == "auth.browser_login.failure"
    )
    assert manager._audit_service.flow_events[-1]["mapped_error"] == "throttled"
    assert manager._audit_service.flow_events[-1]["retry_after"] == 9


def test_oauth_throttle_and_callback_rejection_emit_flow_audit_events(
    client: tuple[TestClient, browser_matrix._FakeManager],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, manager = client

    def _throttled(*, request: Any) -> tuple[bool, int]:
        del request
        return (False, 23)

    monkeypatch.setattr(manager, "_check_oauth_rate_limit", _throttled)
    throttled = http.get(
        "/oauth-login/azure", params={"next": "/datasets"}, follow_redirects=False
    )
    print("oauth_throttled_location=", throttled.headers.get("location"))

    assert throttled.status_code == 303
    assert "error=throttled" in throttled.headers["location"]
    assert "retry_after=23" in throttled.headers["location"]
    assert (
        manager._audit_service.flow_events[-1]["event"] == "auth.oauth_login.throttled"
    )
    assert manager._audit_service.flow_events[-1]["retry_after"] == 23

    monkeypatch.setattr(
        manager, "_check_oauth_rate_limit", lambda *, request: (True, 0)
    )
    started = http.get("/oauth-login/azure", params={"next": "/datasets"})
    print("oauth_started_text=", started.text)
    assert started.status_code == 200
    assert manager._session_service.flow_state is not None

    callback = http.get(
        "/oauth-authorized/azure",
        params={"code": "good-code", "state": "wrong-state"},
        follow_redirects=False,
    )
    print("oauth_callback_reject_location=", callback.headers.get("location"))
    print("oauth_flow_events=", manager._audit_service.flow_events)

    assert callback.status_code == 303
    assert "error=sso" in callback.headers["location"]
    assert (
        manager._audit_service.flow_events[-1]["event"]
        == "auth.oauth_callback.rejected"
    )
    assert manager._audit_service.flow_events[-1]["reason"] == "state_mismatch"
