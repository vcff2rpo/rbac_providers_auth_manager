from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.testclient import TestClient

from rbac_providers_auth_manager.config import (
    AuthConfig,
    AuthConfigValidation,
    EntraIdConfig,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.core.exceptions import EntraIdAuthError, LdapAuthError
from rbac_providers_auth_manager.identity.models import ExternalIdentity, OAuthFlowState
from rbac_providers_auth_manager.services.auth_flow_service import AuthFlowService
from rbac_providers_auth_manager.services.entrypoint_app_service import (
    EntrypointAppService,
)


@dataclass(frozen=True)
class _CfgLoader:
    cfg: AuthConfig

    def get_config(self) -> AuthConfig:
        return self.cfg


class _AuditService:
    def __init__(self) -> None:
        self.flow_events: list[dict[str, Any]] = []
        self.token_events: list[dict[str, Any]] = []

    def log_flow_event(self, **payload: Any) -> None:
        self.flow_events.append(payload)

    def log_token_issue(self, **payload: Any) -> None:
        self.token_events.append(payload)


class _StatusPresenter:
    def login_status_method_label(self, method: str) -> str:
        return {"ldap": "LDAP", "entra": "Microsoft Entra ID"}.get(method, method)

    @staticmethod
    def retry_after_from_query(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def login_status_roles_from_query(value: str | None) -> list[str]:
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    @staticmethod
    def status_from_query(
        error: str | None, status_value: str | None
    ) -> tuple[str, str]:
        if error:
            return ("error", "Sign-in failed")
        if status_value == "success":
            return ("success", "Access granted")
        if status_value == "logged_out":
            return ("info", "Signed out")
        return ("info", "Sign in")

    @staticmethod
    def login_status_title(
        error: str | None, status_value: str | None, method: str | None
    ) -> str:
        del method
        if error:
            return "Sign-in failed"
        if status_value == "success":
            return "Access granted"
        return "Sign in"

    @staticmethod
    def login_status_message(
        error: str | None,
        status_value: str | None,
        method: str | None,
        stage: str | None,
    ) -> str:
        return f"status={status_value or 'ready'} error={error or '-'} method={method or '-'} stage={stage or '-'}"


class _UiRenderer:
    def __init__(self) -> None:
        self.status_presenter = _StatusPresenter()

    def render_login_page(
        self,
        *,
        request: Any,
        next_url: str | None,
        error: str | None,
        status_value: str,
        reference: str | None,
        status_payload: Any,
    ) -> HTMLResponse:
        del request, status_payload
        html = (
            f"LOGIN next={next_url or '/'} status={status_value} "
            f"error={error or '-'} ref={reference or '-'}"
        )
        return HTMLResponse(content=html, status_code=200)

    def render_intermediate_status_page(self, **kwargs: Any) -> HTMLResponse:
        redirect_url = str(kwargs["redirect_url"])
        return HTMLResponse(content=f"redirect:{redirect_url}", status_code=200)


class _SessionService:
    LDAP_CSRF_COOKIE_NAME = "itim_ldap_csrf"
    ENTRA_FLOW_ID_COOKIE_NAME = "itim_entra_flow"
    ENTRA_TRANSIENT_COOKIE_NAMES = (
        ENTRA_FLOW_ID_COOKIE_NAME,
        "itim_entra_state",
        "itim_entra_nonce",
        "itim_entra_next",
        "itim_entra_pkce",
    )

    def __init__(self) -> None:
        self.flow_state: OAuthFlowState | None = None
        self.last_auth_cookie: tuple[str, bool] | None = None
        self.clear_logout_calls = 0

    @staticmethod
    def resolve_cookie_secure(
        request: Any, *, trusted_proxies: tuple[str, ...]
    ) -> bool:
        del request, trusted_proxies
        return True

    def clear_ldap_csrf_cookie(self, response: RedirectResponse) -> None:
        response.delete_cookie(self.LDAP_CSRF_COOKIE_NAME, path="/")

    def persist_entra_flow_state(
        self,
        response: HTMLResponse,
        *,
        state: str,
        nonce: str,
        next_url: str,
        secure: bool,
        code_verifier: str | None = None,
    ) -> None:
        self.flow_state = OAuthFlowState(
            state=state,
            nonce=nonce,
            next_url=next_url,
            code_verifier=code_verifier,
        )
        response.set_cookie(self.ENTRA_FLOW_ID_COOKIE_NAME, state, secure=secure)

    def load_entra_flow_state(self, request: Any) -> OAuthFlowState | None:
        del request
        return self.flow_state

    def clear_entra_flow_state(
        self,
        response: RedirectResponse,
        *,
        request: Any | None = None,
    ) -> None:
        del request
        self.flow_state = None
        response.delete_cookie(self.ENTRA_FLOW_ID_COOKIE_NAME, path="/")

    def clear_logout_cookies(
        self,
        response: RedirectResponse,
        *,
        secure: bool,
        request: Any | None = None,
    ) -> None:
        del request
        self.clear_logout_calls += 1
        response.delete_cookie("_token", secure=secure, httponly=True, path="/")
        response.delete_cookie(self.LDAP_CSRF_COOKIE_NAME, path="/")
        response.delete_cookie(self.ENTRA_FLOW_ID_COOKIE_NAME, path="/")


class _LdapProvider:
    @staticmethod
    def is_enabled() -> bool:
        return True


class _EntraProvider:
    def __init__(self) -> None:
        self.login_calls: list[dict[str, Any]] = []
        self.callback_calls: list[dict[str, Any]] = []

    @staticmethod
    def is_enabled() -> bool:
        return True

    def build_authorize_redirect_url(
        self,
        *,
        request: Any,
        state: str,
        nonce: str,
        code_verifier: str | None,
    ) -> str:
        del request
        self.login_calls.append(
            {"state": state, "nonce": nonce, "code_verifier": code_verifier}
        )
        return f"https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state={state}&nonce={nonce}"

    def authenticate_authorization_code(
        self,
        *,
        request: Any,
        code: str,
        expected_nonce: str | None,
        code_verifier: str | None,
    ) -> ExternalIdentity:
        del request
        self.callback_calls.append(
            {
                "code": code,
                "expected_nonce": expected_nonce,
                "code_verifier": code_verifier,
            }
        )
        if code == "bad-code":
            raise EntraIdAuthError("entra_callback_failed")
        return ExternalIdentity(
            provider="entra",
            user_id="oid-123",
            username="alice@example.com",
            first_name="Alice",
            last_name="Admin",
            email="alice@example.com",
            display_name="Alice Admin",
            claim_values=("group-1", "group-2"),
            claims={"nonce": expected_nonce or ""},
        )


@dataclass(frozen=True)
class _FakeUser:
    user_id: str
    username: str
    first_name: str | None
    last_name: str | None
    email: str | None
    roles: tuple[str, ...]


class _FakeManager:
    def __init__(self, cfg: AuthConfig) -> None:
        self._cfg_loader = _CfgLoader(cfg)
        self._audit_service = _AuditService()
        self._session_service = _SessionService()
        self._ui_renderer = _UiRenderer()
        self._ldap_provider = _LdapProvider()
        self._entra_provider = _EntraProvider()
        self._config_error_message: str | None = None
        self.last_issued_jwt: tuple[str, int] | None = None
        self.last_user_roles: tuple[str, ...] | None = None
        self._auth_flow_service = AuthFlowService(self)
        self._entrypoint_app_service = EntrypointAppService(self)

    def _refresh_if_needed(self) -> None:
        return None

    def _auth_config_broken(self) -> bool:
        return False

    @staticmethod
    def _client_ip(request: Any | None) -> str:
        del request
        return "127.0.0.1"

    @staticmethod
    def _make_ui_reference() -> str:
        return "ui-ref-001"

    @staticmethod
    def _sanitize_next(
        next_url: str | None, request: Any, *, trusted_proxies: tuple[str, ...]
    ) -> str:
        del request, trusted_proxies
        if not next_url:
            return "/"
        return next_url if next_url.startswith("/") else "/"

    @staticmethod
    def _resolve_post_login_redirect_target(
        *, request: Any, next_url: str | None, trusted_proxies: tuple[str, ...]
    ) -> str:
        del request, trusted_proxies
        return next_url or "/"

    @staticmethod
    def _ui_environment_label() -> str:
        return "CI"

    @staticmethod
    def _support_contact_label() -> str:
        return "platform@example.com"

    def _check_oauth_rate_limit(self, *, request: Any) -> tuple[bool, int]:
        del request
        return (True, 0)

    def _record_oauth_start(self, *, request: Any) -> int:
        del request
        return 0

    @staticmethod
    def _normalize_entra_claim_value(value: str) -> str:
        return " ".join((value or "").strip().split()).casefold()

    def _set_auth_cookie(
        self, response: RedirectResponse, *, jwt_token: str, secure: bool
    ) -> None:
        self._session_service.last_auth_cookie = (jwt_token, secure)
        response.set_cookie("_token", jwt_token, secure=secure, httponly=True, path="/")

    def _issue_jwt(self, *, user: _FakeUser, expiration_time_in_seconds: int) -> str:
        self.last_issued_jwt = (user.username, expiration_time_in_seconds)
        self.last_user_roles = user.roles
        return f"jwt::{user.username}::{expiration_time_in_seconds}"

    def _authenticate_ldap(
        self, *, username: str, password: str, request: Any | None
    ) -> _FakeUser:
        del request
        if username == "throttle":
            raise LdapAuthError("Login throttled: 9")
        if password != "correct-password":
            raise LdapAuthError("Invalid credentials")
        return _FakeUser(
            user_id="user-123",
            username=username,
            first_name="Alice",
            last_name="Admin",
            email=f"{username}@example.com",
            roles=("Admin", "Viewer"),
        )

    def _authenticate_entra_identity(
        self, *, identity: ExternalIdentity, request: Any | None
    ) -> _FakeUser:
        del request
        return _FakeUser(
            user_id=identity.user_id,
            username=identity.username,
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            roles=("Admin", "Viewer"),
        )

    def create_token(self, headers: dict[str, str], body: dict[str, Any]) -> _FakeUser:
        del headers
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "").strip()
        if not username or not password:
            raise ValueError("username and password required")
        return self._authenticate_ldap(
            username=username, password=password, request=None
        )

    @staticmethod
    def get_url_login() -> str:
        return "/auth/login/"


@pytest.fixture()
def auth_cfg() -> AuthConfig:
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(
            strict_permissions=True,
            log_level="INFO",
            deny_if_no_roles=True,
            trusted_proxies=(),
            auth_user_registration=False,
            auth_user_registration_role="Public",
            enable_ldap=True,
            enable_entra_id=True,
        ),
        security=SecurityConfig(
            auth_state_backend="cookie",
            auth_state_ttl_seconds=300,
            enable_pkce=True,
        ),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ldap=None,
        entra_id=EntraIdConfig(
            enabled=True,
            tenant_id="tenant",
            client_id="client-id",
            client_secret="client-secret",
            provider_name="entra",
            button_text="Microsoft Sign-In",
            icon="microsoft",
            scope=("openid", "profile", "email"),
            roles_claim_key="groups",
            verify_signature=True,
            allowed_audiences=("client-id",),
            http_timeout_seconds=5,
            http_max_retries=1,
            http_retry_backoff_seconds=1,
            metadata_url="https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration",
            authorize_url=None,
            access_token_url="https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
            issuer="https://login.microsoftonline.com/tenant/v2.0",
            username_claim="preferred_username",
            email_claim="email",
            first_name_claim="given_name",
            last_name_claim="family_name",
            display_name_claim="name",
            graph_fetch_groups_on_overage=True,
            graph_memberof_url="https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id,displayName",
            enable_pkce=True,
            clock_skew_seconds=30,
            allowed_oidc_hosts=("login.microsoftonline.com", "graph.microsoft.com"),
        ),
        role_mapping=RoleMappingConfig(dn_to_roles={}),
        entra_role_mapping=EntraRoleMappingConfig(claim_value_to_roles={}),
        roles=RolesConfig(
            role_to_permissions={"Admin": set(), "Viewer": set(), "Public": set()}
        ),
        role_filters=RoleFiltersConfig(role_to_filters={}),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )


@pytest.fixture()
def client(
    monkeypatch: pytest.MonkeyPatch, auth_cfg: AuthConfig
) -> tuple[TestClient, _FakeManager]:
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

    manager = _FakeManager(auth_cfg)
    app = manager._entrypoint_app_service.get_fastapi_app()
    return TestClient(app), manager


def test_route_matrix_login_logout_and_token_issuance(
    client: tuple[TestClient, _FakeManager],
) -> None:
    http, manager = client

    login_page = http.get("/login", params={"next": "/home"})
    print("login_page=", login_page.status_code, login_page.text)
    assert login_page.status_code == 200
    assert "LOGIN next=/home" in login_page.text

    http.cookies.set(manager._session_service.LDAP_CSRF_COOKIE_NAME, "csrf-ok")
    login_response = http.post(
        "/login",
        data={
            "username": "alice",
            "password": "correct-password",
            "csrf": "csrf-ok",
            "next": "/home",
        },
        follow_redirects=False,
    )
    print("login_headers=", dict(login_response.headers))
    assert login_response.status_code == 303
    location = login_response.headers["location"]
    assert "status=success" in location
    assert "method=ldap" in location
    assert "roles=Admin%2CViewer" in location
    assert "next=%2Fhome" in location
    assert manager.last_issued_jwt == ("alice", 1800)
    assert manager._session_service.last_auth_cookie == ("jwt::alice::1800", True)

    token_response = http.post(
        "/token",
        json={"username": "alice", "password": "correct-password"},
    )
    print("token_json=", token_response.json())
    assert token_response.status_code == 201
    assert token_response.json()["access_token"] == "jwt::alice::1800"

    token_cli_response = http.post(
        "/token/cli",
        json={"username": "alice", "password": "correct-password"},
    )
    print("token_cli_json=", token_cli_response.json())
    assert token_cli_response.status_code == 201
    assert token_cli_response.json()["access_token"] == "jwt::alice::7200"

    logout_response = http.get("/logout", follow_redirects=False)
    print("logout_headers=", dict(logout_response.headers))
    assert logout_response.status_code == 307
    assert logout_response.headers["location"].endswith(
        "/auth/login/?status=logged_out"
    )
    assert manager._session_service.clear_logout_calls == 1

    logout_state = http.get("/flow/logout-state")
    print("logout_state=", logout_state.json())
    assert logout_state.status_code == 200
    assert logout_state.json()["status_value"] == "logged_out"


def test_route_matrix_login_error_and_status_diagnostics(
    client: tuple[TestClient, _FakeManager],
) -> None:
    http, manager = client

    http.cookies.set(manager._session_service.LDAP_CSRF_COOKIE_NAME, "csrf-ok")
    invalid_response = http.post(
        "/login",
        data={
            "username": "alice",
            "password": "wrong-password",
            "csrf": "csrf-ok",
            "next": "/grid",
        },
        follow_redirects=False,
    )
    print("invalid_login_location=", invalid_response.headers.get("location"))
    assert invalid_response.status_code == 303
    assert "error=invalid" in invalid_response.headers["location"]

    throttled_response = http.post(
        "/login",
        data={
            "username": "throttle",
            "password": "correct-password",
            "csrf": "csrf-ok",
            "next": "/grid",
        },
        follow_redirects=False,
    )
    print("throttled_login_location=", throttled_response.headers.get("location"))
    assert throttled_response.status_code == 303
    assert "error=throttled" in throttled_response.headers["location"]
    assert "retry_after=9" in throttled_response.headers["location"]

    providers_response = http.get("/flow/providers")
    print("providers_payload=", providers_response.json())
    assert providers_response.status_code == 200
    providers_payload = providers_response.json()
    assert providers_payload["auth_config_broken"] is False
    assert providers_payload["methods"][0]["enabled"] is True
    assert providers_payload["methods"][1]["enabled"] is True

    status_response = http.get(
        "/flow/login-status",
        params={
            "status_value": "success",
            "method": "ldap",
            "stage": "access_granted",
            "roles": "Admin,Viewer",
            "next": "/grid",
        },
    )
    print("status_payload=", status_response.json())
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["level"] == "success"
    assert status_payload["roles"] == ["Admin", "Viewer"]
    assert status_payload["next_url"] == "/grid"


def test_route_matrix_entra_start_and_callback_success(
    client: tuple[TestClient, _FakeManager],
) -> None:
    http, manager = client

    oauth_start = http.get("/oauth-login/azure", params={"next": "/datasets"})
    print("oauth_start_headers=", dict(oauth_start.headers))
    assert oauth_start.status_code == 200
    assert manager._session_service.flow_state is not None
    assert "redirect:https://login.microsoftonline.com" in oauth_start.text

    state = manager._session_service.flow_state.state
    callback = http.get(
        "/oauth-authorized/azure",
        params={"code": "auth-code-123", "state": state},
        follow_redirects=False,
    )
    print("oauth_callback_location=", callback.headers.get("location"))
    assert callback.status_code == 303
    location = callback.headers["location"]
    assert "status=success" in location
    assert "method=entra" in location
    assert "roles=Admin%2CViewer" in location
    assert "next=%2Fdatasets" in location

    callback_state = http.get(
        "/flow/oauth-callback-state",
        params={"code": "auth-code-123", "state": state},
    )
    print("callback_state=", callback_state.json())
    assert callback_state.status_code == 200
    assert callback_state.json()["code_supplied"] is True
