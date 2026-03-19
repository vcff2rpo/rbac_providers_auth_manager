from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from rbac_providers_auth_manager.config_runtime.models import (
    EntraIdConfig,
    GeneralConfig,
    JwtCookieConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.core.exceptions import EntraIdAuthError
from rbac_providers_auth_manager.identity.models import ExternalIdentity, OAuthFlowState
from rbac_providers_auth_manager.services.oauth_browser_flow_service import (
    OauthBrowserFlowService,
)


@dataclass(frozen=True)
class _FakeConfig:
    general: GeneralConfig
    security: SecurityConfig
    jwt_cookie: JwtCookieConfig
    ui: UiConfig
    entra_id: EntraIdConfig | None


class _FakeConfigLoader:
    def __init__(self, cfg: _FakeConfig) -> None:
        self._cfg = cfg

    def get_config(self) -> _FakeConfig:
        return self._cfg


class _FakeAuditService:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def log_flow_event(self, **payload: Any) -> None:
        self.events.append(payload)


class _FakeSessionService:
    def __init__(self) -> None:
        self.flow_state: OAuthFlowState | None = None
        self.persisted_secure: bool | None = None
        self.cleared = False
        self.auth_cookie: tuple[str, bool] | None = None

    def resolve_cookie_secure(
        self,
        request: Request,  # noqa: ARG002
        *,
        trusted_proxies: tuple[str, ...],  # noqa: ARG002
    ) -> bool:
        return True

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
        self.persisted_secure = secure
        response.set_cookie("itim_entra_state", state, secure=secure)

    def load_entra_flow_state(self, request: Request) -> OAuthFlowState | None:  # noqa: ARG002
        return self.flow_state

    def clear_entra_flow_state(
        self,
        response: RedirectResponse,
        *,
        request: Request | None = None,  # noqa: ARG002
    ) -> None:
        self.cleared = True
        response.delete_cookie("itim_entra_state")


class _FakeUiRenderer:
    def render_intermediate_status_page(self, **kwargs: Any) -> HTMLResponse:
        redirect_url = str(kwargs["redirect_url"])
        return HTMLResponse(content=f"redirect:{redirect_url}", status_code=200)


class _FakeEntraProvider:
    def __init__(self) -> None:
        self.login_calls: list[dict[str, Any]] = []
        self.callback_calls: list[dict[str, Any]] = []
        self.raise_callback_error = False

    def is_enabled(self) -> bool:
        return True

    def build_authorize_redirect_url(
        self,
        *,
        request: Request,  # noqa: ARG002
        state: str,
        nonce: str,
        code_verifier: str | None,
    ) -> str:
        self.login_calls.append(
            {
                "state": state,
                "nonce": nonce,
                "code_verifier": code_verifier,
            }
        )
        return (
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize"
            f"?state={state}&nonce={nonce}"
        )

    def authenticate_authorization_code(
        self,
        *,
        request: Request,  # noqa: ARG002
        code: str,
        expected_nonce: str | None,
        code_verifier: str | None,
    ) -> ExternalIdentity:
        self.callback_calls.append(
            {
                "code": code,
                "expected_nonce": expected_nonce,
                "code_verifier": code_verifier,
            }
        )
        if self.raise_callback_error:
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
    username: str
    roles: tuple[str, ...]


class _FakeManager:
    def __init__(self, cfg: _FakeConfig) -> None:
        self._cfg_loader = _FakeConfigLoader(cfg)
        self._audit_service = _FakeAuditService()
        self._session_service = _FakeSessionService()
        self._ui_renderer = _FakeUiRenderer()
        self._entra_provider = _FakeEntraProvider()
        self.issued_jwt: tuple[str, int] | None = None
        self.auth_cookie_set: tuple[str, bool] | None = None

    def _refresh_if_needed(self) -> None:
        return None

    def _auth_config_broken(self) -> bool:
        return False

    def _check_oauth_rate_limit(self, *, request: Request) -> tuple[bool, int]:  # noqa: ARG002
        return True, 0

    def _record_oauth_start(self, *, request: Request) -> int:  # noqa: ARG002
        return 0

    def _sanitize_next(
        self,
        next_url: str | None,
        request: Request,  # noqa: ARG002
        *,
        trusted_proxies: tuple[str, ...],  # noqa: ARG002
    ) -> str:
        return next_url or "/"

    def _resolve_post_login_redirect_target(
        self,
        *,
        request: Request,  # noqa: ARG002
        next_url: str | None,
        trusted_proxies: tuple[str, ...],  # noqa: ARG002
    ) -> str:
        return next_url or "/"

    def _client_ip(self, request: Request) -> str:  # noqa: ARG002
        return "127.0.0.1"

    def _make_ui_reference(self) -> str:
        return "ui-ref-001"

    def _authenticate_entra_identity(
        self,
        *,
        identity: ExternalIdentity,
        request: Request,  # noqa: ARG002
    ) -> _FakeUser:
        return _FakeUser(username=identity.username, roles=("Admin", "Viewer"))

    def _issue_jwt(
        self, *, user: _FakeUser, expiration_time_in_seconds: int
    ) -> str:
        self.issued_jwt = (user.username, expiration_time_in_seconds)
        return "jwt-token-123"

    def _set_auth_cookie(
        self, response: RedirectResponse, *, jwt_token: str, secure: bool
    ) -> None:
        self.auth_cookie_set = (jwt_token, secure)
        response.set_cookie("_token", jwt_token, secure=secure, httponly=True)


@pytest.fixture()
def entra_cfg() -> _FakeConfig:
    return _FakeConfig(
        general=GeneralConfig(
            config_reload_seconds=60,
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
            allow_plaintext_secrets=False,
            sensitive_debug_logging=False,
            allow_insecure_ldap_tls=False,
            rate_limit_backend="memory",
            redis_url=None,
            redis_prefix="airflow_auth",
            auth_state_backend="cookie",
            auth_state_redis_url=None,
            auth_state_redis_prefix="airflow_auth_state",
            auth_state_ttl_seconds=300,
            enable_ldap_rate_limit=True,
            ldap_max_failures=5,
            ldap_failure_window_seconds=60,
            ldap_lockout_seconds=60,
            enable_oauth_rate_limit=True,
            oauth_max_starts=5,
            oauth_window_seconds=60,
            oauth_lockout_seconds=60,
            enable_pkce=True,
            allow_graph_group_fallback=False,
        ),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="Lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ui=UiConfig(
            enable_rich_login_status=True,
            show_environment=True,
            show_mapped_roles=True,
            show_reference_id=True,
            show_auth_method=True,
            compact_status_details_line=True,
            compact_success_status_line=True,
            title_ready="Sign in",
            title_success="Access granted",
            title_failure="Sign-in failed",
            title_no_roles="No Airflow access assigned",
            ldap_method_label="LDAP",
            entra_method_label="Microsoft Entra ID",
            ldap_ready_text="Use your enterprise username and password.",
            ldap_success_text="LDAP access granted",
            ldap_no_roles_text="No roles mapped",
            entra_ready_text="Use Microsoft Sign-In for enterprise SSO.",
            entra_progress_text="Redirecting to Microsoft Entra ID",
            entra_success_text="Entra access granted",
            entra_no_roles_text="No roles mapped",
        ),
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
    )


def _request(url: str) -> Request:
    scope: dict[str, Any] = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/auth/entra/callback",
        "raw_path": b"/auth/entra/callback",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 443),
        "server": ("airflow.example.com", 443),
        "root_path": "",
        "app": None,
    }
    return Request(scope)


def test_entra_login_start_and_callback_success(
    monkeypatch: pytest.MonkeyPatch,
    entra_cfg: _FakeConfig,
) -> None:
    import rbac_providers_auth_manager.services.oauth_browser_flow_service as oauth_module

    class _FakeAirflowConf:
        @staticmethod
        def getint(section: str, option: str) -> int:
            assert section == "api_auth"
            assert option == "jwt_expiration_time"
            return 1800

    monkeypatch.setattr(oauth_module, "airflow_conf", _FakeAirflowConf())

    manager = _FakeManager(entra_cfg)
    service = OauthBrowserFlowService(manager)

    start_response = service.handle_oauth_login_azure(
        _request("https://airflow.example.com/auth/login"),
        next_url="/home",
    )

    assert start_response.status_code == 200
    assert manager._session_service.flow_state is not None
    assert manager._session_service.persisted_secure is True
    assert manager._entra_provider.login_calls

    parsed = urlsplit(start_response.body.decode("utf-8").removeprefix("redirect:"))
    query = parse_qs(parsed.query)
    assert query["state"] == [manager._session_service.flow_state.state]
    assert query["nonce"] == [manager._session_service.flow_state.nonce]

    callback_response = service.handle_oauth_authorized_azure(
        _request("https://airflow.example.com/auth/entra/callback"),
        code="auth-code-123",
        state=manager._session_service.flow_state.state,
        error=None,
        error_description=None,
    )

    assert callback_response.status_code == 303
    assert manager.issued_jwt == ("alice@example.com", 1800)
    assert manager.auth_cookie_set == ("jwt-token-123", True)
    assert manager._session_service.cleared is True
    location = callback_response.headers["location"]
    assert "status=success" in location
    assert "method=entra" in location
    assert "stage=access_granted" in location
    assert "next=%2Fhome" in location


def test_entra_callback_state_mismatch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    entra_cfg: _FakeConfig,
) -> None:
    import rbac_providers_auth_manager.services.oauth_browser_flow_service as oauth_module

    class _FakeAirflowConf:
        @staticmethod
        def getint(section: str, option: str) -> int:  # noqa: ARG004
            return 1800

    monkeypatch.setattr(oauth_module, "airflow_conf", _FakeAirflowConf())

    manager = _FakeManager(entra_cfg)
    manager._session_service.flow_state = OAuthFlowState(
        state="expected-state",
        nonce="nonce-123",
        next_url="/home",
        code_verifier="verifier-123",
    )
    service = OauthBrowserFlowService(manager)

    response = service.handle_oauth_authorized_azure(
        _request("https://airflow.example.com/auth/entra/callback"),
        code="auth-code-123",
        state="wrong-state",
        error=None,
        error_description=None,
    )

    assert response.status_code == 303
    assert "error=sso" in response.headers["location"]
    assert manager.issued_jwt is None
    assert manager.auth_cookie_set is None
    assert manager._session_service.cleared is True
    assert any(
        event.get("event") == "auth.oauth_callback.rejected"
        and event.get("reason") == "state_mismatch"
        for event in manager._audit_service.events
    )
