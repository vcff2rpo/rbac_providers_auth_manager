"""Normalized auth-flow payload builders shared by browser and JSON routes."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from starlette import status

from rbac_providers_auth_manager.api.models import (
    LoginStatusPayload,
    LogoutStatePayload,
    OAuthCallbackStatePayload,
    ProviderMethodState,
    ProviderReadinessPayload,
    TokenIssueResult,
)
from rbac_providers_auth_manager.compatibility.airflow_public_api import airflow_conf
from rbac_providers_auth_manager.core.exceptions import LdapAuthError


class AuthFlowPayloadBuilder:
    """Build normalized auth-flow payloads without owning request orchestration."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def get_provider_readiness_payload(self) -> ProviderReadinessPayload:
        """Return provider readiness for API and browser consumers."""
        self.manager._refresh_if_needed()
        methods = (
            ProviderMethodState(
                identifier="ldap",
                label=self.manager._ui_renderer.status_presenter.login_status_method_label(
                    "ldap"
                ),
                enabled=bool(
                    self.manager._ldap_provider is not None
                    and self.manager._ldap_provider.is_enabled()
                ),
            ),
            ProviderMethodState(
                identifier="entra",
                label=self.manager._ui_renderer.status_presenter.login_status_method_label(
                    "entra"
                ),
                enabled=bool(
                    self.manager._entra_provider is not None
                    and self.manager._entra_provider.is_enabled()
                ),
            ),
        )
        return ProviderReadinessPayload(
            auth_config_broken=self.manager._auth_config_broken(),
            environment_label=self.manager._ui_environment_label(),
            support_contact=self.manager._support_contact_label(),
            methods=methods,
        )

    def build_login_status_payload(
        self,
        request: Request,
        *,
        next_url: str | None,
        error: str | None,
        status_value: str | None,
        reference: str | None,
    ) -> LoginStatusPayload:
        """Normalize login banner state for browser and JSON consumers."""
        self.manager._refresh_if_needed()
        effective_status = status_value or request.query_params.get("status") or "ready"
        effective_reference = reference or request.query_params.get("ref")
        effective_next = next_url or request.query_params.get("next")
        retry_after = self.manager._ui_renderer.status_presenter.retry_after_from_query(
            request.query_params.get("retry_after")
        )
        method = request.query_params.get("method")
        stage = request.query_params.get("stage")
        roles = tuple(
            self.manager._ui_renderer.status_presenter.login_status_roles_from_query(
                request.query_params.get("roles")
            )
        )
        level, fallback_title = (
            self.manager._ui_renderer.status_presenter.status_from_query(
                error=error,
                status_value=effective_status,
            )
        )
        title = (
            self.manager._ui_renderer.status_presenter.login_status_title(
                error=error,
                status_value=effective_status,
                method=method,
            )
            or fallback_title
        )
        message = self.manager._ui_renderer.status_presenter.login_status_message(
            error=error,
            status_value=effective_status,
            method=method,
            stage=stage,
        )
        auto_redirect_seconds = 1 if effective_status == "success" else 0
        return LoginStatusPayload(
            level=level,
            title=title,
            message=message,
            error=error,
            status_value=effective_status,
            reference=effective_reference,
            method=method,
            stage=stage,
            roles=roles,
            retry_after=retry_after,
            next_url=effective_next,
            auto_redirect_seconds=auto_redirect_seconds,
            environment_label=self.manager._ui_environment_label(),
        )

    def get_oauth_callback_state_payload(
        self,
        request: Request,
        *,
        code: str | None,
        state: str | None,
        error: str | None,
        error_description: str | None,
    ) -> OAuthCallbackStatePayload:
        """Return normalized Entra callback request state for diagnostics."""
        cookies_present = tuple(
            cookie_name
            for cookie_name in self.manager._session_service.ENTRA_TRANSIENT_COOKIE_NAMES
            if request.cookies.get(cookie_name)
        )
        flow_state = self.manager._session_service.load_entra_flow_state(request)
        return OAuthCallbackStatePayload(
            next_url=(flow_state.next_url if flow_state is not None else "/"),
            state_supplied=bool(state),
            code_supplied=bool(code),
            callback_error=error,
            callback_error_description=error_description,
            cookies_present=cookies_present,
        )

    def get_logout_state_payload(self) -> LogoutStatePayload:
        """Return normalized logout redirect state for browser and JSON consumers."""
        return LogoutStatePayload(
            login_url=self.manager.get_url_login(),
            status_value="logged_out",
            transient_cookie_names=(
                self.manager._session_service.LDAP_CSRF_COOKIE_NAME,
                *self.manager._session_service.ENTRA_TRANSIENT_COOKIE_NAMES,
            ),
        )

    def issue_token_result(
        self,
        request: Request,
        *,
        body: dict[str, Any],
        cli: bool,
    ) -> TokenIssueResult:
        """Return a normalized token result for API and CLI callers."""
        self.manager._refresh_if_needed()
        if self.manager._auth_config_broken():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication is unavailable because no auth method is enabled.",
            )
        try:
            user = self.manager.create_token(headers=dict(request.headers), body=body)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        except LdapAuthError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
            )

        expiration_key = "jwt_cli_expiration_time" if cli else "jwt_expiration_time"
        token_value = self.manager._issue_jwt(
            user=user,
            expiration_time_in_seconds=airflow_conf.getint("api_auth", expiration_key),
        )
        return TokenIssueResult(
            access_token=token_value,
            expiration_key=expiration_key,
        )
