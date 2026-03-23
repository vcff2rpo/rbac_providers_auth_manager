"""OAuth/Entra browser sign-in flow execution helpers."""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette import status

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
    airflow_conf,
)
from rbac_providers_auth_manager.core.exceptions import EntraIdAuthError, LdapAuthError
from rbac_providers_auth_manager.runtime.security import generate_pkce_code_verifier


class OauthBrowserFlowService:
    """Execute Entra browser login and callback completion flows."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def handle_oauth_login_azure(
        self,
        request: Request,
        *,
        next_url: str | None,
    ) -> Response:
        """Start the Entra browser sign-in flow."""
        self.manager._refresh_if_needed()

        if self.manager._auth_config_broken():
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_login.blocked",
                level="warning",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                reason="auth_config_disabled",
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?error=config_disabled&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        cfg = self.manager._cfg_loader.get_config()

        if (
            self.manager._entra_provider is None
            or not self.manager._entra_provider.is_enabled()
            or cfg.entra_id is None
        ):
            return RedirectResponse(
                url=f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login?error=sso",
                status_code=status.HTTP_303_SEE_OTHER,
            )

        allowed, retry_after = self.manager._check_oauth_rate_limit(request=request)
        if not allowed:
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_login.throttled",
                level="warning",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                retry_after=retry_after,
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?error=throttled&ref={quote(ui_ref, safe='')}&retry_after={retry_after}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        next_safe = self.manager._sanitize_next(
            next_url,
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )
        secure = self.manager._session_service.resolve_cookie_secure(
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = (
            generate_pkce_code_verifier() if cfg.entra_id.enable_pkce else None
        )
        try:
            redirect_url = self.manager._entra_provider.build_authorize_redirect_url(
                request=request,
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
            )
        except EntraIdAuthError as exc:
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_login.failure",
                level="warning",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                reason=str(exc) or "entra_init_error",
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error=sso"
                    f"&method=entra&stage=redirecting&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        retry_after = self.manager._record_oauth_start(request=request)
        if retry_after > 0:
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_login.throttled",
                level="warning",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                retry_after=retry_after,
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?error=throttled&ref={quote(ui_ref, safe='')}&retry_after={retry_after}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        self.manager._audit_service.log_flow_event(
            event="auth.oauth_login.started",
            provider="entra",
            ip_address=self.manager._client_ip(request),
            next_url=next_safe,
            state_backend=(
                self.manager._cfg_loader.get_config().security.auth_state_backend
                or "cookie"
            ),
        )

        response = self.manager._ui_renderer.render_intermediate_status_page(
            request=request,
            next_url=next_safe,
            title=cfg.ui.entra_method_label,
            message=cfg.ui.entra_progress_text,
            method="entra",
            stage="redirecting",
            redirect_url=redirect_url,
            redirect_delay_seconds=1,
        )
        self.manager._session_service.persist_entra_flow_state(
            response,
            state=state,
            nonce=nonce,
            next_url=next_safe,
            secure=secure,
            code_verifier=code_verifier,
        )
        return response

    def handle_oauth_authorized_azure(
        self,
        request: Request,
        *,
        code: str | None,
        state: str | None,
        error: str | None,
        error_description: str | None,
    ) -> RedirectResponse:
        """Complete the Entra callback flow and issue the Airflow JWT."""
        self.manager._refresh_if_needed()
        cfg = self.manager._cfg_loader.get_config()

        secure = self.manager._session_service.resolve_cookie_secure(
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )

        flow_state = self.manager._session_service.load_entra_flow_state(request)
        raw_next = flow_state.next_url if flow_state is not None else "/"
        next_safe = self.manager._sanitize_next(
            raw_next,
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )
        success_next = self.manager._resolve_post_login_redirect_target(
            request=request,
            next_url=raw_next,
            trusted_proxies=cfg.general.trusted_proxies,
        )

        def _failure_response(*, reason: str, level: str = "sso") -> RedirectResponse:
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_callback.failure",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                reason=reason,
            )
            response = RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error={level}&method=entra&stage=callback&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )
            self.manager._session_service.clear_entra_flow_state(
                response, request=request
            )
            return response

        if (
            self.manager._entra_provider is None
            or not self.manager._entra_provider.is_enabled()
        ):
            return _failure_response(reason="entra_disabled")

        if error:
            return _failure_response(
                reason=f"{error}:{error_description or ''}".strip(":")
            )

        if not code:
            return _failure_response(reason="missing_code")

        expected_state = flow_state.state if flow_state is not None else ""
        if (
            not expected_state
            or not state
            or not secrets.compare_digest(state, expected_state)
        ):
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.oauth_callback.rejected",
                level="warning",
                provider="entra",
                reference=ui_ref,
                ip_address=self.manager._client_ip(request),
                reason="state_mismatch",
            )
            response = RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error=sso&method=entra&stage=callback&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )
            self.manager._session_service.clear_entra_flow_state(
                response, request=request
            )
            return response

        expected_nonce = (
            flow_state.nonce if flow_state is not None and flow_state.nonce else None
        )
        code_verifier = flow_state.code_verifier if flow_state is not None else None

        try:
            identity = self.manager._entra_provider.authenticate_authorization_code(
                request=request,
                code=code,
                expected_nonce=expected_nonce,
                code_verifier=code_verifier,
            )
            user = self.manager._authenticate_entra_identity(
                identity=identity, request=request
            )
        except (EntraIdAuthError, LdapAuthError) as exc:
            return _failure_response(reason=str(exc) or "sso_error")

        jwt_token = self.manager._issue_jwt(
            user=user,
            expiration_time_in_seconds=airflow_conf.getint(
                "api_auth", "jwt_expiration_time"
            ),
        )

        response = RedirectResponse(
            url=(
                f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                f"?status=success&method=entra&stage=access_granted"
                f"&roles={quote(','.join(sorted(user.roles)), safe='')}"
                f"&next={quote(success_next, safe='')}"
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        self.manager._set_auth_cookie(response, jwt_token=jwt_token, secure=secure)
        self.manager._session_service.clear_entra_flow_state(response, request=request)
        return response
