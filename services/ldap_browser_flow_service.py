"""LDAP browser sign-in flow execution helpers."""

from __future__ import annotations

import secrets
from typing import Any, cast
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.datastructures import UploadFile
from starlette import status

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
    airflow_conf,
)
from rbac_providers_auth_manager.core.exceptions import LdapAuthError


def _form_str(value: object | None) -> str:
    """Return a stripped string value from form payloads."""
    if value is None or isinstance(value, UploadFile):
        return ""
    return str(value).strip()


class LdapBrowserFlowService:
    """Execute browser login flows backed by LDAP credentials."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    async def handle_login_submit(self, request: Request) -> RedirectResponse:
        """Handle username/password login form submission."""
        self.manager._refresh_if_needed()

        if self.manager._auth_config_broken():
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.browser_login.blocked",
                level="warning",
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
            self.manager._ldap_provider is None
            or not self.manager._ldap_provider.is_enabled()
        ):
            return RedirectResponse(
                url=f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login?error=ldap_disabled",
                status_code=status.HTTP_303_SEE_OTHER,
            )

        secure = self.manager._session_service.resolve_cookie_secure(
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )

        form = await request.form()
        raw_next = cast(str | None, form.get("next"))
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

        csrf = str(form.get("csrf") or "")
        expected = (
            request.cookies.get(self.manager._session_service.LDAP_CSRF_COOKIE_NAME)
            or ""
        )
        if not expected or not secrets.compare_digest(csrf, expected):
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.browser_login.failure",
                level="warning",
                reference=ui_ref,
                provider="ldap",
                principal=_form_str(form.get("username")),
                ip_address=self.manager._client_ip(request),
                reason="csrf_mismatch",
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error=csrf&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        username = _form_str(form.get("username"))
        password = _form_str(form.get("password"))
        if not username or not password:
            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.browser_login.failure",
                reference=ui_ref,
                provider="ldap",
                principal=username,
                ip_address=self.manager._client_ip(request),
                reason="missing_credentials",
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error=missing&ref={quote(ui_ref, safe='')}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        try:
            user = self.manager._authenticate_ldap(
                username=str(username),
                password=str(password),
                request=request,
            )
        except LdapAuthError as exc:
            reason = (str(exc) or "").lower()
            retry_after = 0

            if reason.startswith("login throttled:"):
                error_code = "throttled"
                try:
                    retry_after = int(reason.split(":", 1)[1].strip())
                except (IndexError, ValueError):
                    retry_after = 0
            elif "no roles" in reason or "roles mapped" in reason:
                error_code = "unauthorized"
            elif "missing" in reason:
                error_code = "missing"
            else:
                error_code = "invalid"

            ui_ref = self.manager._make_ui_reference()
            self.manager._audit_service.log_flow_event(
                event="auth.browser_login.failure",
                reference=ui_ref,
                provider="ldap",
                principal=username,
                ip_address=self.manager._client_ip(request),
                reason=str(exc) or "ldap_auth_error",
                mapped_error=error_code,
                retry_after=retry_after,
            )

            extra = (
                f"&retry_after={retry_after}"
                if error_code == "throttled" and retry_after > 0
                else ""
            )
            return RedirectResponse(
                url=(
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
                    f"?next={quote(next_safe, safe='')}&error={error_code}&ref={quote(ui_ref, safe='')}{extra}"
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        jwt_token = self.manager._issue_jwt(
            user=user,
            expiration_time_in_seconds=airflow_conf.getint(
                "api_auth", "jwt_expiration_time"
            ),
        )

        success_url = (
            f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
            f"?status=success&method=ldap&stage=access_granted"
            f"&roles={quote(','.join(sorted(user.roles)), safe='')}"
            f"&next={quote(success_next, safe='')}"
        )
        response = RedirectResponse(
            url=success_url, status_code=status.HTTP_303_SEE_OTHER
        )
        self.manager._set_auth_cookie(response, jwt_token=jwt_token, secure=secure)
        self.manager._session_service.clear_ldap_csrf_cookie(response)
        return response
