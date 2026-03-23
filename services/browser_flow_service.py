"""Browser-flow facade for login, OAuth, and logout entrypoints."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from rbac_providers_auth_manager.services.ldap_browser_flow_service import (
    LdapBrowserFlowService,
)
from rbac_providers_auth_manager.services.oauth_browser_flow_service import (
    OauthBrowserFlowService,
)


class BrowserFlowService:
    """Coordinate LDAP browser login, Entra browser flows, and logout."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._ldap_flows = LdapBrowserFlowService(manager)
        self._oauth_flows = OauthBrowserFlowService(manager)

    async def handle_login_submit(self, request: Request) -> RedirectResponse:
        """Handle username/password login form submission."""
        return await self._ldap_flows.handle_login_submit(request)

    def handle_oauth_login_azure(
        self,
        request: Request,
        *,
        next_url: str | None,
    ) -> Response:
        """Start the Entra browser sign-in flow."""
        return self._oauth_flows.handle_oauth_login_azure(request, next_url=next_url)

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
        return self._oauth_flows.handle_oauth_authorized_azure(
            request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
        )

    def handle_logout(self, request: Request) -> RedirectResponse:
        """Clear auth cookies and redirect the browser back to the login page."""
        self.manager._refresh_if_needed()

        if self.manager._auth_config_broken():
            return RedirectResponse(
                f"{self.manager.get_url_login()}?error=config_disabled",
                status_code=307,
            )

        cfg = self.manager._cfg_loader.get_config()
        secure = self.manager._session_service.resolve_cookie_secure(
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )

        logout_state = self.manager._flow_payload_builder.get_logout_state_payload()
        response = RedirectResponse(
            f"{logout_state.login_url}?status={logout_state.status_value}",
            status_code=307,
        )
        self.manager._session_service.clear_logout_cookies(
            response, secure=secure, request=request
        )
        return response
