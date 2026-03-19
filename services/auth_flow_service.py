"""High-level auth flow facade for browser and token entrypoints."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from rbac_providers_auth_manager.api.models import (
    LoginStatusPayload,
    LogoutStatePayload,
    OAuthCallbackStatePayload,
    ProviderReadinessPayload,
    TokenIssueResult,
)
from rbac_providers_auth_manager.services.browser_flow_service import BrowserFlowService
from rbac_providers_auth_manager.services.flow_payloads import AuthFlowPayloadBuilder
from rbac_providers_auth_manager.services.token_flow_service import TokenFlowService


class AuthFlowService:
    """Coordinate browser and token flows while sharing normalized payloads."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._payload_builder = AuthFlowPayloadBuilder(manager)
        self.manager._flow_payload_builder = self._payload_builder
        self._browser_flows = BrowserFlowService(manager)
        self._token_flows = TokenFlowService(manager)

    def render_login_form(
        self,
        request: Request,
        *,
        next_url: str | None,
        error: str | None,
        status_value: str | None,
        reference: str | None,
    ) -> HTMLResponse:
        """Render the interactive login page for browser-based sign-in."""
        self.manager._refresh_if_needed()
        status_payload = self._payload_builder.build_login_status_payload(
            request,
            next_url=next_url,
            error=error,
            status_value=status_value,
            reference=reference,
        )
        return self.manager._ui_renderer.render_login_page(
            request=request,
            next_url=next_url or request.query_params.get("next"),
            error=error,
            status_value=status_payload.status_value or "ready",
            reference=status_payload.reference,
            status_payload=status_payload,
        )

    def get_provider_readiness_payload(self) -> ProviderReadinessPayload:
        """Return provider readiness for browser and JSON consumers."""
        return self._payload_builder.get_provider_readiness_payload()

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
        return self._payload_builder.build_login_status_payload(
            request,
            next_url=next_url,
            error=error,
            status_value=status_value,
            reference=reference,
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
        """Return normalized Entra callback state for diagnostics."""
        return self._payload_builder.get_oauth_callback_state_payload(
            request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
        )

    def get_logout_state_payload(self) -> LogoutStatePayload:
        """Return normalized logout redirect state for browser and JSON consumers."""
        return self._payload_builder.get_logout_state_payload()

    def issue_token_result(
        self,
        request: Request,
        *,
        body: dict[str, Any],
        cli: bool,
    ) -> TokenIssueResult:
        """Return a normalized token result for API and CLI callers."""
        return self._payload_builder.issue_token_result(request, body=body, cli=cli)

    async def handle_login_submit(self, request: Request) -> RedirectResponse:
        """Execute the browser LDAP sign-in submission flow."""
        return await self._browser_flows.handle_login_submit(request)

    def handle_oauth_login_azure(
        self,
        request: Request,
        *,
        next_url: str | None,
    ) -> Response:
        """Execute the Entra browser sign-in start flow."""
        return self._browser_flows.handle_oauth_login_azure(request, next_url=next_url)

    def handle_oauth_authorized_azure(
        self,
        request: Request,
        *,
        code: str | None,
        state: str | None,
        error: str | None,
        error_description: str | None,
    ) -> RedirectResponse:
        """Execute the Entra callback completion flow."""
        return self._browser_flows.handle_oauth_authorized_azure(
            request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
        )

    def handle_token(self, request: Request, *, body: dict[str, Any]) -> dict[str, str]:
        """Create an API JWT token for credential-based access."""
        return self._token_flows.handle_token(request, body=body)

    def handle_token_cli(
        self, request: Request, *, body: dict[str, Any]
    ) -> dict[str, str]:
        """Create a CLI JWT token using the CLI-specific expiry setting."""
        return self._token_flows.handle_token_cli(request, body=body)

    def handle_logout(self, request: Request) -> RedirectResponse:
        """Clear auth cookies and redirect the browser back to the login page."""
        return self._browser_flows.handle_logout(request)
