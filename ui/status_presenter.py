"""Status-message facade for the browser auth UI."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.ui.status_panel_renderer import StatusPanelRenderer
from rbac_providers_auth_manager.ui.status_query_service import StatusQueryService


class LoginStatusPresenter:
    """Build and render normalized login status state for the UI layer."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._query_service = StatusQueryService(manager)
        self._panel_renderer = StatusPanelRenderer(manager, self._query_service)

    def retry_after_from_query(self, raw_value: str | None) -> int:
        """Parse retry-after seconds from query parameters safely."""
        return self._query_service.retry_after_from_query(raw_value)

    def status_from_query(
        self, *, error: str | None, status_value: str | None
    ) -> tuple[str, str]:
        """Map query parameters into a status level and user-facing title."""
        return self._query_service.status_from_query(
            error=error, status_value=status_value
        )

    def status_message_from_query(
        self, *, error: str | None, status_value: str | None
    ) -> str:
        """Return a polished user-facing status message."""
        return self._query_service.status_message_from_query(
            error=error, status_value=status_value
        )

    def render_status_banner(
        self,
        *,
        error: str | None,
        status_value: str | None,
        reference: str | None,
        retry_after: int = 0,
    ) -> str:
        """Return a styled login-page banner for success, info, warning, or error states."""
        return self._panel_renderer.render_status_banner(
            error=error,
            status_value=status_value,
            reference=reference,
            retry_after=retry_after,
        )

    def login_status_method_label(self, method: str | None) -> str:
        """Return a display label for an authentication method identifier."""
        return self._query_service.login_status_method_label(method)

    def login_status_roles_from_query(self, raw_value: str | None) -> list[str]:
        """Parse a role summary from a query-string value."""
        return self._query_service.login_status_roles_from_query(raw_value)

    def login_status_title(
        self,
        *,
        error: str | None,
        status_value: str | None,
        method: str | None,
    ) -> str:
        """Return the rich-status title text for the login panel."""
        return self._query_service.login_status_title(
            error=error,
            status_value=status_value,
            method=method,
        )

    def login_status_message(
        self,
        *,
        error: str | None,
        status_value: str | None,
        method: str | None,
        stage: str | None,
    ) -> str:
        """Return the richer configured status message for the login panel."""
        return self._query_service.login_status_message(
            error=error,
            status_value=status_value,
            method=method,
            stage=stage,
        )

    def render_rich_status_panel(
        self,
        *,
        error: str | None,
        status_value: str | None,
        reference: str | None,
        retry_after: int = 0,
        method: str | None = None,
        stage: str | None = None,
        roles: list[str] | tuple[str, ...] = (),
        next_url: str | None = None,
        auto_redirect_seconds: int = 0,
    ) -> str:
        """Return the rich login-page status panel driven by UI config."""
        return self._panel_renderer.render_rich_status_panel(
            error=error,
            status_value=status_value,
            reference=reference,
            retry_after=retry_after,
            method=method,
            stage=stage,
            roles=roles,
            next_url=next_url,
            auto_redirect_seconds=auto_redirect_seconds,
        )
