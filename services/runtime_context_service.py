"""Runtime request and UI context helpers for the auth manager."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Request
from fastapi.responses import RedirectResponse

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
    airflow_conf,
)
from rbac_providers_auth_manager.services.audit_service import AuditService
from rbac_providers_auth_manager.services.redirect_service import RedirectService


class RuntimeContextService:
    """Own request, redirect, cookie, and UI context helpers.

    The auth manager keeps thin wrapper methods for the Airflow-facing surface,
    while this service owns the concrete helper behavior that browser routes,
    providers, and UI rendering build on.
    """

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def get_context(self) -> Any | None:
        """Return the Airflow request context across supported variants."""
        return getattr(self.manager, "context", None) or getattr(
            self.manager, "_context", None
        )

    @staticmethod
    def client_ip(request: Request | None) -> str:
        """Return the client IP or an empty string."""
        return getattr(getattr(request, "client", None), "host", "") or ""

    def env_override(self, name: str, default: str = "") -> str:
        """Return a trimmed environment override string."""
        return (os.environ.get(name) or default).strip()

    def ui_environment_label(self) -> str:
        """Return the login-page environment label."""
        label = self.env_override("AIRFLOW_ITIM_UI_ENV_LABEL")
        if label:
            return label

        executor = airflow_conf.get("core", "executor", fallback="").strip()
        if executor:
            return f"Airflow | {executor}"

        return "Airflow"

    def support_contact_label(self) -> str:
        """Return support contact text shown in the help panel."""
        return self.env_override(
            "AIRFLOW_ITIM_UI_SUPPORT_CONTACT",
            "Platform support: airflow-support@example.com",
        )

    @staticmethod
    def default_success_redirect_path() -> str:
        """Return the safe default destination after successful authentication."""
        return "/"

    def resolve_post_login_redirect_target(
        self,
        *,
        request: Request,
        next_url: str | None,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Resolve the final post-login redirect target."""
        sanitized = self.sanitize_next(
            next_url, request, trusted_proxies=trusted_proxies
        )
        if sanitized == "/":
            return self.default_success_redirect_path()
        return sanitized

    def auth_config_broken(self) -> bool:
        """Return whether the auth manager is running in degraded config-error mode."""
        return bool(self.manager._config_error_message)

    def auth_config_error_text(self) -> str:
        """Return the operator-facing configuration error text for login UI."""
        if self.manager._config_error_message:
            return self.manager._config_error_message
        return "Authentication configuration error."

    def config_error_lines(self) -> list[str]:
        """Split config error text into user-visible lines."""
        raw = self.auth_config_error_text()
        return [line.strip() for line in raw.split("|") if line.strip()] or [raw]

    @staticmethod
    def make_ui_reference() -> str:
        """Return a short reference token shown in auth UI messages."""
        return AuditService.make_ui_reference()

    @staticmethod
    def sanitize_next(
        next_url: str | None,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return a same-origin safe redirect target."""
        return RedirectService.sanitize_next(
            next_url, request, trusted_proxies=trusted_proxies
        )

    @staticmethod
    def is_secure_request(
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> bool:
        """Determine whether the request should be treated as HTTPS."""
        return RedirectService.is_secure_request(
            request, trusted_proxies=trusted_proxies
        )

    def effective_external_base(
        self,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return the externally visible base URL for callback generation."""
        return self.manager._redirect_service.effective_external_base(
            request,
            trusted_proxies=trusted_proxies,
        )

    def entra_callback_url(self, request: Request) -> str:
        """Return the externally reachable Entra callback URL."""
        cfg = self.manager._cfg_loader.get_config()
        base = self.effective_external_base(
            request,
            trusted_proxies=cfg.general.trusted_proxies,
        )
        return f"{base}{AUTH_MANAGER_FASTAPI_APP_PREFIX}/oauth-authorized/azure"

    def set_auth_cookie(
        self,
        response: RedirectResponse,
        *,
        jwt_token: str,
        secure: bool,
    ) -> None:
        """Write the Airflow auth token cookie."""
        self.manager._session_service.set_auth_cookie(
            response,
            jwt_token=jwt_token,
            secure=secure,
        )

    def delete_auth_cookie(self, response: RedirectResponse, *, secure: bool) -> None:
        """Delete the Airflow auth token cookie."""
        self.manager._session_service.delete_auth_cookie(response, secure=secure)
