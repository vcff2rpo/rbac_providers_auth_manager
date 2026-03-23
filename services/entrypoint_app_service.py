"""Thin Airflow-facing entrypoint/app helpers for the auth manager."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from fastapi import FastAPI

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
    airflow_conf,
)
from rbac_providers_auth_manager.api.routes import build_auth_router
from rbac_providers_auth_manager.api.routes_api import build_auth_api_router


class EntrypointAppService:
    """Own the non-auth-business Airflow entrypoint helpers and app wiring."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    @property
    def apiserver_endpoint(self) -> str:
        """Return the configured API server base URL."""
        return airflow_conf.get("api", "base_url", fallback="/")

    @staticmethod
    def get_cli_commands() -> list[Any]:
        """This auth manager does not expose extra Airflow CLI commands."""
        return []

    @staticmethod
    def get_api_endpoints() -> None:
        """No legacy Flask API endpoints are registered by this auth manager."""
        return None

    @staticmethod
    def get_db_manager() -> str | None:
        """This auth manager does not manage custom DB models."""
        return None

    @staticmethod
    def register_views() -> None:
        """No Flask FAB views are registered; this is a FastAPI auth manager."""
        return None

    @staticmethod
    def get_extra_menu_items() -> list[Any]:
        """Return extra UI menu items. None are added by this plugin."""
        return []

    def get_url_login(self) -> str:
        """Return the login URL used by Airflow UI redirection."""
        return urljoin(
            self.apiserver_endpoint, f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login/"
        )

    def get_url_logout(self) -> str | None:
        """Return the logout URL used by Airflow UI."""
        return urljoin(
            self.apiserver_endpoint, f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout"
        )

    def create_token(self, headers: dict[str, str], body: dict[str, Any]) -> Any:
        """Authenticate username/password for API token issuance."""
        self.manager._refresh_if_needed()

        username = (body.get("username") or "").strip()
        password = (body.get("password") or "").strip()
        if not username or not password:
            raise ValueError("username and password required")

        return self.manager._authenticate_ldap(
            username=username, password=password, request=None
        )

    def get_fastapi_app(self) -> FastAPI:
        """Expose the auth-manager FastAPI app."""
        app = FastAPI()
        app.include_router(build_auth_router(self.manager._auth_flow_service))
        app.include_router(build_auth_api_router(self.manager._auth_flow_service))
        return app
