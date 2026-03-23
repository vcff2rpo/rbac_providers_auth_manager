"""FastAPI route registration for the custom Airflow auth manager."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette import status


def build_auth_router(flow_service: Any) -> APIRouter:
    """Build the auth-manager router around the supplied flow service."""
    router = APIRouter()

    @router.get("/login", response_class=HTMLResponse)
    @router.get("/login/", response_class=HTMLResponse)
    def login_form(
        request: Request,
        next: str | None = None,  # noqa: A002
        error: str | None = None,
        status_value: str | None = None,
        ref: str | None = None,
    ) -> HTMLResponse:
        return flow_service.render_login_form(
            request,
            next_url=next,
            error=error,
            status_value=status_value,
            reference=ref,
        )

    @router.post("/login")
    @router.post("/login/")
    async def login_submit(request: Request) -> RedirectResponse:
        return await flow_service.handle_login_submit(request)

    @router.get("/oauth-login/azure", response_model=None)
    def oauth_login_azure(
        request: Request,
        next: str | None = None,  # noqa: A002
    ) -> Response:
        return flow_service.handle_oauth_login_azure(request, next_url=next)

    @router.get("/oauth-authorized/azure")
    def oauth_authorized_azure(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> RedirectResponse:
        return flow_service.handle_oauth_authorized_azure(
            request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
        )

    @router.post("/token", status_code=status.HTTP_201_CREATED)
    def token(request: Request, body: dict[str, Any]) -> dict[str, str]:
        return flow_service.handle_token(request, body=body)

    @router.post("/token/cli", status_code=status.HTTP_201_CREATED)
    def token_cli(request: Request, body: dict[str, Any]) -> dict[str, str]:
        return flow_service.handle_token_cli(request, body=body)

    @router.get("/logout", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    def logout(request: Request) -> RedirectResponse:
        return flow_service.handle_logout(request)

    return router
