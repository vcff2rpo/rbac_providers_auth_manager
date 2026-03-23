"""JSON endpoints that expose normalized auth-flow state.

These endpoints do not replace the interactive browser flow. They expose the
same normalized state so UI changes and future API-driven surfaces can reuse
one auth-flow engine.
"""

from __future__ import annotations

from fastapi import APIRouter, Request


def build_auth_api_router(flow_service) -> APIRouter:
    """Build the JSON router around the supplied auth flow service."""
    router = APIRouter(prefix="/flow", tags=["auth-flow"])

    @router.get("/providers")
    def provider_readiness(request: Request) -> dict[str, object]:
        """Return provider readiness for the current deployment."""
        return flow_service.get_provider_readiness_payload().to_dict()

    @router.get("/login-status")
    def login_status(
        request: Request,
        next: str | None = None,  # noqa: A002
        error: str | None = None,
        status_value: str | None = None,
        ref: str | None = None,
    ) -> dict[str, object]:
        """Return the normalized login banner state for the current request."""
        return flow_service.build_login_status_payload(
            request,
            next_url=next,
            error=error,
            status_value=status_value,
            reference=ref,
        ).to_dict()

    @router.get("/oauth-callback-state")
    def oauth_callback_state(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> dict[str, object]:
        """Return normalized Entra callback request state for diagnostics."""
        return flow_service.get_oauth_callback_state_payload(
            request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
        ).to_dict()

    @router.get("/logout-state")
    def logout_state(request: Request) -> dict[str, object]:
        """Return normalized logout redirect state and cleanup scope."""
        return flow_service.get_logout_state_payload().to_dict()

    return router
