"""Entra provider adapter for browser-based SSO flows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Request

from rbac_providers_auth_manager.core.exceptions import EntraIdAuthError
from rbac_providers_auth_manager.identity.models import ExternalIdentity
from rbac_providers_auth_manager.providers.base import BaseAuthProvider

if TYPE_CHECKING:
    pass


class EntraAuthProvider(BaseAuthProvider):
    """Wrap the Entra client behind a provider-oriented contract."""

    provider_name = "entra"

    def __init__(self, manager: Any, client: Any | None) -> None:
        self._manager = manager
        self._client = client

    def is_enabled(self) -> bool:
        """Return whether the Entra provider has an active client instance."""
        return self._client is not None

    def reconfigure(self, client: Any | None) -> None:
        """Replace the active Entra client instance after config reload."""
        self._client = client

    def build_authorize_redirect_url(
        self,
        *,
        request: Request,
        state: str,
        nonce: str,
        code_verifier: str | None,
    ) -> str:
        """Build the Entra browser redirect URL for an SSO login start."""
        if self._client is None:
            raise EntraIdAuthError("entra_disabled")
        return self._client.build_authorize_redirect_url(
            redirect_uri=self._manager._entra_callback_url(request),
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
        )

    def authenticate_authorization_code(
        self,
        *,
        request: Request,
        code: str,
        expected_nonce: str | None,
        code_verifier: str | None,
    ) -> ExternalIdentity:
        """Exchange an authorization code for a normalized Entra identity."""
        if self._client is None:
            raise EntraIdAuthError("entra_disabled")
        identity = self._client.authenticate_authorization_code(
            code=code,
            redirect_uri=self._manager._entra_callback_url(request),
            expected_nonce=expected_nonce,
            code_verifier=code_verifier,
        )
        return ExternalIdentity(
            provider=self.provider_name,
            user_id=identity.user_id,
            username=identity.username,
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            display_name=identity.display_name,
            claim_values=tuple(identity.claim_values),
            claims=identity.claims,
        )
