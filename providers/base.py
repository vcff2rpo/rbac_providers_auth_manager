"""Provider contracts for browser and credential authentication flows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from fastapi import Request

from rbac_providers_auth_manager.identity.models import ExternalIdentity


class BaseAuthProvider(ABC):
    """Abstract provider contract used by auth-flow orchestration."""

    provider_name: str

    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether the provider is available for runtime use."""

    def authenticate_credentials(
        self,
        *,
        username: str,
        password: str,
        request: Request | None,
    ) -> ExternalIdentity:
        """Authenticate direct credentials when the provider supports it."""
        raise NotImplementedError

    def build_authorize_redirect_url(
        self,
        *,
        request: Request,
        state: str,
        nonce: str,
        code_verifier: str | None,
    ) -> str:
        """Build the browser redirect URL for SSO flows."""
        raise NotImplementedError

    def authenticate_authorization_code(
        self,
        *,
        request: Request,
        code: str,
        expected_nonce: str | None,
        code_verifier: str | None,
    ) -> ExternalIdentity:
        """Complete an authorization-code flow and return a normalized identity."""
        raise NotImplementedError
