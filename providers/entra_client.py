"""Azure Entra ID / OAuth2 / OIDC client facade for the custom auth manager."""

from __future__ import annotations

import threading

from rbac_providers_auth_manager.config import EntraIdConfig
from rbac_providers_auth_manager.providers.entra_http_service import EntraHttpService
from rbac_providers_auth_manager.providers.entra_identity_service import (
    EntraIdIdentity,
    EntraIdentityService,
)


class EntraIdClient:
    """Minimal Azure Entra ID / OpenID Connect client facade.

    The facade keeps the provider-facing surface stable while delegating HTTP/
    discovery concerns and token/identity normalization to dedicated helpers.
    """

    def __init__(self, cfg: EntraIdConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._http_service = EntraHttpService(cfg)
        self._identity_service = EntraIdentityService(cfg, self._http_service)

    def reconfigure(self, cfg: EntraIdConfig) -> None:
        """Replace configuration and clear dependent helper caches."""
        self.cfg = cfg
        with self._lock:
            self._http_service.reconfigure(cfg)
            self._identity_service.reconfigure(cfg)

    def build_authorize_redirect_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_verifier: str | None = None,
    ) -> str:
        """Build the Azure authorization endpoint URL for browser redirect."""
        return self._identity_service.build_authorize_redirect_url(
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
        )

    def authenticate_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        expected_nonce: str | None,
        code_verifier: str | None = None,
    ) -> EntraIdIdentity:
        """Exchange an authorization code and return normalized identity data."""
        return self._identity_service.authenticate_authorization_code(
            code=code,
            redirect_uri=redirect_uri,
            expected_nonce=expected_nonce,
            code_verifier=code_verifier,
        )
