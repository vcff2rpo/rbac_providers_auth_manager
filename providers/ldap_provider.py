"""LDAP provider adapter for credential-based authentication flows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Request

from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.identity.models import ExternalIdentity
from rbac_providers_auth_manager.providers.base import BaseAuthProvider

if TYPE_CHECKING:
    pass


class LdapAuthProvider(BaseAuthProvider):
    """Wrap the LDAP client behind a provider-oriented contract."""

    provider_name = "ldap"

    def __init__(self, manager: Any, client: Any | None) -> None:
        self._manager = manager
        self._client = client

    def is_enabled(self) -> bool:
        """Return whether the LDAP provider has an active client instance."""
        return self._client is not None

    def reconfigure(self, client: Any | None) -> None:
        """Replace the active LDAP client instance after config reload."""
        self._client = client

    def authenticate_credentials(
        self,
        *,
        username: str,
        password: str,
        request: Request | None,
    ) -> ExternalIdentity:
        """Authenticate credentials and emit a normalized LDAP identity."""
        self._manager._refresh_if_needed()
        if self._client is None:
            raise LdapAuthError("LDAP provider is disabled")

        allowed, retry_after = self._manager._check_ldap_rate_limit(
            request=request,
            username=username,
        )
        if not allowed:
            raise LdapAuthError(f"Login throttled: {retry_after}")

        try:
            identity = self._client.authenticate(username=username, password=password)
        except LdapAuthError as exc:
            retry_after = self._manager._record_ldap_failure(
                request=request, username=username
            )
            if retry_after:
                raise LdapAuthError(f"Login throttled: {retry_after}") from exc
            raise

        self._manager._clear_ldap_failures(request=request, username=username)
        return ExternalIdentity(
            provider=self.provider_name,
            user_id=identity.user_id,
            username=identity.username,
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            display_name=identity.display_name,
            group_dns=tuple(identity.group_dns),
        )
