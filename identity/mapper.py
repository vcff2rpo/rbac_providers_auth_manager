"""Identity-mapper facade.

The public facade keeps the auth-manager integration stable while delegating
provider-specific mapping rules to dedicated LDAP and Entra mapper classes.
"""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.identity.entra_mapper import EntraIdentityMapper
from rbac_providers_auth_manager.identity.ldap_mapper import LdapIdentityMapper
from rbac_providers_auth_manager.identity.models import (
    ExternalIdentity,
    RoleMappingResult,
)


class IdentityMapper:
    """Route normalized provider identities to the appropriate mapper."""

    def __init__(self, manager: Any) -> None:
        self._ldap_mapper = LdapIdentityMapper(manager)
        self._entra_mapper = EntraIdentityMapper(manager)

    def map_ldap_identity(
        self,
        *,
        identity: ExternalIdentity,
        ip_address: str,
    ) -> RoleMappingResult:
        """Return Airflow roles for a normalized LDAP identity."""
        return self._ldap_mapper.map_identity(identity=identity, ip_address=ip_address)

    def map_entra_identity(
        self,
        *,
        identity: ExternalIdentity,
        ip_address: str,
    ) -> RoleMappingResult:
        """Return Airflow roles for a normalized Entra identity."""
        return self._entra_mapper.map_identity(identity=identity, ip_address=ip_address)
