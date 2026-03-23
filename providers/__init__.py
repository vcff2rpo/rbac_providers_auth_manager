"""Authentication provider abstractions used by the auth manager.

The provider package stays import-light so the main plugin package can be
imported even when optional LDAP or Entra dependencies are not installed.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = (
    "BaseAuthProvider",
    "LdapAuthProvider",
    "EntraAuthProvider",
)


def __getattr__(name: str) -> Any:
    """Resolve provider classes lazily for optional dependency friendliness."""
    if name == "BaseAuthProvider":
        return import_module(
            "rbac_providers_auth_manager.providers.base"
        ).BaseAuthProvider
    if name == "LdapAuthProvider":
        return import_module(
            "rbac_providers_auth_manager.providers.ldap_provider"
        ).LdapAuthProvider
    if name == "EntraAuthProvider":
        return import_module(
            "rbac_providers_auth_manager.providers.entra_provider"
        ).EntraAuthProvider
    raise AttributeError(name)
