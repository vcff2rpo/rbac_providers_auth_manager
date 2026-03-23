"""Lightweight exception types used across the auth plugin.

This module intentionally has no optional third-party dependencies so other
modules can safely import the shared exception types even when LDAP or Entra
extras are not installed.
"""

from __future__ import annotations


class OptionalProviderDependencyError(RuntimeError):
    """Raised when an enabled provider is missing its optional runtime dependency."""


class LdapAuthError(Exception):
    """Raised for LDAP authentication failures and LDAP access errors."""


class EntraIdAuthError(Exception):
    """Raised for Azure Entra ID and OIDC authentication failures."""
