"""Compatibility auth-manager entrypoint facade.

The real implementation lives in :mod:`rbac_providers_auth_manager.entrypoints.auth_manager`.
This root module remains only because Airflow references it directly from
``[core] auth_manager``.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

from rbac_providers_auth_manager.authorization.helpers import resource_name

if TYPE_CHECKING:
    from rbac_providers_auth_manager.entrypoints.auth_manager import (
        ItimAnonymousUser,
        RbacAuthManager,
        RbacAuthUser,
    )

__all__ = (
    "ItimAnonymousUser",
    "RbacAuthManager",
    "RbacAuthUser",
    "resource_name",
)


def __getattr__(name: str) -> Any:
    """Resolve auth-manager classes lazily to avoid plugin import cycles."""
    if name in {"ItimAnonymousUser", "RbacAuthManager", "RbacAuthUser"}:
        module = import_module("rbac_providers_auth_manager.entrypoints.auth_manager")
        return getattr(module, name)
    raise AttributeError(name)
