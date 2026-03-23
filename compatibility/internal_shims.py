"""Compatibility shims for optional Airflow auth-manager model imports.

The plugin targets the public Airflow auth-manager contract first, but some
resource-detail and request model locations vary slightly across Airflow 3.x
patch releases. This module keeps those fallbacks out of the auth manager and
route services so future upgrades are easier to audit.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from airflow.api_fastapi.auth.managers.base_auth_manager import (
        IsAuthorizedConnectionRequest,
        IsAuthorizedDagRequest,
        IsAuthorizedPoolRequest,
        IsAuthorizedVariableRequest,
    )
except Exception:  # pragma: no cover  # noqa: BLE001
    IsAuthorizedDagRequest = Mapping[str, Any]  # type: ignore[assignment,misc]
    IsAuthorizedConnectionRequest = Mapping[str, Any]  # type: ignore[assignment,misc]
    IsAuthorizedPoolRequest = Mapping[str, Any]  # type: ignore[assignment,misc]
    IsAuthorizedVariableRequest = Mapping[str, Any]  # type: ignore[assignment,misc]

try:
    from airflow.api_fastapi.auth.managers.models.resource_details import (  # type: ignore
        AccessView,
        DagAccessEntity,
    )
except Exception:  # pragma: no cover  # noqa: BLE001
    AccessView = object  # type: ignore[assignment]
    DagAccessEntity = object  # type: ignore[assignment]

__all__ = (
    "AccessView",
    "DagAccessEntity",
    "IsAuthorizedConnectionRequest",
    "IsAuthorizedDagRequest",
    "IsAuthorizedPoolRequest",
    "IsAuthorizedVariableRequest",
)
