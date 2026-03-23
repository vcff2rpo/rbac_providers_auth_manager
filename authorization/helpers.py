"""Shared authorization/resource helper utilities."""

from __future__ import annotations

from rbac_providers_auth_manager.authorization.vocabulary import (
    RESOURCE_DAG,
    RESOURCE_DAG_PREFIX,
    RESOURCE_DAG_RUN,
    RESOURCE_DAG_RUN_PREFIX,
)

_RESOURCE_DETAILS_PREFIX: dict[str, str] = {
    RESOURCE_DAG: RESOURCE_DAG_PREFIX,
    RESOURCE_DAG_RUN: RESOURCE_DAG_RUN_PREFIX,
}


def resource_name(resource_id: str, resource_type: str) -> str:
    """Return the canonical object-scoped resource name."""
    normalized_id = (resource_id or "").strip()
    normalized_type = (resource_type or "").strip()

    if any(
        normalized_id.startswith(prefix) for prefix in _RESOURCE_DETAILS_PREFIX.values()
    ):
        return normalized_id

    prefix = _RESOURCE_DETAILS_PREFIX.get(normalized_type)
    if prefix:
        return f"{prefix}{normalized_id}"
    return f"{normalized_type}:{normalized_id}"
