"""Helpers for evaluating optional resource-scoped policy filters.

The current plugin continues to allow classic FAB-style permission checks.
This module adds a lightweight evaluation layer for future optional filters such
as DAG tags and environment labels when resource context is available.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rbac_providers_auth_manager.authorization.policy_models import (
    AuthorizationContext,
    ResourceAttributes,
    RoleFilterRule,
)


def _normalize_token(value: str) -> str:
    """Normalize a free-form token for case-insensitive comparisons."""
    return " ".join((value or "").strip().split()).casefold()


def _normalize_many(values: Iterable[str]) -> tuple[str, ...]:
    """Return a normalized, de-duplicated tuple of non-empty values."""
    normalized = {
        _normalize_token(value) for value in values if _normalize_token(value)
    }
    return tuple(sorted(normalized))


def _coerce_str_sequence(value: Any) -> tuple[str, ...]:
    """Coerce strings, objects, or iterables into a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(str(item) for item in value.values() if item is not None)
    try:
        result: list[str] = []
        for item in value:
            if item is None:
                continue
            result.append(str(getattr(item, "name", item)))
        return tuple(result)
    except TypeError:
        return (str(value),)


def extract_dag_tags(details: Any | None) -> tuple[str, ...]:
    """Extract DAG tags from Airflow details objects or dict-like structures."""
    if details is None:
        return ()
    candidates: list[str] = []
    for attr in ("tags", "dag_tags"):
        if isinstance(details, dict) and attr in details:
            candidates.extend(_coerce_str_sequence(details.get(attr)))
        else:
            candidates.extend(_coerce_str_sequence(getattr(details, attr, None)))
    return _normalize_many(candidates)


def extract_environment_labels(details: Any | None) -> tuple[str, ...]:
    """Extract optional environment-style labels from request details."""
    if details is None:
        return ()
    candidates: list[str] = []
    for attr in ("environment", "environments", "env", "labels"):
        if isinstance(details, dict) and attr in details:
            candidates.extend(_coerce_str_sequence(details.get(attr)))
        else:
            candidates.extend(_coerce_str_sequence(getattr(details, attr, None)))
    return _normalize_many(candidates)


def build_dag_authorization_context(
    *, dag_id: str | None, details: Any | None
) -> AuthorizationContext | None:
    """Build optional authorization context for DAG-scoped checks.

    The returned context is intentionally sparse and only includes fields that
    are reliably derivable from the current request details object.
    """
    dag_tags = extract_dag_tags(details)
    environments = extract_environment_labels(details)
    if not dag_id and not dag_tags and not environments:
        return None
    return AuthorizationContext(
        resource=ResourceAttributes(
            resource_id=(dag_id or None),
            resource_type="dag",
            dag_tags=dag_tags,
            environments=environments,
        )
    )


class RoleFilterEvaluator:
    """Evaluate optional role filter rules against runtime context."""

    def allows_role(
        self,
        *,
        role_name: str,
        rule: RoleFilterRule | None,
        context: AuthorizationContext | None,
    ) -> bool:
        """Return whether a role remains active under the supplied context.

        When no runtime context is available, the evaluator intentionally keeps
        the role active so existing permission checks remain backward-compatible.
        Filter-aware restrictions are applied only where the caller can provide
        resource metadata.
        """
        if (
            rule is None
            or not rule.has_constraints
            or context is None
            or context.resource is None
        ):
            return True

        resource = context.resource
        resource_tags = set(_normalize_many(resource.dag_tags))
        resource_envs = set(_normalize_many(resource.environments))

        if rule.dag_tags and not resource_tags.intersection(
            _normalize_many(rule.dag_tags)
        ):
            return False
        if rule.environments and not resource_envs.intersection(
            _normalize_many(rule.environments)
        ):
            return False
        if rule.resource_prefixes:
            resource_id = (resource.resource_id or "").strip()
            if resource_id and not any(
                resource_id.startswith(prefix) for prefix in rule.resource_prefixes
            ):
                return False
        return True
