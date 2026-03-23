"""Policy models for optional scoped authorization filters.

These models keep future-looking authorization shape outside the Airflow-facing
entrypoint so richer policy rules can evolve without changing the auth-manager
contract everywhere at once.

The current plugin continues to support the existing role/action/resource model.
These models add optional resource-context filters that can be evaluated when
request details such as DAG tags or environment labels are available.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SubjectAttributes:
    """Optional subject metadata that may affect future authorization decisions."""

    username: str | None = None
    email: str | None = None
    roles: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResourceAttributes:
    """Optional resource metadata used by scoped authorization rules."""

    resource_id: str | None = None
    resource_type: str | None = None
    dag_tags: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Optional context passed into policy evaluation for filter-aware decisions."""

    subject: SubjectAttributes | None = None
    resource: ResourceAttributes | None = None


@dataclass(frozen=True, slots=True)
class RoleFilterRule:
    """Optional role-scoping filters loaded from ``permissions.ini``.

    A role with no populated filter fields behaves exactly like an ordinary role.
    When filters are present, they are evaluated only when matching context is
    available at runtime.
    """

    dag_tags: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()
    resource_prefixes: tuple[str, ...] = ()

    @property
    def has_constraints(self) -> bool:
        """Return whether the rule contains any active filter criteria."""
        return bool(self.dag_tags or self.environments or self.resource_prefixes)
