"""RBAC policy primitives for the custom Airflow auth manager.

This module keeps policy evaluation separate from the canonical authorization
vocabulary. The vocabulary itself lives in ``authorization.vocabulary`` so
resource/action naming drift can be addressed without editing the policy engine.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rbac_providers_auth_manager.authorization.policy_models import AuthorizationContext
from rbac_providers_auth_manager.authorization.resource_filters import (
    RoleFilterEvaluator,
)
from rbac_providers_auth_manager.authorization.vocabulary import (
    ACTION_CAN_CREATE,
    ACTION_CAN_DELETE,
    ACTION_CAN_EDIT,
    ACTION_CAN_READ,
    ACTION_MENU_ACCESS,
    RESOURCE_ADMIN_MENU,
    RESOURCE_ASSET,
    RESOURCE_ASSET_ALIAS,
    RESOURCE_AUDIT_LOG,
    RESOURCE_BACKFILL,
    RESOURCE_BROWSE_MENU,
    RESOURCE_CLUSTER_ACTIVITY,
    RESOURCE_CONFIG,
    RESOURCE_CONNECTION,
    RESOURCE_DAG,
    RESOURCE_DAG_CODE,
    RESOURCE_DAG_DEPENDENCIES,
    RESOURCE_DAG_PREFIX,
    RESOURCE_DAG_RUN,
    RESOURCE_DAG_RUN_PREFIX,
    RESOURCE_DAG_VERSION,
    RESOURCE_DAG_WARNING,
    RESOURCE_DOCS,
    RESOURCE_DOCS_MENU,
    RESOURCE_HITL_DETAIL,
    RESOURCE_IMPORT_ERROR,
    RESOURCE_JOB,
    RESOURCE_PLUGIN,
    RESOURCE_POOL,
    RESOURCE_PROVIDER,
    RESOURCE_SLA_MISSES,
    RESOURCE_TASK_INSTANCE,
    RESOURCE_TASK_LOG,
    RESOURCE_TRIGGER,
    RESOURCE_VARIABLE,
    RESOURCE_WEBSITE,
    RESOURCE_XCOM,
    normalize_action,
    normalize_resource,
)
from rbac_providers_auth_manager.core.util import canonicalize_dn

if TYPE_CHECKING:
    from rbac_providers_auth_manager.config import AuthConfig


@dataclass(frozen=True, slots=True)
class Permission:
    """A single normalized or unnormalized permission pair."""

    action: str
    resource: str

    def normalized(self) -> "Permission":
        """Return a canonicalized permission object."""
        return Permission(
            action=normalize_action(self.action),
            resource=normalize_resource(self.resource),
        )


@dataclass(frozen=True, slots=True)
class RolePermissions:
    """Permissions attached to a single Airflow role."""

    name: str
    permissions: frozenset[Permission]


class PermissionMatrix:
    """In-memory permission matrix with wildcard and DAG umbrella semantics.

    The matrix compiles multi-role permission sets into a cached flattened form
    so repeated checks are cheap during a request.
    """

    def __init__(self, *, roles: dict[str, RolePermissions]) -> None:
        self._roles = roles
        self._compiled_cache: dict[tuple[str, ...], frozenset[Permission]] = {}
        self._compiled_cache_max = 256

    @staticmethod
    def _expand_umbrella(resource: str) -> list[str]:
        """Expand a resource into all umbrella resources that should match it."""
        if resource.startswith(RESOURCE_DAG_PREFIX):
            return [resource, RESOURCE_DAG]
        if resource.startswith(RESOURCE_DAG_RUN_PREFIX):
            return [resource, RESOURCE_DAG_RUN]
        return [resource]

    @staticmethod
    def _match(compiled: frozenset[Permission], action: str, resource: str) -> bool:
        """Return whether a compiled permission set matches the given target."""
        if Permission(action="*", resource="*") in compiled:
            return True
        if Permission(action=action, resource=resource) in compiled:
            return True
        if Permission(action="*", resource=resource) in compiled:
            return True
        if Permission(action=action, resource="*") in compiled:
            return True
        return False

    def compile(self, *, role_names: Iterable[str]) -> frozenset[Permission]:
        """Compile a set of role names into a flattened permission set."""
        cache_key = tuple(sorted({role for role in role_names if role}))
        cached = self._compiled_cache.get(cache_key)
        if cached is not None:
            return cached

        flattened: set[Permission] = set()
        for role_name in cache_key:
            role_permissions = self._roles.get(role_name)
            if role_permissions is not None:
                flattened.update(role_permissions.permissions)

        compiled = frozenset(flattened)
        if len(self._compiled_cache) >= self._compiled_cache_max:
            self._compiled_cache.clear()
        self._compiled_cache[cache_key] = compiled
        return compiled

    def allows(self, *, role_names: Iterable[str], action: str, resource: str) -> bool:
        """Return whether any of the roles allows the requested action/resource."""
        compiled = self.compile(role_names=role_names)
        return self.allows_compiled(compiled=compiled, action=action, resource=resource)

    def allows_compiled(
        self,
        *,
        compiled: frozenset[Permission],
        action: str,
        resource: str,
    ) -> bool:
        """Return whether a precompiled permission set allows a target."""
        normalized_action = normalize_action(action)
        normalized_resource = normalize_resource(resource)
        if not normalized_action or not normalized_resource:
            return False

        for expanded_resource in self._expand_umbrella(normalized_resource):
            if self._match(compiled, normalized_action, expanded_resource):
                return True
        return False


class RbacPolicy:
    """Bind ``AuthConfig`` to a compiled permission matrix.

    This wrapper is what the auth manager talks to at runtime. It preserves the
    current business logic around:
    - strict vs non-strict role handling
    - action/resource lookups
    - prefix-based resource discovery
    - LDAP DN -> role resolution
    """

    def __init__(self, cfg: "AuthConfig") -> None:
        self.cfg = cfg
        self._matrix = self._build_matrix(cfg)
        self._filter_evaluator = RoleFilterEvaluator()

    def reconfigure(self, cfg: "AuthConfig") -> None:
        """Replace configuration and rebuild the internal matrix."""
        self.cfg = cfg
        self._matrix = self._build_matrix(cfg)

    def _active_roles_for_context(
        self,
        *,
        roles: Iterable[str],
        context: AuthorizationContext | None,
    ) -> tuple[str, ...]:
        """Return the roles that remain active for the supplied context."""
        role_filters = getattr(self.cfg, "role_filters", None)
        if role_filters is None or not role_filters.role_to_filters:
            return tuple(role for role in roles if role)

        active: list[str] = []
        for role_name in roles:
            if not role_name:
                continue
            rule = role_filters.role_to_filters.get(role_name)
            if self._filter_evaluator.allows_role(
                role_name=role_name,
                rule=rule,
                context=context,
            ):
                active.append(role_name)
        return tuple(active)

    @staticmethod
    def _build_matrix(cfg: "AuthConfig") -> PermissionMatrix:
        roles: dict[str, RolePermissions] = {}
        for role_name, raw_permissions in cfg.roles.role_to_permissions.items():
            normalized_permissions = frozenset(
                Permission(action=action, resource=resource).normalized()
                for action, resource in raw_permissions
                if action and resource
            )
            roles[role_name] = RolePermissions(
                name=role_name,
                permissions=normalized_permissions,
            )
        return PermissionMatrix(roles=roles)

    def is_allowed(
        self,
        *,
        roles: Iterable[str],
        action: str,
        resource: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Return whether the given roles allow a specific action/resource."""
        compiled = self._matrix.compile(
            role_names=self._active_roles_for_context(roles=roles, context=context)
        )
        return self._matrix.allows_compiled(
            compiled=compiled,
            action=action,
            resource=resource,
        )

    def allowed_resources_for_action(
        self,
        *,
        roles: Iterable[str],
        action: str,
        context: AuthorizationContext | None = None,
    ) -> set[str]:
        """Return all resources allowed for the requested action.

        A wildcard resource immediately short-circuits to ``{"*"}``.
        """
        normalized_action = normalize_action(action)
        compiled = self._matrix.compile(
            role_names=self._active_roles_for_context(roles=roles, context=context)
        )

        allowed: set[str] = set()
        for permission in compiled:
            if permission.action not in {normalized_action, "*"}:
                continue
            if permission.resource == "*":
                return {"*"}
            allowed.add(permission.resource)
        return allowed

    def has_any_resource_with_prefix(
        self,
        *,
        roles: Iterable[str],
        action: str,
        prefix: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Return whether any allowed resource for the action starts with ``prefix``."""
        normalized_action = normalize_action(action)
        compiled = self._matrix.compile(
            role_names=self._active_roles_for_context(roles=roles, context=context)
        )

        for permission in compiled:
            if permission.action not in {normalized_action, "*"}:
                continue
            if permission.resource == "*":
                return True
            if permission.resource.startswith(prefix):
                return True
        return False

    def map_dns_to_roles(self, group_dns: Iterable[str]) -> set[str]:
        """Map LDAP group DNs to Airflow roles using ``[role_mapping]``.

        In strict mode, only roles that are explicitly defined in ``[role:*]``
        sections are returned.
        """
        mapped_roles: set[str] = set()
        defined_roles = set(self.cfg.roles.role_to_permissions.keys())
        strict = bool(getattr(self.cfg.general, "strict_permissions", True))

        for dn in group_dns:
            canonical_dn = canonicalize_dn(dn)
            if not canonical_dn:
                continue

            roles = self.cfg.role_mapping.dn_to_roles.get(canonical_dn)
            if not roles:
                continue

            if strict:
                mapped_roles.update(role for role in roles if role in defined_roles)
            else:
                mapped_roles.update(roles)

        return mapped_roles


__all__ = (
    "ACTION_MENU_ACCESS",
    "ACTION_CAN_READ",
    "ACTION_CAN_EDIT",
    "ACTION_CAN_CREATE",
    "ACTION_CAN_DELETE",
    "RESOURCE_DAG",
    "RESOURCE_DAG_RUN",
    "RESOURCE_DAG_CODE",
    "RESOURCE_DAG_DEPENDENCIES",
    "RESOURCE_DAG_VERSION",
    "RESOURCE_DAG_WARNING",
    "RESOURCE_TASK_INSTANCE",
    "RESOURCE_TASK_LOG",
    "RESOURCE_XCOM",
    "RESOURCE_POOL",
    "RESOURCE_CONNECTION",
    "RESOURCE_VARIABLE",
    "RESOURCE_JOB",
    "RESOURCE_SLA_MISSES",
    "RESOURCE_IMPORT_ERROR",
    "RESOURCE_CLUSTER_ACTIVITY",
    "RESOURCE_BACKFILL",
    "RESOURCE_ASSET",
    "RESOURCE_ASSET_ALIAS",
    "RESOURCE_ADMIN_MENU",
    "RESOURCE_BROWSE_MENU",
    "RESOURCE_DOCS",
    "RESOURCE_DOCS_MENU",
    "RESOURCE_WEBSITE",
    "RESOURCE_PLUGIN",
    "RESOURCE_PROVIDER",
    "RESOURCE_TRIGGER",
    "RESOURCE_CONFIG",
    "RESOURCE_AUDIT_LOG",
    "RESOURCE_HITL_DETAIL",
    "RESOURCE_DAG_PREFIX",
    "RESOURCE_DAG_RUN_PREFIX",
    "normalize_action",
    "normalize_resource",
    "Permission",
    "RolePermissions",
    "PermissionMatrix",
    "RbacPolicy",
)
