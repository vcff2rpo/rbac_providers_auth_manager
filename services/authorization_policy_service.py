"""Policy-decision helpers for the auth manager authorization layer."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    MenuItem,
    ResourceMethod,
)
from rbac_providers_auth_manager.compatibility.fab_adapter import (
    access_view_to_resource_type,
    dag_access_entity_to_resource_types,
    is_docs_access_view,
    menu_item_to_resource_type,
)
from rbac_providers_auth_manager.compatibility.internal_shims import (
    IsAuthorizedConnectionRequest,
    IsAuthorizedDagRequest,
    IsAuthorizedPoolRequest,
    IsAuthorizedVariableRequest,
)
from rbac_providers_auth_manager.core.logging_utils import get_logger
from rbac_providers_auth_manager.authorization.helpers import resource_name
from rbac_providers_auth_manager.authorization.rbac import (
    ACTION_CAN_CREATE,
    ACTION_CAN_DELETE,
    ACTION_CAN_EDIT,
    ACTION_CAN_READ,
    ACTION_MENU_ACCESS,
    RESOURCE_ASSET,
    RESOURCE_ASSET_ALIAS,
    RESOURCE_CONFIG,
    RESOURCE_CONNECTION,
    RESOURCE_DAG,
    RESOURCE_DAG_RUN,
    RESOURCE_POOL,
    RESOURCE_VARIABLE,
)
from rbac_providers_auth_manager.authorization.resource_filters import (
    build_dag_authorization_context,
)
from rbac_providers_auth_manager.authorization.vocabulary import RESOURCE_DAG_PREFIX

log = get_logger("auth_manager")


class AuthorizationPolicyService:
    """Own policy decisions for UI, resource, DAG, and batch authorization."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    @staticmethod
    def fab_action(method: ResourceMethod | str) -> str:
        """Map HTTP or auth-manager methods to FAB-style action strings."""
        if isinstance(method, str):
            method_value = method
        else:
            method_value = getattr(method, "value", method)

        normalized = (str(method_value) or "").upper()
        if normalized.startswith("RESOURCEMETHOD."):
            normalized = normalized.split(".", 1)[1]

        if normalized == "GET":
            return ACTION_CAN_READ
        if normalized == "POST":
            return ACTION_CAN_CREATE
        if normalized in {"PUT", "PATCH"}:
            return ACTION_CAN_EDIT
        if normalized == "DELETE":
            return ACTION_CAN_DELETE
        if normalized in {"MENU", "MENU_ACCESS"}:
            return ACTION_MENU_ACCESS
        if normalized.startswith("CAN_"):
            return normalized.lower()
        return normalized.lower()

    def allowed(
        self,
        *,
        user: Any,
        action: str,
        resource: str,
        context: object | None = None,
    ) -> bool:
        """Return whether the given user is allowed to access a resource."""
        self.manager._refresh_if_needed()
        if user.is_anonymous or self.manager._policy is None:
            return False
        return self.manager._policy.is_allowed(
            roles=user.roles,
            action=action,
            resource=resource,
            context=context,
        )

    @staticmethod
    def menu_item_resource(menu_item: Any) -> str:
        """Translate a menu item object into the underlying permission resource."""
        return menu_item_to_resource_type(menu_item)

    def is_authorized_view(self, *, access_view: Any, user: Any) -> bool:
        """Authorize read-only UI views using FAB-style semantics."""
        resource = access_view_to_resource_type(access_view)
        action = (
            ACTION_MENU_ACCESS if is_docs_access_view(access_view) else ACTION_CAN_READ
        )
        return self.allowed(user=user, action=action, resource=resource)

    def is_authorized_custom_view(
        self,
        *,
        method: ResourceMethod | str,
        resource_name: str,
        user: Any,
    ) -> bool:
        """Authorize a custom Airflow view/resource pair."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=resource_name
        )

    def filter_authorized_menu_items(
        self, menu_items: list[MenuItem], user: Any
    ) -> list[MenuItem]:
        """Filter UI menu items according to the current RBAC policy."""
        self.manager._refresh_if_needed()
        if user.is_anonymous or self.manager._policy is None:
            return []

        authorized: list[MenuItem] = []
        for menu_item in menu_items:
            try:
                resource = self.menu_item_resource(menu_item)
            except (AttributeError, TypeError, ValueError):
                continue

            if self.manager._policy.is_allowed(
                roles=user.roles,
                action=ACTION_MENU_ACCESS,
                resource=resource,
            ):
                authorized.append(menu_item)

        return authorized

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: Any,
        access_entity: Any | None = None,
        details: Any | None = None,
    ) -> bool:
        """Authorize DAG access with FAB-style DAG and DAG-run semantics."""
        self.manager._refresh_if_needed()
        if user.is_anonymous or self.manager._policy is None:
            return False

        dag_id = getattr(details, "id", None) if details is not None else None
        action = self.fab_action(method)
        dag_context = build_dag_authorization_context(dag_id=dag_id, details=details)

        if method == "GET" and access_entity is None and not dag_id:
            if self.allowed(
                user=user, action=action, resource=RESOURCE_DAG, context=dag_context
            ):
                return True
            return self.manager._policy.has_any_resource_with_prefix(
                roles=user.roles,
                action=action,
                prefix=RESOURCE_DAG_PREFIX,
                context=dag_context,
            )

        def _allowed_dag(method_for_dag: ResourceMethod) -> bool:
            dag_action = self.fab_action(method_for_dag)
            if self.allowed(
                user=user, action=dag_action, resource=RESOURCE_DAG, context=dag_context
            ):
                return True
            if dag_id:
                return self.allowed(
                    user=user,
                    action=dag_action,
                    resource=resource_name(dag_id, RESOURCE_DAG),
                    context=dag_context,
                )
            return False

        if access_entity is None:
            return _allowed_dag(method)

        resource_types = dag_access_entity_to_resource_types(access_entity)
        for resource_type in resource_types:
            if resource_type == RESOURCE_DAG_RUN and dag_id:
                if not (
                    self.allowed(
                        user=user,
                        action=action,
                        resource=RESOURCE_DAG_RUN,
                        context=dag_context,
                    )
                    or self.allowed(
                        user=user,
                        action=action,
                        resource=resource_name(dag_id, RESOURCE_DAG_RUN),
                        context=dag_context,
                    )
                ):
                    return False
                continue

            if not self.allowed(
                user=user, action=action, resource=resource_type, context=dag_context
            ):
                return False

        dag_method: ResourceMethod = "GET" if method == "GET" else "PUT"
        return _allowed_dag(dag_method)

    def is_authorized_connection(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Connection endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_CONNECTION
        )

    def is_authorized_pool(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Pool endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_POOL
        )

    def is_authorized_variable(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Variable endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_VARIABLE
        )

    def is_authorized_configuration(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Configuration endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_CONFIG
        )

    @staticmethod
    def _backfill_dag_id(details: Any | None) -> str | None:
        """Extract a DAG identifier from backfill details when available."""
        for field in ("dag_id", "id"):
            value = getattr(details, field, None) if details is not None else None
            if value:
                return str(value)
        return None

    def is_authorized_backfill(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize Backfill endpoints through DAG Run semantics.

        Backfill-specific authorization is compatibility-only. Effective access
        is evaluated through DAG Run semantics so the runtime follows current
        Airflow auth-manager direction without relying on a distinct backfill
        permission path.
        """
        dag_id = self._backfill_dag_id(details)
        action = self.fab_action(method)
        dag_context = build_dag_authorization_context(dag_id=dag_id, details=details)
        if self.allowed(
            user=user, action=action, resource=RESOURCE_DAG_RUN, context=dag_context
        ):
            return True
        if dag_id:
            return self.allowed(
                user=user,
                action=action,
                resource=resource_name(dag_id, RESOURCE_DAG_RUN),
                context=dag_context,
            )
        return False

    def is_authorized_asset(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Asset endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_ASSET
        )

    def is_authorized_asset_alias(
        self, *, method: ResourceMethod, user: Any, details: Any | None = None
    ) -> bool:
        """Authorize access to Asset Alias endpoints."""
        return self.allowed(
            user=user, action=self.fab_action(method), resource=RESOURCE_ASSET_ALIAS
        )

    def is_authorized_hitl_task(self, *, user: Any, task_instance: Any) -> bool:
        """Authorize access to a HITL task using assigned-user semantics."""
        if user.is_anonymous:
            return False

        assigned_users = getattr(task_instance, "assigned_users", None) or []
        candidate_ids = {user.user_id, user.username}
        if user.email:
            candidate_ids.add(user.email)

        allowed = any(str(item) in candidate_ids for item in assigned_users)
        log.debug(
            "HITL authorization %s principal=%s task_assignees=%s",
            "granted" if allowed else "denied",
            user.username,
            list(assigned_users),
        )
        return allowed

    def batch_is_authorized_dag(
        self, requests: Sequence[IsAuthorizedDagRequest], *, user: Any
    ) -> bool:
        """Batch DAG authorization."""
        self.manager._refresh_if_needed()
        if user.is_anonymous:
            return False

        for request in requests:
            method = cast(ResourceMethod, request.get("method"))  # type: ignore[attr-defined]
            access_entity = request.get("access_entity")  # type: ignore[attr-defined]
            details = request.get("details")  # type: ignore[attr-defined]
            if not self.is_authorized_dag(
                method=method,
                user=user,
                access_entity=access_entity,
                details=details,
            ):
                return False
        return True

    def _batch_authorized_resource_requests(
        self,
        requests: Sequence[dict[str, Any]],
        *,
        user: Any,
        resource: str,
    ) -> bool:
        """Evaluate a batch of single-resource authorization requests."""
        self.manager._refresh_if_needed()
        if user.is_anonymous or self.manager._policy is None:
            return False

        action_cache: dict[str, bool] = {}
        for request in requests:
            action = self.fab_action(cast(ResourceMethod, request["method"]))
            allowed = action_cache.get(action)
            if allowed is None:
                allowed = self.manager._policy.is_allowed(
                    roles=user.roles,
                    action=action,
                    resource=resource,
                )
                action_cache[action] = allowed
            if not allowed:
                return False
        return True

    def batch_is_authorized_connection(
        self,
        requests: Sequence[IsAuthorizedConnectionRequest],
        *,
        user: Any,
    ) -> bool:
        """Batch authorization for Connection requests."""
        return self._batch_authorized_resource_requests(
            requests, user=user, resource=RESOURCE_CONNECTION
        )

    def batch_is_authorized_pool(
        self,
        requests: Sequence[IsAuthorizedPoolRequest],
        *,
        user: Any,
    ) -> bool:
        """Batch authorization for Pool requests."""
        return self._batch_authorized_resource_requests(
            requests, user=user, resource=RESOURCE_POOL
        )

    def batch_is_authorized_variable(
        self,
        requests: Sequence[IsAuthorizedVariableRequest],
        *,
        user: Any,
    ) -> bool:
        """Batch authorization for Variable requests."""
        return self._batch_authorized_resource_requests(
            requests, user=user, resource=RESOURCE_VARIABLE
        )
