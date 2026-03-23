"""Authorization facade for policy decisions and read-side access lookups."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.services.authorization_lookup_service import (
    AuthorizationLookupService,
)
from rbac_providers_auth_manager.services.authorization_policy_service import (
    AuthorizationPolicyService,
)


class AuthorizationService:
    """Coordinate policy decisions and read-side authorization lookups."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._policy_service = AuthorizationPolicyService(manager)
        self._lookup_service = AuthorizationLookupService(manager, self._policy_service)

    @staticmethod
    def fab_action(method: Any) -> str:
        """Map HTTP or auth-manager methods to FAB-style action strings."""
        return AuthorizationPolicyService.fab_action(method)

    def allowed(
        self, *, user: Any, action: str, resource: str, context: object | None = None
    ) -> bool:
        """Return whether the given user is allowed to access a resource."""
        return self._policy_service.allowed(
            user=user, action=action, resource=resource, context=context
        )

    @staticmethod
    def menu_item_resource(menu_item: Any) -> str:
        """Translate a menu item object into the underlying permission resource."""
        return AuthorizationPolicyService.menu_item_resource(menu_item)

    def is_authorized_view(self, *, access_view: Any, user: Any) -> bool:
        return self._policy_service.is_authorized_view(
            access_view=access_view, user=user
        )

    def is_authorized_custom_view(
        self, *, method: Any, resource_name: str, user: Any
    ) -> bool:
        return self._policy_service.is_authorized_custom_view(
            method=method, resource_name=resource_name, user=user
        )

    def filter_authorized_menu_items(
        self, menu_items: list[Any], user: Any
    ) -> list[Any]:
        return self._policy_service.filter_authorized_menu_items(menu_items, user)

    def get_authorized_connections(
        self, *, user: Any, method: Any = "GET", session: Any
    ) -> set[str]:
        return self._lookup_service.get_authorized_connections(
            user=user, method=method, session=session
        )

    def get_authorized_dag_ids(
        self, *, user: Any, method: Any = "GET", session: Any
    ) -> set[str]:
        return self._lookup_service.get_authorized_dag_ids(
            user=user, method=method, session=session
        )

    def get_authorized_pools(
        self, *, user: Any, method: Any = "GET", session: Any
    ) -> set[str]:
        return self._lookup_service.get_authorized_pools(
            user=user, method=method, session=session
        )

    def get_authorized_variables(
        self, *, user: Any, method: Any = "GET", session: Any
    ) -> set[str]:
        return self._lookup_service.get_authorized_variables(
            user=user, method=method, session=session
        )

    def is_authorized_dag(
        self,
        *,
        method: Any,
        user: Any,
        access_entity: Any | None = None,
        details: Any | None = None,
    ) -> bool:
        return self._policy_service.is_authorized_dag(
            method=method, user=user, access_entity=access_entity, details=details
        )

    def is_authorized_connection(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_connection(
            method=method, user=user, details=details
        )

    def is_authorized_pool(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_pool(
            method=method, user=user, details=details
        )

    def is_authorized_variable(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_variable(
            method=method, user=user, details=details
        )

    def is_authorized_configuration(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_configuration(
            method=method, user=user, details=details
        )

    def is_authorized_backfill(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_backfill(
            method=method, user=user, details=details
        )

    def is_authorized_asset(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_asset(
            method=method, user=user, details=details
        )

    def is_authorized_asset_alias(
        self, *, method: Any, user: Any, details: Any | None = None
    ) -> bool:
        return self._policy_service.is_authorized_asset_alias(
            method=method, user=user, details=details
        )

    def is_authorized_hitl_task(self, *, user: Any, task_instance: Any) -> bool:
        return self._policy_service.is_authorized_hitl_task(
            user=user, task_instance=task_instance
        )

    def batch_is_authorized_dag(self, requests: Any, *, user: Any) -> bool:
        return self._policy_service.batch_is_authorized_dag(requests, user=user)

    def batch_is_authorized_connection(self, requests: Any, *, user: Any) -> bool:
        return self._policy_service.batch_is_authorized_connection(requests, user=user)

    def batch_is_authorized_pool(self, requests: Any, *, user: Any) -> bool:
        return self._policy_service.batch_is_authorized_pool(requests, user=user)

    def batch_is_authorized_variable(self, requests: Any, *, user: Any) -> bool:
        return self._policy_service.batch_is_authorized_variable(requests, user=user)
