"""Read-side authorization lookup helpers for the auth manager."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.authorization.vocabulary import RESOURCE_DAG_PREFIX
from rbac_providers_auth_manager.authorization.rbac import (
    RESOURCE_CONNECTION,
    RESOURCE_DAG,
    RESOURCE_POOL,
    RESOURCE_VARIABLE,
)
from rbac_providers_auth_manager.core.session_guards import execute_scalars_all


class AuthorizationLookupService:
    """Own read-side authorization lookups backed by the current RBAC policy."""

    def __init__(self, manager: Any, policy_service: Any) -> None:
        self.manager = manager
        self._policy_service = policy_service

    def get_authorized_connections(
        self,
        *,
        user: Any,
        method: str = "GET",
        session: Any,
    ) -> set[str]:
        """Return visible connection IDs for the current user."""
        if not self._policy_service.allowed(
            user=user,
            action=self._policy_service.fab_action(method),
            resource=RESOURCE_CONNECTION,
        ):
            return set()

        from airflow.models.connection import Connection
        from sqlalchemy import select

        rows = execute_scalars_all(session, select(Connection.conn_id))
        return set(rows)

    def get_authorized_dag_ids(
        self,
        *,
        user: Any,
        method: str = "GET",
        session: Any,
    ) -> set[str]:
        """Return visible DAG IDs for the current user."""
        self.manager._refresh_if_needed()
        if user.is_anonymous or self.manager._policy is None:
            return set()

        action = self._policy_service.fab_action(method)

        from airflow.models.dag import DagModel
        from sqlalchemy import select

        if self._policy_service.allowed(
            user=user, action=action, resource=RESOURCE_DAG
        ):
            rows = execute_scalars_all(session, select(DagModel.dag_id))
            return set(rows)

        allowed_resources = self.manager._policy.allowed_resources_for_action(
            roles=user.roles,
            action=action,
        )
        if "*" in allowed_resources:
            rows = execute_scalars_all(session, select(DagModel.dag_id))
            return set(rows)

        dag_ids = {
            resource[len(RESOURCE_DAG_PREFIX) :]
            for resource in allowed_resources
            if resource.startswith(RESOURCE_DAG_PREFIX)
        }
        if not dag_ids:
            return set()

        rows = execute_scalars_all(
            session,
            select(DagModel.dag_id).where(DagModel.dag_id.in_(dag_ids)),
        )
        return set(rows)

    def get_authorized_pools(
        self, *, user: Any, method: str = "GET", session: Any
    ) -> set[str]:
        """Return visible pool names for the current user."""
        if not self._policy_service.allowed(
            user=user,
            action=self._policy_service.fab_action(method),
            resource=RESOURCE_POOL,
        ):
            return set()

        from airflow.models.pool import Pool
        from sqlalchemy import select

        rows = execute_scalars_all(session, select(Pool.pool))
        return set(rows)

    def get_authorized_variables(
        self, *, user: Any, method: str = "GET", session: Any
    ) -> set[str]:
        """Return visible variable keys for the current user."""
        if not self._policy_service.allowed(
            user=user,
            action=self._policy_service.fab_action(method),
            resource=RESOURCE_VARIABLE,
        ):
            return set()

        from airflow.models.variable import Variable
        from sqlalchemy import select

        rows = execute_scalars_all(session, select(Variable.key))
        return set(rows)
