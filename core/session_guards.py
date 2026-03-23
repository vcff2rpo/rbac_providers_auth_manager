"""DB-session safety helpers for Airflow/FAB session-touching paths.

Airflow and FAB continue to evolve their session handling. These helpers keep
session rollback and cleanup behavior centralized for auth-manager queries that
use provided sessions.
"""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.core.logging_utils import get_logger

log = get_logger("session_guards")


def rollback_session_quietly(session: Any) -> None:
    """Attempt to rollback a session without masking the original failure."""
    rollback = getattr(session, "rollback", None)
    if rollback is None:
        return
    try:
        rollback()
    except Exception as exc:  # noqa: BLE001
        log.warning("Session rollback failed during auth-manager cleanup: %s", exc)


def execute_scalars_all(session: Any, statement: Any) -> list[Any]:
    """Execute a scalar select and rollback the session on failure."""
    try:
        return list(session.execute(statement).scalars().all())
    except Exception:
        rollback_session_quietly(session)
        raise


__all__ = (
    "execute_scalars_all",
    "rollback_session_quietly",
)
