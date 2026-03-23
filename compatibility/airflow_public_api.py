"""Centralized lazy imports for Airflow public authentication APIs.

This module isolates the runtime contract the plugin expects from Airflow's
public auth-manager surface. The imports are intentionally lazy so Airflow
plugin discovery does not re-enter auth-manager modules while this module is
still being initialized.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

# Airflow 3.x exposes auth-manager routes under the stable ``/auth`` prefix.
# Keeping this as a lightweight constant avoids importing ``airflow.api_fastapi.app``
# during plugin discovery, which can re-enter plugin loading.
AUTH_MANAGER_FASTAPI_APP_PREFIX = "/auth"

if TYPE_CHECKING:
    from airflow.api_fastapi.auth.managers.base_auth_manager import (
        BaseAuthManager,
        COOKIE_NAME_JWT_TOKEN,
        ResourceMethod,
    )
    from airflow.api_fastapi.common.types import ExtraMenuItem, MenuItem
    from airflow.configuration import conf as airflow_conf
    from airflow.utils.session import NEW_SESSION, provide_session

    try:
        from airflow.api_fastapi.auth.managers.models.base_user import BaseUser
    except Exception:  # pragma: no cover  # noqa: BLE001
        from airflow.api_fastapi.auth.managers.base_auth_manager import BaseUser  # type: ignore[no-redef]


class _ConfProxy:
    """Lazy proxy to ``airflow.configuration.conf``."""

    def _target(self) -> Any:
        return import_module("airflow.configuration").conf

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target(), name)


airflow_conf = _ConfProxy()


def _load_base_auth_manager_attr(name: str) -> Any:
    module = import_module("airflow.api_fastapi.auth.managers.base_auth_manager")
    return getattr(module, name)


def _load_base_user() -> Any:
    try:
        module = import_module("airflow.api_fastapi.auth.managers.models.base_user")
        return getattr(module, "BaseUser")
    except Exception:  # pragma: no cover  # noqa: BLE001
        return _load_base_auth_manager_attr("BaseUser")


def __getattr__(name: str) -> Any:
    if name in {"BaseAuthManager", "COOKIE_NAME_JWT_TOKEN", "ResourceMethod"}:
        return _load_base_auth_manager_attr(name)
    if name == "BaseUser":
        return _load_base_user()
    if name in {"ExtraMenuItem", "MenuItem"}:
        module = import_module("airflow.api_fastapi.common.types")
        return getattr(module, name)
    if name in {"NEW_SESSION", "provide_session"}:
        module = import_module("airflow.utils.session")
        return getattr(module, name)
    if name == "airflow_conf":
        return airflow_conf
    if name == "AUTH_MANAGER_FASTAPI_APP_PREFIX":
        return AUTH_MANAGER_FASTAPI_APP_PREFIX
    raise AttributeError(name)


__all__ = (
    "AUTH_MANAGER_FASTAPI_APP_PREFIX",
    "BaseAuthManager",
    "BaseUser",
    "COOKIE_NAME_JWT_TOKEN",
    "ExtraMenuItem",
    "MenuItem",
    "NEW_SESSION",
    "ResourceMethod",
    "airflow_conf",
    "provide_session",
)
