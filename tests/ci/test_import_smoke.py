from __future__ import annotations

import importlib
import pkgutil
import sys
import types
from pathlib import Path
from typing import Any


def _ensure_module(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


def _set_module_attr(module_name: str, attr_name: str, value: object) -> None:
    setattr(_ensure_module(module_name), attr_name, value)


def _install_airflow_stubs() -> None:
    for name in (
        "airflow",
        "airflow.api_fastapi",
        "airflow.api_fastapi.auth",
        "airflow.api_fastapi.auth.managers",
        "airflow.api_fastapi.auth.managers.models",
        "airflow.api_fastapi.common",
        "airflow.configuration",
        "airflow.utils",
        "airflow.providers",
        "airflow.providers.common",
        "airflow.providers.common.compat",
        "airflow.models",
    ):
        _ensure_module(name)

    class _Conf:
        def get(
            self, *_args: object, fallback: object = None, **_kwargs: object
        ) -> object:
            return fallback

        def getint(self, *_args: object, fallback: int = 0, **_kwargs: object) -> int:
            return int(fallback or 0)

    _set_module_attr("airflow.configuration", "conf", _Conf())

    def provide_session(fn: Any = None, **_kwargs: object) -> Any:
        def decorator(func: Any) -> Any:
            return func

        return decorator(fn) if fn is not None else decorator

    _set_module_attr("airflow.utils.session", "NEW_SESSION", object())
    _set_module_attr("airflow.utils.session", "provide_session", provide_session)

    class MenuItem:
        ASSETS = "ASSETS"
        AUDIT_LOG = "AUDIT_LOG"
        CONFIG = "CONFIG"
        CONNECTIONS = "CONNECTIONS"
        DAGS = "DAGS"
        DOCS = "DOCS"
        PLUGINS = "PLUGINS"
        POOLS = "POOLS"
        PROVIDERS = "PROVIDERS"
        VARIABLES = "VARIABLES"
        XCOMS = "XCOMS"
        ADMIN = "ADMIN"
        BROWSE = "BROWSE"
        REQUIRED_ACTIONS = "REQUIRED_ACTIONS"

    class ExtraMenuItem:
        pass

    _set_module_attr("airflow.api_fastapi.common.types", "MenuItem", MenuItem)
    _set_module_attr("airflow.api_fastapi.common.types", "ExtraMenuItem", ExtraMenuItem)

    class BaseUser:
        pass

    class BaseAuthManager:
        def __class_getitem__(cls, _item: object) -> type["BaseAuthManager"]:
            return cls

        def __init__(self, context: object = None) -> None:
            self.context = context

        def generate_jwt(self, user: object, expiration_time_in_seconds: int) -> str:
            return f"jwt:{expiration_time_in_seconds}:{user!r}"

    class ResourceMethod(str):
        pass

    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager", "BaseUser", BaseUser
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "BaseAuthManager",
        BaseAuthManager,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "COOKIE_NAME_JWT_TOKEN",
        "_token",
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "ResourceMethod",
        ResourceMethod,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "IsAuthorizedConnectionRequest",
        dict,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "IsAuthorizedDagRequest",
        dict,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "IsAuthorizedPoolRequest",
        dict,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.base_auth_manager",
        "IsAuthorizedVariableRequest",
        dict,
    )

    _set_module_attr(
        "airflow.api_fastapi.auth.managers.models.base_user", "BaseUser", BaseUser
    )

    class AccessView:
        CLUSTER_ACTIVITY = "CLUSTER_ACTIVITY"
        DOCS = "DOCS"
        IMPORT_ERRORS = "IMPORT_ERRORS"
        JOBS = "JOBS"
        PLUGINS = "PLUGINS"
        PROVIDERS = "PROVIDERS"
        TRIGGERS = "TRIGGERS"
        WEBSITE = "WEBSITE"

    class DagAccessEntity:
        AUDIT_LOG = "AUDIT_LOG"
        CODE = "CODE"
        DEPENDENCIES = "DEPENDENCIES"
        RUN = "RUN"
        TASK = "TASK"
        TASK_INSTANCE = "TASK_INSTANCE"
        TASK_LOGS = "TASK_LOGS"
        VERSION = "VERSION"
        WARNING = "WARNING"
        XCOM = "XCOM"
        HITL_DETAIL = "HITL_DETAIL"

    _set_module_attr(
        "airflow.api_fastapi.auth.managers.models.resource_details",
        "AccessView",
        AccessView,
    )
    _set_module_attr(
        "airflow.api_fastapi.auth.managers.models.resource_details",
        "DagAccessEntity",
        DagAccessEntity,
    )
    for name in (
        "BackfillDetails",
        "ConfigurationDetails",
        "ConnectionDetails",
        "DagDetails",
        "PoolDetails",
        "VariableDetails",
    ):
        _set_module_attr(
            "airflow.api_fastapi.auth.managers.models.resource_details",
            name,
            type(name, (), {}),
        )

    _set_module_attr(
        "airflow.providers.common.compat.assets",
        "AssetAliasDetails",
        type("AssetAliasDetails", (), {}),
    )
    _set_module_attr(
        "airflow.providers.common.compat.assets",
        "AssetDetails",
        type("AssetDetails", (), {}),
    )

    class Variable:
        @staticmethod
        def get(_name: str, default_var: object = None) -> object:
            return default_var

    _set_module_attr("airflow.models.variable", "Variable", Variable)


def test_walk_imports_for_all_package_modules() -> None:
    _install_airflow_stubs()

    package_root = Path(__file__).resolve().parents[2]
    package_parent = package_root.parent
    if str(package_parent) not in sys.path:
        sys.path.insert(0, str(package_parent))

    package = importlib.import_module("rbac_providers_auth_manager")
    package_paths = [str(path) for path in getattr(package, "__path__", ())]

    imported: list[str] = []
    for module_info in pkgutil.walk_packages(
        package_paths,
        prefix=f"{package.__name__}.",
    ):
        if module_info.name == "rbac_providers_auth_manager.setup":
            continue
        module = importlib.import_module(module_info.name)
        imported.append(module.__name__)

    assert imported
    assert "rbac_providers_auth_manager.auth_manager" in imported
    assert "rbac_providers_auth_manager.entrypoints.auth_manager" in imported
    assert "rbac_providers_auth_manager.services.session_service" in imported
