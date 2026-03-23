from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import cast

FAKE_COOKIE_NAME_JWT_TOKEN = "_token"


def _module(name: str) -> ModuleType:
    return cast(ModuleType, sys.modules.setdefault(name, ModuleType(name)))


def _set_attr(module: ModuleType, name: str, value: object) -> None:
    cast(dict[str, object], module.__dict__)[name] = value


def install_fake_airflow() -> None:
    if (
        "airflow.configuration" in sys.modules
        and "airflow.api_fastapi.auth.managers.base_auth_manager" in sys.modules
    ):
        return

    airflow = _module("airflow")
    configuration = _module("airflow.configuration")
    _set_attr(
        configuration,
        "conf",
        SimpleNamespace(get=lambda *args, **kwargs: kwargs.get("fallback", "")),
    )

    api_fastapi = _module("airflow.api_fastapi")
    auth = _module("airflow.api_fastapi.auth")
    managers = _module("airflow.api_fastapi.auth.managers")
    base_auth = _module("airflow.api_fastapi.auth.managers.base_auth_manager")
    _set_attr(base_auth, "COOKIE_NAME_JWT_TOKEN", FAKE_COOKIE_NAME_JWT_TOKEN)
    _set_attr(base_auth, "ResourceMethod", str)
    _set_attr(base_auth, "BaseAuthManager", object)

    _set_attr(airflow, "api_fastapi", api_fastapi)
    _set_attr(api_fastapi, "auth", auth)
    _set_attr(auth, "managers", managers)


__all__ = ("FAKE_COOKIE_NAME_JWT_TOKEN", "install_fake_airflow")
