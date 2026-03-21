from __future__ import annotations

from types import ModuleType, SimpleNamespace
import sys


def install_fake_airflow() -> None:
    if (
        "airflow.configuration" in sys.modules
        and "airflow.api_fastapi.auth.managers.base_auth_manager" in sys.modules
    ):
        return

    airflow = sys.modules.setdefault("airflow", ModuleType("airflow"))
    configuration = ModuleType("airflow.configuration")
    configuration.conf = SimpleNamespace(
        get=lambda *args, **kwargs: kwargs.get("fallback", "")
    )
    sys.modules["airflow.configuration"] = configuration

    api_fastapi = sys.modules.setdefault(
        "airflow.api_fastapi", ModuleType("airflow.api_fastapi")
    )
    auth = sys.modules.setdefault(
        "airflow.api_fastapi.auth", ModuleType("airflow.api_fastapi.auth")
    )
    managers = sys.modules.setdefault(
        "airflow.api_fastapi.auth.managers",
        ModuleType("airflow.api_fastapi.auth.managers"),
    )
    base_auth = ModuleType("airflow.api_fastapi.auth.managers.base_auth_manager")
    base_auth.COOKIE_NAME_JWT_TOKEN = "_token"
    base_auth.ResourceMethod = str
    base_auth.BaseAuthManager = object
    sys.modules["airflow.api_fastapi.auth.managers.base_auth_manager"] = base_auth

    airflow.api_fastapi = api_fastapi
    api_fastapi.auth = auth
    auth.managers = managers


install_fake_airflow()
