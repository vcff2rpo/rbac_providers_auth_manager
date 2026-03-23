from __future__ import annotations

import pytest


def test_auth_manager_import_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import RbacAuthManager

    print("airflow_auth_manager_name=", RbacAuthManager.__name__)
    assert RbacAuthManager.__name__ == "RbacAuthManager"


def test_entrypoint_fastapi_app_builds_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import RbacAuthManager

    manager = RbacAuthManager(context=None)
    app = manager.get_fastapi_app()
    route_paths = sorted(
        path
        for path in (getattr(route, "path", None) for route in app.routes)
        if isinstance(path, str)
    )
    print("airflow_route_paths=", route_paths)

    assert any(path.endswith("/login") for path in route_paths)
    assert any(path.endswith("/token") for path in route_paths)
    assert any(path.endswith("/logout") for path in route_paths)
