from __future__ import annotations

import pytest


def test_auth_manager_import_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import ItimLdapAuthManager

    print("airflow_auth_manager_name=", ItimLdapAuthManager.__name__)
    assert ItimLdapAuthManager.__name__ == "ItimLdapAuthManager"


def test_entrypoint_fastapi_app_builds_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import ItimLdapAuthManager

    manager = ItimLdapAuthManager(context=None)
    app = manager.get_fastapi_app()
    route_paths = sorted(route.path for route in app.routes)
    print("airflow_route_paths=", route_paths)

    assert any(path.endswith("/login") for path in route_paths)
    assert any(path.endswith("/token") for path in route_paths)
    assert any(path.endswith("/logout") for path in route_paths)
