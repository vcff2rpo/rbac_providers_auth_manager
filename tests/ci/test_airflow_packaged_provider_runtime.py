from __future__ import annotations

from importlib import metadata

import pytest

from rbac_providers_auth_manager import __version__


@pytest.mark.airflow_runtime
def test_packaged_distribution_metadata_is_available_under_airflow() -> None:
    pytest.importorskip("airflow")
    try:
        installed_version = metadata.version("rbac-providers-auth-manager")
    except metadata.PackageNotFoundError:
        pytest.skip("distribution metadata is only present after the CI install step")
    print("installed_provider_version=", installed_version)
    assert installed_version == __version__


@pytest.mark.airflow_runtime
def test_packaged_root_facade_matches_entrypoint_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import RbacAuthManager as root_cls
    from rbac_providers_auth_manager.entrypoints.auth_manager import (
        RbacAuthManager as entry_cls,
    )

    manager = root_cls(context=None)
    app = manager.get_fastapi_app()
    route_paths = {
        path
        for path in (getattr(route, "path", None) for route in app.routes)
        if isinstance(path, str)
    }
    print("packaged_route_paths=", sorted(route_paths))

    assert root_cls is entry_cls
    assert "/flow/providers" in route_paths
    assert "/flow/login-status" in route_paths
    assert "/login" in route_paths
    assert "/token" in route_paths
    assert "/logout" in route_paths
