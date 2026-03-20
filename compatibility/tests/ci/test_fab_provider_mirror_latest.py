from __future__ import annotations

import pytest

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    build_support_report,
)


@pytest.mark.slow
def test_custom_plugin_supports_official_fab_provider_permissions_by_design() -> None:
    pytest.importorskip("airflow")
    pytest.importorskip("airflow.providers.fab.auth_manager.security_manager.override")

    report = build_support_report()
    assert not report.unsupported_permissions, (
        "Custom plugin design does not support the full official FAB provider non-DB permission surface: "
        f"{[item.__dict__ for item in report.unsupported_permissions]}"
    )
