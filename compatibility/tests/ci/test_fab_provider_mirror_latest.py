from __future__ import annotations

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    build_support_report,
)


def test_official_fab_provider_permissions_are_supported_by_plugin_design() -> None:
    report = build_support_report()
    assert not report.has_blocking_gaps
