from __future__ import annotations

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    ROLE_ORDER,
    build_support_report,
)


def test_official_fab_provider_permissions_are_supported_by_plugin_design() -> None:
    report = build_support_report()
    assert not report.has_blocking_gaps, (
        "Official FAB provider permissions are not fully supported by the custom plugin design: "
        f"{[gap.__dict__ for gap in report.unsupported_permissions]}"
    )


def test_support_report_contains_all_expected_roles_and_counts() -> None:
    report = build_support_report()
    for role_name in ROLE_ORDER:
        assert role_name in report.official_permission_counts
        assert role_name in report.supported_permission_counts
        assert role_name in report.official_permissions_by_role
        assert role_name in report.supported_official_permissions_by_role
        assert role_name in report.plugin_contract_permissions_by_role
        assert (
            report.supported_permission_counts[role_name]
            <= report.official_permission_counts[role_name]
        )


def test_support_report_has_no_missing_official_permissions_per_role() -> None:
    report = build_support_report()
    for role_name in ROLE_ORDER:
        missing = report.unsupported_official_permissions_by_role[role_name]
        assert not missing, (
            f"Role {role_name} is missing official FAB permissions: {missing}"
        )


def test_support_report_contains_deduped_constant_catalogs() -> None:
    report = build_support_report()
    assert report.official_action_constants
    assert report.official_resource_constants
    assert report.plugin_action_constants
    assert report.plugin_resource_constants
    assert not report.missing_action_constants_in_plugin
    assert not report.missing_resource_constants_in_plugin
