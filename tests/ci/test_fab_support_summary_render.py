from __future__ import annotations

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    SupportGap,
    SupportReport,
    render_support_markdown,
)


def _empty_role_map() -> dict[str, tuple[dict[str, str], ...]]:
    return {role: () for role in ("Viewer", "User", "Op", "Admin")}


def test_render_support_markdown_uses_matrix_layout(monkeypatch) -> None:
    class _Airflow:
        __version__ = "3.1.8"

    class _Metadata:
        @staticmethod
        def version(name: str) -> str:
            assert name == "apache-airflow-providers-fab"
            return "3.5.0"

    def _fake_import_module(name: str):
        if name == "airflow":
            return _Airflow
        if name == "importlib.metadata":
            return _Metadata
        raise AssertionError(name)

    monkeypatch.setattr(
        "rbac_providers_auth_manager.compatibility.fab_provider_support.importlib.import_module",
        _fake_import_module,
    )

    report = SupportReport(
        official_permission_counts={"Viewer": 1, "User": 2, "Op": 2, "Admin": 2},
        supported_permission_counts={"Viewer": 1, "User": 1, "Op": 2, "Admin": 2},
        official_permissions_by_role={
            "Viewer": ({"action": "can_read", "resource": "DAGs"},),
            "User": (
                {"action": "can_read", "resource": "DAGs"},
                {"action": "can_edit", "resource": "DAGs"},
            ),
            "Op": (
                {"action": "can_read", "resource": "DAGs"},
                {"action": "can_edit", "resource": "DAGs"},
            ),
            "Admin": (
                {"action": "can_read", "resource": "DAGs"},
                {"action": "can_edit", "resource": "DAGs"},
            ),
        },
        plugin_contract_permissions_by_role={
            "Viewer": ({"action": "can_read", "resource": "DAGs"},),
            "User": ({"action": "can_read", "resource": "DAGs"},),
            "Op": (
                {"action": "can_read", "resource": "DAGs"},
                {"action": "can_edit", "resource": "DAGs"},
            ),
            "Admin": (
                {"action": "can_read", "resource": "DAGs"},
                {"action": "can_edit", "resource": "DAGs"},
            ),
        },
        supported_official_permissions_by_role=_empty_role_map(),
        unsupported_official_permissions_by_role={
            "Viewer": (),
            "User": ({"action": "can_edit", "resource": "DAGs"},),
            "Op": (),
            "Admin": (),
        },
        plugin_extra_permissions_by_role=_empty_role_map(),
        official_action_constants=("can_edit", "can_read"),
        official_resource_constants=("DAGs",),
        plugin_action_constants=("can_edit", "can_read"),
        plugin_resource_constants=("DAGs",),
        missing_action_constants_in_plugin=(),
        extra_action_constants_in_plugin=(),
        missing_resource_constants_in_plugin=(),
        extra_resource_constants_in_plugin=(),
        contract_advisories=(),
        compatibility_matrix=(
            {
                "resource": "DAGs",
                "action": "can_read",
                "viewer_has_access": True,
                "user_has_access": True,
                "op_has_access": True,
                "admin_has_access": True,
                "minimum_role": "Viewer",
            },
            {
                "resource": "DAGs",
                "action": "can_edit",
                "viewer_has_access": False,
                "user_has_access": False,
                "op_has_access": True,
                "admin_has_access": True,
                "minimum_role": "Op",
            },
        ),
        unsupported_permissions=(
            SupportGap(
                role="User",
                action="can_edit",
                resource="DAGs",
                normalized_action="can_edit",
                normalized_resource="DAGs",
                reason="policy_engine_rejected_official_permission",
            ),
        ),
    )

    markdown = render_support_markdown(report)

    assert "## RBAC permission comparison matrix" in markdown
    assert (
        "| Resource | Action | Official roles | Plugin roles | Status | Role delta | Explanation |"
        in markdown
    )
    assert (
        "| DAGs | can_edit | User, Op, Admin | Op, Admin | role-drift | missing: User |"
        in markdown
    )
    assert "## Action constant comparison matrix" in markdown
    assert "## Resource constant comparison matrix" in markdown
    assert "## Non-admin role progression matrix" in markdown
