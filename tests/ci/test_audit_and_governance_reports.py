from __future__ import annotations

from types import SimpleNamespace

import pytest

from rbac_providers_auth_manager.config import AuthConfig
from rbac_providers_auth_manager.runtime.compat_governance import (
    OperatorDoctorReport,
    build_operator_doctor_report,
)
from rbac_providers_auth_manager.runtime.version_policy import (
    RuntimeVersionPolicyReport,
)
from rbac_providers_auth_manager.services.audit_service import AuditService

from . import test_browser_token_flow_matrix as browser_matrix


@pytest.fixture()
def auth_cfg() -> AuthConfig:
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


@pytest.mark.unit
def test_audit_payload_infers_surface_and_outcome() -> None:
    payload = AuditService._build_payload(
        event="ui.auth.login.success",
        level="INFO",
        provider="ldap",
        principal="alice",
    )

    assert payload["event"] == "ui.auth.login.success"
    assert payload["severity"] == "info"
    assert payload["surface"] == "ui"
    assert payload["outcome"] == "success"
    assert payload["provider"] == "ldap"
    assert payload["principal"] == "alice"
    assert "timestamp" in payload


@pytest.mark.unit
def test_audit_ui_reference_shape() -> None:
    reference = AuditService.make_ui_reference()
    assert 6 <= len(reference) <= 10
    assert reference.isalnum()
    assert reference.upper() == reference


@pytest.mark.unit
def test_runtime_version_policy_report_detects_next_minor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rbac_providers_auth_manager.runtime.version_policy as version_policy

    versions = {
        "apache-airflow": "3.2.1",
        "apache-airflow-providers-fab": "3.5.0",
    }

    monkeypatch.setattr(
        version_policy,
        "_distribution_version",
        lambda distribution_name: versions.get(distribution_name),
    )
    monkeypatch.setattr(
        version_policy,
        "sys",
        SimpleNamespace(version_info=SimpleNamespace(major=3, minor=13, micro=2)),
    )

    report = version_policy.build_runtime_version_policy_report()

    assert report.airflow_status == "next_minor"
    assert report.fab_provider_status == "current_or_newer"
    assert report.python_status == "supported"
    assert any("3.2+" in advisory for advisory in report.advisories)


@pytest.mark.unit
def test_operator_doctor_report_aggregates_capability_and_version_signals(
    monkeypatch: pytest.MonkeyPatch,
    auth_cfg: AuthConfig,
) -> None:
    import rbac_providers_auth_manager.runtime.compat_governance as compat_governance

    version_report = RuntimeVersionPolicyReport(
        airflow_version="3.2.0",
        fab_provider_version="3.5.0",
        python_version="3.13.1",
        airflow_status="next_minor",
        fab_provider_status="current_or_newer",
        python_status="supported",
        advisories=("Validate adapter boundaries.",),
    )

    monkeypatch.setattr(
        compat_governance,
        "build_runtime_capability_report",
        lambda cfg: {"config_advisories": "2"},
    )
    monkeypatch.setattr(
        compat_governance,
        "build_runtime_version_policy_report",
        lambda: version_report,
    )
    monkeypatch.setattr(
        compat_governance,
        "build_non_admin_compatibility_matrix",
        lambda cfg: [
            SimpleNamespace(shipped_role_consistency=True),
            SimpleNamespace(shipped_role_consistency=False),
        ],
    )
    monkeypatch.setattr(
        compat_governance,
        "evaluate_non_admin_role_consistency",
        lambda cfg: ["issue-1"],
    )

    report = build_operator_doctor_report(auth_cfg)

    assert isinstance(report, OperatorDoctorReport)
    assert report.capability_advisory_count == 2
    assert report.version_advisory_count == 1
    assert report.non_admin_contract_count == 2
    assert report.non_admin_contract_gap_count == 1
    assert report.non_admin_role_consistency_issue_count == 1
    assert report.as_dict()["compatibility_recommendation_count"] == str(
        len(report.recommendations)
    )
    assert any(
        "verify compatibility adapters" in item for item in report.recommendations
    )
