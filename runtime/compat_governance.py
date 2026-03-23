"""Compatibility governance and operator-facing doctor-style reporting helpers."""

from __future__ import annotations

from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.compat_matrix import (
    build_non_admin_compatibility_matrix,
    evaluate_non_admin_role_consistency,
)
from rbac_providers_auth_manager.config_runtime.advisories import (
    build_runtime_capability_report,
)
from rbac_providers_auth_manager.config_runtime.models import AuthConfig
from rbac_providers_auth_manager.runtime.version_policy import (
    build_runtime_version_policy_report,
)

_TARGET_AIRFLOW_LINES: tuple[str, ...] = ("3.1.x", "3.2.x", "3.3.x", "4.x")


@dataclass(frozen=True, slots=True)
class OperatorDoctorReport:
    """Flattened compatibility/governance report for maintainers and operators."""

    airflow_runtime_version: str
    fab_provider_version: str
    python_runtime_version: str
    airflow_version_status: str
    fab_provider_status: str
    python_version_status: str
    capability_advisory_count: int
    version_advisory_count: int
    non_admin_contract_count: int
    non_admin_contract_gap_count: int
    non_admin_role_consistency_issue_count: int
    target_airflow_lines: tuple[str, ...]
    recommendations: tuple[str, ...]
    advisories: tuple[str, ...]

    def as_dict(self) -> dict[str, str]:
        """Return a flat dictionary representation suitable for logs and support output."""
        return {
            "airflow_runtime_version": self.airflow_runtime_version,
            "fab_provider_version": self.fab_provider_version,
            "python_runtime_version": self.python_runtime_version,
            "airflow_version_status": self.airflow_version_status,
            "fab_provider_version_status": self.fab_provider_status,
            "python_version_status": self.python_version_status,
            "capability_advisory_count": str(self.capability_advisory_count),
            "version_advisory_count": str(self.version_advisory_count),
            "non_admin_contract_count": str(self.non_admin_contract_count),
            "non_admin_contract_gap_count": str(self.non_admin_contract_gap_count),
            "non_admin_role_consistency_issue_count": str(
                self.non_admin_role_consistency_issue_count
            ),
            "target_airflow_lines": ",".join(self.target_airflow_lines),
            "compatibility_recommendation_count": str(len(self.recommendations)),
            "compatibility_advisory_count": str(len(self.advisories)),
        }


def _build_recommendations(
    *,
    contract_gap_count: int,
    consistency_issue_count: int,
    version_statuses: tuple[str, str, str],
) -> tuple[str, ...]:
    """Return deterministic governance recommendations based on the current report state."""
    airflow_status, fab_status, python_status = version_statuses
    recommendations: list[str] = []

    if contract_gap_count or consistency_issue_count:
        recommendations.append(
            "Review non-admin mirrored RBAC contracts and shipped role bundles before promoting the deploy bundle."
        )
    if airflow_status in {"next_minor", "future_minor", "unsupported_major"}:
        recommendations.append(
            "Run auth-manager contract tests against the current Airflow line and verify compatibility adapters before upgrade."
        )
    if fab_status in {"older_than_latest_baseline", "unknown"}:
        recommendations.append(
            "Review the FAB provider line and refresh compatibility validation before release."
        )
    if python_status in {"future_minor", "unsupported"}:
        recommendations.append(
            "Validate the runtime on the active Python minor with the Airflow/FAB matrix before release."
        )
    if not recommendations:
        recommendations.append(
            "Compatibility governance checks are clean; continue with live Airflow matrix validation for the target environment."
        )
    return tuple(recommendations)


def build_operator_doctor_report(cfg: AuthConfig) -> OperatorDoctorReport:
    """Build a compact compatibility/governance report for operators and maintainers."""
    capability_report = build_runtime_capability_report(cfg)
    version_policy = build_runtime_version_policy_report()
    matrix = build_non_admin_compatibility_matrix(cfg)
    consistency_issues = evaluate_non_admin_role_consistency(cfg)
    contract_gap_count = sum(1 for row in matrix if row.shipped_role_consistency)
    advisories = tuple(version_policy.advisories)
    recommendations = _build_recommendations(
        contract_gap_count=contract_gap_count,
        consistency_issue_count=len(consistency_issues),
        version_statuses=(
            version_policy.airflow_status,
            version_policy.fab_provider_status,
            version_policy.python_status,
        ),
    )

    return OperatorDoctorReport(
        airflow_runtime_version=version_policy.airflow_version or "unavailable",
        fab_provider_version=version_policy.fab_provider_version or "unavailable",
        python_runtime_version=version_policy.python_version,
        airflow_version_status=version_policy.airflow_status,
        fab_provider_status=version_policy.fab_provider_status,
        python_version_status=version_policy.python_status,
        capability_advisory_count=int(capability_report.get("config_advisories", "0")),
        version_advisory_count=len(version_policy.advisories),
        non_admin_contract_count=len(matrix),
        non_admin_contract_gap_count=contract_gap_count,
        non_admin_role_consistency_issue_count=len(consistency_issues),
        target_airflow_lines=_TARGET_AIRFLOW_LINES,
        recommendations=recommendations,
        advisories=advisories,
    )


__all__ = (
    "OperatorDoctorReport",
    "build_operator_doctor_report",
)
