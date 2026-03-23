from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class LanePolicy:
    lane: str
    workflow: str
    cadence: str
    blocking: bool
    secrets_profile: str
    artifact_prefix: str
    summary_group: str
    notes: str = ""


LANE_POLICIES: Final[tuple[LanePolicy, ...]] = (
    LanePolicy(
        lane="ci_self_check",
        workflow="reusable_ci_self_check.yml",
        cadence="per-change on CI-owned files",
        blocking=False,
        secrets_profile="none",
        artifact_prefix="ci-self-check",
        summary_group="ci-infrastructure",
        notes="Fast CI integrity lane for workflows, actions, registries, and summaries.",
    ),
    LanePolicy(
        lane="quality",
        workflow="reusable_quality.yml",
        cadence="per-change",
        blocking=True,
        secrets_profile="none",
        artifact_prefix="quality",
        summary_group="core-quality",
        notes="Fast lint, typing, unit, and family coverage gates.",
    ),
    LanePolicy(
        lane="deep_validation",
        workflow="reusable_deep_validation.yml",
        cadence="per-change optional",
        blocking=True,
        secrets_profile="none",
        artifact_prefix="deep-validation",
        summary_group="deep-validation",
        notes="Area-sharded coverage, dead-code, and wider behavioral validation.",
    ),
    LanePolicy(
        lane="airflow_integration",
        workflow="reusable_airflow_integration.yml",
        cadence="per-change optional",
        blocking=True,
        secrets_profile="none",
        artifact_prefix="airflow-integration",
        summary_group="integration",
        notes="Bootstraps Airflow runtime and validates plugin install/import health.",
    ),
    LanePolicy(
        lane="identity_provider_integration",
        workflow="reusable_identity_provider_integration.yml",
        cadence="per-change optional",
        blocking=True,
        secrets_profile="test-services",
        artifact_prefix="idp-integration",
        summary_group="integration",
        notes="Exercises LDAP and Entra integration-style flows without external enterprise secrets.",
    ),
    LanePolicy(
        lane="fab_provider_validation",
        workflow="reusable_fab_provider_validation.yml",
        cadence="per-change optional",
        blocking=True,
        secrets_profile="none",
        artifact_prefix="fab-provider-validation",
        summary_group="compatibility",
        notes="Installs official FAB provider and checks mirror drift.",
    ),
    LanePolicy(
        lane="nightly_compatibility",
        workflow="reusable_nightly_compatibility.yml",
        cadence="nightly or manual",
        blocking=False,
        secrets_profile="none",
        artifact_prefix="nightly-compatibility",
        summary_group="compatibility",
        notes="Matrix canary against pinned Airflow and FAB versions.",
    ),
    LanePolicy(
        lane="external_real_validation",
        workflow="reusable_external_real_validation.yml",
        cadence="manual opt-in",
        blocking=False,
        secrets_profile="external-real",
        artifact_prefix="external-real-validation",
        summary_group="external-validation",
        notes="Requires real external identity and DB-backed resources.",
    ),
    LanePolicy(
        lane="license_compliance",
        workflow="reusable_license_compliance.yml",
        cadence="per-change optional",
        blocking=True,
        secrets_profile="none",
        artifact_prefix="license-compliance",
        summary_group="release-readiness",
        notes="OSS compliance, build smoke, SBOM, and static security.",
    ),
)


def lane_policy_by_name() -> dict[str, LanePolicy]:
    return {policy.lane: policy for policy in LANE_POLICIES}


def workflow_names() -> tuple[str, ...]:
    return tuple(policy.workflow for policy in LANE_POLICIES)


def blocking_lane_names() -> tuple[str, ...]:
    return tuple(policy.lane for policy in LANE_POLICIES if policy.blocking)
