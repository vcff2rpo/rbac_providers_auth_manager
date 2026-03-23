from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

ci_lane_policy = importlib.import_module("ci_lane_policy")


def test_lane_policy_names_are_unique() -> None:
    names = [policy.lane for policy in ci_lane_policy.LANE_POLICIES]
    assert len(names) == len(set(names))


def test_lane_policies_point_to_existing_workflows() -> None:
    workflows_root = REPO_ROOT / ".github" / "workflows"
    for policy in ci_lane_policy.LANE_POLICIES:
        assert (workflows_root / policy.workflow).exists(), policy.workflow


def test_blocking_lanes_are_expected_release_gates() -> None:
    expected = {
        "quality",
        "deep_validation",
        "airflow_integration",
        "identity_provider_integration",
        "fab_provider_validation",
        "license_compliance",
    }
    assert set(ci_lane_policy.blocking_lane_names()) == expected
