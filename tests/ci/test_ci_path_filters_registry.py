from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

ci_path_filters = importlib.import_module("ci_path_filters")


def test_path_filter_registry_has_ci_self_check_entries() -> None:
    data = ci_path_filters.load_path_filters()
    assert tuple(data["workflows"]["ci_self_check"]["pull_request"]) == (
        ".github/workflows/**",
        "ci/**",
        "tests/ci/**",
        "pyproject.toml",
        "pytest.ini",
        "mypy.ini",
        "docs/CI_OVERVIEW.md",
    )


def test_path_filter_registry_has_quality_fast_entries() -> None:
    data = ci_path_filters.load_path_filters()
    paths = tuple(data["workflows"]["quality_fast"]["pull_request"])
    assert "authorization/**" in paths
    assert "services/**" in paths
    assert ".github/workflows/quality_fast.yml" in paths


def test_ci_self_check_workflow_paths_match_registry() -> None:
    data = ci_path_filters.load_path_filters()
    workflow_path = ci_path_filters.workflow_file_path("ci_self_check")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "pull_request"
    ) == ci_path_filters.workflow_paths(data, "ci_self_check", "pull_request")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "push"
    ) == ci_path_filters.workflow_paths(data, "ci_self_check", "push")


def test_quality_fast_workflow_paths_match_registry() -> None:
    data = ci_path_filters.load_path_filters()
    workflow_path = ci_path_filters.workflow_file_path("quality_fast")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "pull_request"
    ) == ci_path_filters.workflow_paths(data, "quality_fast", "pull_request")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "push"
    ) == ci_path_filters.workflow_paths(data, "quality_fast", "push")


def test_path_filter_registry_has_compliance_fast_entries() -> None:
    data = ci_path_filters.load_path_filters()
    paths = tuple(data["workflows"]["compliance_fast"]["pull_request"])
    assert "LICENSE" in paths
    assert "LICENSES/**" in paths
    assert ".github/workflows/compliance_fast.yml" in paths


def test_compliance_fast_workflow_paths_match_registry() -> None:
    data = ci_path_filters.load_path_filters()
    workflow_path = ci_path_filters.workflow_file_path("compliance_fast")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "pull_request"
    ) == ci_path_filters.workflow_paths(data, "compliance_fast", "pull_request")
    assert ci_path_filters.workflow_declared_paths(
        workflow_path, "push"
    ) == ci_path_filters.workflow_paths(data, "compliance_fast", "push")
