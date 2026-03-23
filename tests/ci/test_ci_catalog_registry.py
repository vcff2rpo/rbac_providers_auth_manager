from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

manifest = importlib.import_module("tests.ci.contract_manifest")
ci_catalog_registry = importlib.import_module("ci_catalog_registry")
ci_summary_catalog = importlib.import_module("ci_summary_catalog")


def test_quality_family_files_follow_manifest_union() -> None:
    expected = tuple(
        sorted(
            {
                path
                for family in manifest.coverage_family_names()
                for path in manifest.coverage_family_files(family)
            }
        )
    )

    assert ci_catalog_registry.QUALITY_FAMILY_FILES == expected

    quality_tasks = {
        task.task: task.files for task in ci_summary_catalog.LANE_TASKS["quality"]
    }
    assert quality_tasks["pytest plugin-function families"] == expected


def test_deep_validation_shards_follow_manifest_groups() -> None:
    shard_tasks = {
        task.task.removeprefix("area shard: "): task.files
        for task in ci_summary_catalog.LANE_TASKS["deep_validation"]
        if task.task.startswith("area shard: ")
    }

    expected_families = tuple(
        family
        for family in manifest.coverage_family_names()
        if family != "bootstrap-imports"
    )
    assert tuple(shard_tasks) == expected_families

    for family in expected_families:
        assert shard_tasks[family] == manifest.deep_validation_group_files(family)


def test_suite_source_areas_cover_manifest_targets() -> None:
    expected = tuple(
        sorted(
            {
                str(area)
                for family in manifest.coverage_family_names()
                for area in manifest.COVERAGE_FAMILIES[family]["cov_targets"]
            }
        )
    )

    assert ci_catalog_registry.QUALITY_AND_DEEP_SOURCE_AREAS == expected
    assert set(expected).issubset(ci_summary_catalog.SUITE_SOURCE_AREAS["quality"])
    assert set(expected).issubset(
        ci_summary_catalog.SUITE_SOURCE_AREAS["deep_validation"]
    )
    assert {"tests/ci", "ci/scripts"}.issubset(
        ci_summary_catalog.SUITE_SOURCE_AREAS["quality"]
    )
    assert {"rbac_providers_auth_manager", "tests/ci", "ci/scripts"}.issubset(
        ci_summary_catalog.SUITE_SOURCE_AREAS["deep_validation"]
    )
