from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

ci_versions = importlib.import_module("ci_versions")


def _load_yaml(path: str) -> dict[str, Any]:
    return yaml.load(
        (REPO_ROOT / path).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def _workflow_call_default(path: str, input_name: str) -> str:
    data = _load_yaml(path)
    on_block = cast(dict[str, Any], data["on"])
    workflow_call = cast(dict[str, Any], on_block["workflow_call"])
    inputs = cast(dict[str, Any], workflow_call["inputs"])
    input_meta = cast(dict[str, Any], inputs[input_name])
    return str(input_meta["default"])


def test_versions_registry_has_expected_keys() -> None:
    data = ci_versions.load_versions()
    assert data["python"]["primary"] == "3.13"
    assert data["python"]["secondary"] == "3.12"
    assert data["airflow"]["default"] == "3.1.8"
    assert data["fab_provider"]["default"] == "3.5.0"


def test_reusable_workflow_defaults_match_versions_registry() -> None:
    data = ci_versions.load_versions()
    assert _workflow_call_default(
        ".github/workflows/reusable_airflow_integration.yml", "airflow-version"
    ) == str(data["airflow"]["default"])
    assert _workflow_call_default(
        ".github/workflows/reusable_fab_provider_validation.yml",
        "airflow-version",
    ) == str(data["airflow"]["default"])
    assert _workflow_call_default(
        ".github/workflows/reusable_fab_provider_validation.yml",
        "fab-provider-version",
    ) == str(data["fab_provider"]["default"])
    assert _workflow_call_default(
        ".github/workflows/reusable_external_real_validation.yml",
        "airflow-version",
    ) == str(data["airflow"]["default"])
    assert _workflow_call_default(
        ".github/workflows/reusable_external_real_validation.yml",
        "fab-provider-version",
    ) == str(data["fab_provider"]["default"])
    assert _workflow_call_default(
        ".github/workflows/reusable_identity_provider_integration.yml",
        "python-version",
    ) == str(data["python"]["primary"])
    assert _workflow_call_default(
        ".github/workflows/reusable_license_compliance.yml", "python-version"
    ) == str(data["python"]["primary"])
    assert _workflow_call_default(
        ".github/workflows/reusable_quality.yml", "python-version"
    ) == str(data["python"]["primary"])
    assert _workflow_call_default(
        ".github/workflows/reusable_nightly_compatibility.yml", "airflow-versions"
    ) == json.dumps(data["airflow"]["nightly"])
    assert _workflow_call_default(
        ".github/workflows/reusable_nightly_compatibility.yml", "fab-provider-versions"
    ) == json.dumps(data["fab_provider"]["nightly"])
    assert _workflow_call_default(
        ".github/workflows/reusable_nightly_compatibility.yml", "python-versions"
    ) == json.dumps(data["python"]["nightly"])


def test_ci_versions_can_emit_workflow_context() -> None:
    data = ci_versions.load_versions()
    payload = ci_versions.build_ci_context(data)
    assert payload["python_primary"] == str(data["python"]["primary"])
    assert payload["python_secondary"] == str(data["python"]["secondary"])
    assert payload["airflow_default"] == str(data["airflow"]["default"])
    assert payload["fab_provider_default"] == str(data["fab_provider"]["default"])
    assert payload["python_deep_validation"] == json.dumps(
        data["python"]["deep_validation"]
    )


def test_top_level_workflows_use_resolved_ci_context() -> None:
    manual_ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    nightly = (REPO_ROOT / ".github/workflows/nightly_compatibility.yml").read_text(
        encoding="utf-8"
    )
    quality_fast = (REPO_ROOT / ".github/workflows/quality_fast.yml").read_text(
        encoding="utf-8"
    )
    ci_self_check = (REPO_ROOT / ".github/workflows/ci_self_check.yml").read_text(
        encoding="utf-8"
    )
    compliance_fast = (REPO_ROOT / ".github/workflows/compliance_fast.yml").read_text(
        encoding="utf-8"
    )

    for content in (manual_ci, nightly, quality_fast, ci_self_check, compliance_fast):
        assert "uses: ./ci/actions/export-ci-context" in content
        assert "resolve_ci_context:" in content

    assert "needs.resolve_ci_context.outputs.airflow_default" in manual_ci
    assert "needs.resolve_ci_context.outputs.fab_provider_default" in manual_ci
    assert "needs.resolve_ci_context.outputs.python_deep_validation" in manual_ci
    assert "needs.resolve_ci_context.outputs.airflow_nightly" in nightly
    assert "needs.resolve_ci_context.outputs.python_primary" in quality_fast
    assert "needs.resolve_ci_context.outputs.python_primary" in ci_self_check
    assert "needs.resolve_ci_context.outputs.python_primary" in compliance_fast
