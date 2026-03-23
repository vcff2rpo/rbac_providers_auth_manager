from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

ci_lane_policy = importlib.import_module("ci_lane_policy")
ci_path_filters = importlib.import_module("ci_path_filters")
ci_versions = importlib.import_module("ci_versions")
render_ci_inventory = importlib.import_module("render_ci_inventory")
render_ci_reference = importlib.import_module("render_ci_reference")


def _reference_payload() -> dict[str, object]:
    return {
        "versions": ci_versions.load_versions(),
        "path_filters": ci_path_filters.load_path_filters(),
        "lane_policies": [policy.__dict__ for policy in ci_lane_policy.LANE_POLICIES],
        "inventory": render_ci_inventory.build_inventory(REPO_ROOT),
        "workflow_inputs": importlib.import_module(
            "render_ci_workflow_inputs"
        ).build_workflow_inputs(REPO_ROOT),
    }


def test_committed_ci_reference_markdown_is_synchronized() -> None:
    payload = _reference_payload()
    expected = render_ci_reference.render_markdown(payload)
    committed = (REPO_ROOT / "ci" / "CI_REFERENCE.md").read_text(encoding="utf-8")
    assert committed == expected


def test_committed_ci_reference_json_is_synchronized() -> None:
    payload = _reference_payload()
    expected = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    committed = (REPO_ROOT / "ci" / "CI_REFERENCE.json").read_text(encoding="utf-8")
    assert committed == expected
