from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

render_final_ci_summary = importlib.import_module("render_final_ci_summary")
ci_summary_catalog = importlib.import_module("ci_summary_catalog")


def test_ci_self_check_is_first_class_final_summary_lane() -> None:
    assert render_final_ci_summary.LANE_ORDER[0] == "ci_self_check"
    assert render_final_ci_summary.SUITE_BY_LANE["ci_self_check"] is None
    assert ci_summary_catalog.LANE_DISPLAY_NAMES["ci_self_check"] == "CI self-check"


def test_non_blocking_lane_does_not_create_blocker() -> None:
    lane_status = {
        lane: {"enabled": True, "result": "success"}
        for lane in render_final_ci_summary.LANE_ORDER
    }
    lane_status["ci_self_check"] = {"enabled": True, "result": "failure"}
    blockers = render_final_ci_summary._blocking_items(lane_status)
    assert ("CI self-check", "failure") not in blockers
