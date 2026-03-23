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

render_ci_workflow_inputs = importlib.import_module("render_ci_workflow_inputs")


def _payload() -> dict[str, object]:
    return render_ci_workflow_inputs.build_workflow_inputs(REPO_ROOT)


def test_committed_ci_workflow_inputs_markdown_is_synchronized() -> None:
    payload = _payload()
    expected = render_ci_workflow_inputs.render_markdown(payload)
    committed = (REPO_ROOT / "ci" / "CI_WORKFLOW_INPUTS.md").read_text(encoding="utf-8")
    assert committed == expected


def test_committed_ci_workflow_inputs_json_is_synchronized() -> None:
    payload = _payload()
    expected = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    committed = (REPO_ROOT / "ci" / "CI_WORKFLOW_INPUTS.json").read_text(
        encoding="utf-8"
    )
    assert committed == expected
