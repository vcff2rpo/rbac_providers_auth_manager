from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_SCRIPTS = REPO_ROOT / "ci" / "scripts"
for candidate in (str(REPO_ROOT), str(CI_SCRIPTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

render_project_ci_overview = importlib.import_module("render_project_ci_overview")


def test_committed_project_ci_overview_is_synchronized() -> None:
    payload = render_project_ci_overview.build_payload(REPO_ROOT)
    expected = render_project_ci_overview.render_markdown(payload)
    committed = (REPO_ROOT / "docs" / "CI_OVERVIEW.md").read_text(encoding="utf-8")
    assert committed == expected
