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

render_ci_ownership = importlib.import_module("render_ci_ownership")


def test_committed_ci_ownership_json_is_synchronized() -> None:
    expected = (
        json.dumps(
            render_ci_ownership.build_ownership_payload(), indent=2, sort_keys=True
        )
        + "\n"
    )
    committed = (REPO_ROOT / "ci" / "CI_OWNERSHIP.json").read_text(encoding="utf-8")
    assert committed == expected
