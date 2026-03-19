from __future__ import annotations

from pathlib import Path

import pytest

from .contract_manifest import contract_by_path, marker_names_for


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    contracts = contract_by_path()
    tier_counts: dict[str, int] = {}
    for item in items:
        rel_path = Path(str(item.fspath)).as_posix()
        marker_path = rel_path[rel_path.index("tests/ci/"):] if "tests/ci/" in rel_path else rel_path
        contract = contracts.get(marker_path)
        if contract is None:
            continue
        for marker_name in marker_names_for(marker_path):
            item.add_marker(getattr(pytest.mark, marker_name))
            tier_counts[marker_name] = tier_counts.get(marker_name, 0) + 1

    if tier_counts:
        summary = ", ".join(f"{name}={tier_counts[name]}" for name in sorted(tier_counts))
        tr = config.pluginmanager.get_plugin("terminalreporter")
        if tr is not None:
            tr.write_line(f"contract tier summary: {summary}")
