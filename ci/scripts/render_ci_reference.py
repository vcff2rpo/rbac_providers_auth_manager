from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ci_lane_policy import LANE_POLICIES
from ci_path_filters import load_path_filters
from ci_versions import load_versions
from render_ci_inventory import build_inventory
from render_ci_workflow_inputs import build_workflow_inputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render committed CI reference documentation"
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    return parser.parse_args()


def render_markdown(payload: dict[str, Any]) -> str:
    versions = payload["versions"]
    filters = payload["path_filters"]["workflows"]
    inventory = payload["inventory"]
    workflow_inputs = payload["workflow_inputs"]
    lines: list[str] = [
        "# CI reference",
        "",
        "This file is generated from the CI-owned registries under `ci/` and should be updated whenever workflow structure, version pins, or path-filter ownership changes.",
        "",
        "## Version registry",
        "",
        "| Area | Value |",
        "| --- | --- |",
        f"| Python primary | {versions['python']['primary']} |",
        f"| Python secondary | {versions['python']['secondary']} |",
        f"| Deep-validation matrix | {', '.join(versions['python']['deep_validation'])} |",
        f"| Nightly matrix | {', '.join(versions['python']['nightly'])} |",
        f"| Airflow default | {versions['airflow']['default']} |",
        f"| FAB provider default | {versions['fab_provider']['default']} |",
        f"| Derived deep-validation Python context | {', '.join(versions['python']['deep_validation'])} |",
        f"| Derived nightly Airflow context | {', '.join(versions['airflow']['nightly'])} |",
        "",
        "Top-level workflows resolve their version and matrix defaults from the `export-ci-context` action backed by `ci/scripts/ci_versions.py`, so the pinned context lives in one CI-owned registry.",
        "",
        "## Lane policy registry",
        "",
        "| Lane | Workflow | Blocking | Cadence | Secrets profile | Artifact prefix | Summary group | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for lane in payload["lane_policies"]:
        lines.append(
            f"| {lane['lane']} | {lane['workflow']} | {'yes' if lane['blocking'] else 'no'} | {lane['cadence']} | {lane['secrets_profile']} | {lane['artifact_prefix']} | {lane['summary_group']} | {lane['notes']} |"
        )

    lines.extend(
        [
            "",
            "## Path-filter registry",
            "",
            "| Workflow | Event | Paths |",
            "| --- | --- | --- |",
        ]
    )
    for workflow, events in sorted(filters.items()):
        for event, paths in sorted(events.items()):
            lines.append(
                f"| {workflow} | {event} | {'<br>'.join(str(item) for item in paths)} |"
            )

    lines.extend(
        [
            "",
            "## CI-owned file layout",
            "",
            f"- composite actions: {len(inventory['actions'])}",
            f"- bash helpers: {len(inventory['bash_helpers'])}",
            f"- python helpers: {len(inventory['python_helpers'])}",
            f"- requirement sets: {len(inventory['requirements'])}",
            f"- config files: {len(inventory['config'])}",
            f"- workflows: {len(inventory['workflows'])}",
            f"- reusable workflows with declared inputs: {len(workflow_inputs['reusable_workflows'])}",
            f"- manual entrypoints with dispatch inputs: {len(workflow_inputs['workflow_dispatch_entrypoints'])}",
            "",
            "### Composite actions",
            "",
        ]
    )
    for item in inventory["actions"]:
        lines.append(f"- `{item}`")
    lines.extend(["", "### Python helpers", ""])
    for item in inventory["python_helpers"]:
        lines.append(f"- `{item}`")
    lines.extend(["", "### Workflows", ""])
    for item in inventory["workflows"]:
        lines.append(f"- `{item}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    payload = {
        "versions": load_versions(),
        "path_filters": load_path_filters(),
        "lane_policies": [policy.__dict__ for policy in LANE_POLICIES],
        "inventory": build_inventory(repo_root),
        "workflow_inputs": build_workflow_inputs(repo_root),
    }
    out_md = Path(args.output_md)
    out_json = Path(args.output_json)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
