from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ci_lane_policy import LANE_POLICIES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render CI inventory documentation.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    return parser.parse_args()


def relative_sorted_files(base: Path) -> list[str]:
    return sorted(
        str(path.relative_to(base.parent)).replace("\\", "/")
        for path in base.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    )


def build_inventory(repo_root: Path) -> dict[str, Any]:
    ci_root = repo_root / "ci"
    workflows_root = repo_root / ".github" / "workflows"
    return {
        "lanes": [asdict(policy) for policy in LANE_POLICIES],
        "actions": relative_sorted_files(ci_root / "actions"),
        "bash_helpers": relative_sorted_files(ci_root / "bash"),
        "python_helpers": relative_sorted_files(ci_root / "scripts"),
        "requirements": relative_sorted_files(ci_root / "requirements"),
        "config": relative_sorted_files(ci_root / "config"),
        "workflows": sorted(path.name for path in workflows_root.glob("*.yml")),
    }


def render_markdown(inventory: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# CI inventory")
    lines.append("")
    lines.append("## Lane policy registry")
    lines.append("")
    lines.append(
        "| Lane | Workflow | Blocking | Cadence | Secrets profile | Artifact prefix | Summary group | Notes |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for lane in inventory["lanes"]:
        lines.append(
            f"| {lane['lane']} | {lane['workflow']} | {'yes' if lane['blocking'] else 'no'} | {lane['cadence']} | {lane['secrets_profile']} | {lane['artifact_prefix']} | {lane['summary_group']} | {lane['notes']} |"
        )
    for section, title in (
        ("actions", "Composite actions"),
        ("bash_helpers", "Bash helpers"),
        ("python_helpers", "Python helpers"),
        ("requirements", "Requirement sets"),
        ("config", "CI configuration files"),
        ("workflows", "Workflows"),
    ):
        lines.append("")
        lines.append(f"## {title}")
        lines.append("")
        for item in inventory[section]:
            lines.append(f"- `{item}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    inventory = build_inventory(repo_root)
    Path(args.output_json).write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(args.output_md).write_text(render_markdown(inventory), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
