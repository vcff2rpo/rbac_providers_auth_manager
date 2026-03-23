from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render committed CI workflow input/default reference artifacts"
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    return parser.parse_args()


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _normalize_inputs(raw_inputs: dict[str, Any] | None) -> list[dict[str, str]]:
    if not raw_inputs:
        return []
    rows: list[dict[str, str]] = []
    for input_name, meta in sorted(raw_inputs.items()):
        meta_dict = dict(meta or {})
        rows.append(
            {
                "name": str(input_name),
                "type": str(meta_dict.get("type", "string")),
                "required": str(meta_dict.get("required", "false")),
                "default": str(meta_dict.get("default", "")),
                "description": str(meta_dict.get("description", "")),
            }
        )
    return rows


def build_workflow_inputs(repo_root: Path) -> dict[str, Any]:
    workflows_dir = repo_root / ".github" / "workflows"
    reusable: list[dict[str, Any]] = []
    entrypoints: list[dict[str, Any]] = []
    for workflow_path in sorted(workflows_dir.glob("*.yml")):
        payload = _load_yaml(workflow_path)
        on_block = dict(payload.get("on", {}))
        workflow_name = str(payload.get("name", workflow_path.stem))
        workflow_ref = workflow_path.relative_to(repo_root).as_posix()

        workflow_call = on_block.get("workflow_call")
        workflow_call_inputs = (
            workflow_call.get("inputs") if isinstance(workflow_call, dict) else None
        )
        if "workflow_call" in on_block:
            reusable.append(
                {
                    "workflow": workflow_path.stem,
                    "name": workflow_name,
                    "path": workflow_ref,
                    "inputs": _normalize_inputs(workflow_call_inputs),
                }
            )

        workflow_dispatch = on_block.get("workflow_dispatch")
        workflow_dispatch_inputs = (
            workflow_dispatch.get("inputs")
            if isinstance(workflow_dispatch, dict)
            else None
        )
        if "workflow_dispatch" in on_block:
            entrypoints.append(
                {
                    "workflow": workflow_path.stem,
                    "name": workflow_name,
                    "path": workflow_ref,
                    "inputs": _normalize_inputs(workflow_dispatch_inputs),
                }
            )

    return {
        "reusable_workflows": reusable,
        "workflow_dispatch_entrypoints": entrypoints,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# CI workflow inputs",
        "",
        "This file is generated from workflow YAML and summarizes reusable-workflow defaults plus manual entrypoint inputs.",
        "",
        "## Reusable workflow inputs",
        "",
    ]
    for workflow in payload["reusable_workflows"]:
        lines.extend(
            [
                f"### {workflow['name']}",
                "",
                f"- workflow: `{workflow['workflow']}`",
                f"- path: `{workflow['path']}`",
                "",
                "| Input | Type | Required | Default | Description |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        if workflow["inputs"]:
            for item in workflow["inputs"]:
                default = item["default"].replace("\n", "<br>")
                description = item["description"].replace("\n", " ")
                lines.append(
                    f"| {item['name']} | {item['type']} | {item['required']} | {default} | {description} |"
                )
        else:
            lines.append("| - | - | - | - | No workflow_call inputs declared. |")
        lines.append("")

    lines.extend(["## Manual entrypoint inputs", ""])
    for workflow in payload["workflow_dispatch_entrypoints"]:
        lines.extend(
            [
                f"### {workflow['name']}",
                "",
                f"- workflow: `{workflow['workflow']}`",
                f"- path: `{workflow['path']}`",
                "",
                "| Input | Type | Required | Default | Description |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        if workflow["inputs"]:
            for item in workflow["inputs"]:
                default = item["default"].replace("\n", "<br>")
                description = item["description"].replace("\n", " ")
                lines.append(
                    f"| {item['name']} | {item['type']} | {item['required']} | {default} | {description} |"
                )
        else:
            lines.append("| - | - | - | - | No workflow_dispatch inputs declared. |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    payload = build_workflow_inputs(repo_root)
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
