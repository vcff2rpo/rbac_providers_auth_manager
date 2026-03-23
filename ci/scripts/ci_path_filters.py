from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PATH_FILTERS_PATH = REPO_ROOT / "ci" / "config" / "path_filters.json"


def load_path_filters() -> dict[str, Any]:
    return json.loads(PATH_FILTERS_PATH.read_text(encoding="utf-8"))


def workflow_paths(data: dict[str, Any], workflow: str, event: str) -> tuple[str, ...]:
    return tuple(str(item) for item in data["workflows"][workflow][event])


def workflow_file_path(workflow: str) -> Path:
    return REPO_ROOT / ".github" / "workflows" / f"{workflow}.yml"


def workflow_declared_paths(workflow_path: Path, event: str) -> tuple[str, ...]:
    payload = yaml.load(
        workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    event_data = payload["on"][event]
    return tuple(str(item) for item in event_data["paths"])


def emit_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# CI path-filter registry",
        "",
        "| Workflow | Event | Paths |",
        "| --- | --- | --- |",
    ]
    for workflow, events in sorted(data["workflows"].items()):
        for event, paths in sorted(events.items()):
            lines.append(
                f"| {workflow} | {event} | {'<br>'.join(str(item) for item in paths)} |"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read or render CI path-filter registry"
    )
    parser.add_argument("--workflow")
    parser.add_argument("--event")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()

    data = load_path_filters()
    if args.workflow and args.event:
        output = json.dumps(workflow_paths(data, args.workflow, args.event))
    elif args.markdown:
        output = emit_markdown(data)
    else:
        output = json.dumps(data, indent=2, sort_keys=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            output + ("" if output.endswith("\n") else "\n"), encoding="utf-8"
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
