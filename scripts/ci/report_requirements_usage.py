from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def build_usage(repo_root: Path) -> dict[str, list[str]]:
    workflows_dir = repo_root / ".github" / "workflows"
    requirements = sorted(
        p.relative_to(repo_root).as_posix()
        for p in repo_root.rglob("requirements*.txt")
    )
    workflow_text = {
        p.relative_to(repo_root).as_posix(): p.read_text(
            encoding="utf-8", errors="ignore"
        )
        for p in workflows_dir.glob("*.yml")
    }
    result: dict[str, list[str]] = {}
    for req in requirements:
        hits: list[str] = []
        basename = Path(req).name
        for wf, text in workflow_text.items():
            if req in text or basename in text:
                hits.append(wf)
        result[req] = sorted(hits)
    return result


def render_md(mapping: dict[str, list[str]]) -> str:
    lines = [
        "# Requirements usage report",
        "",
        "| Requirements file | Used by workflows | Status |",
        "|---|---|---|",
    ]
    for req, workflows in mapping.items():
        used = "<br>".join(workflows) if workflows else "—"
        status = "used" if workflows else "unused"
        lines.append(f"| `{req}` | {used} | {status} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    mapping = build_usage(repo_root)
    Path(args.output_md).write_text(render_md(mapping), encoding="utf-8")
    Path(args.output_json).write_text(
        json.dumps(mapping, indent=2) + "\n", encoding="utf-8"
    )
    print(render_md(mapping))


if __name__ == "__main__":
    main()
