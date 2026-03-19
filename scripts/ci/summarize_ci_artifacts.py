from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

FAILURE_HINTS = (
    "Traceback",
    "FAILED",
    "ERROR",
    "Exception",
    "ModuleNotFoundError",
    "ImportError",
    "AssertionError",
    "Error:",
    "RuntimeError",
)


def _iter_files(artifact_dir: Path) -> list[Path]:
    return sorted(path for path in artifact_dir.rglob("*") if path.is_file())


def _candidate_logs(files: Iterable[Path]) -> list[Path]:
    suffixes = {".log", ".txt", ".out", ".err", ".xml", ".md"}
    return [path for path in files if path.suffix.lower() in suffixes]


def _first_failure_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                text = line.rstrip()
                if any(hint in text for hint in FAILURE_HINTS):
                    return text
    except OSError:
        return None
    return None


def _tail_lines(path: Path, limit: int) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-limit:]


def build_summary(
    artifact_dir: Path, lane_name: str, tail_limit: int
) -> dict[str, object]:
    files = _iter_files(artifact_dir)
    logs = _candidate_logs(files)
    first_failure: dict[str, str] | None = None
    for path in logs:
        failure = _first_failure_line(path)
        if failure:
            first_failure = {"file": path.name, "line": failure}
            break

    relevant_log = logs[0] if logs else None
    if first_failure is not None:
        for path in logs:
            if path.name == first_failure["file"]:
                relevant_log = path
                break

    tail = _tail_lines(relevant_log, tail_limit) if relevant_log else []
    return {
        "lane_name": lane_name,
        "artifact_dir": artifact_dir.as_posix(),
        "file_count": len(files),
        "files": [path.relative_to(artifact_dir).as_posix() for path in files],
        "first_failure": first_failure,
        "relevant_log": relevant_log.name if relevant_log else None,
        "tail": tail,
    }


def write_outputs(
    summary: dict[str, object], output_md: Path, output_json: Path
) -> None:
    output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# {summary['lane_name']} artifact summary",
        "",
        f"- artifact dir: `{summary['artifact_dir']}`",
        f"- produced files: {summary['file_count']}",
    ]
    first_failure = summary.get("first_failure")
    if isinstance(first_failure, dict):
        lines.extend(
            [
                f"- first failure file: `{first_failure['file']}`",
                f"- first failure line: `{first_failure['line']}`",
            ]
        )
    else:
        lines.append("- first failure line: none detected")

    files = summary.get("files", [])
    if isinstance(files, list) and files:
        lines.extend(["", "## Produced files"])
        lines.extend(f"- `{item}`" for item in files)

    tail = summary.get("tail", [])
    if isinstance(tail, list) and tail:
        lines.extend(["", "## Tail of relevant log", "```text"])
        lines.extend(str(item) for item in tail)
        lines.append("```")

    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize CI artifact directory contents."
    )
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--lane-name", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--tail-lines", type=int, default=100)
    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(artifact_dir, args.lane_name, args.tail_lines)
    write_outputs(summary, Path(args.output_md), Path(args.output_json))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
