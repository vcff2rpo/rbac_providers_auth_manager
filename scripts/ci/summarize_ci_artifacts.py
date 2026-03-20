from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable, Sequence

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
SEVERITY_PATTERNS = {
    "critical": re.compile(r"\b(CRITICAL|FATAL)\b", re.IGNORECASE),
    "error": re.compile(r"\b(ERROR|FAILED|Exception|Traceback)\b", re.IGNORECASE),
    "warning": re.compile(r"\b(WARNING|WARN)\b", re.IGNORECASE),
    "info": re.compile(r"\bINFO\b", re.IGNORECASE),
    "debug": re.compile(r"\bDEBUG\b", re.IGNORECASE),
}


def _iter_files(artifact_dir: Path) -> list[Path]:
    return sorted(path for path in artifact_dir.rglob("*") if path.is_file())


def _candidate_logs(files: Iterable[Path]) -> list[Path]:
    suffixes = {".log", ".txt", ".out", ".err", ".xml", ".md", ".json"}
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


def _severity_counts(logs: Iterable[Path]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_PATTERNS}
    for path in logs:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            for level, pattern in SEVERITY_PATTERNS.items():
                if pattern.search(line):
                    counts[level] += 1
    return counts


def build_summary(
    artifact_dir: Path, lane_name: str, tail_limit: int
) -> dict[str, Any]:
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
    severity = _severity_counts(logs)
    return {
        "lane_name": lane_name,
        "artifact_dir": artifact_dir.as_posix(),
        "file_count": len(files),
        "files": [path.relative_to(artifact_dir).as_posix() for path in files],
        "first_failure": first_failure,
        "relevant_log": relevant_log.name if relevant_log else None,
        "tail": tail,
        "severity": severity,
        "status": "failed" if first_failure else "success",
    }


def _table(
    lines: list[str], headers: Sequence[str], rows: Sequence[Sequence[str]]
) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    if rows:
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")


def write_outputs(
    summary: dict[str, Any], output_md: Path, output_json: Path | None
) -> None:
    output_md.parent.mkdir(parents=True, exist_ok=True)
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [f"# {summary['lane_name']} artifact summary", "", "## Overview", ""]
    overview_rows: list[tuple[str, str]] = [
        ("Status", str(summary.get("status", "unknown"))),
        ("Artifact dir", f"`{summary['artifact_dir']}`"),
        ("Produced files", str(summary["file_count"])),
        ("Relevant log", str(summary.get("relevant_log") or "-")),
    ]
    first_failure_obj = summary.get("first_failure")
    if isinstance(first_failure_obj, dict):
        overview_rows.append(
            ("First failure file", str(first_failure_obj.get("file", "-")))
        )
        overview_rows.append(
            ("First failure line", str(first_failure_obj.get("line", "-")))
        )
    else:
        overview_rows.append(("First failure line", "none detected"))
    _table(lines, ("Field", "Value"), overview_rows)

    severity_obj = summary.get("severity")
    severity_map = severity_obj if isinstance(severity_obj, dict) else {}
    severity_rows = [
        (level, str(int(severity_map.get(level, 0))))
        for level in ("critical", "error", "warning", "info", "debug")
    ]
    lines.extend(["", "## Severity scan", ""])
    _table(lines, ("Level", "Count"), severity_rows)

    files_obj = summary.get("files")
    files: list[str] = (
        [str(item) for item in files_obj] if isinstance(files_obj, list) else []
    )
    lines.extend(["", "## Produced files", ""])
    _table(lines, ("File",), [(item,) for item in files])

    tail_obj = summary.get("tail")
    tail: list[str] = (
        [str(item) for item in tail_obj] if isinstance(tail_obj, list) else []
    )
    if tail:
        lines.extend(["", "## Tail of relevant log", "", "```text"])
        lines.extend(tail)
        lines.append("```")

    lines.extend(["", "## Result guide", ""])
    lines.append("- success: no failure line detected in captured artifacts")
    lines.append("- failed: failure line detected in captured artifacts")
    lines.append(
        "- critical/error/warning/info/debug: counts derived from artifact log content"
    )
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize CI artifact directory contents."
    )
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--lane-name", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json")
    parser.add_argument("--tail-lines", type=int, default=100)
    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    output_json = Path(args.output_json) if args.output_json else None
    summary = build_summary(artifact_dir, args.lane_name, args.tail_lines)
    write_outputs(summary, Path(args.output_md), output_json)
    print(Path(args.output_md).read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
