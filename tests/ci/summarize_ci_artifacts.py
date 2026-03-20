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
SEVERITY_PATTERNS = {
    "critical": ("CRITICAL",),
    "warning": ("WARNING", "WARN"),
    "info": ("INFO",),
    "debug": ("DEBUG",),
    "error": ("ERROR", "FAILED", "TRACEBACK"),
}


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


def _severity_counts(logs: Iterable[Path]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_PATTERNS}
    for path in logs:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            upper = line.upper()
            for key, patterns in SEVERITY_PATTERNS.items():
                if any(pattern in upper for pattern in patterns):
                    counts[key] += 1
    return counts


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
        "severity_counts": _severity_counts(logs),
    }


def _table(
    lines: list[str], headers: tuple[str, ...], rows: list[tuple[str, ...]]
) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    if rows:
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")


def write_outputs(
    summary: dict[str, object], output_md: Path, output_json: Path
) -> None:
    output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    severity_counts = summary.get("severity_counts", {})
    files = summary.get("files", [])
    lines = [f"# {summary['lane_name']} artifact summary", "", "## Result overview", ""]
    _table(
        lines,
        ("Field", "Value"),
        [
            ("Artifact dir", f"`{summary['artifact_dir']}`"),
            ("Produced files", str(summary["file_count"])),
            ("Relevant log", str(summary.get("relevant_log") or "-")),
            (
                "First failure line",
                str((summary.get("first_failure") or {}).get("line", "none detected")),
            ),
        ],
    )
    lines.extend(["", "## Log severity scan", ""])
    severity_rows = []
    if isinstance(severity_counts, dict):
        severity_rows = [(key, str(value)) for key, value in severity_counts.items()]
    _table(lines, ("Level", "Count"), severity_rows)
    if isinstance(files, list) and files:
        lines.extend(["", "## Produced files", ""])
        _table(lines, ("File",), [(str(item),) for item in files])
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
    print(Path(args.output_md).read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
