from __future__ import annotations

import argparse
import json
import re
from defusedxml import ElementTree as ET  # type: ignore[import-untyped]
from pathlib import Path
from typing import Any, Iterable, Sequence

FAILURE_PATTERNS = (
    re.compile(r"^FAILED\b"),
    re.compile(r"^ERROR\b"),
    re.compile(r"Traceback \(most recent call last\):"),
    re.compile(r"##\[error\]"),
    re.compile(r"Process completed with exit code"),
    re.compile(r"ModuleNotFoundError:"),
    re.compile(r"ImportError:"),
    re.compile(r"AssertionError:"),
    re.compile(r"RuntimeError:"),
    re.compile(r"SystemExit:"),
)
SEVERITY_PATTERNS = {
    "critical": re.compile(r"\b(CRITICAL|FATAL)\b", re.IGNORECASE),
    "error": re.compile(r"\b(ERROR|FAILED|Exception|Traceback)\b", re.IGNORECASE),
    "warning": re.compile(r"\b(WARNING|WARN)\b", re.IGNORECASE),
    "info": re.compile(r"\bINFO\b", re.IGNORECASE),
    "debug": re.compile(r"\bDEBUG\b", re.IGNORECASE),
}
IGNORED_FAILURE_SNIPPETS = (
    "Dependencies not met for <TaskInstance:",
    "dependency 'Trigger Rule' FAILED",
)


def _iter_files(artifact_dir: Path) -> list[Path]:
    return sorted(path for path in artifact_dir.rglob("*") if path.is_file())


def _candidate_logs(files: Iterable[Path]) -> list[Path]:
    suffixes = {".log", ".txt", ".out", ".err", ".xml"}
    return [path for path in files if path.suffix.lower() in suffixes]


def _first_failure_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                text = line.rstrip()
                if any(snippet in text for snippet in IGNORED_FAILURE_SNIPPETS):
                    continue
                if any(pattern.search(text) for pattern in FAILURE_PATTERNS):
                    return text
    except OSError:
        return None
    return None


def _read_junit_summary(path: Path) -> dict[str, int] | None:
    if path.suffix.lower() != ".xml":
        return None
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    except (ET.ParseError, OSError, ValueError):
        return None

    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    if not suites:
        return None

    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0"))
        failures += int(suite.attrib.get("failures", "0"))
        errors += int(suite.attrib.get("errors", "0"))
        skipped += int(suite.attrib.get("skipped", "0"))
    return {
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
    }


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
    junit_files = [path for path in logs if path.suffix.lower() == ".xml"]
    junit_summaries = {
        path.relative_to(artifact_dir).as_posix(): summary
        for path in junit_files
        if (summary := _read_junit_summary(path)) is not None
    }

    first_failure: dict[str, str] | None = None
    for rel_name, summary in junit_summaries.items():
        if summary["failures"] or summary["errors"]:
            first_failure = {
                "file": Path(rel_name).name,
                "line": (
                    f"JUnit reported failures={summary['failures']} "
                    f"errors={summary['errors']} skipped={summary['skipped']}"
                ),
            }
            break

    if first_failure is None:
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
        "junit": junit_summaries,
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

    lines = [
        f"# {summary['lane_name']} artifact summary",
        "",
        "## High-level status",
        "",
    ]
    overview_rows: list[tuple[str, str]] = [
        ("Job or lane", str(summary["lane_name"])),
        ("Status", str(summary.get("status", "unknown"))),
        ("Artifact directory scanned", f"`{summary['artifact_dir']}`"),
        ("Produced files", str(summary["file_count"])),
        ("Primary evidence file", str(summary.get("relevant_log") or "-")),
    ]
    first_failure_obj = summary.get("first_failure")
    if isinstance(first_failure_obj, dict):
        overview_rows.append(
            ("First failing file", str(first_failure_obj.get("file", "-")))
        )
        overview_rows.append(
            ("First failing line", str(first_failure_obj.get("line", "-")))
        )
    else:
        overview_rows.append(("First failing line", "none detected"))
    _table(lines, ("Field", "Value"), overview_rows)

    severity_obj = summary.get("severity")
    severity_map = severity_obj if isinstance(severity_obj, dict) else {}
    severity_rows = [
        (level, str(int(severity_map.get(level, 0))))
        for level in ("critical", "error", "warning", "info", "debug")
    ]
    lines.extend(["", "## What was produced and how it was judged", ""])
    _table(lines, ("Signal", "Value"), severity_rows)

    junit_obj = summary.get("junit")
    if isinstance(junit_obj, dict) and junit_obj:
        lines.extend(["", "## JUnit evidence", ""])
        junit_rows: list[tuple[str, str, str, str, str]] = []
        for name, result in junit_obj.items():
            if isinstance(result, dict):
                junit_rows.append(
                    (
                        str(name),
                        str(int(result.get("tests", 0))),
                        str(int(result.get("failures", 0))),
                        str(int(result.get("errors", 0))),
                        str(int(result.get("skipped", 0))),
                    )
                )
        _table(
            lines, ("JUnit file", "Tests", "Failures", "Errors", "Skipped"), junit_rows
        )

    files_obj = summary.get("files")
    files: list[str] = (
        [str(item) for item in files_obj] if isinstance(files_obj, list) else []
    )
    lines.extend(["", "## Files used for this judgment", ""])
    _table(lines, ("Artifact file",), [(item,) for item in files])

    tail_obj = summary.get("tail")
    tail: list[str] = (
        [str(item) for item in tail_obj] if isinstance(tail_obj, list) else []
    )
    lines.extend(["", "## Detailed result evidence", ""])
    if tail:
        lines.extend(["", "```text"])
        lines.extend(tail)
        lines.append("```")
    else:
        lines.append("No log tail was available for this lane.")

    lines.extend(["", "## Result guide", ""])
    lines.append(
        "- success: no failure signature was detected in the captured artifacts or JUnit outputs"
    )
    lines.append(
        "- failed: a JUnit failure/error or a strict failure signature was detected and the first matching evidence is shown above"
    )
    lines.append(
        "- counts: critical/error/warning/info/debug are pattern-based counts derived from the captured files"
    )
    lines.append(
        "- Airflow runtime debug messages that contain the word FAILED inside dependency diagnostics are ignored to avoid false negatives"
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
