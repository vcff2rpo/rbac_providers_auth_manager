from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable, Sequence, cast

from ci_summary_catalog import (
    LANE_DISPLAY_NAMES,
    LANE_PURPOSE,
    LANE_TASKS,
    PHASES,
    SUITE_SOURCE_AREAS,
    SUPPLEMENTAL_AREAS,
    checkbox,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

LANE_ORDER = (
    "quality",
    "deep_validation",
    "airflow_integration",
    "identity_provider_integration",
    "fab_provider_validation",
    "nightly_compatibility",
    "external_real_validation",
    "license_compliance",
)

SUITE_BY_LANE = {
    "quality": "quality",
    "deep_validation": "quality",
    "airflow_integration": "airflow_integration",
    "identity_provider_integration": "identity_provider_integration",
    "fab_provider_validation": "fab_provider_validation",
    "nightly_compatibility": "fab_provider_validation",
    "external_real_validation": "external_real_validation",
    "license_compliance": None,
}

SUITE_FILE_OVERRIDES = {
    "identity_provider_integration": {
        "tests/ci/test_entra_browser_flow_integration.py",
    },
}


def _load_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render top-level manual CI summary")
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--run-url", default="")
    parser.add_argument("--source-sha", default="")
    for lane in LANE_ORDER:
        parser.add_argument(f"--{lane}-enabled", default="false")
        parser.add_argument(f"--{lane}-result", default="skipped")
    return parser.parse_args()


def _suite_files(manifest: ModuleType, lane: str) -> list[str]:
    suite = SUITE_BY_LANE.get(lane)
    if suite is None:
        return []
    if lane == "deep_validation":
        files: set[str] = set()
        for group in manifest.DEEP_VALIDATION_GROUPS.values():
            files.update(group)
        files.add("tests/ci/test_import_smoke.py")
        return sorted(files)
    if lane == "nightly_compatibility":
        return ["tests/ci/test_fab_provider_mirror_latest.py"]
    files = {str(item) for item in manifest.suite_files(suite)}
    files.update(SUITE_FILE_OVERRIDES.get(lane, set()))
    return sorted(files)


def _lane_capability_names(manifest: ModuleType, lane: str) -> list[str]:
    suite = SUITE_BY_LANE.get(lane)
    if suite is None:
        return []
    files = _suite_files(manifest, lane)
    file_set = set(files)
    tags: set[str] = set()
    if lane == "nightly_compatibility":
        tags.add("nightly_matrix")
    for contract in manifest.CONTRACTS:
        if contract.path in file_set:
            tags.update(str(tag) for tag in contract.capability_tags)
    names_by_tag = {
        str(item["tag"]): str(item["name"]) for item in manifest.CAPABILITY_CATALOG
    }
    return sorted(names_by_tag[tag] for tag in tags if tag in names_by_tag)


def _all_capability_rows(
    manifest: ModuleType, lane_status: dict[str, dict[str, object]]
) -> list[tuple[str, bool, str]]:
    tags_tested_in_run: set[str] = set()
    for lane, status in lane_status.items():
        if not bool(status["enabled"]):
            continue
        suite = SUITE_BY_LANE.get(lane)
        if suite is None:
            continue
        lane_files = set(_suite_files(manifest, lane))
        for contract in manifest.CONTRACTS:
            if contract.path in lane_files:
                tags_tested_in_run.update(str(tag) for tag in contract.capability_tags)
        if lane == "nightly_compatibility":
            tags_tested_in_run.add("nightly_matrix")

    rows: list[tuple[str, bool, str]] = []
    for item in manifest.CAPABILITY_CATALOG:
        tag = str(item["tag"])
        rows.append((str(item["name"]), tag in tags_tested_in_run, "contract manifest"))

    for item in SUPPLEMENTAL_AREAS:
        raw_lanes = cast(object, item.get("lanes", ()))
        lanes = tuple(str(v) for v in cast(Iterable[object], raw_lanes))
        tested = any(bool(lane_status.get(lane, {}).get("enabled")) for lane in lanes)
        rows.append(
            (
                str(item["name"]),
                tested and str(item["status"]) == "covered",
                "supplemental CI catalog",
            )
        )

    rows.sort(key=lambda row: (not row[1], row[0].casefold()))
    return rows


def _phase_result(
    lanes: Sequence[str], lane_status: dict[str, dict[str, object]]
) -> str:
    results: list[str] = []
    for lane in lanes:
        status = lane_status.get(lane)
        if not status or not bool(status["enabled"]):
            continue
        results.append(str(status["result"]))
    if not results:
        return "skipped"
    if any(result != "success" for result in results):
        return "failed"
    return "success"


def _blocking_items(lane_status: dict[str, dict[str, object]]) -> list[tuple[str, str]]:
    blockers: list[tuple[str, str]] = []
    for lane in LANE_ORDER:
        enabled = bool(lane_status[lane]["enabled"])
        result = str(lane_status[lane]["result"])
        if enabled and result != "success":
            blockers.append((LANE_DISPLAY_NAMES.get(lane, lane), result))
    return blockers


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


def main() -> None:
    args = _parse_args()
    manifest = _load_manifest()

    lane_status: dict[str, dict[str, object]] = {}
    for lane in LANE_ORDER:
        lane_status[lane] = {
            "enabled": _parse_bool(getattr(args, f"{lane}_enabled")),
            "result": str(getattr(args, f"{lane}_result")),
        }

    blockers = _blocking_items(lane_status)
    executed_lanes = [lane for lane in LANE_ORDER if bool(lane_status[lane]["enabled"])]
    passed_lanes = [
        lane for lane in executed_lanes if str(lane_status[lane]["result"]) == "success"
    ]

    lines: list[str] = [
        "# Final CI workflow summary",
        "",
        "## Executive overview",
        "",
    ]
    _table(
        lines,
        ("Metric", "Value"),
        [
            ("Enabled lanes in this run", str(len(executed_lanes))),
            ("Successful enabled lanes", str(len(passed_lanes))),
            ("Lanes with blocking results", str(len(blockers))),
            ("Run URL", args.run_url or "-"),
            ("Source SHA", args.source_sha or "-"),
        ],
    )

    lines.extend(["", "## Blocking items from this run", ""])
    if blockers:
        _table(lines, ("Lane", "Result"), blockers)
    else:
        lines.append("No blocking lane results were reported.")

    lines.extend(["", "## Logical phase overview", ""])
    _table(
        lines,
        ("Phase", "Lanes", "Phase result"),
        [
            (
                phase,
                "<br>".join(LANE_DISPLAY_NAMES.get(lane, lane) for lane in lanes),
                _phase_result(lanes, lane_status),
            )
            for phase, lanes in PHASES
        ],
    )

    lines.extend(["", "## High-level lane overview", ""])
    _table(
        lines,
        (
            "Lane",
            "Enabled",
            "Result",
            "Why this lane exists",
            "Job tasks executed",
            "Selected test files",
            "Main source areas",
        ),
        [
            (
                LANE_DISPLAY_NAMES.get(lane, lane),
                checkbox(bool(lane_status[lane]["enabled"])),
                str(lane_status[lane]["result"]),
                LANE_PURPOSE.get(lane, "-"),
                "<br>".join(task.task for task in LANE_TASKS.get(lane, ())) or "-",
                "<br>".join(_suite_files(manifest, lane)) or "-",
                "<br>".join(SUITE_SOURCE_AREAS.get(lane, ())) or "-",
            )
            for lane in LANE_ORDER
        ],
    )

    lines.extend(["", "## Detailed job-task report", ""])
    for phase, phase_lanes in PHASES:
        lines.extend([f"### {phase}", ""])
        for lane in phase_lanes:
            enabled = bool(lane_status[lane]["enabled"])
            result = str(lane_status[lane]["result"])
            lines.extend([f"#### {LANE_DISPLAY_NAMES.get(lane, lane)}", ""])
            lines.append(f"- enabled: {checkbox(enabled)}")
            lines.append(f"- result: {result}")
            lines.append(f"- purpose: {LANE_PURPOSE.get(lane, '-')}")
            lines.append(
                f"- capability areas planned in this lane: {', '.join(_lane_capability_names(manifest, lane)) or '-'}"
            )
            lines.append("")
            _table(
                lines,
                ("Job task", "Files used for the task", "What was tested"),
                [
                    (
                        task.task,
                        "<br>".join(task.files),
                        task.description,
                    )
                    for task in LANE_TASKS.get(lane, ())
                ],
            )
            lines.append("")

    lines.extend(["## Repository-wide area checklist for this run", ""])
    _table(
        lines,
        ("Tested in this run", "Area", "Source"),
        [
            (checkbox(tested), name, source)
            for name, tested, source in _all_capability_rows(manifest, lane_status)
        ],
    )

    lines.extend(["", "## Reading guide", ""])
    lines.append(
        "- Enabled/result tell you whether a lane was requested and whether the reusable workflow finished successfully."
    )
    lines.append(
        "- Job tasks executed lists the major checks the lane ran, while Selected test files highlights the contract files tied to that lane."
    )
    lines.append(
        "- The repository-wide checklist is the best place to see which areas were truly exercised in this workflow run versus still marked as not tested."
    )

    text = "\n".join(lines) + "\n"
    output_md = Path(args.output_md)
    output_json = Path(args.output_json)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(text, encoding="utf-8")
    output_json.write_text(json.dumps(lane_status, indent=2) + "\n", encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
