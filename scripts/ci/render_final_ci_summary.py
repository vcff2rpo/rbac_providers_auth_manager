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


def checkbox(value: bool) -> str:
    return "[x] yes" if value else "[ ] no"


def _load_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render final manual CI summary")
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
        files: set[str] = {"tests/ci/test_import_smoke.py"}
        for group in manifest.DEEP_VALIDATION_GROUPS.values():
            files.update(str(item) for item in group)
        return sorted(files)
    if lane == "nightly_compatibility":
        return ["tests/ci/test_fab_provider_mirror_latest.py"]
    files = {str(item) for item in manifest.suite_files(suite)}
    files.update(SUITE_FILE_OVERRIDES.get(lane, set()))
    return sorted(files)


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


def _lane_capability_map(
    manifest: ModuleType,
    lane_status: dict[str, dict[str, object]],
    *,
    enabled_only: bool,
) -> tuple[dict[str, set[str]], dict[str, str]]:
    names_by_tag = {
        str(item["tag"]): str(item["name"]) for item in manifest.CAPABILITY_CATALOG
    }
    lane_to_tags: dict[str, set[str]] = {lane: set() for lane in LANE_ORDER}
    for lane in LANE_ORDER:
        if enabled_only and not bool(lane_status[lane]["enabled"]):
            continue
        for contract in manifest.CONTRACTS:
            if contract.path in set(_suite_files(manifest, lane)):
                lane_to_tags[lane].update(str(tag) for tag in contract.capability_tags)
        if lane == "nightly_compatibility":
            lane_to_tags[lane].add("nightly_matrix")
    return lane_to_tags, names_by_tag


def _capability_run_rows(
    manifest: ModuleType, lane_status: dict[str, dict[str, object]]
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    lane_to_tags, names_by_tag = _lane_capability_map(
        manifest, lane_status, enabled_only=True
    )
    all_lane_tags, _ = _lane_capability_map(manifest, lane_status, enabled_only=False)
    tag_to_lanes: dict[str, list[str]] = {}
    for lane, tags in lane_to_tags.items():
        for tag in tags:
            tag_to_lanes.setdefault(tag, []).append(lane)

    tested_rows: list[tuple[str, str, str]] = []
    missing_rows: list[tuple[str, str, str]] = []

    for item in manifest.CAPABILITY_CATALOG:
        tag = str(item["tag"])
        lanes = sorted(
            LANE_DISPLAY_NAMES.get(lane, lane) for lane in tag_to_lanes.get(tag, [])
        )
        if lanes:
            tested_rows.append(
                (
                    str(item["name"]),
                    "<br>".join(lanes),
                    "covered by executed contract tests",
                )
            )
            continue

        owning_lanes = [
            lane for lane in LANE_ORDER if tag in all_lane_tags.get(lane, set())
        ]
        if owning_lanes and not any(
            bool(lane_status[lane]["enabled"]) for lane in owning_lanes
        ):
            reason = "owning lane was not enabled in this run"
            expected = "<br>".join(
                LANE_DISPLAY_NAMES.get(lane, lane) for lane in owning_lanes
            )
        elif owning_lanes:
            reason = "lane executed but no tag mapping was resolved"
            expected = "<br>".join(
                LANE_DISPLAY_NAMES.get(lane, lane) for lane in owning_lanes
            )
        else:
            reason = "no CI contract lane is currently assigned to this area"
            expected = "-"
        missing_rows.append((str(item["name"]), expected, reason))

    for item in SUPPLEMENTAL_AREAS:
        lanes = [str(v) for v in cast(Iterable[object], item.get("lanes", ()))]
        enabled_lanes = [
            LANE_DISPLAY_NAMES.get(lane, lane)
            for lane in lanes
            if bool(lane_status.get(lane, {}).get("enabled"))
        ]
        status = str(item.get("status", "gap"))
        reason = str(item.get("reason", "")) or "no reason recorded"
        if status == "covered" and enabled_lanes:
            tested_rows.append((str(item["name"]), "<br>".join(enabled_lanes), reason))
        else:
            if lanes:
                if enabled_lanes:
                    gap_reason = reason
                else:
                    gap_reason = "owning lane was not enabled in this run"
            else:
                gap_reason = reason
            missing_rows.append(
                (
                    str(item["name"]),
                    "<br>".join(LANE_DISPLAY_NAMES.get(lane, lane) for lane in lanes)
                    or "-",
                    gap_reason,
                )
            )

    tested_rows.sort(key=lambda row: row[0].casefold())
    missing_rows.sort(key=lambda row: row[0].casefold())
    return tested_rows, missing_rows


def _blocking_items(lane_status: dict[str, dict[str, object]]) -> list[tuple[str, str]]:
    blockers: list[tuple[str, str]] = []
    for lane in LANE_ORDER:
        enabled = bool(lane_status[lane]["enabled"])
        result = str(lane_status[lane]["result"])
        if enabled and result != "success":
            blockers.append((LANE_DISPLAY_NAMES.get(lane, lane), result))
    return blockers


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
    tested_rows, missing_rows = _capability_run_rows(manifest, lane_status)
    total_areas = len(tested_rows) + len(missing_rows)
    coverage_percent = (
        round((len(tested_rows) / total_areas) * 100, 1) if total_areas else 0.0
    )

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
            (
                "Plugin functionality areas covered in this run",
                f"{len(tested_rows)}/{total_areas}",
            ),
            ("Coverage percentage for this run", f"{coverage_percent}%"),
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

    lines.extend(["", "## Lane overview", ""])
    _table(
        lines,
        (
            "Lane",
            "Executed",
            "Result",
            "Purpose",
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
            lines.append(f"- executed: {checkbox(enabled)}")
            lines.append(f"- result: {result}")
            lines.append(f"- purpose: {LANE_PURPOSE.get(lane, '-')}")
            lines.append("")
            _table(
                lines,
                ("Job task", "Files used for the task", "What was tested"),
                [
                    (task.task, "<br>".join(task.files), task.description)
                    for task in LANE_TASKS.get(lane, ())
                ],
            )
            lines.append("")

    lines.extend(["## Plugin functionality areas tested in this run", ""])
    _table(lines, ("Area", "Covered by lane(s)", "Evidence"), tested_rows)

    lines.extend(["", "## Areas still missing in this run", ""])
    _table(lines, ("Area", "Expected lane(s)", "Why it is missing"), missing_rows)

    lines.extend(["", "## Reading guide", ""])
    lines.append(
        "- Lane overview shows what actually ran and which test files or runtime checks were attached to that lane."
    )
    lines.append(
        "- Plugin functionality areas tested in this run is the main human-readable coverage section for the finished workflow."
    )
    lines.append(
        "- Areas still missing in this run explains whether coverage is absent because a lane was disabled or because the CI catalog still has an explicit gap."
    )

    payload = {
        "lane_status": lane_status,
        "tested_count": len(tested_rows),
        "missing_count": len(missing_rows),
        "coverage_percent": coverage_percent,
        "tested_rows": tested_rows,
        "missing_rows": missing_rows,
    }

    text = "\n".join(lines) + "\n"
    output_md = Path(args.output_md)
    output_json = Path(args.output_json)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(text, encoding="utf-8")
    output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
