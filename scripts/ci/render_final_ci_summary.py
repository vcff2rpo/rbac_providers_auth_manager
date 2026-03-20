from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

from ci_summary_catalog import (
    LANE_TASKS,
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


SUITE_FILE_OVERRIDES = {
    "identity_provider_integration": {
        "tests/ci/test_entra_browser_flow_integration.py",
    },
}


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
            tags.update(contract.capability_tags)
    names_by_tag = {
        str(item["tag"]): str(item["name"]) for item in manifest.CAPABILITY_CATALOG
    }
    return sorted(names_by_tag[tag] for tag in tags if tag in names_by_tag)


def _all_capability_rows(
    manifest: ModuleType, lane_status: dict[str, dict[str, object]]
) -> list[tuple[str, bool, str]]:
    names_by_tag = {
        str(item["tag"]): str(item["name"]) for item in manifest.CAPABILITY_CATALOG
    }
    tags_tested_in_run: set[str] = set()
    for lane, status in lane_status.items():
        if not status["enabled"]:
            continue
        suite = SUITE_BY_LANE.get(lane)
        if suite is None:
            continue
        for contract in manifest.CONTRACTS:
            if contract.path in set(_suite_files(manifest, lane)):
                tags_tested_in_run.update(str(tag) for tag in contract.capability_tags)
        if lane == "nightly_compatibility":
            tags_tested_in_run.add("nightly_matrix")

    rows: list[tuple[str, bool, str]] = []
    for item in manifest.CAPABILITY_CATALOG:
        tag = str(item["tag"])
        rows.append((str(item["name"]), tag in tags_tested_in_run, "contract manifest"))
    for item in SUPPLEMENTAL_AREAS:
        lanes = tuple(str(v) for v in item.get("lanes", ()))
        tested = any(bool(lane_status.get(lane, {}).get("enabled")) for lane in lanes)
        rows.append(
            (
                str(item["name"]),
                tested and item["status"] == "covered",
                "supplemental CI catalog",
            )
        )
    # Stable ordering: tested first, then alpha.
    rows.sort(key=lambda row: (not row[1], row[0].casefold()))
    return rows


def main() -> None:
    args = _parse_args()
    manifest = _load_manifest()

    lane_status: dict[str, dict[str, object]] = {}
    for lane in LANE_ORDER:
        lane_status[lane] = {
            "enabled": _parse_bool(getattr(args, f"{lane}_enabled")),
            "result": str(getattr(args, f"{lane}_result")),
        }

    lines: list[str] = [
        "# Final CI workflow summary",
        "",
        "## High-level lane overview",
        "",
    ]
    lines.append(
        "| Lane | Enabled in this run | Result | Job tasks executed | Selected test files | Main source areas |"
    )
    lines.append("|---|---|---|---|---|---|")

    for lane in LANE_ORDER:
        enabled = bool(lane_status[lane]["enabled"])
        result = str(lane_status[lane]["result"])
        tasks = "<br>".join(task.task for task in LANE_TASKS.get(lane, ())) or "-"
        files = _suite_files(manifest, lane)
        file_text = "<br>".join(files) if files else "-"
        source_areas = "<br>".join(SUITE_SOURCE_AREAS.get(lane, ())) or "-"
        lines.append(
            f"| {lane} | {checkbox(enabled)} | {result} | {tasks} | {file_text} | {source_areas} |"
        )

    lines.extend(["", "## Detailed job-task report", ""])
    for lane in LANE_ORDER:
        enabled = bool(lane_status[lane]["enabled"])
        result = str(lane_status[lane]["result"])
        lines.extend([f"### {lane}", ""])
        lines.append(f"- enabled: {checkbox(enabled)}")
        lines.append(f"- result: {result}")
        lines.append(
            f"- capability areas planned in this lane: {', '.join(_lane_capability_names(manifest, lane)) or '-'}"
        )
        lines.append("")
        lines.append("| Job task | Files used for the task | What was tested |")
        lines.append("|---|---|---|")
        for task in LANE_TASKS.get(lane, ()):
            lines.append(
                f"| {task.task} | {'<br>'.join(task.files)} | {task.description} |"
            )
        if lane not in LANE_TASKS:
            lines.append("| - | - | - |")
        lines.append("")

    lines.extend(["## Repository-wide area checklist for this run", ""])
    lines.append("| Tested in this run | Area | Source |")
    lines.append("|---|---|---|")
    for name, tested, source in _all_capability_rows(manifest, lane_status):
        lines.append(f"| {checkbox(tested)} | {name} | {source} |")

    lines.extend(["", "## Run metadata", ""])
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Run URL | {args.run_url or '-'} |")
    lines.append(f"| Source SHA | {args.source_sha or '-'} |")

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
